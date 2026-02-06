from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import requests
import socket
import ssl
import json
import hashlib
import re
import subprocess
from datetime import datetime
import os
import sqlite3
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database yaratish
def init_db():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    # Foydalanuvchilar jadvali
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Scan natijalari jadvali
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        results TEXT NOT NULL,
        severity TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Dastur ishga tushganda bazani tayyorlash
init_db()

# XSS himoyasi
def sanitize_input(input_string):
    if input_string:
        # HTML xavfli belgilarni o'zgartirish
        sanitized = input_string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;').replace("'", '&#39;')
        return sanitized
    return ""

# Login talab qiluvchi middleware
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Iltimos, avval tizimga kiring', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        email = sanitize_input(request.form.get('email'))
        
        if not username or not password or not email:
            flash('Barcha maydonlarni to\'ldiring', 'danger')
            return render_template('register.html')
        
        # Email validatsiyasi
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Yaroqli email manzilini kiriting', 'danger')
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                        (username, hashed_password, email))
            conn.commit()
            flash('Muvaffaqiyatli ro\'yxatdan o\'tdingiz! Endi tizimga kirishingiz mumkin', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Bu foydalanuvchi nomi yoki email allaqachon mavjud', 'danger')
        finally:
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Tizimga muvaffaqiyatli kirdingiz!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Noto\'g\'ri foydalanuvchi nomi yoki parol', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Siz tizimdan chiqdingiz', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id, target, scan_type, severity, created_at 
    FROM scans 
    WHERE user_id = ? 
    ORDER BY created_at DESC LIMIT 10
    """, (session['user_id'],))
    
    recent_scans = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', recent_scans=recent_scans)

# Port skanerlash
def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append({'port': port, 'service': service})
        sock.close()
    return open_ports

# SSL/TLS sertifikatlarini tekshirish
def check_ssl_certificate(hostname, port=443):
    results = {}
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Sertifikat ma'lumotlarini olish
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                
                # Sertifikat amal qilish muddati
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                current_date = datetime.now()
                days_left = (expiry_date - current_date).days
                
                results = {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'days_left': days_left,
                    'status': 'Valid' if days_left > 0 else 'Expired',
                    'severity': 'Low' if days_left > 30 else ('Medium' if days_left > 0 else 'High')
                }
    except Exception as e:
        results = {
            'error': str(e),
            'status': 'Error',
            'severity': 'High'
        }
    
    return results

# HTTP headerlarni tekshirish
def check_http_headers(url):
    results = {}
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': 'Missing',
            'Content-Security-Policy': 'Missing',
            'X-Content-Type-Options': 'Missing',
            'X-Frame-Options': 'Missing',
            'X-XSS-Protection': 'Missing'
        }
        
        # Mavjud headerlarni tekshirish
        for header in security_headers:
            if header in headers:
                security_headers[header] = headers[header]
        
        # Xavfsizlik darajasini baholash
        missing_headers = sum(1 for value in security_headers.values() if value == 'Missing')
        if missing_headers == 0:
            severity = 'Low'
        elif missing_headers <= 2:
            severity = 'Medium'
        else:
            severity = 'High'
            
        results = {
            'headers': security_headers,
            'missing_count': missing_headers,
            'severity': severity
        }
    except Exception as e:
        results = {
            'error': str(e),
            'severity': 'Unknown'
        }
    
    return results

# SQL Injection testini tekshiruvchi funksiya
def check_sql_injection(url):
    # SQL injection uchun test parametrlari
    payloads = ["' OR '1'='1", "1' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "admin'--"]
    results = []
    
    try:
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            
            # Natijalarni tekshirish
            if response.status_code == 200:
                # Natijada SQL xatosi bo'lishi mumkin
                if "error" in response.text.lower() or "syntax" in response.text.lower() or "mysql" in response.text.lower():
                    results.append({
                        "payload": payload,
                        "description": "Potencial SQL injection zaiflik topildi",
                        "severity": "High"
                    })
    except Exception as e:
        results.append({
            "error": str(e),
            "description": "SQL injection testini o'tkazishda xatolik yuz berdi",
            "severity": "Unknown"
        })
    
    return results

# XSS zaifliklarini tekshirish
def check_xss_vulnerability(url):
    # XSS uchun test parametrlari
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<svg onload='alert(\"XSS\")'>"
    ]
    results = []
    
    try:
        for payload in payloads:
            test_url = f"{url}?search={payload}"
            response = requests.get(test_url, timeout=5)
            
            # Agar javobda payload qaytsa, demak xavf bor
            if payload in response.text:
                results.append({
                    "payload": payload,
                    "description": "Potencial XSS zaiflik topildi",
                    "severity": "High"
                })
    except Exception as e:
        results.append({
            "error": str(e),
            "description": "XSS testini o'tkazishda xatolik yuz berdi",
            "severity": "Unknown"
        })
    
    return results

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target = sanitize_input(request.form.get('target'))
        scan_type = request.form.get('scan_type')
        
        # Target validatsiyasi
        if not target:
            flash('Iltimos, skanerlash manzilini kiriting', 'danger')
            return render_template('scan.html')
            
        # URL formatini tekshirish
        if scan_type in ['headers', 'sql_injection', 'xss'] and not (target.startswith('http://') or target.startswith('https://')):
            target = 'http://' + target
            
        results = {}
        severity = "Low"
        
        # Skanerlash turini tanlash
        if scan_type == 'ports':
            # Standart portlar ro'yxati
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
            hostname = target
            if target.startswith('http://') or target.startswith('https://'):
                hostname = target.split('//')[1].split('/')[0]
            results = scan_ports(hostname, ports)
            # Ochiq portlar soniga qarab xavfni baholash
            if len(results) > 10:
                severity = "High"
            elif len(results) > 5:
                severity = "Medium"
                
        elif scan_type == 'ssl':
            hostname = target
            if target.startswith('http://') or target.startswith('https://'):
                hostname = target.split('//')[1].split('/')[0]
            results = check_ssl_certificate(hostname)
            severity = results.get('severity', 'Unknown')
            
        elif scan_type == 'headers':
            results = check_http_headers(target)
            severity = results.get('severity', 'Unknown')
            
        elif scan_type == 'sql_injection':
            results = check_sql_injection(target)
            if results and any(item.get('severity') == 'High' for item in results):
                severity = "High"
                
        elif scan_type == 'xss':
            results = check_xss_vulnerability(target)
            if results and any(item.get('severity') == 'High' for item in results):
                severity = "High"
        
        # Natijalarni bazaga saqlash
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO scans (user_id, target, scan_type, results, severity)
        VALUES (?, ?, ?, ?, ?)
        """, (session['user_id'], target, scan_type, json.dumps(results), severity))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return redirect(url_for('scan_results', scan_id=scan_id))
        
    return render_template('scan.html')

@app.route('/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT target, scan_type, results, severity, created_at 
    FROM scans 
    WHERE id = ? AND user_id = ?
    """, (scan_id, session['user_id']))
    
    scan = cursor.fetchone()
    conn.close()
    
    if not scan:
        flash('Skanerlash natijasi topilmadi', 'danger')
        return redirect(url_for('dashboard'))
        
    target, scan_type, results_json, severity, created_at = scan
    results = json.loads(results_json)
    
    return render_template('scan_results.html', 
                          scan_id=scan_id,
                          target=target, 
                          scan_type=scan_type,
                          results=results,
                          severity=severity,
                          created_at=created_at)

@app.route('/history')
@login_required
def history():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id, target, scan_type, severity, created_at 
    FROM scans 
    WHERE user_id = ? 
    ORDER BY created_at DESC
    """, (session['user_id'],))
    
    scans = cursor.fetchall()
    conn.close()
    
    return render_template('history.html', scans=scans)

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    
    cursor.execute("""
    DELETE FROM scans 
    WHERE id = ? AND user_id = ?
    """, (scan_id, session['user_id']))
    
    conn.commit()
    conn.close()
    
    flash('Skanerlash natijasi o\'chirildi', 'success')
    return redirect(url_for('history'))

if __name__ == '__main__':
    app.run(debug=True)
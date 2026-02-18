from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, send_file
import requests
import socket
import ssl
import json
import hashlib
import re
import subprocess
from datetime import datetime, timezone, timedelta
import os
import sqlite3
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import threading
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import mimetypes
import zipfile
import io

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─── TOSHKENT VAQT ZONASI (UTC+5) ───────────────────────────
TASHKENT_TZ = timezone(timedelta(hours=5))

def now_tashkent():
    """Toshkent vaqtida hozirgi vaqtni qaytaradi"""
    return datetime.now(TASHKENT_TZ).strftime('%Y-%m-%d %H:%M:%S')

# ─── MONITORING GLOBAL ───────────────────────────────────────
monitoring_data = {}
monitoring_lock = threading.Lock()
DEFAULT_MONITOR_URL = "https://kun.uz"

# ─── YUKLAB OLISH PAPKASI ────────────────────────────────────
DOWNLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'downloads')
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# ─── DATABASE ────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

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

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS monitoring_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        status_code INTEGER,
        response_time REAL,
        is_up INTEGER DEFAULT 1,
        ssl_days_left INTEGER,
        error TEXT,
        checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS monitoring_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        check_interval INTEGER DEFAULT 60,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    conn.commit()
    conn.close()

init_db()

# ─── YORDAMCHI FUNKSIYALAR ───────────────────────────────────
def sanitize_input(input_string):
    if input_string:
        sanitized = input_string.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;').replace("'", '&#39;')
        return sanitized
    return ""

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Iltimos, avval tizimga kiring', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ─── MONITORING FUNKSIYALAR ──────────────────────────────────
def check_website_status(url):
    result = {
        'url': url,
        'is_up': False,
        'status_code': None,
        'response_time': None,
        'ssl_days_left': None,
        'error': None,
        'checked_at': now_tashkent()  # Toshkent vaqti
    }
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10, allow_redirects=True)
        response_time = round((time.time() - start_time) * 1000, 2)
        result['is_up'] = True
        result['status_code'] = response.status_code
        result['response_time'] = response_time

        if url.startswith('https://'):
            try:
                hostname = url.split('//')[1].split('/')[0]
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        result['ssl_days_left'] = (expiry - datetime.now()).days
            except:
                result['ssl_days_left'] = None
    except requests.ConnectionError:
        result['error'] = "Ulanib bo'lmadi"
    except requests.Timeout:
        result['error'] = 'Kutish vaqti tugadi (timeout)'
    except Exception as e:
        result['error'] = str(e)
    return result


def save_monitoring_log(result):
    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        tashkent_time = now_tashkent()  # Toshkent vaqti
        cursor.execute("""
            INSERT INTO monitoring_logs
            (url, status_code, response_time, is_up, ssl_days_left, error, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result['url'],
            result.get('status_code'),
            result.get('response_time'),
            1 if result.get('is_up') else 0,
            result.get('ssl_days_left'),
            result.get('error'),
            tashkent_time
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Monitoring log xatolik: {e}")


def get_monitoring_history(url, limit=50):
    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT status_code, response_time, is_up, ssl_days_left, error, checked_at
            FROM monitoring_logs
            WHERE url = ?
            ORDER BY checked_at DESC
            LIMIT ?
        """, (url, limit))
        rows = cursor.fetchall()
        conn.close()
        history = [{'status_code': r[0], 'response_time': r[1], 'is_up': bool(r[2]),
                    'ssl_days_left': r[3], 'error': r[4], 'checked_at': r[5]} for r in rows]
        return list(reversed(history))
    except:
        return []


def get_uptime_stats(url, hours=24):
    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        # Toshkent vaqti asosida so'nggi N soatni hisoblash
        since_time = (datetime.now(TASHKENT_TZ) - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            SELECT COUNT(*) as total, SUM(is_up) as up_count,
                   AVG(response_time) as avg_response,
                   MIN(response_time) as min_response,
                   MAX(response_time) as max_response
            FROM monitoring_logs
            WHERE url = ? AND checked_at >= ?
        """, (url, since_time))
        row = cursor.fetchone()
        conn.close()
        if row and row[0] > 0:
            total, up_count, avg_resp, min_resp, max_resp = row
            return {
                'total_checks': total,
                'up_count': up_count or 0,
                'down_count': total - (up_count or 0),
                'uptime_percent': round(((up_count or 0) / total) * 100, 2),
                'avg_response_time': round(avg_resp, 2) if avg_resp else 0,
                'min_response_time': round(min_resp, 2) if min_resp else 0,
                'max_response_time': round(max_resp, 2) if max_resp else 0,
            }
    except Exception as e:
        print(f"Uptime stats xatolik: {e}")
    return {'total_checks': 0, 'up_count': 0, 'down_count': 0, 'uptime_percent': 0,
            'avg_response_time': 0, 'min_response_time': 0, 'max_response_time': 0}


def background_monitor():
    while True:
        try:
            conn = sqlite3.connect('security_scanner.db')
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT url FROM monitoring_targets WHERE is_active = 1")
            targets = [row[0] for row in cursor.fetchall()]
            conn.close()

            if DEFAULT_MONITOR_URL not in targets:
                targets.append(DEFAULT_MONITOR_URL)

            for url in targets:
                result = check_website_status(url)
                save_monitoring_log(result)
                with monitoring_lock:
                    monitoring_data[url] = {
                        'last_check': result,
                        'status': 'up' if result['is_up'] else 'down'
                    }
        except Exception as e:
            print(f"Background monitor xatolik: {e}")
        time.sleep(60)


monitor_thread = threading.Thread(target=background_monitor, daemon=True)
monitor_thread.start()

# ─── ASSET RECON FUNKSIYALAR ─────────────────────────────────

def analyze_assets(url):
    """
    Domendan barcha rasmlar, videolar va sizib chiqqan
    ma'lumotlarni topib qaytaradi.
    """
    results = {
        'images': [],
        'videos': [],
        'sensitive_text': [],
        'leakage_found': False
    }
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'
        }
        response = requests.get(url, timeout=10, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Rasmlarni yig'ish — src, data-src, srcset
        for img in soup.find_all('img'):
            for attr in ['src', 'data-src', 'data-lazy-src']:
                img_url = img.get(attr)
                if img_url:
                    full_url = urljoin(url, img_url)
                    ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                    results['images'].append({
                        'url': full_url,
                        'type': ext if ext else 'img',
                        'alt': img.get('alt', ''),
                    })

            # srcset ichidagi urllar
            srcset = img.get('srcset', '')
            if srcset:
                for part in srcset.split(','):
                    src_url = part.strip().split(' ')[0]
                    if src_url:
                        full_url = urljoin(url, src_url)
                        ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                        results['images'].append({
                            'url': full_url,
                            'type': ext if ext else 'img',
                            'alt': '',
                        })

        # CSS background-image ichidagi rasmlar
        for tag in soup.find_all(style=True):
            style_val = tag.get('style', '')
            css_urls = re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', style_val)
            for cu in css_urls:
                full_url = urljoin(url, cu)
                ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                results['images'].append({'url': full_url, 'type': ext or 'img', 'alt': 'css-bg'})

        # Takrorlanganlarni olib tashlash
        seen = set()
        unique_images = []
        for img in results['images']:
            if img['url'] not in seen:
                seen.add(img['url'])
                unique_images.append(img)
        results['images'] = unique_images

        # 2. Videolarni yig'ish — video, source, iframe (YouTube/Vimeo)
        for video in soup.find_all(['video', 'source']):
            video_url = video.get('src')
            if video_url:
                full_url = urljoin(url, video_url)
                ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                results['videos'].append({
                    'url': full_url,
                    'type': ext if ext else 'video',
                })

        # iframe orqali embed qilingan videolar (YouTube, Vimeo)
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if 'youtube' in src or 'vimeo' in src or 'youtu.be' in src:
                results['videos'].append({
                    'url': src,
                    'type': 'embed',
                })

        # 3. Ma'lumotlar sizib chiqishini tekshirish
        page_content = response.text
        patterns = {
            'Email manzillar': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'API kalitlar / Tokenlar': r'(?:key|api|token|secret|password|auth)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'Ichki IP manzillar': r'\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b',
            "Server ma'lumotlari": None,  # Header'dan olinadi
        }

        for label, pattern in patterns.items():
            if pattern is None:
                continue
            found = re.findall(pattern, page_content, re.IGNORECASE)
            if found:
                unique_found = list(set(found))
                severity = 'critical' if 'API' in label or 'Token' in label else 'medium' if 'IP' in label else 'low'
                results['sensitive_text'].append({
                    'type': label,
                    'found_count': len(found),
                    'examples': unique_found[:3],
                    'severity': severity,
                    'description': _get_leak_description(label),
                })
                results['leakage_found'] = True

        # Server header tekshirish
        server_header = response.headers.get('Server', '')
        x_powered = response.headers.get('X-Powered-By', '')
        if server_header or x_powered:
            examples = [v for v in [server_header, x_powered] if v]
            results['sensitive_text'].append({
                "type": "Server ma'lumotlari",
                'found_count': len(examples),
                'examples': examples,
                'severity': 'low',
                'description': 'Server versiyasi response headerda oshkor qilingan',
            })
            results['leakage_found'] = True

    except requests.ConnectionError:
        results['error'] = "Saytga ulanib bo'lmadi"
    except requests.Timeout:
        results['error'] = 'Kutish vaqti tugadi (timeout)'
    except Exception as e:
        results['error'] = str(e)

    return results


def _get_leak_description(label):
    descriptions = {
        'Email manzillar': 'Sahifa kodida ochiq holda email manzillar aniqlandi',
        'API kalitlar / Tokenlar': 'JavaScript yoki HTML kodida yashirilmagan API kalitlar topildi',
        'Ichki IP manzillar': 'Ichki tarmoq IP manzillari HTML yoki skript kodida aniqlandi',
    }
    return descriptions.get(label, "Ma'lumot sizib chiqishi aniqlandi")


def download_single_file(file_url, save_dir):
    """
    Bitta fayl (rasm yoki video) ni yuklab olib,
    save_dir papkasiga saqlaydi. Fayl yo'lini qaytaradi.
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
        resp.raise_for_status()

        parsed = urlparse(file_url)
        filename = os.path.basename(parsed.path)
        if not filename or '.' not in filename:
            content_type = resp.headers.get('Content-Type', '')
            ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
            filename = hashlib.md5(file_url.encode()).hexdigest()[:10] + ext

        filename = secure_filename(filename)
        save_path = os.path.join(save_dir, filename)

        counter = 1
        base, ext = os.path.splitext(save_path)
        while os.path.exists(save_path):
            save_path = f"{base}_{counter}{ext}"
            counter += 1

        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        return {'success': True, 'path': save_path, 'filename': os.path.basename(save_path)}
    except Exception as e:
        return {'success': False, 'url': file_url, 'error': str(e)}


# ─── MAVJUD ROUTELAR ─────────────────────────────────────────
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
            flash("Barcha maydonlarni to'ldiring", 'danger')
            return render_template('register.html')
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
            flash("Muvaffaqiyatli ro'yxatdan o'tdingiz!", 'success')
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
            flash("Noto'g'ri foydalanuvchi nomi yoki parol", 'danger')
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
        FROM scans WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 10
    """, (session['user_id'],))
    recent_scans = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', recent_scans=recent_scans)


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


def check_ssl_certificate(hostname, port=443):
    results = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                results = {
                    'subject': subject, 'issuer': issuer,
                    'not_before': not_before, 'not_after': not_after,
                    'days_left': days_left,
                    'status': 'Valid' if days_left > 0 else 'Expired',
                    'severity': 'Low' if days_left > 30 else ('Medium' if days_left > 0 else 'High')
                }
    except Exception as e:
        results = {'error': str(e), 'status': 'Error', 'severity': 'High'}
    return results


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
        for header in security_headers:
            if header in headers:
                security_headers[header] = headers[header]
        missing_headers = sum(1 for value in security_headers.values() if value == 'Missing')
        severity = 'Low' if missing_headers == 0 else ('Medium' if missing_headers <= 2 else 'High')
        results = {'headers': security_headers, 'missing_count': missing_headers, 'severity': severity}
    except Exception as e:
        results = {'error': str(e), 'severity': 'Unknown'}
    return results


def check_sql_injection(url):
    payloads = ["' OR '1'='1", "1' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "admin'--"]
    results = []
    try:
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                if any(kw in response.text.lower() for kw in ['error', 'syntax', 'mysql']):
                    results.append({"payload": payload, "description": "Potencial SQL injection zaiflik topildi", "severity": "High"})
    except Exception as e:
        results.append({"error": str(e), "description": "SQL injection testini o'tkazishda xatolik", "severity": "Unknown"})
    return results


def check_xss_vulnerability(url):
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
            if payload in response.text:
                results.append({"payload": payload, "description": "Potencial XSS zaiflik topildi", "severity": "High"})
    except Exception as e:
        results.append({"error": str(e), "description": "XSS testini o'tkazishda xatolik", "severity": "Unknown"})
    return results


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target = sanitize_input(request.form.get('target'))
        scan_type = request.form.get('scan_type')
        if not target:
            flash('Iltimos, skanerlash manzilini kiriting', 'danger')
            return render_template('scan.html')
        if scan_type in ['headers', 'sql_injection', 'xss'] and not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        results = {}
        severity = "Low"
        if scan_type == 'ports':
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
            hostname = target
            if target.startswith(('http://', 'https://')):
                hostname = target.split('//')[1].split('/')[0]
            results = scan_ports(hostname, ports)
            if len(results) > 10: severity = "High"
            elif len(results) > 5: severity = "Medium"
        elif scan_type == 'ssl':
            hostname = target
            if target.startswith(('http://', 'https://')):
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

        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        # ✅ TUZATILDI: scan_type qiymati ham qo'shildi (avval tushib qolgan edi)
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
        FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, session['user_id']))
    scan = cursor.fetchone()
    conn.close()
    if not scan:
        flash('Skanerlash natijasi topilmadi', 'danger')
        return redirect(url_for('dashboard'))
    target, scan_type, results_json, severity, created_at = scan
    results = json.loads(results_json)
    return render_template('scan_results.html', scan_id=scan_id, target=target,
                           scan_type=scan_type, results=results, severity=severity, created_at=created_at)


@app.route('/history')
@login_required
def history():
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, target, scan_type, severity, created_at
        FROM scans WHERE user_id = ?
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
    cursor.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Skanerlash natijasi o'chirildi", 'success')
    return redirect(url_for('history'))


# ─── MONITORING ROUTELAR ─────────────────────────────────────
@app.route('/monitoring')
@login_required
def monitoring():
    return render_template('monitoring.html', default_url=DEFAULT_MONITOR_URL)


@app.route('/monitoring/add', methods=['POST'])
@login_required
def add_monitoring_target():
    url = request.form.get('url', '').strip()
    interval = int(request.form.get('interval', 60))
    if not url:
        flash('URL kiriting', 'danger')
        return redirect(url_for('monitoring'))
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    domain_part = url.split('://')[-1].split('/')[0]
    if '.' not in domain_part or len(domain_part) < 3:
        flash("To'g'ri URL kiriting (masalan: a1cafe.uz yoki https://a1cafe.uz)", 'danger')
        return redirect(url_for('monitoring'))
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM monitoring_targets WHERE user_id = ? AND url = ?", (session['user_id'], url))
    if cursor.fetchone():
        flash("Bu URL allaqachon monitoring ro'yxatida", 'warning')
    else:
        cursor.execute("""
            INSERT INTO monitoring_targets (user_id, url, check_interval)
            VALUES (?, ?, ?)
        """, (session['user_id'], url, interval))
        conn.commit()
        flash(f"{url} monitoring ro'yxatiga qo'shildi", 'success')
    conn.close()
    return redirect(url_for('monitoring'))


@app.route('/monitoring/remove/<int:target_id>', methods=['POST'])
@login_required
def remove_monitoring_target(target_id):
    conn = sqlite3.connect('security_scanner.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM monitoring_targets WHERE id = ? AND user_id = ?", (target_id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Monitoring manzili o'chirildi", 'info')
    return redirect(url_for('monitoring'))


@app.route('/monitoring/check', methods=['POST'])
@login_required
def manual_check():
    url = request.json.get('url', DEFAULT_MONITOR_URL)
    if not url:
        url = DEFAULT_MONITOR_URL
    result = check_website_status(url)
    save_monitoring_log(result)
    return jsonify(result)


@app.route('/monitoring/stats')
@login_required
def monitoring_stats():
    url = request.args.get('url', DEFAULT_MONITOR_URL)
    hours = int(request.args.get('hours', 24))
    stats = get_uptime_stats(url, hours)
    history = get_monitoring_history(url, limit=60)

    chart_labels = [h['checked_at'][11:16] for h in history]
    chart_response_times = [h['response_time'] or 0 for h in history]
    chart_status = [1 if h['is_up'] else 0 for h in history]

    hourly_data = []
    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        # ✅ TUZATILDI: Toshkent vaqti asosida so'nggi 24 soat
        since_time = (datetime.now(TASHKENT_TZ) - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            SELECT strftime('%H', checked_at) as hour,
                   COUNT(*) as total, SUM(is_up) as up_count,
                   AVG(response_time) as avg_resp
            FROM monitoring_logs
            WHERE url = ? AND checked_at >= ?
            GROUP BY strftime('%H', checked_at)
            ORDER BY hour
        """, (url, since_time))
        hourly_data = [{'hour': r[0], 'uptime': round((r[2] / r[1]) * 100, 1), 'avg_resp': round(r[3] or 0, 1)}
                       for r in cursor.fetchall()]
        conn.close()
    except Exception as e:
        print(f"Hourly stats xatolik: {e}")

    return jsonify({
        'stats': stats,
        'history': history[-20:],
        'chart': {
            'labels': chart_labels,
            'response_times': chart_response_times,
            'statuses': chart_status,
        },
        'hourly': hourly_data
    })


# ─── ASSET RECON ROUTELAR ────────────────────────────────────

@app.route('/asset_recon')
@login_required
def asset_recon():
    """Asset Reconnaissance sahifasi"""
    return render_template('asset_recon.html')


@app.route('/asset_recon/scan', methods=['POST'])
@login_required
def asset_recon_scan():
    """
    URL ni qabul qilib, saytdagi barcha rasm, video va
    sizib chiqqan ma'lumotlarni JSON ko'rinishida qaytaradi.
    """
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    results = analyze_assets(url)
    return jsonify(results)


@app.route('/asset_recon/download/single', methods=['POST'])
@login_required
def download_single():
    """
    Bitta rasm yoki videoni serverga yuklab olib,
    foydalanuvchiga yuboradi (Content-Disposition: attachment).
    """
    data = request.get_json()
    file_url = data.get('url', '').strip()

    if not file_url:
        return jsonify({'error': 'URL kiritilmagan'}), 400

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
        resp.raise_for_status()

        parsed = urlparse(file_url)
        filename = os.path.basename(parsed.path)
        if not filename or '.' not in filename:
            content_type = resp.headers.get('Content-Type', 'application/octet-stream')
            ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
            filename = hashlib.md5(file_url.encode()).hexdigest()[:10] + ext

        filename = secure_filename(filename)

        file_data = io.BytesIO()
        for chunk in resp.iter_content(chunk_size=8192):
            file_data.write(chunk)
        file_data.seek(0)

        content_type = resp.headers.get('Content-Type', 'application/octet-stream').split(';')[0].strip()

        return send_file(
            file_data,
            mimetype=content_type,
            as_attachment=True,
            download_name=filename
        )

    except requests.HTTPError as e:
        return jsonify({'error': f'HTTP xatolik: {e.response.status_code}'}), 400
    except requests.ConnectionError:
        return jsonify({'error': "Faylga ulanib bo'lmadi"}), 400
    except requests.Timeout:
        return jsonify({'error': 'Kutish vaqti tugadi'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/asset_recon/download/bulk', methods=['POST'])
@login_required
def download_bulk():
    """
    Tanlangan rasm va videolarni ZIP arxivga joylab,
    foydalanuvchiga yuboradi.
    """
    data = request.get_json()
    urls = data.get('urls', [])
    folder_name = data.get('folder', 'assets')

    if not urls:
        return jsonify({'error': "URL ro'yxati bo'sh"}), 400

    if len(urls) > 50:
        return jsonify({'error': 'Bir vaqtda maksimal 50 ta fayl yuklanadi'}), 400

    zip_buffer = io.BytesIO()
    success_count = 0
    errors = []

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_url in urls:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
                resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
                resp.raise_for_status()

                parsed = urlparse(file_url)
                filename = os.path.basename(parsed.path)
                if not filename or '.' not in filename:
                    content_type = resp.headers.get('Content-Type', 'application/octet-stream')
                    ext = mimetypes.guess_extension(content_type.split(';')[0].strip()) or '.bin'
                    filename = hashlib.md5(file_url.encode()).hexdigest()[:10] + ext

                filename = secure_filename(filename)
                zip_path = os.path.join(folder_name, filename)

                file_bytes = b''.join(resp.iter_content(chunk_size=8192))
                zf.writestr(zip_path, file_bytes)
                success_count += 1

            except Exception as e:
                errors.append({'url': file_url, 'error': str(e)})

    zip_buffer.seek(0)

    # ✅ ZIP fayl nomi Toshkent vaqtida
    timestamp = datetime.now(TASHKENT_TZ).strftime('%Y-%m-%d_%H%M%S')
    zip_filename = f"{folder_name}_{timestamp}.zip"

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_filename
    )


if __name__ == '__main__':
    app.run(debug=True)

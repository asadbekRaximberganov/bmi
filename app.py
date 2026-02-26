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

# Kengaytirilgan monitoring uchun qo'shimcha kutubxonalar
# O'rnatish: pip install python-whois dnspython
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️  python-whois o'rnatilmagan: pip install python-whois")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("⚠️  dnspython o'rnatilmagan: pip install dnspython")


app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─── TOSHKENT VAQT ZONASI (UTC+5) ───────────────────────────
TASHKENT_TZ = timezone(timedelta(hours=5))

def now_tashkent():
    return datetime.now(TASHKENT_TZ).strftime('%Y-%m-%d %H:%M:%S')

# ─── MONITORING GLOBAL ───────────────────────────────────────
monitoring_data = {}
monitoring_lock = threading.Lock()
DEFAULT_MONITOR_URL = "https://kun.uz"

# ─── YUKLAB OLISH PAPKASI ────────────────────────────────────
DOWNLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'downloads')
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)


# ═════════════════════════════════════════════════════════════
#  DATABASE
# ═════════════════════════════════════════════════════════════
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
    )''')

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
    )''')

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
    )''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS monitoring_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        check_interval INTEGER DEFAULT 60,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')

    # ── Kengaytirilgan monitoring uchun yangi jadvallar ──────
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dns_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        record_type TEXT NOT NULL,
        value TEXT NOT NULL,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        is_active INTEGER DEFAULT 1
    )''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS port_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        service TEXT,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        is_open INTEGER DEFAULT 1
    )''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS content_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        content_size INTEGER,
        checked_at TIMESTAMP
    )''')

    conn.commit()
    conn.close()

init_db()


# ═════════════════════════════════════════════════════════════
#  YORDAMCHI FUNKSIYALAR
# ═════════════════════════════════════════════════════════════
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


# ═════════════════════════════════════════════════════════════
#  ASOSIY MONITORING FUNKSIYALAR
# ═════════════════════════════════════════════════════════════
def check_website_status(url):
    result = {
        'url': url,
        'is_up': False,
        'status_code': None,
        'response_time': None,
        'ssl_days_left': None,
        'error': None,
        'checked_at': now_tashkent()
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
            now_tashkent()
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


# ─── RENDER KEEP-ALIVE ───────────────────────────────────────
# Render bepul tarifi 30 soniya so'rov bo'lmasa serverni o'chiradi.
RENDER_APP_URL = os.environ.get('RENDER_EXTERNAL_URL', '')

def keep_alive_ping():
    time.sleep(15)
    while True:
        try:
            if RENDER_APP_URL:
                requests.get(RENDER_APP_URL, timeout=8)
                print(f"[keep-alive] ping OK → {RENDER_APP_URL}")
        except Exception as e:
            print(f"[keep-alive] xato: {e}")
        time.sleep(30)

keep_alive_thread = threading.Thread(target=keep_alive_ping, daemon=True)
keep_alive_thread.start()


# ═════════════════════════════════════════════════════════════
#  KENGAYTIRILGAN MONITORING FUNKSIYALAR
# ═════════════════════════════════════════════════════════════

# ── 1. DNS MONITORING ────────────────────────────────────────
def get_dns_records(domain):
    """A, AAAA, MX, NS, TXT DNS yozuvlarini qaytaradi."""
    result = {
        'domain': domain,
        'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [],
        'checked_at': now_tashkent(),
        'error': None
    }
    if not DNS_AVAILABLE:
        result['error'] = 'dnspython kutubxonasi o\'rnatilmagan'
        return result

    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            for rdata in answers:
                result[rtype].append(str(rdata))
        except Exception:
            pass
    return result


def detect_dns_change(domain):
    """
    DNS yozuvlarini bazadagi avvalgi bilan solishtiradi.
    Domen o'zgarishini (IP, NS) aniqlaydi.
    """
    current = get_dns_records(domain)
    if current.get('error'):
        return {'domain': domain, 'has_changes': False, 'error': current['error']}

    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        changes = []

        for rtype in ['A', 'AAAA', 'MX', 'NS']:
            cursor.execute("""
                SELECT value FROM dns_history
                WHERE domain=? AND record_type=? AND is_active=1
            """, (domain, rtype))
            old_values = set(r[0] for r in cursor.fetchall())
            new_values = set(current.get(rtype, []))

            for v in new_values - old_values:
                changes.append({'type': 'ADDED', 'record': rtype, 'value': v})
                cursor.execute("""
                    INSERT INTO dns_history (domain, record_type, value, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                """, (domain, rtype, v, now_tashkent(), now_tashkent()))

            for v in old_values - new_values:
                changes.append({'type': 'REMOVED', 'record': rtype, 'value': v})
                cursor.execute("""
                    UPDATE dns_history SET is_active=0, last_seen=?
                    WHERE domain=? AND record_type=? AND value=?
                """, (now_tashkent(), domain, rtype, v))

            for v in new_values & old_values:
                cursor.execute("""
                    UPDATE dns_history SET last_seen=?
                    WHERE domain=? AND record_type=? AND value=? AND is_active=1
                """, (now_tashkent(), domain, rtype, v))

        conn.commit()
        conn.close()
        return {
            'domain': domain,
            'has_changes': len(changes) > 0,
            'changes': changes,
            'current_records': current,
            'checked_at': now_tashkent()
        }
    except Exception as e:
        return {'domain': domain, 'has_changes': False, 'error': str(e)}


# ── 2. WHOIS ─────────────────────────────────────────────────
def get_whois_info(domain):
    """Domen egasi, muddat, registrar ma'lumotlarini qaytaradi."""
    if not WHOIS_AVAILABLE:
        return {'domain': domain, 'error': 'python-whois o\'rnatilmagan', 'severity': 'unknown'}
    try:
        w = whois.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        days_left = None
        if expiry and isinstance(expiry, datetime):
            days_left = (expiry - datetime.now()).days

        return {
            'domain': domain,
            'registrar': str(w.registrar or ''),
            'registrant': str(w.registrant_name or w.org or ''),
            'creation_date': str(creation) if creation else None,
            'expiry_date': str(expiry) if expiry else None,
            'days_until_expiry': days_left,
            'name_servers': list(w.name_servers or []),
            'status': list(w.status) if isinstance(w.status, list) else [str(w.status or '')],
            'severity': (
                'critical' if days_left is not None and days_left < 7
                else 'high'   if days_left is not None and days_left < 30
                else 'medium' if days_left is not None and days_left < 90
                else 'low'
            ),
            'checked_at': now_tashkent()
        }
    except Exception as e:
        return {'domain': domain, 'error': str(e), 'severity': 'unknown'}


# ── 3. REDIRECT ZANJIRI ───────────────────────────────────────
def trace_redirect_chain(url, max_redirects=10):
    """Barcha HTTP redirect'larni kuzatadi, domen o'zgarishini aniqlaydi."""
    chain = []
    try:
        sess = requests.Session()
        sess.max_redirects = max_redirects
        response = sess.get(
            url, timeout=10, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        )
        for resp in response.history:
            chain.append({
                'url': resp.url,
                'status_code': resp.status_code,
                'location': resp.headers.get('Location', ''),
            })
        chain.append({'url': response.url, 'status_code': response.status_code, 'location': None})

        warnings = []
        original_domain = urlparse(url).netloc
        final_domain    = urlparse(response.url).netloc
        if original_domain != final_domain:
            warnings.append({
                'type': 'domain_change',
                'message': f"Domen o'zgardi: {original_domain} → {final_domain}",
                'severity': 'high'
            })
        if len(chain) > 5:
            warnings.append({
                'type': 'too_many_redirects',
                'message': f"{len(chain)-1} ta redirect — juda ko'p",
                'severity': 'medium'
            })

        return {
            'original_url': url,
            'final_url': response.url,
            'redirect_count': len(chain) - 1,
            'chain': chain,
            'warnings': warnings,
            'checked_at': now_tashkent()
        }
    except requests.TooManyRedirects:
        return {'original_url': url, 'error': "Juda ko'p redirect (loop)", 'chain': chain}
    except Exception as e:
        return {'original_url': url, 'error': str(e), 'chain': chain}


# ── 4. CHUQUR HEADER TAHLILI ─────────────────────────────────
SECURITY_HEADERS_CONFIG = {
    'Strict-Transport-Security': {
        'required': True, 'description': 'HTTPS majburiy qilish (HSTS)',
        'recommendation': 'max-age=31536000; includeSubDomains; preload', 'severity': 'high'
    },
    'Content-Security-Policy': {
        'required': True, 'description': 'XSS va injection hujumlaridan himoya',
        'recommendation': "default-src 'self'", 'severity': 'high'
    },
    'X-Content-Type-Options': {
        'required': True, 'description': 'MIME sniffing oldini olish',
        'recommendation': 'nosniff', 'severity': 'medium'
    },
    'X-Frame-Options': {
        'required': True, 'description': 'Clickjacking oldini olish',
        'recommendation': 'DENY yoki SAMEORIGIN', 'severity': 'medium'
    },
    'X-XSS-Protection': {
        'required': False, 'description': 'Brauzer XSS filtri',
        'recommendation': '1; mode=block', 'severity': 'low'
    },
    'Referrer-Policy': {
        'required': True, 'description': "Referer ma'lumot nazorati",
        'recommendation': 'strict-origin-when-cross-origin', 'severity': 'low'
    },
    'Permissions-Policy': {
        'required': False, 'description': 'Brauzer API ruxsatlarini cheklash',
        'recommendation': 'camera=(), microphone=(), geolocation=()', 'severity': 'low'
    },
}

def deep_header_analysis(url):
    """
    HTTP headerlarni chuqur tahlil qiladi:
    xavfsizlik headerlari, cookie flags, CORS, texnologiya oshkori.
    A/B/C/F baho beradi.
    """
    try:
        resp = requests.get(
            url, timeout=8, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        )
        headers = resp.headers

        # Xavfsizlik headerlari tekshiruvi
        security_check = {}
        missing_critical = 0
        score = 100

        for h_name, config in SECURITY_HEADERS_CONFIG.items():
            present = h_name in headers
            value   = headers.get(h_name, '')
            security_check[h_name] = {
                'present': present,
                'value': value,
                'description': config['description'],
                'recommendation': config['recommendation'],
                'severity': config['severity'] if not present else 'ok',
            }
            if not present and config['required']:
                missing_critical += 1
                score -= 15 if config['severity'] == 'high' else 10
        score = max(0, score)

        # Texnologiya oshkori
        tech_disclosure = []
        for h in ['Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version',
                  'X-Runtime', 'X-Version']:
            val = headers.get(h)
            if val:
                tech_disclosure.append({
                    'header': h, 'value': val,
                    'risk': "Texnologiya versiyasi oshkor — hujumchilar uchun ma'lumot"
                })

        # Cookie xavfsizligi
        cookie_issues = []
        set_cookie = resp.headers.get('Set-Cookie', '')
        if set_cookie:
            if 'HttpOnly' not in set_cookie:
                cookie_issues.append("HttpOnly flag yo'q — JS orqali o'g'irlanishi mumkin")
            if 'Secure' not in set_cookie:
                cookie_issues.append("Secure flag yo'q — HTTP orqali yuborilishi mumkin")
            if 'SameSite' not in set_cookie:
                cookie_issues.append("SameSite yo'q — CSRF xavfi bor")

        # CORS
        cors_info = {}
        acao = headers.get('Access-Control-Allow-Origin', '')
        if acao:
            cors_info = {
                'allow_origin': acao,
                'allow_methods': headers.get('Access-Control-Allow-Methods', ''),
                'risky': acao == '*',
                'warning': "Wildcard CORS — har qanday sayt so'rov yuborishi mumkin" if acao == '*' else ''
            }

        grade = 'A' if score >= 80 else 'B' if score >= 60 else 'C' if score >= 40 else 'F'

        return {
            'url': url,
            'status_code': resp.status_code,
            'security_headers': security_check,
            'missing_critical': missing_critical,
            'score': score,
            'grade': grade,
            'tech_disclosure': tech_disclosure,
            'cookie_issues': cookie_issues,
            'cors': cors_info,
            'response_time_ms': round(resp.elapsed.total_seconds() * 1000, 2),
            'checked_at': now_tashkent()
        }
    except Exception as e:
        return {'url': url, 'error': str(e)}


# ── 5. PING ───────────────────────────────────────────────────
def ping_host(host, count=5):
    """Ping yuboradi: RTT, paket yo'qotish foizi."""
    try:
        cmd = ['ping', '-c', str(count), '-W', '2', host]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                         timeout=30).decode('utf-8')
        rtt_match  = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        loss_match = re.search(r'(\d+)% packet loss', output)

        rtt_min = rtt_avg = rtt_max = None
        if rtt_match:
            rtt_min = float(rtt_match.group(1))
            rtt_avg = float(rtt_match.group(2))
            rtt_max = float(rtt_match.group(3))

        packet_loss = int(loss_match.group(1)) if loss_match else 100

        severity = (
            'critical' if packet_loss >= 50
            else 'high'   if packet_loss >= 20
            else 'medium' if packet_loss > 0
            else 'low'    if rtt_avg and rtt_avg > 200
            else 'ok'
        )

        return {
            'host': host,
            'reachable': packet_loss < 100,
            'packet_loss_percent': packet_loss,
            'rtt_min_ms': rtt_min,
            'rtt_avg_ms': rtt_avg,
            'rtt_max_ms': rtt_max,
            'severity': severity,
            'checked_at': now_tashkent()
        }
    except subprocess.TimeoutExpired:
        return {'host': host, 'reachable': False, 'error': 'Timeout', 'severity': 'critical'}
    except Exception as e:
        return {'host': host, 'reachable': False, 'error': str(e), 'severity': 'unknown'}


# ── 6. PORT O'ZGARISHLARINI KUZATISH ─────────────────────────
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    9200: 'Elasticsearch', 11211: 'Memcached'
}

def scan_and_compare_ports(host):
    """
    Portlarni skanerlaydi va avvalgi skan bilan solishtiradi.
    Yangi ochilgan / yopilgan portlarni aniqlaydi.
    """
    current_open = {}
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        if sock.connect_ex((host, port)) == 0:
            current_open[port] = service
        sock.close()

    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()

        cursor.execute("SELECT port, service FROM port_history WHERE host=? AND is_open=1", (host,))
        prev_open = {r[0]: r[1] for r in cursor.fetchall()}

        changes = []
        newly_opened = set(current_open.keys()) - set(prev_open.keys())
        newly_closed = set(prev_open.keys()) - set(current_open.keys())

        for p in newly_opened:
            changes.append({
                'type': 'OPENED', 'port': p, 'service': current_open[p],
                'severity': 'critical' if p in [22, 23, 3389, 445] else 'high',
                'message': f"Port {p} ({current_open[p]}) yangi ochildi!"
            })
            cursor.execute("""
                INSERT INTO port_history (host, port, service, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (host, p, current_open[p], now_tashkent(), now_tashkent()))

        for p in newly_closed:
            changes.append({
                'type': 'CLOSED', 'port': p, 'service': prev_open[p],
                'severity': 'medium',
                'message': f"Port {p} ({prev_open[p]}) yopildi"
            })
            cursor.execute("""
                UPDATE port_history SET is_open=0, last_seen=?
                WHERE host=? AND port=? AND is_open=1
            """, (now_tashkent(), host, p))

        for p in set(current_open.keys()) & set(prev_open.keys()):
            cursor.execute("""
                UPDATE port_history SET last_seen=?
                WHERE host=? AND port=? AND is_open=1
            """, (now_tashkent(), host, p))

        conn.commit()
        conn.close()

        risky = {p for p in current_open if p in [23, 445, 3389, 6379, 27017, 9200, 11211]}

        return {
            'host': host,
            'open_ports': [{'port': p, 'service': s} for p, s in sorted(current_open.items())],
            'open_count': len(current_open),
            'changes': changes,
            'has_changes': len(changes) > 0,
            'risky_ports': [{'port': p, 'service': current_open[p]} for p in risky],
            'checked_at': now_tashkent()
        }
    except Exception as e:
        return {'host': host, 'error': str(e),
                'open_ports': [{'port': p, 'service': s} for p, s in current_open.items()]}


# ── 7. SAHIFA TARKIBI O'ZGARISHI ─────────────────────────────
def check_content_change(url):
    """
    Sahifa HTML mazmunini SHA-256 hash qilib avvalgi bilan solishtiradi.
    Defacement yoki kutilmagan o'zgarishlarni aniqlaydi.
    """
    try:
        resp = requests.get(
            url, timeout=10,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        )
        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup(['script', 'style', 'noscript']):
            tag.decompose()
        text_content  = soup.get_text(separator=' ', strip=True)
        current_hash  = hashlib.sha256(text_content.encode('utf-8')).hexdigest()
        content_size  = len(resp.content)

        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT content_hash, content_size, checked_at
            FROM content_snapshots WHERE url=?
            ORDER BY checked_at DESC LIMIT 1
        """, (url,))
        prev = cursor.fetchone()

        changed = False
        change_info = {}
        if prev:
            prev_hash, prev_size, prev_time = prev
            if prev_hash != current_hash:
                changed = True
                size_diff = content_size - (prev_size or 0)
                change_info = {
                    'previous_hash': prev_hash,
                    'current_hash': current_hash,
                    'size_change_bytes': size_diff,
                    'last_stable': prev_time,
                    'severity': 'high' if abs(size_diff) > 5000 else 'medium'
                }

        cursor.execute("""
            INSERT INTO content_snapshots (url, content_hash, content_size, checked_at)
            VALUES (?, ?, ?, ?)
        """, (url, current_hash, content_size, now_tashkent()))
        conn.commit()
        conn.close()

        return {
            'url': url,
            'content_hash': current_hash,
            'content_size_bytes': content_size,
            'has_changed': changed,
            'change_details': change_info,
            'is_first_check': prev is None,
            'checked_at': now_tashkent()
        }
    except Exception as e:
        return {'url': url, 'error': str(e), 'has_changed': False}


# ── 8. GeoIP ─────────────────────────────────────────────────
def get_geoip_info(host):
    """Server joylashuvi, ISP, ASN — bepul ip-api.com orqali."""
    try:
        ip = socket.gethostbyname(host)
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,message,'
            f'country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query',
            timeout=5
        )
        data = resp.json()
        if data.get('status') == 'success':
            return {
                'host': host, 'ip': ip,
                'country': data.get('country'),
                'country_code': data.get('countryCode'),
                'city': data.get('city'),
                'region': data.get('regionName'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'asn': data.get('as'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'timezone': data.get('timezone'),
                'checked_at': now_tashkent()
            }
        return {'host': host, 'ip': ip, 'error': data.get('message', 'GeoIP xatolik')}
    except Exception as e:
        return {'host': host, 'error': str(e)}


# ── 9. TO'LIQ KENGAYTIRILGAN TEKSHIRUV ───────────────────────
def full_advanced_check(url):
    """
    Bitta URL uchun barcha kengaytirilgan tekshiruvlarni bajaradi.
    DNS, WHOIS, Redirect, Headers, Ping, Ports, Content, GeoIP.
    """
    parsed = urlparse(url if '://' in url else 'https://' + url)
    domain = parsed.netloc or parsed.path
    host   = domain.split(':')[0]

    report = {'url': url, 'domain': domain, 'checked_at': now_tashkent()}

    # HTTP
    try:
        start = time.time()
        r = requests.get(url, timeout=10, allow_redirects=True,
                         headers={'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'})
        report['http'] = {
            'is_up': True, 'status_code': r.status_code,
            'response_time_ms': round((time.time() - start) * 1000, 2),
            'final_url': r.url,
        }
    except Exception as e:
        report['http'] = {'is_up': False, 'error': str(e)}

    report['dns']       = detect_dns_change(domain)
    report['whois']     = get_whois_info(domain)
    report['redirects'] = trace_redirect_chain(url)
    report['headers']   = deep_header_analysis(url)
    report['ping']      = ping_host(host, count=4)
    report['ports']     = scan_and_compare_ports(host)
    report['content']   = check_content_change(url)
    report['geoip']     = get_geoip_info(host)

    # Umumiy xavf darajasi
    severities = []
    for key in ['whois', 'ping', 'content']:
        sev = report.get(key, {}).get('severity', '')
        if sev:
            severities.append(str(sev).lower())
    grade = report.get('headers', {}).get('grade', '')
    if grade:
        severities.append(grade.lower())

    if any(s in ('critical', 'f') for s in severities):
        overall = 'critical'
    elif any(s in ('high', 'c') for s in severities):
        overall = 'high'
    elif any(s in ('medium', 'b') for s in severities):
        overall = 'medium'
    else:
        overall = 'low'

    report['overall_severity'] = overall
    return report


# ═════════════════════════════════════════════════════════════
#  ASSET RECON FUNKSIYALAR — TAKOMILLASHTIRILGAN VERSIYA
# ═════════════════════════════════════════════════════════════

# Video hosting domenlarini aniqlash uchun pattern
VIDEO_DOMAINS = [
    'youtube.com', 'youtu.be', 'vimeo.com', 'dailymotion.com',
    'twitch.tv', 'tiktok.com', 'facebook.com', 'twitter.com', 'x.com',
    'instagram.com', 'rutube.ru', 'ok.ru', 'mail.ru', 'coub.com',
    'wistia.com', 'brightcove.com', 'jwplatform.com', 'kaltura.com',
    'sproutvideo.com', 'vidyard.com', 'loom.com', 'streamable.com',
    'rumble.com', 'odysee.com', 'bitchute.com',
]

VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg', 'avi', 'mov', 'mkv', 'flv', 'm4v', 'wmv', '3gp', 'm3u8', 'ts', 'ogv'}

IMAGE_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico',
    'tiff', 'tif', 'avif', 'heic', 'heif'
}

# YouTube video ID aniqlash pattern
_YT_ID_RE = re.compile(
    r'(?:youtube\.com/(?:embed/|v/|watch\?v=|shorts/)|youtu\.be/)([a-zA-Z0-9_-]{11})'
)


def _extract_url_ext(url_str):
    """URL dan fayl kengaytmasini ajratib oladi."""
    try:
        path = urlparse(url_str).path
        ext = os.path.splitext(path)[1].lower().strip('.')
        return ext
    except:
        return ''


def _normalize_url(url_str, base_url=''):
    """
    Protocol-relative URL larni to'g'rilaydi:
    //youtube.com/embed/abc  →  https://youtube.com/embed/abc
    Nisbiy URL larni ham to'liq URL ga aylantiradi.
    """
    if not url_str:
        return ''
    url_str = url_str.strip()
    # Protocol-relative  //domain/path
    if url_str.startswith('//'):
        return 'https:' + url_str
    # To'liq URL
    if url_str.startswith(('http://', 'https://')):
        return url_str
    # Nisbiy URL
    if base_url:
        return urljoin(base_url, url_str)
    return url_str


def _yt_id_to_url(video_id):
    """YouTube video ID dan embed URL yasaydi."""
    return f'https://www.youtube.com/embed/{video_id}'


def _is_video_url(url_str):
    """URL video ekanligini tekshiradi (domen, kengaytma, pattern bo'yicha)."""
    if not url_str:
        return False
    try:
        # Protocol-relative ni to'g'irlab parse qilamiz
        norm = _normalize_url(url_str)
        parsed = urlparse(norm)
        netloc = parsed.netloc.lower().lstrip('www.')
        ext = _extract_url_ext(norm)

        if ext in VIDEO_EXTENSIONS:
            return True
        for vd in VIDEO_DOMAINS:
            if vd in netloc or vd in norm.lower():
                return True
        # Keng tarqalgan embed / player pattern
        lower = norm.lower()
        if any(p in lower for p in [
            '/embed/', '/video/', 'player.', '/watch?v=', '/shorts/',
            'jwplayer', 'flowplayer', 'kaltura', 'brightcove',
            'wistia.net', 'fast.wistia', '/v/', 'vimeo.com/video'
        ]):
            return True
    except:
        pass
    return False


def _detect_video_platform(url_str):
    """Video platformasini aniqlaydi."""
    url_lower = url_str.lower()
    if 'youtube.com' in url_lower or 'youtu.be' in url_lower:
        return 'YouTube'
    elif 'vimeo.com' in url_lower:
        return 'Vimeo'
    elif 'dailymotion.com' in url_lower:
        return 'Dailymotion'
    elif 'twitch.tv' in url_lower:
        return 'Twitch'
    elif 'tiktok.com' in url_lower:
        return 'TikTok'
    elif 'rutube.ru' in url_lower:
        return 'RuTube'
    elif 'ok.ru' in url_lower:
        return 'OK.ru'
    elif 'facebook.com' in url_lower:
        return 'Facebook'
    elif 'twitter.com' in url_lower or 'x.com' in url_lower:
        return 'Twitter/X'
    elif 'instagram.com' in url_lower:
        return 'Instagram'
    elif 'wistia' in url_lower:
        return 'Wistia'
    elif 'brightcove' in url_lower:
        return 'Brightcove'
    elif 'jwplatform' in url_lower or 'jwplayer' in url_lower:
        return 'JWPlayer'
    elif 'rumble.com' in url_lower:
        return 'Rumble'
    elif 'loom.com' in url_lower:
        return 'Loom'
    else:
        ext = _extract_url_ext(url_str)
        return ext.upper() if ext in VIDEO_EXTENSIONS else 'Embed'


def analyze_assets(url):
    """
    Saytdan barcha resurslarni aniqlaydi:
    - Rasmlar (img, picture, srcset, CSS background, og:image, favicon)
    - Videolar (video, source, iframe embeds — YouTube/Vimeo va boshqalar)
    - JavaScript fayllari
    - CSS fayllari
    - Fontlar (woff, woff2, ttf, eot)
    - Meta/OG ma'lumotlari
    - Formalar (action URL, method)
    - Tashqi havolalar
    - Ma'lumot sizib chiqishi (email, API key, ichki IP)
    """
    results = {
        'url': url,
        'images': [],
        'videos': [],
        'scripts': [],
        'stylesheets': [],
        'fonts': [],
        'meta_info': {},
        'forms': [],
        'external_links': [],
        'sensitive_text': [],
        'leakage_found': False,
        'summary': {},
        'checked_at': now_tashkent()
    }

    try:
        headers_req = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        response = requests.get(url, timeout=10, headers=headers_req)
        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc

        # ── 1. RASMLAR ────────────────────────────────────────
        seen_images = set()

        def add_image(img_url, source_type='img', alt='', width=None, height=None):
            if not img_url or img_url.startswith('data:'):
                return
            full_url = urljoin(url, img_url)
            if full_url in seen_images:
                return
            seen_images.add(full_url)
            ext = _extract_url_ext(full_url) or 'unknown'
            results['images'].append({
                'url': full_url,
                'type': ext,
                'source': source_type,
                'alt': alt or '',
                'width': width,
                'height': height
            })

        # <img> teglari
        for img in soup.find_all('img'):
            for attr in ['src', 'data-src', 'data-lazy-src', 'data-original',
                         'data-lazy', 'data-url', 'data-image']:
                val = img.get(attr)
                if val:
                    add_image(val, 'img', img.get('alt', ''),
                              img.get('width'), img.get('height'))

            srcset = img.get('srcset', '')
            if srcset:
                for part in srcset.split(','):
                    src_part = part.strip().split(' ')[0]
                    if src_part:
                        add_image(src_part, 'img-srcset', img.get('alt', ''))

        # <picture> / <source> rasm manbalari
        for source in soup.find_all('source'):
            # Faqat rasm source — video emas
            src_type = source.get('type', '')
            if src_type.startswith('video/') or src_type == 'application/x-mpegURL':
                continue
            src = source.get('src') or source.get('srcset', '').split(',')[0].strip().split(' ')[0]
            if src:
                add_image(src, 'picture-source')

        # CSS background-image inline
        for tag in soup.find_all(style=True):
            css_urls = re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', tag.get('style', ''))
            for cu in css_urls:
                if not any(cu.lower().endswith(v) for v in VIDEO_EXTENSIONS):
                    add_image(cu, 'css-inline-bg')

        # Meta og:image, twitter:image
        for meta in soup.find_all('meta'):
            prop = meta.get('property', '') or meta.get('name', '')
            content_val = meta.get('content', '')
            if prop in ('og:image', 'twitter:image', 'og:image:secure_url') and content_val:
                add_image(content_val, 'meta-og')

        # Favicon
        for link in soup.find_all('link', rel=True):
            rel_val = ' '.join(link.get('rel', [])).lower()
            if 'icon' in rel_val or 'apple-touch-icon' in rel_val:
                href = link.get('href', '')
                if href:
                    add_image(href, 'favicon')

        # ── 2. VIDEOLAR ───────────────────────────────────────
        seen_videos = set()

        def add_video(v_url, source_type='video', platform=None, title=''):
            if not v_url or v_url.startswith('data:'):
                return
            # Protocol-relative va nisbiy URL larni to'g'irlaymiz
            full_url = _normalize_url(v_url, url)
            if not full_url or full_url in seen_videos:
                return
            seen_videos.add(full_url)
            ext = _extract_url_ext(full_url)
            results['videos'].append({
                'url': full_url,
                'type': ext or 'embed',
                'source': source_type,
                'platform': platform or _detect_video_platform(full_url),
                'title': title or ''
            })

        # ── <video> teglari ──────────────────────────────────
        for video_tag in soup.find_all('video'):
            # src attributi
            for attr in ['src', 'data-src']:
                src = video_tag.get(attr, '')
                if src:
                    add_video(src, 'video-tag')
            # Poster rasm
            poster = video_tag.get('poster', '')
            if poster:
                add_image(poster, 'video-poster')
            # <source> bolalari — type bo'lsa ham bo'lmasa ham
            for source_child in video_tag.find_all('source'):
                s_src = source_child.get('src', '') or source_child.get('data-src', '')
                if s_src:
                    add_video(s_src, 'video-source')

        # ── Mustaqil <source> teglari ────────────────────────
        # type='video/...' bo'lganda ham, bo'lmasa ham kengaytma bo'yicha
        for source_tag in soup.find_all('source'):
            s_type = source_tag.get('type', '')
            s_src  = source_tag.get('src', '') or source_tag.get('data-src', '')
            if not s_src:
                continue
            is_video_type = s_type.startswith('video/') or s_type == 'application/x-mpegURL'
            is_video_ext  = _extract_url_ext(s_src) in VIDEO_EXTENSIONS
            if is_video_type or is_video_ext:
                add_video(s_src, 'source-tag')

        # ── <iframe> embed videolar ──────────────────────────
        for iframe in soup.find_all('iframe'):
            # src yoki data-src (lazy-load)
            src = (iframe.get('src') or iframe.get('data-src') or
                   iframe.get('data-lazy-src') or '').strip()
            if not src:
                continue
            # Protocol-relative ni to'g'irlab tekshiramiz
            norm_src = _normalize_url(src, url)
            if _is_video_url(norm_src):
                title = (iframe.get('title') or iframe.get('aria-label') or
                         iframe.get('name') or '')
                add_video(src, 'iframe-embed', title=title)

        # ── <embed> va <object> teglari ──────────────────────
        for embed_tag in soup.find_all(['embed', 'object']):
            src = embed_tag.get('src', '') or embed_tag.get('data', '')
            if src:
                norm_src = _normalize_url(src, url)
                if _is_video_url(norm_src):
                    add_video(src, 'embed-tag')

        # ── data-* atributlar (video player'lar) ─────────────
        DATA_VIDEO_ATTRS = [
            'data-video', 'data-video-src', 'data-video-url', 'data-video-file',
            'data-mp4', 'data-webm', 'data-ogg', 'data-src',
            'data-lazy-src', 'data-original',
        ]
        for tag in soup.find_all(True):
            for attr in DATA_VIDEO_ATTRS:
                val = tag.get(attr, '').strip()
                if not val or val.startswith('data:') or val == '#':
                    continue
                norm_val = _normalize_url(val, url)
                if _is_video_url(norm_val):
                    add_video(val, 'data-attr')

        # ── data-video-id (YouTube embed ID) ─────────────────
        for tag in soup.find_all(True):
            for attr in ['data-video-id', 'data-videoid', 'data-youtube-id',
                         'data-yt-id', 'data-ytid']:
                yt_id = tag.get(attr, '').strip()
                # YouTube ID: 11 belgi, harf/raqam/_/-
                if yt_id and re.match(r'^[a-zA-Z0-9_-]{11}$', yt_id):
                    add_video(_yt_id_to_url(yt_id), 'data-yt-id',
                              platform='YouTube',
                              title=tag.get('data-title', tag.get('title', '')))

        # ── amp-youtube / amp-video / amp-vimeo ──────────────
        for amp_tag in soup.find_all(re.compile(r'^amp-(youtube|video|vimeo|dailymotion)')):
            tag_name = amp_tag.name
            if 'youtube' in tag_name:
                yt_id = amp_tag.get('data-videoid', '') or amp_tag.get('data-video-id', '')
                if yt_id:
                    add_video(_yt_id_to_url(yt_id), 'amp-youtube', platform='YouTube')
            elif 'vimeo' in tag_name:
                vid = amp_tag.get('data-videoid', '')
                if vid:
                    add_video(f'https://player.vimeo.com/video/{vid}', 'amp-vimeo', platform='Vimeo')
            elif 'video' in tag_name:
                src = amp_tag.get('src', '')
                if src:
                    add_video(src, 'amp-video')
            elif 'dailymotion' in tag_name:
                vid = amp_tag.get('data-videoid', '')
                if vid:
                    add_video(f'https://www.dailymotion.com/embed/video/{vid}', 'amp-dailymotion', platform='Dailymotion')

        # ── JavaScript ichidagi video URL larni qidirish ─────
        # jwplayer({file:'...'}), videojs({src:'...'}), setup({sources:[{src:'...'}]})
        js_video_patterns = [
            # file: 'url.mp4'  yoki  file: "url.mp4"
            r'''["\']file["\']\s*:\s*["\'](https?://[^"']+\.(?:mp4|webm|m3u8|ogv|ogg))["\']''',
            # src: 'url.mp4'
            r'''["\']src["\']\s*:\s*["\'](https?://[^"']+\.(?:mp4|webm|m3u8|ogv))["\']''',
            # videoUrl: '...'
            r'''videoUrl\s*[:=]\s*["\'](https?://[^"']+)["\']''',
            # sources: [{src: '...'}]
            r'''sources\s*:\s*\[.*?src\s*:\s*["\'](https?://[^"']+)["\']''',
            # YouTube embed URL to'g'ridan-to'g'ri JS ichida
            r'''(https?://(?:www\.)?youtube\.com/embed/[a-zA-Z0-9_-]{11}(?:[?&][^"'\s]*)?)''',
            # Vimeo player URL
            r'''(https?://player\.vimeo\.com/video/\d+(?:[?&][^"'\s]*)?)''',
        ]
        for script_tag in soup.find_all('script', src=False):
            js_text = script_tag.get_text() or ''
            if not js_text.strip():
                continue
            for pattern in js_video_patterns:
                for match in re.findall(pattern, js_text, re.IGNORECASE | re.DOTALL):
                    v_url = match.strip().rstrip('\\')
                    if v_url and _is_video_url(_normalize_url(v_url, url)):
                        add_video(v_url, 'js-inline')

        # ── 3. JAVASCRIPT FAYLLARI ────────────────────────────
        seen_scripts = set()
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                full_url_s = urljoin(url, src)
                if full_url_s not in seen_scripts:
                    seen_scripts.add(full_url_s)
                    is_external = urlparse(full_url_s).netloc != base_domain
                    results['scripts'].append({
                        'url': full_url_s,
                        'type': script.get('type', 'text/javascript'),
                        'async': script.has_attr('async'),
                        'defer': script.has_attr('defer'),
                        'external': is_external,
                        'integrity': script.get('integrity', '')
                    })

        # ── 4. CSS FAYLLARI ───────────────────────────────────
        seen_css = set()
        for link_tag in soup.find_all('link', rel=True):
            rel = ' '.join(link_tag.get('rel', [])).lower()
            if 'stylesheet' in rel:
                href = link_tag.get('href', '')
                if href:
                    full_url_c = urljoin(url, href)
                    if full_url_c not in seen_css:
                        seen_css.add(full_url_c)
                        is_external = urlparse(full_url_c).netloc != base_domain
                        results['stylesheets'].append({
                            'url': full_url_c,
                            'media': link_tag.get('media', 'all'),
                            'external': is_external,
                            'integrity': link_tag.get('integrity', '')
                        })

        # ── 5. FONTLAR ────────────────────────────────────────
        font_extensions = {'woff', 'woff2', 'ttf', 'otf', 'eot'}
        seen_fonts = set()

        # HTML ichidagi <link> fontlar
        for link_tag in soup.find_all('link', href=True):
            href = link_tag.get('href', '')
            ext = _extract_url_ext(href)
            if ext in font_extensions:
                full_url_f = urljoin(url, href)
                if full_url_f not in seen_fonts:
                    seen_fonts.add(full_url_f)
                    results['fonts'].append({
                        'url': full_url_f,
                        'format': ext,
                        'source': 'link-tag'
                    })

        # Google Fonts, Adobe Fonts kabi CDN fontlar
        for link_tag in soup.find_all('link', href=True):
            href = link_tag.get('href', '')
            if any(fd in href for fd in ['fonts.googleapis.com', 'fonts.gstatic.com',
                                          'use.typekit.net', 'use.fontawesome.com',
                                          'cdnjs.cloudflare.com/ajax/libs/font-awesome']):
                if href not in seen_fonts:
                    seen_fonts.add(href)
                    results['fonts'].append({
                        'url': href,
                        'format': 'cdn',
                        'source': 'cdn-font'
                    })

        # ── 6. META VA OG MA'LUMOTLARI ────────────────────────
        meta_info = {}

        # Asosiy meta teglari
        title_tag = soup.find('title')
        if title_tag:
            meta_info['title'] = title_tag.get_text(strip=True)

        desc_tag = soup.find('meta', attrs={'name': 'description'})
        if desc_tag:
            meta_info['description'] = desc_tag.get('content', '')

        keywords_tag = soup.find('meta', attrs={'name': 'keywords'})
        if keywords_tag:
            meta_info['keywords'] = keywords_tag.get('content', '')

        robots_tag = soup.find('meta', attrs={'name': 'robots'})
        if robots_tag:
            meta_info['robots'] = robots_tag.get('content', '')

        # Charset
        charset_tag = soup.find('meta', charset=True)
        if charset_tag:
            meta_info['charset'] = charset_tag.get('charset', '')

        # Viewport
        viewport_tag = soup.find('meta', attrs={'name': 'viewport'})
        if viewport_tag:
            meta_info['viewport'] = viewport_tag.get('content', '')

        # Open Graph
        og_data = {}
        for meta_tag in soup.find_all('meta', property=True):
            prop = meta_tag.get('property', '')
            if prop.startswith('og:'):
                og_data[prop] = meta_tag.get('content', '')
        if og_data:
            meta_info['open_graph'] = og_data

        # Twitter Card
        twitter_data = {}
        for meta_tag in soup.find_all('meta', attrs={'name': True}):
            name = meta_tag.get('name', '')
            if name.startswith('twitter:'):
                twitter_data[name] = meta_tag.get('content', '')
        if twitter_data:
            meta_info['twitter_card'] = twitter_data

        # Canonical URL
        canonical = soup.find('link', rel='canonical')
        if canonical:
            meta_info['canonical'] = canonical.get('href', '')

        # Generator (CMS aniqlash)
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag:
            meta_info['generator'] = generator_tag.get('content', '')

        # HTTP response headerlaridan ma'lumot
        meta_info['content_type'] = response.headers.get('Content-Type', '')
        meta_info['server'] = response.headers.get('Server', '')
        meta_info['x_powered_by'] = response.headers.get('X-Powered-By', '')
        meta_info['status_code'] = response.status_code
        meta_info['response_time_ms'] = round(response.elapsed.total_seconds() * 1000, 2)
        meta_info['content_length'] = len(response.content)

        results['meta_info'] = meta_info

        # ── 7. FORMALAR ───────────────────────────────────────
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            full_action = urljoin(url, action) if action else url
            is_external = urlparse(full_action).netloc not in ('', base_domain)

            form_fields = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                field_type = inp.get('type', inp.name or 'text').lower()
                field_name = inp.get('name', '') or inp.get('id', '')
                form_fields.append({
                    'name': field_name,
                    'type': field_type,
                    'required': inp.has_attr('required'),
                    'sensitive': field_type in ['password', 'email', 'tel', 'credit-card']
                })

            # Xavf darajasi
            has_password = any(f['type'] == 'password' for f in form_fields)
            form_severity = 'high' if (is_external and has_password) else (
                'medium' if is_external else 'low'
            )

            results['forms'].append({
                'action': full_action,
                'method': method,
                'fields': form_fields,
                'field_count': len(form_fields),
                'has_password_field': has_password,
                'is_external_action': is_external,
                'severity': form_severity,
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
            })

        # ── 8. TASHQI HAVOLALAR ───────────────────────────────
        seen_ext_links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href', '')
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue
            full_href = urljoin(url, href)
            parsed_href = urlparse(full_href)
            if parsed_href.netloc and parsed_href.netloc != base_domain:
                if full_href not in seen_ext_links:
                    seen_ext_links.add(full_href)
                    results['external_links'].append({
                        'url': full_href,
                        'text': a_tag.get_text(strip=True)[:80],
                        'domain': parsed_href.netloc,
                        'rel': a_tag.get('rel', []),
                        'nofollow': 'nofollow' in (a_tag.get('rel') or [])
                    })

        # ── 9. MA'LUMOT SIZIB CHIQISHI ────────────────────────
        page_content = response.text

        leak_patterns = {
            'Email manzillar': (
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'low',
                'Sahifa kodida ochiq holda email manzillar aniqlandi'
            ),
            'API kalitlar / Tokenlar': (
                r'(?:key|api|token|secret|password|auth|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                'critical',
                'JavaScript yoki HTML kodida yashirilmagan API kalitlar topildi'
            ),
            'Ichki IP manzillar': (
                r'\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b',
                'medium',
                'Ichki tarmoq IP manzillari HTML yoki skript kodida aniqlandi'
            ),
            'JWT Tokenlar': (
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
                'critical',
                'JWT token sahifa kodida aniqlandi — autentifikatsiya xavfi'
            ),
            'AWS Kalitlar': (
                r'AKIA[0-9A-Z]{16}',
                'critical',
                'Amazon AWS kirish kaliti HTML/JS kodida topildi'
            ),
            'Telefon raqamlar': (
                r'(?:\+998|8)[\s\-]?(?:\d{2})[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}',
                'low',
                "O'zbek telefon raqamlari sahifada aniqlandi"
            ),
            'Kredit karta raqamlari': (
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
                'critical',
                'Potentsial kredit karta raqamlari aniqlandi'
            ),
            'SQL so\'rovlar': (
                r'(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\s+\w+',
                'high',
                'Ochiq SQL so\'rovlari HTML/JS kodida aniqlandi'
            ),
        }

        for label, (pattern, severity, description) in leak_patterns.items():
            found = re.findall(pattern, page_content, re.IGNORECASE)
            # Filtrlash: keng tarqalgan yolg'on musbatlarni olib tashlash
            if label == 'Email manzillar':
                found = [e for e in found if not any(
                    skip in e.lower() for skip in [
                        'example.com', 'yourdomain', 'test@', 'noreply@',
                        'user@', 'email@', 'info@example', 'admin@example'
                    ]
                )]
            if found:
                results['sensitive_text'].append({
                    'type': label,
                    'found_count': len(found),
                    'examples': list(set(str(f) for f in found))[:3],
                    'severity': severity,
                    'description': description
                })
                results['leakage_found'] = True

        # Server headerlari orqali ma'lumot oshkori
        server_header = response.headers.get('Server', '')
        x_powered     = response.headers.get('X-Powered-By', '')
        x_generator   = response.headers.get('X-Generator', '')
        if server_header or x_powered or x_generator:
            examples = [v for v in [server_header, x_powered, x_generator] if v]
            results['sensitive_text'].append({
                'type': "Server ma'lumotlari",
                'found_count': len(examples),
                'examples': examples,
                'severity': 'low',
                'description': 'Server versiyasi response headerda oshkor qilingan',
            })
            results['leakage_found'] = True

        # ── 10. UMUMIY STATISTIKA ─────────────────────────────
        results['summary'] = {
            'total_images': len(results['images']),
            'total_videos': len(results['videos']),
            'total_scripts': len(results['scripts']),
            'total_stylesheets': len(results['stylesheets']),
            'total_fonts': len(results['fonts']),
            'total_forms': len(results['forms']),
            'total_external_links': len(results['external_links']),
            'total_leaks': len(results['sensitive_text']),
            'external_scripts': sum(1 for s in results['scripts'] if s.get('external')),
            'external_css': sum(1 for c in results['stylesheets'] if c.get('external')),
            'high_risk_forms': sum(1 for f in results['forms'] if f.get('severity') == 'high'),
            'critical_leaks': sum(1 for l in results['sensitive_text'] if l.get('severity') == 'critical'),
        }

    except requests.ConnectionError:
        results['error'] = "Saytga ulanib bo'lmadi"
    except requests.Timeout:
        results['error'] = 'Kutish vaqti tugadi (timeout)'
    except Exception as e:
        results['error'] = str(e)

    return results


def download_single_file(file_url, save_dir):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
        resp.raise_for_status()
        parsed = urlparse(file_url)
        filename = os.path.basename(parsed.path)
        if not filename or '.' not in filename:
            ext = mimetypes.guess_extension(resp.headers.get('Content-Type', '').split(';')[0].strip()) or '.bin'
            filename = hashlib.md5(file_url.encode()).hexdigest()[:10] + ext
        filename  = secure_filename(filename)
        save_path = os.path.join(save_dir, filename)
        base, ext = os.path.splitext(save_path)
        counter = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{counter}{ext}"
            counter += 1
        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return {'success': True, 'path': save_path, 'filename': os.path.basename(save_path)}
    except Exception as e:
        return {'success': False, 'url': file_url, 'error': str(e)}


# ═════════════════════════════════════════════════════════════
#  SKANERLASH FUNKSIYALAR
# ═════════════════════════════════════════════════════════════
def scan_ports(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((target, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            open_ports.append({'port': port, 'service': service})
        sock.close()
    return open_ports


def check_ssl_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer  = dict(x[0] for x in cert['issuer'])
                not_after = cert['notAfter']
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                return {
                    'subject': subject, 'issuer': issuer,
                    'not_before': cert['notBefore'], 'not_after': not_after,
                    'days_left': days_left,
                    'status': 'Valid' if days_left > 0 else 'Expired',
                    'severity': 'Low' if days_left > 30 else ('Medium' if days_left > 0 else 'High')
                }
    except Exception as e:
        return {'error': str(e), 'status': 'Error', 'severity': 'High'}


def check_http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        security_headers = {
            'Strict-Transport-Security': 'Missing',
            'Content-Security-Policy': 'Missing',
            'X-Content-Type-Options': 'Missing',
            'X-Frame-Options': 'Missing',
            'X-XSS-Protection': 'Missing'
        }
        for header in security_headers:
            if header in response.headers:
                security_headers[header] = response.headers[header]
        missing_headers = sum(1 for v in security_headers.values() if v == 'Missing')
        severity = 'Low' if missing_headers == 0 else ('Medium' if missing_headers <= 2 else 'High')
        return {'headers': security_headers, 'missing_count': missing_headers, 'severity': severity}
    except Exception as e:
        return {'error': str(e), 'severity': 'Unknown'}


def check_sql_injection(url):
    payloads = ["' OR '1'='1", "1' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "admin'--"]
    results = []
    try:
        for payload in payloads:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            if response.status_code == 200:
                if any(kw in response.text.lower() for kw in ['error', 'syntax', 'mysql']):
                    results.append({"payload": payload,
                                    "description": "Potencial SQL injection zaiflik topildi",
                                    "severity": "High"})
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
            response = requests.get(f"{url}?search={payload}", timeout=5)
            if payload in response.text:
                results.append({"payload": payload,
                                 "description": "Potencial XSS zaiflik topildi",
                                 "severity": "High"})
    except Exception as e:
        results.append({"error": str(e), "description": "XSS testini o'tkazishda xatolik", "severity": "Unknown"})
    return results


# ═════════════════════════════════════════════════════════════
#  ROUTELAR — AUTH
# ═════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        email    = sanitize_input(request.form.get('email'))
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


# ═════════════════════════════════════════════════════════════
#  ROUTELAR — DASHBOARD & SCAN
# ═════════════════════════════════════════════════════════════
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


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target    = sanitize_input(request.form.get('target'))
        scan_type = request.form.get('scan_type')
        if not target:
            flash('Iltimos, skanerlash manzilini kiriting', 'danger')
            return render_template('scan.html')
        if scan_type in ['headers', 'sql_injection', 'xss'] and not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        results  = {}
        severity = "Low"

        if scan_type == 'ports':
            hostname = target.split('//')[1].split('/')[0] if '://' in target else target
            ports = [21,22,23,25,53,80,110,139,143,443,445,465,587,993,995,1433,3306,3389,5432,8080,8443]
            results  = scan_ports(hostname, ports)
            severity = "High" if len(results) > 10 else ("Medium" if len(results) > 5 else "Low")
        elif scan_type == 'ssl':
            hostname = target.split('//')[1].split('/')[0] if '://' in target else target
            results  = check_ssl_certificate(hostname)
            severity = results.get('severity', 'Unknown')
        elif scan_type == 'headers':
            results  = check_http_headers(target)
            severity = results.get('severity', 'Unknown')
        elif scan_type == 'sql_injection':
            results  = check_sql_injection(target)
            if results and any(i.get('severity') == 'High' for i in results):
                severity = "High"
        elif scan_type == 'xss':
            results  = check_xss_vulnerability(target)
            if results and any(i.get('severity') == 'High' for i in results):
                severity = "High"

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
                           scan_type=scan_type, results=results,
                           severity=severity, created_at=created_at)


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


# ═════════════════════════════════════════════════════════════
#  ROUTELAR — ASOSIY MONITORING
# ═════════════════════════════════════════════════════════════
@app.route('/monitoring')
@login_required
def monitoring():
    return render_template('monitoring.html', default_url=DEFAULT_MONITOR_URL)


@app.route('/monitoring/add', methods=['POST'])
@login_required
def add_monitoring_target():
    url      = request.form.get('url', '').strip()
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
    cursor.execute("SELECT id FROM monitoring_targets WHERE user_id = ? AND url = ?",
                   (session['user_id'], url))
    if cursor.fetchone():
        flash("Bu URL allaqachon monitoring ro'yxatida", 'warning')
    else:
        cursor.execute("""
            INSERT INTO monitoring_targets (user_id, url, check_interval) VALUES (?, ?, ?)
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
    cursor.execute("DELETE FROM monitoring_targets WHERE id = ? AND user_id = ?",
                   (target_id, session['user_id']))
    conn.commit()
    conn.close()
    flash("Monitoring manzili o'chirildi", 'info')
    return redirect(url_for('monitoring'))


@app.route('/monitoring/check', methods=['POST'])
@login_required
def manual_check():
    url = request.json.get('url', DEFAULT_MONITOR_URL) or DEFAULT_MONITOR_URL
    result = check_website_status(url)
    save_monitoring_log(result)
    return jsonify(result)


@app.route('/monitoring/stats')
@login_required
def monitoring_stats():
    url   = request.args.get('url', DEFAULT_MONITOR_URL)
    hours = int(request.args.get('hours', 24))
    stats   = get_uptime_stats(url, hours)
    history = get_monitoring_history(url, limit=60)

    chart_labels         = [h['checked_at'][11:16] for h in history]
    chart_response_times = [h['response_time'] or 0 for h in history]
    chart_status         = [1 if h['is_up'] else 0 for h in history]

    hourly_data = []
    try:
        conn = sqlite3.connect('security_scanner.db')
        cursor = conn.cursor()
        since_time = (datetime.now(TASHKENT_TZ) - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            SELECT strftime('%H', checked_at) as hour,
                   COUNT(*) as total, SUM(is_up) as up_count, AVG(response_time) as avg_resp
            FROM monitoring_logs
            WHERE url = ? AND checked_at >= ?
            GROUP BY strftime('%H', checked_at)
            ORDER BY hour
        """, (url, since_time))
        hourly_data = [{'hour': r[0], 'uptime': round((r[2]/r[1])*100, 1),
                        'avg_resp': round(r[3] or 0, 1)} for r in cursor.fetchall()]
        conn.close()
    except Exception as e:
        print(f"Hourly stats xatolik: {e}")

    return jsonify({
        'stats': stats,
        'history': history[-20:],
        'chart': {'labels': chart_labels, 'response_times': chart_response_times, 'statuses': chart_status},
        'hourly': hourly_data
    })


# ═════════════════════════════════════════════════════════════
#  ROUTELAR — KENGAYTIRILGAN MONITORING API
# ═════════════════════════════════════════════════════════════

@app.route('/monitoring/advanced', methods=['POST'])
@login_required
def advanced_monitoring():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = full_advanced_check(url)
    return jsonify(result)


@app.route('/monitoring/dns', methods=['POST'])
@login_required
def check_dns():
    data   = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domen kiritilmagan'}), 400
    result = detect_dns_change(domain)
    return jsonify(result)


@app.route('/monitoring/whois', methods=['POST'])
@login_required
def check_whois():
    data   = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domen kiritilmagan'}), 400
    result = get_whois_info(domain)
    return jsonify(result)


@app.route('/monitoring/redirects', methods=['POST'])
@login_required
def check_redirects():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = trace_redirect_chain(url)
    return jsonify(result)


@app.route('/monitoring/headers/deep', methods=['POST'])
@login_required
def check_headers_deep():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = deep_header_analysis(url)
    return jsonify(result)


@app.route('/monitoring/ping', methods=['POST'])
@login_required
def check_ping():
    data = request.get_json()
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Host kiritilmagan'}), 400
    result = ping_host(host)
    return jsonify(result)


@app.route('/monitoring/ports/history', methods=['POST'])
@login_required
def check_ports_history():
    data = request.get_json()
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Host kiritilmagan'}), 400
    result = scan_and_compare_ports(host)
    return jsonify(result)


@app.route('/monitoring/content', methods=['POST'])
@login_required
def check_content():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = check_content_change(url)
    return jsonify(result)


@app.route('/monitoring/geoip', methods=['POST'])
@login_required
def check_geoip():
    data = request.get_json()
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Host kiritilmagan'}), 400
    result = get_geoip_info(host)
    return jsonify(result)


# ═════════════════════════════════════════════════════════════
#  ROUTELAR — ASSET RECON
# ═════════════════════════════════════════════════════════════
@app.route('/asset_recon')
@login_required
def asset_recon():
    return render_template('asset_recon.html')


@app.route('/asset_recon/scan', methods=['POST'])
@login_required
def asset_recon_scan():
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    results = analyze_assets(url)
    return jsonify(results)


@app.route('/asset_recon/download/single', methods=['POST'])
@login_required
def download_single():
    data     = request.get_json()
    file_url = data.get('url', '').strip()
    if not file_url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
        resp.raise_for_status()

        parsed   = urlparse(file_url)
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
        return send_file(file_data, mimetype=content_type, as_attachment=True, download_name=filename)

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
    data        = request.get_json()
    urls        = data.get('urls', [])
    folder_name = data.get('folder', 'assets')

    if not urls:
        return jsonify({'error': "URL ro'yxati bo'sh"}), 400
    if len(urls) > 50:
        return jsonify({'error': 'Bir vaqtda maksimal 50 ta fayl yuklanadi'}), 400

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_url in urls:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
                resp = requests.get(file_url, timeout=15, stream=True, headers=headers)
                resp.raise_for_status()
                parsed   = urlparse(file_url)
                filename = os.path.basename(parsed.path)
                if not filename or '.' not in filename:
                    ext = mimetypes.guess_extension(
                        resp.headers.get('Content-Type', 'application/octet-stream').split(';')[0].strip()
                    ) or '.bin'
                    filename = hashlib.md5(file_url.encode()).hexdigest()[:10] + ext
                filename = secure_filename(filename)
                zf.writestr(os.path.join(folder_name, filename),
                            b''.join(resp.iter_content(chunk_size=8192)))
            except Exception:
                pass

    zip_buffer.seek(0)
    timestamp    = datetime.now(TASHKENT_TZ).strftime('%Y-%m-%d_%H%M%S')
    zip_filename = f"{folder_name}_{timestamp}.zip"
    return send_file(zip_buffer, mimetype='application/zip',
                     as_attachment=True, download_name=zip_filename)


# ═════════════════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(debug=True)

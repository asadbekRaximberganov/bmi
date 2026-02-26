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
#  ASSET RECON FUNKSIYALAR
# ═════════════════════════════════════════════════════════════
def analyze_assets(url):
    results = {
        'images': [], 'videos': [],
        'sensitive_text': [], 'leakage_found': False
    }
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecureScanner/1.0)'}
        response = requests.get(url, timeout=10, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Rasmlar
        for img in soup.find_all('img'):
            for attr in ['src', 'data-src', 'data-lazy-src']:
                img_url = img.get(attr)
                if img_url:
                    full_url = urljoin(url, img_url)
                    ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                    results['images'].append({'url': full_url, 'type': ext or 'img', 'alt': img.get('alt', '')})
            srcset = img.get('srcset', '')
            if srcset:
                for part in srcset.split(','):
                    src_url = part.strip().split(' ')[0]
                    if src_url:
                        full_url = urljoin(url, src_url)
                        ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                        results['images'].append({'url': full_url, 'type': ext or 'img', 'alt': ''})

        for tag in soup.find_all(style=True):
            css_urls = re.findall(r'url\(["\']?([^"\')\s]+)["\']?\)', tag.get('style', ''))
            for cu in css_urls:
                full_url = urljoin(url, cu)
                ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                results['images'].append({'url': full_url, 'type': ext or 'img', 'alt': 'css-bg'})

        seen = set()
        results['images'] = [img for img in results['images']
                              if img['url'] not in seen and not seen.add(img['url'])]

        # Videolar
        for video in soup.find_all(['video', 'source']):
            video_url = video.get('src')
            if video_url:
                full_url = urljoin(url, video_url)
                ext = os.path.splitext(urlparse(full_url).path)[1].lower().strip('.')
                results['videos'].append({'url': full_url, 'type': ext or 'video'})

        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            if 'youtube' in src or 'vimeo' in src or 'youtu.be' in src:
                results['videos'].append({'url': src, 'type': 'embed'})

        # Ma'lumot sizib chiqishi
        page_content = response.text
        patterns = {
            'Email manzillar': (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'low'),
            'API kalitlar / Tokenlar': (r'(?:key|api|token|secret|password|auth)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'critical'),
            'Ichki IP manzillar': (r'\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b', 'medium'),
        }
        for label, (pattern, severity) in patterns.items():
            found = re.findall(pattern, page_content, re.IGNORECASE)
            if found:
                results['sensitive_text'].append({
                    'type': label, 'found_count': len(found),
                    'examples': list(set(found))[:3], 'severity': severity,
                    'description': {
                        'Email manzillar': 'Sahifa kodida ochiq holda email manzillar aniqlandi',
                        'API kalitlar / Tokenlar': 'JavaScript yoki HTML kodida yashirilmagan API kalitlar topildi',
                        'Ichki IP manzillar': 'Ichki tarmoq IP manzillari HTML yoki skript kodida aniqlandi',
                    }.get(label, "Ma'lumot sizib chiqishi aniqlandi")
                })
                results['leakage_found'] = True

        server_header = response.headers.get('Server', '')
        x_powered     = response.headers.get('X-Powered-By', '')
        if server_header or x_powered:
            examples = [v for v in [server_header, x_powered] if v]
            results['sensitive_text'].append({
                "type": "Server ma'lumotlari", 'found_count': len(examples),
                'examples': examples, 'severity': 'low',
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
    """
    To'liq kengaytirilgan tekshiruv:
    DNS, WHOIS, Redirect, Headers, Ping, Ports, Content, GeoIP.
    """
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
    """DNS yozuvlarini tekshiradi va o'zgarishlarni aniqlaydi."""
    data   = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domen kiritilmagan'}), 400
    result = detect_dns_change(domain)
    return jsonify(result)


@app.route('/monitoring/whois', methods=['POST'])
@login_required
def check_whois():
    """Domen WHOIS ma'lumotlarini qaytaradi."""
    data   = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domen kiritilmagan'}), 400
    result = get_whois_info(domain)
    return jsonify(result)


@app.route('/monitoring/redirects', methods=['POST'])
@login_required
def check_redirects():
    """HTTP redirect zanjirini kuzatadi."""
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = trace_redirect_chain(url)
    return jsonify(result)


@app.route('/monitoring/headers/deep', methods=['POST'])
@login_required
def check_headers_deep():
    """Chuqur header tahlili — A/B/C/F baho."""
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = deep_header_analysis(url)
    return jsonify(result)


@app.route('/monitoring/ping', methods=['POST'])
@login_required
def check_ping():
    """Ping tekshiruvi — RTT va paket yo'qotish."""
    data = request.get_json()
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Host kiritilmagan'}), 400
    result = ping_host(host)
    return jsonify(result)


@app.route('/monitoring/ports/history', methods=['POST'])
@login_required
def check_ports_history():
    """Port o'zgarishlarini tekshiradi va tarixini qaytaradi."""
    data = request.get_json()
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'error': 'Host kiritilmagan'}), 400
    result = scan_and_compare_ports(host)
    return jsonify(result)


@app.route('/monitoring/content', methods=['POST'])
@login_required
def check_content():
    """Sahifa mazmunini hash qilib o'zgarishni aniqlaydi."""
    data = request.get_json()
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kiritilmagan'}), 400
    result = check_content_change(url)
    return jsonify(result)


@app.route('/monitoring/geoip', methods=['POST'])
@login_required
def check_geoip():
    """Server joylashuvi va ISP ma'lumotlarini qaytaradi."""
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

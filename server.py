#!/usr/bin/env python3
"""
EML SOC Dashboard - Email Threat Analysis Tool
Run: python3 server.py
Open: http://localhost:8000
"""

import email
import email.policy
import re
import json
import csv
import io
import os
import sys
import hashlib
import base64
import socket
import urllib.parse
import time
import ipaddress
import traceback
from email import utils as email_utils
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ─── IOC Extraction ────────────────────────────────────────────────────────────

IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|uk|de|fr|ru|cn|info|biz|xyz|top|club|site|online|store|tech|app|dev|gov|edu|mil|int|mobi|name|pro|tel|travel|museum|coop|aero|arpa|[a-z]{2,6})\b',
    re.IGNORECASE
)
URL_RE = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)
EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)
HASH_RE = {
    'MD5':    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'SHA1':   re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'SHA256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
}

PRIVATE_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
]

BENIGN_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'cloudflare.com',
    'github.com', 'linkedin.com', 'twitter.com', 'facebook.com', 'w3.org',
    'schema.org', 'gstatic.com', 'googleapis.com', 'googletagmanager.com',
    'doubleclick.net', 'akamaiedge.net', 'fastly.net',
}

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_IP_RANGES)
    except ValueError:
        return False

def extract_iocs(text):
    iocs = {
        'ips': [],
        'domains': [],
        'urls': [],
        'emails': [],
        'hashes': {'MD5': [], 'SHA1': [], 'SHA256': []},
    }

    # URLs first
    found_urls = set(URL_RE.findall(text))
    iocs['urls'] = sorted(found_urls)

    # IPs
    found_ips = set(IP_RE.findall(text))
    iocs['ips'] = sorted([ip for ip in found_ips if not is_private_ip(ip)])

    # Domains (exclude those already in URLs, deduplicate)
    found_domains = set(DOMAIN_RE.findall(text))
    # Also extract from URLs
    for url in found_urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                found_domains.add(parsed.hostname)
        except Exception:
            pass
    iocs['domains'] = sorted(found_domains)

    # Emails
    found_emails = set(EMAIL_RE.findall(text))
    iocs['emails'] = sorted(found_emails)

    # Hashes
    for htype, pattern in HASH_RE.items():
        iocs['hashes'][htype] = sorted(set(pattern.findall(text)))

    return iocs

# ─── EML Parsing ───────────────────────────────────────────────────────────────

def parse_eml(raw_bytes):
    result = {
        'headers': {},
        'auth': {},
        'body_text': '',
        'body_html': '',
        'attachments': [],
        'iocs': {},
        'routing': [],
        'raw_headers': '',
    }

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as e:
        return {'error': f'Failed to parse EML: {e}'}

    # ── Core headers ──
    def decode_header_val(val):
        if not val:
            return ''
        parts = email.header.decode_header(val)
        decoded = []
        for part, enc in parts:
            if isinstance(part, bytes):
                try:
                    decoded.append(part.decode(enc or 'utf-8', errors='replace'))
                except Exception:
                    decoded.append(part.decode('utf-8', errors='replace'))
            else:
                decoded.append(str(part))
        return ' '.join(decoded)

    result['headers'] = {
        'from':       decode_header_val(msg.get('From', '')),
        'to':         decode_header_val(msg.get('To', '')),
        'cc':         decode_header_val(msg.get('Cc', '')),
        'subject':    decode_header_val(msg.get('Subject', '')),
        'date':       decode_header_val(msg.get('Date', '')),
        'message_id': decode_header_val(msg.get('Message-ID', '')),
        'reply_to':   decode_header_val(msg.get('Reply-To', '')),
        'x_mailer':   decode_header_val(msg.get('X-Mailer', '')),
        'x_originating_ip': decode_header_val(msg.get('X-Originating-IP', '')),
        'user_agent': decode_header_val(msg.get('User-Agent', '')),
        'mime_version': decode_header_val(msg.get('MIME-Version', '')),
        'content_type': decode_header_val(msg.get('Content-Type', '')),
    }

    # ── Raw headers (first 4KB) ──
    raw_str = raw_bytes.decode('utf-8', errors='replace')
    header_end = raw_str.find('\n\n')
    result['raw_headers'] = raw_str[:header_end] if header_end > 0 else raw_str[:4096]

    # ── Auth results ──
    auth_results = msg.get('Authentication-Results', '')
    spf_header = msg.get('Received-SPF', '')
    dkim_header = msg.get('DKIM-Signature', '')

    def extract_auth_status(text, keyword):
        pattern = re.compile(rf'{keyword}=(\w+)', re.IGNORECASE)
        m = pattern.search(text)
        return m.group(1).lower() if m else 'none'

    result['auth'] = {
        'spf':  extract_auth_status(auth_results + ' ' + spf_header, 'spf'),
        'dkim': 'pass' if dkim_header else extract_auth_status(auth_results, 'dkim'),
        'dmarc': extract_auth_status(auth_results, 'dmarc'),
        'spf_raw':  spf_header[:500] if spf_header else '',
        'dkim_raw': dkim_header[:500] if dkim_header else '',
        'auth_raw': auth_results[:1000] if auth_results else '',
    }

    # ── Received chain ──
    received_headers = msg.get_all('Received', [])
    routing = []
    for r in received_headers:
        ip_matches = IP_RE.findall(r)
        routing.append({
            'raw': r.strip()[:300],
            'ips': [ip for ip in ip_matches if not is_private_ip(ip)],
        })
    result['routing'] = routing

    # ── Body extraction ──
    all_text = []

    def walk_part(part):
        ctype = part.get_content_type()
        disp = str(part.get('Content-Disposition', ''))
        fname = part.get_filename()

        if 'attachment' in disp.lower() or (fname and fname.strip()):
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = b''
            sha256 = hashlib.sha256(payload).hexdigest()
            md5 = hashlib.md5(payload).hexdigest()
            result['attachments'].append({
                'filename': decode_header_val(fname) if fname else 'unnamed',
                'content_type': ctype,
                'size': len(payload),
                'md5': md5,
                'sha256': sha256,
                'b64_preview': base64.b64encode(payload[:128]).decode() if payload else '',
            })
            return

        if ctype == 'text/plain':
            payload = part.get_payload(decode=True)
            if payload:
                txt = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                result['body_text'] += txt
                all_text.append(txt)
        elif ctype == 'text/html':
            payload = part.get_payload(decode=True)
            if payload:
                html = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                result['body_html'] += html
                # Strip tags for IOC extraction
                stripped = re.sub(r'<[^>]+>', ' ', html)
                all_text.append(stripped)

    if msg.is_multipart():
        for part in msg.walk():
            walk_part(part)
    else:
        walk_part(msg)

    # ── IOC extraction from everything ──
    full_text = ' '.join(all_text) + ' ' + result['raw_headers']
    # Add headers fields to text
    for v in result['headers'].values():
        full_text += ' ' + v

    result['iocs'] = extract_iocs(full_text)

    # Add attachment hashes to IOCs
    for att in result['attachments']:
        if att['sha256']:
            result['iocs']['hashes']['SHA256'].append(att['sha256'])
        if att['md5']:
            result['iocs']['hashes']['MD5'].append(att['md5'])

    return result

# ─── Threat Intelligence ───────────────────────────────────────────────────────

def vt_lookup(ioc, ioc_type, api_key):
    """Query VirusTotal API v3"""
    if not api_key:
        return {'no_key': True}
    if not REQUESTS_OK:
        return {'error': 'requests not installed'}
    
    endpoints = {
        'ip':     f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}',
        'domain': f'https://www.virustotal.com/api/v3/domains/{ioc}',
        'url':    f'https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")}',
        'hash':   f'https://www.virustotal.com/api/v3/files/{ioc}',
    }
    
    url = endpoints.get(ioc_type)
    if not url:
        return None

    try:
        resp = requests.get(url, headers={'x-apikey': api_key}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            reputation = data.get('data', {}).get('attributes', {}).get('reputation', 0)
            return {
                'malicious':   stats.get('malicious', 0),
                'suspicious':  stats.get('suspicious', 0),
                'harmless':    stats.get('harmless', 0),
                'undetected':  stats.get('undetected', 0),
                'reputation':  reputation,
                'total':       sum(stats.values()),
                'link':        f'https://www.virustotal.com/gui/{ioc_type}/{ioc}',
            }
        elif resp.status_code == 401:
            return {'no_key': True, 'error': 'Invalid API key'}
        elif resp.status_code == 404:
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0,
                    'reputation': 0, 'total': 0, 'not_found': True, 'link': ''}
        elif resp.status_code == 429:
            return {'error': 'VT rate limit hit — wait 1 minute'}
    except Exception as e:
        return {'error': str(e)}
    return None



def whois_lookup(domain):
    """WHOIS via RDAP (HTTPS port 443 — works everywhere)."""
    if not REQUESTS_OK:
        return {'error': 'requests not installed'}
    try:
        # RDAP bootstrap: try common registries first, fall back to rdap.org
        urls = [
            f'https://rdap.org/domain/{domain}',
            f'https://rdap.iana.org/domain/{domain}',
        ]
        data = None
        for url in urls:
            try:
                r = requests.get(url, timeout=8, headers={'Accept': 'application/json'})
                if r.status_code == 200:
                    data = r.json()
                    break
            except Exception:
                continue

        if not data:
            return {'error': 'RDAP lookup failed'}

        # Extract creation date from events
        created_raw = None
        expires_raw = None
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date   = event.get('eventDate', '')
            if action == 'registration':
                created_raw = date
            elif action == 'expiration':
                expires_raw = date

        # Parse date and compute age
        age_days = None
        created_fmt = 'Unknown'
        if created_raw:
            try:
                # RDAP dates are ISO 8601
                dt = datetime.fromisoformat(created_raw.replace('Z', '+00:00'))
                created_fmt = dt.strftime('%Y-%m-%d')
                age_days = (datetime.now(timezone.utc) - dt).days
            except Exception:
                created_fmt = created_raw[:10] if created_raw else 'Unknown'

        expires_fmt = 'Unknown'
        if expires_raw:
            try:
                expires_fmt = expires_raw[:10]
            except Exception:
                pass

        # Registrar
        registrar = 'Unknown'
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            if 'registrar' in roles:
                vcard = entity.get('vcardArray', [])
                if vcard and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == 'fn':
                            registrar = field[3]
                            break
                if registrar == 'Unknown':
                    registrar = entity.get('handle', 'Unknown')
                break

        # Name servers
        ns_list = [ns.get('ldhName', '') for ns in data.get('nameservers', [])][:5]

        return {
            'registrar':   registrar,
            'created':     created_fmt,
            'expires':     expires_fmt,
            'age_days':    age_days,
            'name_servers': ns_list,
            'status':      ', '.join(data.get('status', []))[:200],
        }
    except Exception as e:
        return {'error': str(e)}

def dns_lookup(domain):
    """DNS resolution"""
    if not DNS_OK:
        return None
    result = {}
    for rtype in ['A', 'MX', 'TXT', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            result[rtype] = [str(r) for r in answers][:5]
        except Exception:
            result[rtype] = []
    return result

def enrich_iocs(iocs, vt_key='', sender_domain=''):
    enriched = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': [],
        'sender_whois': None,
    }

    # Sender domain WHOIS — only for the From: domain
    if sender_domain:
        enriched['sender_whois'] = {
            'domain': sender_domain,
            'whois': whois_lookup(sender_domain),
        }

    # IPs — VT only
    for ip in iocs.get('ips', [])[:10]:
        entry = {'value': ip, 'vt': None}
        if vt_key:
            entry['vt'] = vt_lookup(ip, 'ip', vt_key)
            time.sleep(0.2)
        enriched['ips'].append(entry)

    # Domains — VT only, no more per-domain whois
    for domain in iocs.get('domains', [])[:10]:
        if domain in BENIGN_DOMAINS:
            continue
        entry = {'value': domain, 'vt': None}
        if vt_key:
            entry['vt'] = vt_lookup(domain, 'domain', vt_key)
            time.sleep(0.2)
        enriched['domains'].append(entry)

    # URLs
    for url in iocs.get('urls', [])[:5]:
        entry = {'value': url, 'vt': None}
        if vt_key:
            entry['vt'] = vt_lookup(url, 'url', vt_key)
            time.sleep(0.2)
        enriched['urls'].append(entry)

    # Hashes
    all_hashes = []
    for htype, hlist in iocs.get('hashes', {}).items():
        for h in hlist[:5]:
            all_hashes.append((htype, h))
    for htype, h in all_hashes:
        entry = {'value': h, 'type': htype, 'vt': None}
        if vt_key:
            entry['vt'] = vt_lookup(h, 'hash', vt_key)
            time.sleep(0.2)
        enriched['hashes'].append(entry)

    return enriched

# ─── HTTP Handler ──────────────────────────────────────────────────────────────

# ─── Static file resolution ────────────────────────────────────────────────────
# Supports two layouts:
#   A) server.py + index.html in the same folder  (flat, zip-extracted)
#   B) server.py in root, index.html in static/   (structured)
# On first run in layout A, we auto-create static/ and move index.html there.

_BASE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(_BASE, 'static')

def _ensure_static():
    """Move index.html into static/ if it sits next to server.py."""
    flat_index = os.path.join(_BASE, 'index.html')
    static_index = os.path.join(STATIC_DIR, 'index.html')
    os.makedirs(STATIC_DIR, exist_ok=True)
    if os.path.exists(flat_index) and not os.path.exists(static_index):
        import shutil
        shutil.move(flat_index, static_index)
        print('[*] Moved index.html → static/index.html')

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f'[{datetime.now().strftime("%H:%M:%S")}] {format % args}')

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, content_type='text/html'):
        with open(path, 'rb') as f:
            body = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?')[0]
        if path == '/' or path == '/index.html':
            self.send_file(os.path.join(STATIC_DIR, 'index.html'), 'text/html')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = self.path.split('?')[0]

        if path == '/api/parse':
            self._handle_parse()
        elif path == '/api/enrich':
            self._handle_enrich()
        elif path == '/api/export/csv':
            self._handle_export_csv()
        elif path == '/api/export/json':
            self._handle_export_json()
        else:
            self.send_json({'error': 'Not found'}, 404)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length)

    def _handle_parse(self):
        try:
            body = self._read_body()
            # Multipart form data parsing
            content_type = self.headers.get('Content-Type', '')
            
            if 'multipart/form-data' in content_type:
                boundary = content_type.split('boundary=')[-1].encode()
                parts = body.split(b'--' + boundary)
                eml_bytes = None
                for part in parts:
                    if b'filename=' in part and b'.eml' in part.lower():
                        # Find double CRLF that separates headers from content
                        idx = part.find(b'\r\n\r\n')
                        if idx == -1:
                            idx = part.find(b'\n\n')
                            if idx != -1:
                                eml_bytes = part[idx+2:].rstrip(b'\r\n')
                        else:
                            eml_bytes = part[idx+4:].rstrip(b'\r\n')
                        break
                
                if not eml_bytes:
                    # Try to find any content part
                    for part in parts:
                        if b'Content-Disposition' in part:
                            idx = part.find(b'\r\n\r\n')
                            if idx != -1:
                                eml_bytes = part[idx+4:].rstrip(b'\r\n')
                                break

                if not eml_bytes:
                    self.send_json({'error': 'No EML file found in upload'}, 400)
                    return
            else:
                eml_bytes = body

            result = parse_eml(eml_bytes)
            self.send_json(result)

        except Exception as e:
            self.send_json({'error': str(e), 'trace': traceback.format_exc()}, 500)

    def _handle_enrich(self):
        try:
            body = self._read_body()
            data = json.loads(body)
            iocs = data.get('iocs', {})
            vt_key = data.get('vt_key', '')
            sender_domain = data.get('sender_domain', '')

            enriched = enrich_iocs(iocs, vt_key, sender_domain)
            self.send_json(enriched)
        except Exception as e:
            self.send_json({'error': str(e), 'trace': traceback.format_exc()}, 500)

    def _handle_export_csv(self):
        try:
            body = self._read_body()
            data = json.loads(body)
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Headers section
            writer.writerow(['=== EMAIL HEADERS ==='])
            writer.writerow(['Field', 'Value'])
            headers = data.get('headers', {})
            for k, v in headers.items():
                writer.writerow([k, v])
            
            writer.writerow([])
            writer.writerow(['=== AUTHENTICATION ==='])
            writer.writerow(['Check', 'Result'])
            auth = data.get('auth', {})
            for k in ['spf', 'dkim', 'dmarc']:
                writer.writerow([k.upper(), auth.get(k, 'N/A')])
            
            writer.writerow([])
            writer.writerow(['=== IOCs - IP ADDRESSES ==='])
            writer.writerow(['IP', 'VT Malicious', 'VT Suspicious', 'Shodan Org', 'Shodan Country'])
            enriched = data.get('enriched', {})
            for ip_entry in enriched.get('ips', []):
                vt = ip_entry.get('vt') or {}
                sh = ip_entry.get('shodan') or {}
                writer.writerow([
                    ip_entry.get('value', ''),
                    vt.get('malicious', ''),
                    vt.get('suspicious', ''),
                    sh.get('org', ''),
                    sh.get('country', ''),
                ])

            writer.writerow([])
            writer.writerow(['=== IOCs - DOMAINS ==='])
            writer.writerow(['Domain', 'VT Malicious', 'Registrar', 'Age (days)', 'Created'])
            for d_entry in enriched.get('domains', []):
                vt = d_entry.get('vt') or {}
                wi = d_entry.get('whois') or {}
                writer.writerow([
                    d_entry.get('value', ''),
                    vt.get('malicious', ''),
                    wi.get('registrar', ''),
                    wi.get('age_days', ''),
                    wi.get('created', ''),
                ])

            writer.writerow([])
            writer.writerow(['=== IOCs - URLs ==='])
            writer.writerow(['URL', 'VT Malicious'])
            for u_entry in enriched.get('urls', []):
                vt = u_entry.get('vt') or {}
                writer.writerow([u_entry.get('value', ''), vt.get('malicious', '')])

            writer.writerow([])
            writer.writerow(['=== IOCs - HASHES ==='])
            writer.writerow(['Hash', 'Type', 'VT Malicious', 'VT Detected/Total'])
            for h_entry in enriched.get('hashes', []):
                vt = h_entry.get('vt') or {}
                writer.writerow([
                    h_entry.get('value', ''),
                    h_entry.get('type', ''),
                    vt.get('malicious', ''),
                    f"{vt.get('malicious',0)+vt.get('suspicious',0)}/{vt.get('total',0)}",
                ])

            writer.writerow([])
            writer.writerow(['=== ATTACHMENTS ==='])
            writer.writerow(['Filename', 'Content-Type', 'Size', 'MD5', 'SHA256'])
            for att in data.get('attachments', []):
                writer.writerow([
                    att.get('filename', ''),
                    att.get('content_type', ''),
                    att.get('size', ''),
                    att.get('md5', ''),
                    att.get('sha256', ''),
                ])

            csv_bytes = output.getvalue().encode('utf-8-sig')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="eml_analysis.csv"')
            self.send_header('Content-Length', len(csv_bytes))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(csv_bytes)

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def _handle_export_json(self):
        try:
            body = self._read_body()
            data = json.loads(body)
            json_bytes = json.dumps(data, indent=2, default=str, ensure_ascii=False).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', 'attachment; filename="eml_analysis.json"')
            self.send_header('Content-Length', len(json_bytes))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json_bytes)
        except Exception as e:
            self.send_json({'error': str(e)}, 500)

# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import webbrowser, threading
    _ensure_static()
    port = 8000
    url = f'http://localhost:{port}'
    print(f'\n{"="*50}')
    print(f'  🐱  A Mai — Email Threat Analyzer')
    print(f'{"="*50}')
    print(f'  Open: {url}')
    print(f'  WHOIS:    {"✓" if WHOIS_OK else "✗  pip install python-whois"}')
    print(f'  DNS:      {"✓" if DNS_OK else "✗  pip install dnspython"}')
    print(f'  Requests: {"✓" if REQUESTS_OK else "✗  pip install requests"}')
    print(f'{"="*50}\n')

    server = HTTPServer(('0.0.0.0', port), Handler)
    # Open browser after a short delay so the server is ready
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[*] Server stopped.')

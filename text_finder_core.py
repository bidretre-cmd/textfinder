"""
Text Finder Core Engine
Berisi semua logika regex, parsing cookie, ekstraksi credentials,
pencarian multi-threaded, dan export data.
Dapat digunakan oleh GUI Tkinter (desktop) maupun Flet (Android APK / mobile).
"""

import os
import re
import mmap
import queue
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from email.utils import parsedate_to_datetime

# ─────────────────────────── SORTER ENGINE CONSTANTS & UTILS ───────────────────
# Cookie patterns
_COOKIE_NETSCAPE = re.compile(
    r'^\.?\S+\t(TRUE|FALSE)\t[^\t]*\t(TRUE|FALSE)\t\d{8,13}\t[^\t]*\t.*$',
    re.IGNORECASE)

_COOKIE_HEADER = re.compile(
    r'^(Set-Cookie|Cookie)\s*:\s*\S+=', re.IGNORECASE)

_COOKIE_JSON = re.compile(
    r'"name"\s*:\s*"[^"]+".{0,300}"value"\s*:\s*"', re.DOTALL | re.IGNORECASE)

_COOKIE_ATTRS = re.compile(
    r'(;\s*(path|domain|expires|max-age|secure|httponly|samesite)\b)',
    re.IGNORECASE)

COOKIE_PATTERNS = [_COOKIE_NETSCAPE, _COOKIE_HEADER, _COOKIE_JSON, _COOKIE_ATTRS]

# Credential patterns
_CRED_DOMAIN_USER_PASS = re.compile(
    r'^(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})(?::\d+)?(?:/[^\s:|]*)?:([^\s:|]+):([^\s|]+)$', re.IGNORECASE)
_CRED_DOMAIN_PIPE = re.compile(
    r'^(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})(?::\d+)?(?:/[^\s:|]*)?\|([^\s:|]+)\|([^\s|]+)$', re.IGNORECASE)
_CRED_DOMAIN_USER_PASS_EQUALS = re.compile(
    r'^(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})(?::\d+)?(?:/[^\s:|]*)?:(?:user|username|login|email)?\s*=\s*[^\s:|]+:(?:pass|password)?\s*=\s*[^\s:|]+$', re.IGNORECASE)

_CRED_URL_USER_PASS = re.compile(
    r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?:[^\s:]{1,128}:[^\s]{1,128}$', re.IGNORECASE)
_CRED_ANDROID_URL = re.compile(
    r'^android://[^\s@]+@[\w.]+/', re.IGNORECASE)
_CRED_URL_PIPE = re.compile(
    r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?\|[^\s|]{1,128}\|[^\s]{1,128}$', re.IGNORECASE)
_CRED_USER_PASS_EQUALS = re.compile(
    r'^(?:user|username|login|email)?\s*=\s*[^\s:|]+:(?:pass|password)?\s*=\s*[^\s:|]+$', re.IGNORECASE)
_CRED_URL_USER_PASS_EQUALS = re.compile(
    r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?:(?:user|username|login|email)?\s*=\s*[^\s:|]+:(?:pass|password)?\s*=\s*[^\s:|]+$', re.IGNORECASE)
_CRED_EMAIL_PASS = re.compile(
    r'^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,64}\.[a-zA-Z]{2,10}:[^\s:]{1,256}$')
_CRED_USER_PASS_COLON = re.compile(
    r'^[a-zA-Z0-9._%+\-]{2,64}:[^\s:]{3,256}$')
_CRED_USER_PASS_PIPE = re.compile(
    r'^[a-zA-Z0-9._%+\-@]{2,64}\|[^\s|]{3,256}$')
_CRED_USER_PASS_SEMI = re.compile(
    r'^[a-zA-Z0-9._%+\-@]{2,64};[^\s;]{3,256}$')

CREDENTIAL_PATTERNS = [
    _CRED_DOMAIN_USER_PASS, _CRED_DOMAIN_PIPE, _CRED_DOMAIN_USER_PASS_EQUALS,
    _CRED_URL_USER_PASS, _CRED_URL_PIPE, _CRED_ANDROID_URL,
    _CRED_URL_USER_PASS_EQUALS, _CRED_USER_PASS_EQUALS,
    _CRED_EMAIL_PASS, _CRED_USER_PASS_COLON,
    _CRED_USER_PASS_PIPE, _CRED_USER_PASS_SEMI,
]

_NOT_CRED = re.compile(
    r'(^\s*#|^\s*//|<html|<body|DOCTYPE|<\?xml|import |def |class |'
    r'function\s*\(|;\s*(path|domain|expires|httponly|secure|samesite)\b)',
    re.IGNORECASE)

_TF_LINE_RE = re.compile(r'^\s*(?:>>>\s*)?\s*\d+\s*[|│]\s*(.+)$')

_TF_SKIP = re.compile(
    r'^={10,}|^[-─]{10,}|^\s*FILE\s*:|^\s*\[Baris \d|^\s*TEXT FINDER|'
    r'^\s*Kata kunci|^\s*Folder target|^\s*Waktu\s*:|^\s*Total',
    re.IGNORECASE)

_CRED_URL_KEY   = re.compile(r'^(?:URL|Host|Url)\s*:\s*(.+)$', re.IGNORECASE)
_CRED_LOGIN_KEY = re.compile(r'^(?:Login|Username|User|Email)\s*:\s*(.+)$', re.IGNORECASE)
_CRED_PASS_KEY  = re.compile(r'^(?:Password|Pass|Passwd|Pwd)\s*:\s*(.+)$', re.IGNORECASE)


def strip_tf_marker(line: str):
    stripped = line.strip()
    if not stripped:
        return None
    if _TF_SKIP.match(stripped):
        return None
    m = _TF_LINE_RE.match(stripped)
    if m:
        return m.group(1).strip()
    return stripped


def get_base_domain(domain: str) -> str:
    if not domain or domain in ("unknown_domain", "other_credentials", "—"):
        return domain
    domain = domain.lower().strip()
    if domain.startswith('.'):
        domain = domain[1:]
    if domain.startswith('www.'):
        domain = domain[4:]
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    second_level_tlds = {'co', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'ac', 'go', 'or', 'id', 'in', 'us'}
    if len(parts) >= 3 and parts[-2] in second_level_tlds and len(parts[-1]) <= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def extract_domain_from_filename(filename: str) -> str | None:
    name = filename.lower()
    name = os.path.splitext(name)[0]
    
    m = re.search(r'\b([a-z0-9\-]+\.[a-z]{2,6}(?:\.[a-z]{2,3})?)\b', name)
    if m:
        return get_base_domain(m.group(1))
        
    words_to_remove = [
        r'cookies', r'cookie', r'passwords', r'password', r'pass', r'credentials',
        r'credential', r'creds', r'cred', r'users', r'user', r'emails', r'email',
        r'accounts', r'account', r'logins', r'login', r'autofills', r'autofill',
        r'cards', r'card', r'info', r'results', r'result', r'netflix', r'spotify',
        r'facebook', r'google', r'hulu', r'disneyplus', r'hulu', r'disney'
    ]
    
    services = ['netflix', 'spotify', 'facebook', 'google', 'hulu', 'disneyplus', 'disney', 'instagram', 'twitter', 'tiktok', 'epicgames', 'steam', 'roblox']
    for service in services:
        if service in name:
            if service == 'disneyplus':
                return 'disneyplus.com'
            return f"{service}.com"
            
    name = re.sub(r'[^a-z0-9\-]', ' ', name)
    name = re.sub(r'\b\d{4,}\b', ' ', name)
    
    parts = [p for p in name.split() if p not in words_to_remove and len(p) >= 2]
    if parts:
        clean_name = parts[0]
        return f"{clean_name}.com"
        
    return None


def parse_date_to_timestamp(date_str: str) -> str:
    try:
        dt = parsedate_to_datetime(date_str)
        return str(int(dt.timestamp()))
    except Exception:
        if date_str.isdigit():
            return date_str
        return "0"


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    d = domain.strip().lower()
    if d.startswith('.'):
        d = d[1:]
    if any(c in d for c in (' ', '\t', ':', '|', ';', '=', '\\', '/', '*', '?', '"', '<', '>', ',', '@')):
        return False
    if d.startswith(('http://', 'https://', 'android://', 'ftp://', 'file://')):
        return False
    parts = d.split('.')
    if len(parts) < 2:
        return False
    for part in parts:
        if not part or not re.match(r'^[a-z0-9\-]+$', part):
            return False
    if not re.match(r'^[a-z\-]{2,10}$', parts[-1]):
        return False
    return True


def is_valid_cookie_name_val(name: str, val: str) -> bool:
    if not name or not val:
        return False
    if '\n' in name or '\r' in name or '\n' in val or '\r' in val:
        return False
    if any(c in name for c in '()<>@,;:\\"[]?={} \t'):
        return False
    if any(c in val for c in ';, \t'):
        return False
    if name.lower().startswith(('http', 'ftp', 'file', '//')):
        return False
    if '(' in val or ')' in val or '{' in val or '}' in val or ';' in val:
        return False
    if len(name) > 256 or len(val) > 4096:
        return False
    return True


def parse_json_cookie(text: str) -> list:
    text = text.strip()
    if not text:
        return []
    if (text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']')):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
            results = []
            for item in data:
                if isinstance(item, dict) and "name" in item and "value" in item:
                    domain = item.get("domain", "").strip()
                    if not domain:
                        domain = item.get("host", "").strip()
                    if not domain or not is_valid_domain(domain):
                        continue
                    
                    sub = "TRUE" if domain.startswith('.') else "FALSE"
                    if "hostOnly" in item:
                        sub = "FALSE" if item["hostOnly"] else "TRUE"
                        
                    path = item.get("path", "/").strip()
                    sec = "TRUE" if item.get("secure", False) else "FALSE"
                    
                    exp = item.get("expirationDate") or item.get("expiry") or item.get("expires")
                    exp_str = "0"
                    if exp is not None:
                        try:
                            exp_val = int(float(exp))
                            if exp_val > 9999999999:
                                exp_val = exp_val // 1000
                            exp_str = str(exp_val)
                        except (ValueError, TypeError):
                            pass
                            
                    name = item.get("name", "").strip()
                    val = item.get("value", "").strip()
                    
                    name_parts = name.split()
                    if name_parts:
                        name = name_parts[0]
                    val_parts = val.split()
                    if val_parts:
                        val = val_parts[0]
                        
                    if is_valid_cookie_name_val(name, val):
                        results.append(f"{domain}\t{sub}\t{path}\t{sec}\t{exp_str}\t{name}\t{val}")
            return results
        except Exception:
            pass
    return []


def normalize_netscape_line(line: str) -> str | None:
    parts = line.split('\t')
    if len(parts) == 7:
        domain = parts[0].strip()
        if is_valid_domain(domain):
            sub = parts[1].strip().upper()
            if sub not in ("TRUE", "FALSE"):
                sub = "TRUE" if domain.startswith('.') else "FALSE"
            path = parts[2].strip()
            if not path:
                path = "/"
            sec = parts[3].strip().upper()
            if sec not in ("TRUE", "FALSE"):
                sec = "FALSE"
            
            exp_str = parts[4].strip()
            try:
                exp_val = int(exp_str)
                if len(exp_str) == 13:
                    exp_val = exp_val // 1000
                elif len(exp_str) > 13:
                    exp_val = exp_val // (10 ** (len(exp_str) - 10))
                exp_str = str(exp_val)
            except ValueError:
                exp_str = "0"
                
            name = parts[5].strip()
            val = parts[6].strip()
            
            name_parts = name.split()
            if name_parts:
                name = name_parts[0]
            val_parts = val.split()
            if val_parts:
                val = val_parts[0]
                
            if is_valid_cookie_name_val(name, val):
                return f"{domain}\t{sub}\t{path}\t{sec}\t{exp_str}\t{name}\t{val}"
    return None


def parse_semicolon_cookie(line: str, fallback_domain: str = None) -> list[str]:
    line = line.strip()
    if not line or ';' not in line or '=' not in line:
        return []
    if line.startswith('#') or line.startswith('//'):
        return []
    
    cookie_prefix = re.match(r'^(?:Set-Cookie|Cookie)\s*:\s*(.+)$', line, re.IGNORECASE)
    if cookie_prefix:
        line = cookie_prefix.group(1).strip()
        
    parts = line.split(';')
    
    has_attrs = False
    for part in parts[1:]:
        p = part.strip().lower()
        if p.startswith(('domain=', 'path=', 'expires=', 'max-age=', 'secure', 'httponly', 'samesite=')):
            has_attrs = True
            break
            
    if has_attrs:
        kv_part = parts[0].strip()
        if '=' not in kv_part:
            return []
        
        name, val = kv_part.split('=', 1)
        name = name.strip()
        val = val.strip()
        
        name_parts = name.split()
        if name_parts:
            name = name_parts[0]
        val_parts = val.split()
        if val_parts:
            val = val_parts[0]
            
        if not is_valid_cookie_name_val(name, val):
            return []
            
        domain = ""
        path = "/"
        secure = "FALSE"
        expires = "0"
        
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            if '=' in part:
                k, v = part.split('=', 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "domain":
                    domain = v
                    if domain.lower().startswith(('http://', 'https://')):
                        domain = extract_host_from_url(domain)
                elif k == "path":
                    path = v
                elif k in ("expires", "expiry"):
                    expires = parse_date_to_timestamp(v)
            else:
                k = part.lower()
                if k == "secure":
                    secure = "TRUE"
                    
        if not domain and fallback_domain:
            domain = fallback_domain
            
        if domain and is_valid_domain(domain):
            sub = "TRUE" if domain.startswith('.') else "FALSE"
            return [f"{domain}\t{sub}\t{path}\t{secure}\t{expires}\t{name}\t{val}"]
    else:
        results = []
        domain = fallback_domain or ""
        if not domain or not is_valid_domain(domain):
            return []
            
        sub = "TRUE" if domain.startswith('.') else "FALSE"
        
        for part in parts:
            part = part.strip()
            if not part or '=' not in part:
                continue
            name, val = part.split('=', 1)
            name = name.strip()
            val = val.strip()
            
            name_parts = name.split()
            if name_parts:
                name = name_parts[0]
            val_parts = val.split()
            if val_parts:
                val = val_parts[0]
                
            if is_valid_cookie_name_val(name, val):
                results.append(f"{domain}\t{sub}\t/\tFALSE\t0\t{name}\t{val}")
        return results
        
    return []


def fallback_normalize_cookie(content: str, fallback_domain: str = None) -> list[str]:
    content = content.strip()
    if ':' in content:
        return []
    if '=' in content and ';' not in content and '\t' not in content:
        parts = content.split('=', 1)
        name = parts[0].strip()
        val = parts[1].strip()
        
        name_parts = name.split()
        if name_parts:
            name = name_parts[0]
        val_parts = val.split()
        if val_parts:
            val = val_parts[0]
            
        if is_valid_cookie_name_val(name, val):
            domain = fallback_domain
            if domain and is_valid_domain(domain):
                sub = "TRUE" if domain.startswith('.') else "FALSE"
                return [f"{domain}\t{sub}\t/\tFALSE\t0\t{name}\t{val}"]
    return []


def parse_to_netscape_cookie(line: str, fallback_domain: str = None) -> list[str]:
    line = line.strip()
    if not line or len(line) > 4000:
        return []
    if line.startswith('#') or line.startswith('//') or '<html' in line.lower() or '<body' in line.lower():
        return []
    if line.startswith(('import ', 'def ', 'class ', 'function ', 'var ', 'const ', 'let ')):
        return []

    if ('"name"' in line and '"value"' in line) or (line.startswith('{') and line.endswith('}')) or (line.startswith('[') and line.endswith(']')):
        json_str = line
        if not (line.startswith('{') or line.startswith('[')):
            m = re.search(r'(\[.*\])', line)
            if m:
                json_str = m.group(1)
            else:
                m = re.search(r'(\{.*\})', line)
                if m:
                    json_str = m.group(1)
        json_results = parse_json_cookie(json_str)
        if json_results:
            return json_results
            
    parts = line.split('\t')
    if len(parts) == 7:
        norm = normalize_netscape_line(line)
        return [norm] if norm else []
        
    if ';' in line and '=' in line:
        return parse_semicolon_cookie(line, fallback_domain)
        
    return fallback_normalize_cookie(line, fallback_domain)


def normalize_cookie(line: str, fallback_domain: str = None) -> list[str]:
    return parse_to_netscape_cookie(line, fallback_domain)


def classify_line(line: str, fallback_domain: str = None) -> str:
    stripped = line.strip()
    if not stripped or len(stripped) > 4000:
        return "other"
    
    if not any(c in stripped for c in ('\t', ':', '|', ';', '=')):
        return "other"
        
    if not _NOT_CRED.search(stripped):
        if stripped.lower().startswith(("http://", "https://", "android://")):
            for pat in (_CRED_URL_USER_PASS, _CRED_URL_PIPE, _CRED_ANDROID_URL, _CRED_URL_USER_PASS_EQUALS):
                if pat.match(stripped):
                    return "credential"
        else:
            for pat in CREDENTIAL_PATTERNS:
                if pat.match(stripped):
                    return "credential"
                    
    if parse_to_netscape_cookie(stripped, fallback_domain):
        return "cookie"
        
    return "other"


def classify_file_netscape(lines: list[str]) -> bool:
    count = 0
    checked = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        checked += 1
        if _COOKIE_NETSCAPE.match(s):
            count += 1
        if checked >= 15:
            break
    return checked > 0 and count >= checked * 0.4


def extract_cookie_domain(content: str) -> str:
    parts = content.split('\t')
    if parts:
        domain = parts[0].strip().lower()
        if domain.startswith('.'):
            domain = domain[1:]
        domain = re.sub(r'[\\/:*?"<>|]', '_', domain)
        if not domain:
            return "unknown_domain"
        return get_base_domain(domain)
    return "unknown_domain"


def extract_host_from_url(url: str) -> str:
    try:
        cleaned = re.sub(r'^(https?://|android://)', '', url, flags=re.IGNORECASE)
        if '@' in cleaned:
            cleaned = cleaned.split('@', 1)[1]
        host = cleaned.split('/', 1)[0].split(':', 1)[0].strip().lower()
        if host.startswith('www.'):
            host = host[4:]
        host = re.sub(r'[\\/:*?"<>|]', '_', host)
        if is_valid_domain(host):
            return get_base_domain(host)
        return "other_credentials"
    except Exception:
        return "other_credentials"


def extract_cred_domain(content: str, fallback_domain: str = None) -> str:
    content = content.strip()
    
    for pat in (_CRED_DOMAIN_USER_PASS, _CRED_DOMAIN_PIPE, _CRED_DOMAIN_USER_PASS_EQUALS):
        m = pat.match(content)
        if m:
            dom = m.group(1).lower().strip()
            if is_valid_domain(dom):
                return get_base_domain(dom)

    if '|' in content:
        parts = content.split('|')
        first = parts[0].strip()
        if first.lower().startswith(('http://', 'https://', 'android://')):
            return extract_host_from_url(first)
            
    if content.lower().startswith(('http://', 'https://', 'android://')):
        m = re.match(r'^(https?://[^\s:]+|android://[^\s:]+)', content, re.IGNORECASE)
        if m:
            return extract_host_from_url(m.group(1))
            
    email_match = re.search(r'\b[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})\b', content)
    if email_match:
        dom = email_match.group(1).lower().strip()
        if is_valid_domain(dom):
            return get_base_domain(dom)
            
    if fallback_domain and is_valid_domain(fallback_domain):
        return get_base_domain(fallback_domain)
            
    return "other_credentials"


def extract_user_pass_clean(content: str) -> str | None:
    content = content.strip()
    if not content:
        return None

    if content.count('|') == 2:
        parts = content.split('|')
        first = parts[0].lower()
        if first.startswith(('http://', 'https://', 'android://', 'ftp://', 'file://')) or is_valid_domain(first):
            user = parts[1].strip()
            val = parts[2].strip()
            if '=' in user and any(x in user.lower() for x in ('user=', 'login=', 'email=', 'username=')):
                user = user.split('=', 1)[1].strip()
            if '=' in val and any(x in val.lower() for x in ('pass=', 'password=', 'pwd=')):
                val = val.split('=', 1)[1].strip()
            if user and val:
                return f"{user}:{val}"

    m = re.match(r'^(?:user|username|login|email)?\s*=\s*([^\s:|]+):(?:pass|password)?\s*=\s*([^\s:|]+)$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    m = re.match(r'^(?:https?://)?[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}(?::\d+)?(?:/[^\s:|]*)?:(?:user|username|login|email)?\s*=\s*([^\s:|]+):(?:pass|password)?\s*=\s*([^\s:|]+)$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    m = _CRED_DOMAIN_USER_PASS.match(content)
    if m:
        return f"{m.group(2)}:{m.group(3)}"

    m = _CRED_DOMAIN_PIPE.match(content)
    if m:
        return f"{m.group(2)}:{m.group(3)}"

    m = re.match(r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?:([^\s:]{1,128}):([^\s]{1,128})$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
        
    m = re.match(r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?\|([^\s|]{1,128})\|([^\s]{1,128})$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    if ':' in content:
        parts = content.split(':')
        if len(parts) == 2:
            return f"{parts[0].strip()}:{parts[1].strip()}"
        elif len(parts) == 3:
            if is_valid_domain(parts[0]) or parts[0].lower().startswith(('http://', 'https://')):
                return f"{parts[1].strip()}:{parts[2].strip()}"

    if '|' in content:
        parts = content.split('|')
        if len(parts) == 2:
            return f"{parts[0].strip()}:{parts[1].strip()}"
        elif len(parts) == 3:
            if is_valid_domain(parts[0]) or parts[0].lower().startswith(('http://', 'https://')):
                return f"{parts[1].strip()}:{parts[2].strip()}"

    if ';' in content:
        parts = content.split(';')
        if len(parts) == 2:
            return f"{parts[0].strip()}:{parts[1].strip()}"
        elif len(parts) == 3:
            if is_valid_domain(parts[0]) or parts[0].lower().startswith(('http://', 'https://')):
                return f"{parts[1].strip()}:{parts[2].strip()}"

    return None


def format_size(size: float | int) -> str:
    if size < 1024:
        return f"{int(size)} B"
    for unit in ['KB', 'MB', 'GB', 'TB']:
        size /= 1024.0
        if size < 1024.0:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"


# ─────────────────────────── SEARCH ENGINE ───────────────────────────
class SearchEngine:
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or min(16, (os.cpu_count() or 4) * 2)

    def search(
        self,
        folder: str,
        keyword: str,
        case_sensitive: bool = False,
        is_regex: bool = False,
        scan_all: bool = False,
        context_lines: int = 2,
        use_cache: bool = True,
        stop_event: threading.Event = None,
        on_discovered: callable = None,
        on_progress: callable = None,
        on_results: callable = None,
        on_large_file: callable = None,
        on_done: callable = None,
    ):
        """
        Mengeksekusi pencarian teks/cookie/kredensial secara multi-threaded.
        """
        stop = stop_event or threading.Event()
        
        # Compile Regex
        if scan_all:
            pattern = None
        else:
            if not is_regex:
                escaped = re.escape(keyword)
                flags = 0 if case_sensitive else re.IGNORECASE
                pattern = re.compile(escaped, flags)
            else:
                flags = 0 if case_sensitive else re.IGNORECASE
                pattern = re.compile(keyword, flags)

        kw_bytes_lower = keyword.lower().encode("utf-8") if keyword else b""
        ctx = context_lines

        file_queue = queue.Queue(maxsize=1000)

        def worker_loop():
            while not stop.is_set():
                try:
                    item = file_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                if item is None:
                    file_queue.task_done()
                    break

                filepath, fsize = item
                filename = os.path.basename(filepath)
                rel_folder = os.path.relpath(os.path.dirname(filepath), folder)

                matches = []
                lines_processed = 0
                bytes_processed = 0

                if fsize > 50 * 1024 * 1024 and on_large_file:
                    on_large_file(filepath, 0, fsize)

                try:
                    # mmap pre-filter
                    if not scan_all and keyword:
                        if not case_sensitive and fsize < 200_000_000:
                            try:
                                with open(filepath, "rb") as fh:
                                    with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                        data_low = mm[:].lower()
                                        if kw_bytes_lower not in data_low:
                                            if on_progress:
                                                on_progress(1, fsize, filepath)
                                            file_queue.task_done()
                                            continue
                            except (ValueError, OSError):
                                pass

                    is_tf_output = False
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                            head = fh.read(512)
                            is_tf_output = "TEXT FINDER" in head or ("====" in head and "FILE:" in head)
                    except Exception:
                        pass

                    file_lines = []
                    if fsize > 10 * 1024 * 1024:
                        def stream_lines():
                            with open(filepath, "r", encoding="utf-8", errors="replace", buffering=1<<20) as fh:
                                for i, line in enumerate(fh, 1):
                                    yield i, line
                        lines_generator = stream_lines()
                    else:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                            file_lines = fh.readlines()
                        lines_generator = enumerate(file_lines, 1)

                    is_bulk_netscape = False
                    if not is_tf_output and fsize <= 10 * 1024 * 1024:
                        is_bulk_netscape = classify_file_netscape(file_lines)

                    fallback_domain = extract_domain_from_filename(filename)

                    cred_url = None
                    cred_login = None
                    cred_pass = None
                    cred_line = 0
                    cred_buffer = []

                    def flush_cred_buffer():
                        nonlocal cred_buffer
                        for bl_no, bl_raw, bl_content, bl_match in cred_buffer:
                            if bl_match:
                                kind = classify_line(bl_content, fallback_domain)
                                domain = "—"
                                snippet = bl_content
                                
                                if kind == "cookie":
                                    normalized_list = normalize_cookie(bl_content, fallback_domain)
                                    if normalized_list:
                                        for normalized in normalized_list:
                                            domain = extract_cookie_domain(normalized)
                                            if fsize <= 10 * 1024 * 1024:
                                                start = max(0, bl_no - 1 - ctx)
                                                end = min(len(file_lines), bl_no + ctx)
                                                ctx_lines = [line.rstrip() for line in file_lines[start:end]]
                                                ctx_start = start + 1
                                            else:
                                                ctx_lines = [bl_raw.rstrip()]
                                                ctx_start = bl_no
                                                
                                            matches.append({
                                                "filepath": filepath, "filename": filename, "folder": rel_folder,
                                                "lineno": bl_no, "type": "cookie", "domain": domain,
                                                "snippet": normalized, "ctx_lines": ctx_lines, "ctx_start": ctx_start,
                                                "keyword": keyword, "pattern": pattern
                                            })
                                        continue
                                elif kind == "credential":
                                    domain = extract_cred_domain(bl_content, fallback_domain)
                                    
                                if fsize <= 10 * 1024 * 1024:
                                    start = max(0, bl_no - 1 - ctx)
                                    end = min(len(file_lines), bl_no + ctx)
                                    ctx_lines = [line.rstrip() for line in file_lines[start:end]]
                                    ctx_start = start + 1
                                else:
                                    ctx_lines = [bl_raw.rstrip()]
                                    ctx_start = bl_no

                                matches.append({
                                    "filepath": filepath, "filename": filename, "folder": rel_folder,
                                    "lineno": bl_no, "type": kind, "domain": domain,
                                    "snippet": snippet, "ctx_lines": ctx_lines, "ctx_start": ctx_start,
                                    "keyword": keyword, "pattern": pattern
                                })
                        cred_buffer.clear()

                    for lineno, raw in lines_generator:
                        if stop.is_set():
                            break
                        
                        lines_processed += 1
                        bytes_processed += len(raw.encode("utf-8", errors="ignore"))
                        
                        if lines_processed % 10000 == 0:
                            import time
                            time.sleep(0.001)

                        if lines_processed % 100_000 == 0:
                            if fsize > 50 * 1024 * 1024 and on_large_file:
                                on_large_file(filepath, bytes_processed, fsize)
                                
                        if len(matches) >= 300:
                            if on_results:
                                on_results(matches.copy())
                            matches.clear()

                        if is_tf_output:
                            content = strip_tf_marker(raw)
                            if content is None: continue
                        else:
                            content = raw.strip()
                            if not content: continue

                        if scan_all and is_bulk_netscape:
                            normalized_list = normalize_cookie(content, fallback_domain)
                            for normalized in normalized_list:
                                matches.append({
                                    "filepath": filepath, "filename": filename, "folder": rel_folder,
                                    "lineno": lineno, "type": "cookie", "domain": extract_cookie_domain(normalized),
                                    "snippet": normalized, "ctx_lines": [normalized], "ctx_start": lineno,
                                    "keyword": "", "pattern": None
                                })
                            continue

                        mu = _CRED_URL_KEY.match(content)
                        ml = _CRED_LOGIN_KEY.match(content)
                        mp = _CRED_PASS_KEY.match(content)

                        is_kw_match = False
                        if not scan_all and pattern.search(content):
                            is_kw_match = True

                        if mu:
                            flush_cred_buffer()
                            cred_url = mu.group(1).strip()
                            cred_login = None; cred_pass = None; cred_line = lineno
                            cred_buffer = [(lineno, raw, content, is_kw_match)]
                            continue
                        elif cred_url:
                            if lineno - cred_line > 8:
                                flush_cred_buffer()
                                cred_url = cred_login = cred_pass = None
                            else:
                                cred_buffer.append((lineno, raw, content, is_kw_match))
                                if ml:
                                    cred_login = ml.group(1).strip()
                                    continue
                                elif mp:
                                    cred_pass = mp.group(1).strip()
                                    if cred_login and cred_pass:
                                        combined = f"{cred_url}|{cred_login}|{cred_pass}"
                                        block_domain = extract_cred_domain(combined, fallback_domain)
                                        emit_block = True if scan_all else (bool(pattern.search("".join([i[1] for i in cred_buffer]))) or bool(pattern.search(combined)))
                                        if emit_block:
                                            matches.append({
                                                "filepath": filepath, "filename": filename, "folder": rel_folder,
                                                "lineno": cred_line, "type": "credential", "domain": block_domain,
                                                "snippet": combined, "ctx_lines": [i[1].rstrip() for i in cred_buffer], "ctx_start": cred_line,
                                                "keyword": "" if scan_all else keyword, "pattern": pattern
                                            })
                                            cred_buffer.clear()
                                        else:
                                            flush_cred_buffer()
                                        cred_url = cred_login = cred_pass = None
                                    continue
                                else:
                                    continue

                        if scan_all:
                            kind = classify_line(content, fallback_domain)
                            if kind == "cookie":
                                normalized_list = normalize_cookie(content, fallback_domain)
                                for normalized in normalized_list:
                                    matches.append({
                                        "filepath": filepath, "filename": filename, "folder": rel_folder,
                                        "lineno": lineno, "type": "cookie", "domain": extract_cookie_domain(normalized),
                                        "snippet": normalized, "ctx_lines": [normalized], "ctx_start": lineno,
                                        "keyword": "", "pattern": None
                                    })
                            elif kind == "credential":
                                matches.append({
                                    "filepath": filepath, "filename": filename, "folder": rel_folder,
                                    "lineno": lineno, "type": "credential", "domain": extract_cred_domain(content, fallback_domain),
                                    "snippet": content, "ctx_lines": [content], "ctx_start": lineno,
                                    "keyword": "", "pattern": None
                                })
                        else:
                            if is_kw_match:
                                kind = classify_line(content, fallback_domain)
                                domain = "—"; snippet = content
                                if kind == "cookie":
                                    normalized_list = normalize_cookie(content, fallback_domain)
                                    if normalized_list:
                                        for normalized in normalized_list:
                                            domain = extract_cookie_domain(normalized)
                                            if fsize <= 10 * 1024 * 1024:
                                                start = max(0, lineno - 1 - ctx)
                                                end = min(len(file_lines), lineno + ctx)
                                                ctx_lines = [line.rstrip() for line in file_lines[start:end]]
                                                ctx_start = start + 1
                                            else:
                                                ctx_lines = [raw.rstrip()]
                                                ctx_start = lineno
                                            matches.append({
                                                "filepath": filepath, "filename": filename, "folder": rel_folder,
                                                "lineno": lineno, "type": "cookie", "domain": domain,
                                                "snippet": normalized, "ctx_lines": ctx_lines, "ctx_start": ctx_start,
                                                "keyword": keyword, "pattern": pattern
                                            })
                                        continue
                                elif kind == "credential":
                                    domain = extract_cred_domain(content, fallback_domain)
                                if fsize <= 10 * 1024 * 1024:
                                    start = max(0, lineno - 1 - ctx)
                                    end = min(len(file_lines), lineno + ctx)
                                    ctx_lines = [line.rstrip() for line in file_lines[start:end]]
                                    ctx_start = start + 1
                                else:
                                    ctx_lines = [raw.rstrip()]
                                    ctx_start = lineno
                                matches.append({
                                    "filepath": filepath, "filename": filename, "folder": rel_folder,
                                    "lineno": lineno, "type": kind, "domain": domain,
                                    "snippet": snippet, "ctx_lines": ctx_lines, "ctx_start": ctx_start,
                                    "keyword": keyword, "pattern": pattern
                                })
                    flush_cred_buffer()
                except Exception:
                    pass
                
                if matches and on_results:
                    on_results(matches)
                if on_progress:
                    on_progress(1, fsize, filepath)
                file_queue.task_done()

        # Start Workers
        workers = []
        for _ in range(self.max_workers):
            w = threading.Thread(target=worker_loop, daemon=True)
            w.start()
            workers.append(w)

        # Discovery & Caching
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tf_cache")
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except Exception:
            pass

        folder_hash = hashlib.md5(folder.encode('utf-8')).hexdigest()
        cache_file = os.path.join(cache_dir, folder_hash + ".txt")

        cache_loaded = False
        if use_cache and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if stop.is_set(): break
                        parts = line.rstrip().split('\t')
                        if len(parts) == 2:
                            fp = parts[0]
                            sz = int(parts[1])
                            file_queue.put((fp, sz))
                            if on_discovered:
                                on_discovered(1, sz)
                cache_loaded = True
            except Exception:
                cache_loaded = False

        if not cache_loaded:
            collected_paths = []
            try:
                for root, dirs, files in os.walk(folder):
                    if stop.is_set(): break
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for f in files:
                        if f.lower().endswith(".txt"):
                            filepath = os.path.join(root, f)
                            try:
                                sz = os.path.getsize(filepath)
                                file_queue.put((filepath, sz))
                                if on_discovered:
                                    on_discovered(1, sz)
                                collected_paths.append(f"{filepath}\t{sz}\n")
                            except OSError:
                                pass
            except Exception:
                pass

            if not stop.is_set():
                try:
                    with open(cache_file, "w", encoding="utf-8") as f:
                        f.writelines(collected_paths)
                except Exception:
                    pass

        # Stop workers
        for _ in range(self.max_workers):
            file_queue.put(None)

        for w in workers:
            w.join()

        if on_done:
            on_done()


# ─────────────────────────── EXPORT ENGINE ───────────────────────────
def export_split_results(
    results: list[dict],
    target_folder: str,
    on_progress: callable = None,
    on_done: callable = None
):
    """
    Memilah hasil pencarian menjadi:
    - /Cookies/<domain>/<source_session>.txt
    - /Credentials/<domain>.txt
    """
    def worker():
        try:
            cookies_by_domain = {}
            creds_by_host = {}

            total_items = len(results)
            
            for idx, r in enumerate(results):
                content = r["snippet"].strip()
                if not content:
                    continue

                t = r.get("type", "other")
                if t == "cookie":
                    domain = r.get("domain", "")
                    if not domain or domain == "—" or domain == "unknown_domain":
                        domain = extract_cookie_domain(content)
                    cookies_by_domain.setdefault(domain, {}).setdefault(r["filepath"], []).append(content)
                elif t == "credential":
                    host = r.get("domain", "other_credentials")
                    if not host or host == "—" or host == "unknown_domain":
                        host = extract_cred_domain(content)
                    creds_by_host.setdefault(host, []).append((r["filepath"], content))
                
                if on_progress and (idx % 100 == 0 or idx == total_items - 1):
                    on_progress(idx + 1, total_items, f"Membaca & mengelompokkan data ({idx + 1}/{total_items})…", "")

            def get_safe_source_name(filepath: str) -> str:
                parts = filepath.replace('\\', '/').split('/')
                if len(parts) >= 2:
                    name = f"{parts[-2]}_{parts[-1]}"
                else:
                    name = parts[-1]
                return re.sub(r'[\\/:*?"<>|]', '_', name)

            write_tasks = []

            # 1. Cookies
            if cookies_by_domain:
                cookie_dir = os.path.join(target_folder, "Cookies")
                for domain, path_dict in cookies_by_domain.items():
                    domain_folder = os.path.join(cookie_dir, domain)
                    used_names = {}
                    for filepath, entries in path_dict.items():
                        sessions = []
                        for entry in entries:
                            parts = entry.split('\t')
                            if len(parts) != 7:
                                continue
                            c_domain, c_flag, c_path, c_sec, c_exp, c_name, c_val = parts
                            if not c_domain or not is_valid_domain(c_domain): continue
                            if c_flag not in ("TRUE", "FALSE"): continue
                            if not c_path.startswith('/'): continue
                            if c_sec not in ("TRUE", "FALSE"): continue
                            if not c_exp.isdigit(): continue
                            if not is_valid_cookie_name_val(c_name, c_val): continue
                            
                            cookie_identity = (c_domain.lower(), c_path, c_name)
                            placed = False
                            for session in sessions:
                                session_identities = []
                                for s_entry in session:
                                    s_parts = s_entry.split('\t')
                                    session_identities.append((s_parts[0].lower(), s_parts[2], s_parts[5]))
                                if cookie_identity not in session_identities:
                                    session.append(entry)
                                    placed = True
                                    break
                            if not placed:
                                sessions.append([entry])

                        base_name = get_safe_source_name(filepath)
                        name_part, ext_part = os.path.splitext(base_name)
                        if not ext_part:
                            ext_part = ".txt"
                            
                        for idx, session in enumerate(sessions, 1):
                            if len(sessions) == 1:
                                safe_src_name = f"{name_part}{ext_part}"
                            else:
                                safe_src_name = f"{name_part}_session_{idx}{ext_part}"
                            
                            counter = 1
                            original_safe_src_name = safe_src_name
                            while safe_src_name in used_names:
                                n_part, e_part = os.path.splitext(original_safe_src_name)
                                safe_src_name = f"{n_part}_{counter}{e_part}"
                                counter += 1
                            used_names[safe_src_name] = filepath
                            
                            fp = os.path.join(domain_folder, safe_src_name)
                            file_content = "# Netscape HTTP Cookie File\n# This file was generated by Text Finder\n\n" + "\n".join(session) + "\n"
                            write_tasks.append((fp, file_content, len(session), "cookie"))

            # 2. Credentials
            if creds_by_host:
                cred_dir = os.path.join(target_folder, "Credentials")
                for host, entries in creds_by_host.items():
                    fp = os.path.join(cred_dir, f"{host}.txt")
                    lines = []
                    seen_lines = set()
                    for _, cred_line in entries:
                        cleaned = extract_user_pass_clean(cred_line)
                        if cleaned and cleaned not in seen_lines:
                            seen_lines.add(cleaned)
                            lines.append(cleaned)
                            
                    if lines:
                        file_content = "\n".join(lines) + "\n"
                        write_tasks.append((fp, file_content, len(lines), "cred"))

            total_files = len(write_tasks)
            completed_files = 0
            total_cookies_saved = 0
            total_creds_saved = 0

            def write_file_task(task):
                fp, file_content = task[0], task[1]
                os.makedirs(os.path.dirname(fp), exist_ok=True)
                with open(fp, "w", encoding="utf-8", errors="replace") as f:
                    f.write(file_content)
                return task

            with ThreadPoolExecutor(max_workers=min(16, (os.cpu_count() or 4) * 2)) as executor:
                futures = [executor.submit(write_file_task, task) for task in write_tasks]
                for fut in as_completed(futures):
                    task = fut.result()
                    completed_files += 1
                    if on_progress:
                        on_progress(total_items + completed_files, total_items + total_files, f"Menulis file ({completed_files}/{total_files})…", os.path.basename(task[0]))
                    if task[2] > 0:
                        if task[3] == "cookie":
                            total_cookies_saved += task[2]
                        else:
                            total_creds_saved += task[2]

            if on_done:
                on_done({
                    "cookies_saved": total_cookies_saved,
                    "creds_saved": total_creds_saved,
                    "domain_cookies_count": len(cookies_by_domain),
                    "domain_creds_count": len(creds_by_host),
                    "folder": target_folder,
                    "error": None
                })
        except Exception as e:
            if on_done:
                on_done({
                    "cookies_saved": 0,
                    "creds_saved": 0,
                    "domain_cookies_count": 0,
                    "domain_creds_count": 0,
                    "folder": target_folder,
                    "error": str(e)
                })

    threading.Thread(target=worker, daemon=True).start()

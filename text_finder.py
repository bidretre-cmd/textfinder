"""
Text Finder — Pencarian teks di ribuan file .txt secara paralel.
Optimasi: ThreadPoolExecutor, streaming queue, progress nyata, cancel support.
"""
import os
import re
import hashlib
import queue
import threading
import mmap
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
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
    
    # Check for direct domains in name (e.g., netflix.com)
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
    # Reject if it contains spaces, tabs, colons, pipes, or semicolons or other invalid chars
    if any(c in d for c in (' ', '\t', ':', '|', ';', '=', '\\', '/', '*', '?', '"', '<', '>', ',', '@')):
        return False
    # Reject common protocols / local paths
    if d.startswith(('http://', 'https://', 'android://', 'ftp://', 'file://')):
        return False
    parts = d.split('.')
    if len(parts) < 2:
        return False
    for part in parts:
        if not part or not re.match(r'^[a-z0-9\-]+$', part):
            return False
    # TLD must be valid letters (at least 2 chars)
    if not re.match(r'^[a-z\-]{2,10}$', parts[-1]):
        return False
    return True


def is_valid_cookie_name_val(name: str, val: str) -> bool:
    if not name or not val:
        return False
    # Reject newlines or carriage returns
    if '\n' in name or '\r' in name or '\n' in val or '\r' in val:
        return False
    # Names cannot contain control chars, spaces, tabs, or these special characters: ( ) < > @ , ; : \ " / [ ] ? = { }
    if any(c in name for c in '()<>@,;:\\"[]?={} \t'):
        return False
    # Values cannot contain control chars, spaces, tabs, or semicolons/commas
    if any(c in val for c in ';, \t'):
        return False
    # Name must not be empty or start with protocol/slashes
    if name.lower().startswith(('http', 'ftp', 'file', '//')):
        return False
    # Avoid javascript snippets
    if '(' in val or ')' in val or '{' in val or '}' in val or ';' in val:
        return False
    # Length limits
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
                    
                    # Clean trailing spaces / junk from name and val
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
            
            # Clean trailing spaces / junk from name and val
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
    
    # Check if this contains standard attributes
    has_attrs = False
    for part in parts[1:]:
        p = part.strip().lower()
        if p.startswith(('domain=', 'path=', 'expires=', 'max-age=', 'secure', 'httponly', 'samesite=')):
            has_attrs = True
            break
            
    if has_attrs:
        # Case A: Standard Set-Cookie style (single cookie with attributes)
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
        # Case B: Semicolon-separated list of key-value pairs (multiple cookies)
        # e.g., A=1; B=2; C=3
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
        
        # Clean name and val
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
    
    # Fast pre-check to speed up parsing
    if not any(c in stripped for c in ('\t', ':', '|', ';', '=')):
        return "other"
        
    # 1. Credential checks first!
    if not _NOT_CRED.search(stripped):
        # If it starts with http://, https://, or android://
        # only allow it to be classified as credential if it fits URL credentials
        if stripped.lower().startswith(("http://", "https://", "android://")):
            for pat in (_CRED_URL_USER_PASS, _CRED_URL_PIPE, _CRED_ANDROID_URL, _CRED_URL_USER_PASS_EQUALS):
                if pat.match(stripped):
                    return "credential"
        else:
            for pat in CREDENTIAL_PATTERNS:
                if pat.match(stripped):
                    return "credential"
                    
    # 2. Cookie checks second!
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
    
    # 1. Try matching _CRED_DOMAIN_USER_PASS, _CRED_DOMAIN_PIPE, _CRED_DOMAIN_USER_PASS_EQUALS
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
            
    # Try to find email domain if no URL is found
    # e.g., email@domain.com
    email_match = re.search(r'\b[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})\b', content)
    if email_match:
        dom = email_match.group(1).lower().strip()
        if is_valid_domain(dom):
            return get_base_domain(dom)
            
    # Fallback to domain extracted from filename
    if fallback_domain and is_valid_domain(fallback_domain):
        return get_base_domain(fallback_domain)
            
    return "other_credentials"


def extract_user_pass_clean(content: str) -> str | None:
    content = content.strip()
    if not content:
        return None

    # Case 0: Block credentials combined: URL|Login|Pass
    if content.count('|') == 2:
        parts = content.split('|')
        first = parts[0].lower()
        if first.startswith(('http://', 'https://', 'android://', 'ftp://', 'file://')) or is_valid_domain(first):
            user = parts[1].strip()
            val = parts[2].strip()
            # Clean "username=" or "password=" prefixes if present
            if '=' in user and any(x in user.lower() for x in ('user=', 'login=', 'email=', 'username=')):
                user = user.split('=', 1)[1].strip()
            if '=' in val and any(x in val.lower() for x in ('pass=', 'password=', 'pwd=')):
                val = val.split('=', 1)[1].strip()
            if user and val:
                return f"{user}:{val}"

    # Case 1: user=name:pass=word or similar (without domain)
    m = re.match(r'^(?:user|username|login|email)?\s*=\s*([^\s:|]+):(?:pass|password)?\s*=\s*([^\s:|]+)$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    # Case 2: domain:user=name:pass=word or url:user=name:pass=word
    m = re.match(r'^(?:https?://)?[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}(?::\d+)?(?:/[^\s:|]*)?:(?:user|username|login|email)?\s*=\s*([^\s:|]+):(?:pass|password)?\s*=\s*([^\s:|]+)$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    # Case 3: Match _CRED_DOMAIN_USER_PASS: domain:user:pass
    m = _CRED_DOMAIN_USER_PASS.match(content)
    if m:
        return f"{m.group(2)}:{m.group(3)}"

    # Case 4: Match _CRED_DOMAIN_PIPE: domain|user|pass
    m = _CRED_DOMAIN_PIPE.match(content)
    if m:
        return f"{m.group(2)}:{m.group(3)}"

    # Case 5: Match _CRED_URL_USER_PASS or URL|user|pass
    m = re.match(r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?:([^\s:]{1,128}):([^\s]{1,128})$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
        
    m = re.match(r'^https?://[^\s:/|]+(?::\d+)?(?:/[^\s:|]*)?\|([^\s|]{1,128})\|([^\s]{1,128})$', content, re.IGNORECASE)
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    # Case 6: Plain email:pass, user:pass, user|pass, user;pass
    if ':' in content:
        parts = content.split(':')
        if len(parts) == 2:
            return f"{parts[0].strip()}:{parts[1].strip()}"
        elif len(parts) == 3:
            # check if first is domain/url
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



# ─────────────────────────── THEME COLORS (LIGHT) ───────────────────
BG_DARK        = "#f0f4f8"   # halaman utama
BG_PANEL       = "#ffffff"   # panel kiri
BG_CARD        = "#f6f8fa"   # card / toolbar
BG_INPUT       = "#ffffff"   # kotak input
ACCENT         = "#0969da"   # biru GitHub
ACCENT_DARK    = "#0550ae"
ACCENT_GREEN   = "#1a7f37"   # hijau tua
ACCENT_GREEN_BG= "#dafbe1"   # hijau latar
ACCENT_ORANGE  = "#bc4c00"   # oranye tua
ACCENT_ORANGE_BG="#fff1e5"   # oranye latar
ACCENT_RED     = "#cf222e"   # merah
ACCENT_RED_BG  = "#ffebe9"   # merah latar
TEXT_PRIMARY   = "#1f2328"   # teks utama
TEXT_SECONDARY = "#656d76"   # teks sekunder
TEXT_MUTED     = "#9ca3af"   # teks redup
BORDER         = "#d0d7de"   # garis batas
HIGHLIGHT_BG   = "#dbeafe"   # seleksi baris
RESULT_ODD     = "#ffffff"
RESULT_EVEN    = "#f6f8fa"
TAG_MATCH_BG   = "#fff8c5"   # kuning highlight
TAG_MATCH_FG   = "#7d4e00"   # coklat teks match

# Tuning
MAX_WORKERS    = min(32, (os.cpu_count() or 4) * 4)   # banyak worker I/O
POLL_MS        = 80          # interval poll queue ke UI (ms)
BATCH_SIZE     = 150         # baris yang dimasukkan ke tree per batch
MAX_RESULTS    = 50_000      # batas aman hasil agar UI tidak berat

FONT_UI        = ("Segoe UI", 10)
FONT_UI_SM     = ("Segoe UI", 9)
FONT_UI_BOLD   = ("Segoe UI", 10, "bold")
FONT_MONO      = ("Consolas", 10)


# ─────────────────────────────────────────────────────────────────────
class TextFinderApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Text Finder — Pencarian Cepat File TXT")
        self.geometry("1140x740")
        self.minsize(900, 600)
        self.configure(bg=BG_DARK)
        self.resizable(True, True)

        # ── State ─────────────────────────────────────────────────────
        self.search_path   = tk.StringVar()
        self.keyword_var   = tk.StringVar()
        self.case_var      = tk.BooleanVar(value=False)
        self.regex_var     = tk.BooleanVar(value=False)
        self.context_lines = tk.IntVar(value=2)
        self.use_cache_var = tk.BooleanVar(value=True)

        # New Sorting & Scan State
        self.scan_all_var  = tk.BooleanVar(value=False)
        self.dedup_var     = tk.BooleanVar(value=True)
        self.incl_src_var  = tk.BooleanVar(value=True)

        self.results: list[dict] = []         # semua hasil lengkap (master)
        self._result_queue: queue.Queue = queue.Queue(maxsize=2000) # komunikasi worker → UI
        self._stop_event  = threading.Event() # sinyal cancel ke worker
        self._is_searching = False
        self._total_files  = 0
        self._done_files   = 0
        self._total_bytes  = 0
        self._done_bytes   = 0
        self._discovery_done = False
        self._large_files  = {}
        self._executor: ThreadPoolExecutor | None = None

        # iid counter untuk tree (unik meski ada filter)
        self._tree_iid = 0

        self._build_ui()
        self._apply_style()
        
        # Add trace to Scan Semua variable to disable/enable keyword entry
        self.scan_all_var.trace_add("write", self._on_scan_all_toggle)
        
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─────────────────────── STYLE ───────────────────────────────────
    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TScrollbar",
                    background=BG_CARD, troughcolor=BG_DARK,
                    bordercolor=BORDER, arrowcolor=TEXT_SECONDARY, relief="flat")
        s.configure("TCheckbutton",
                    background=BG_PANEL, foreground=TEXT_SECONDARY,
                    font=FONT_UI, focuscolor=BG_PANEL)
        s.map("TCheckbutton",
              background=[("active", BG_PANEL)],
              foreground=[("active", TEXT_PRIMARY)])
        s.configure("green.Horizontal.TProgressbar",
                    troughcolor=BORDER, background=ACCENT,
                    bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT_DARK)
        s.configure("TPanedwindow", background=BORDER)

    # ─────────────────────── UI BUILD ────────────────────────────────
    def _build_ui(self):
        # Header
        self.header = tk.Frame(self, bg=ACCENT, height=58)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        
        # Icon + title
        self.title_frame = tk.Frame(self.header, bg=ACCENT)
        self.title_frame.pack(side="left", padx=20, pady=10)
        self.title_icon = tk.Label(self.title_frame, text="⌕",
                 bg=ACCENT, fg="#ffffff",
                 font=("Segoe UI", 22, "bold"))
        self.title_icon.pack(side="left", padx=(0, 6))
        
        inner = tk.Frame(self.title_frame, bg=ACCENT)
        inner.pack(side="left")
        
        self.title_lbl = tk.Label(inner, text="Text Finder",
                 bg=ACCENT, fg="#ffffff",
                 font=("Segoe UI", 15, "bold"))
        self.title_lbl.pack(anchor="w")
        
        self.subtitle_lbl = tk.Label(inner, text="Cari teks di ribuan file .txt — paralel & cepat",
                 bg=ACCENT, fg="#cce0ff",
                 font=("Segoe UI", 8))
        self.subtitle_lbl.pack(anchor="w")
        
        # Right side: worker badge
        self.badge_frame = tk.Frame(self.header, bg=ACCENT_DARK, padx=10, pady=4)
        self.badge_frame.pack(side="right", padx=16, pady=14)
        self.badge_lbl = tk.Label(self.badge_frame,
                 text=f"⚙ {MAX_WORKERS} worker thread",
                 bg=ACCENT_DARK, fg="#ffffff",
                 font=("Segoe UI", 8, "bold"))
        self.badge_lbl.pack()

        self.header_bg_stripe = tk.Frame(self, bg=BORDER, height=1)
        self.header_bg_stripe.pack(fill="x")

        # Container for main layout
        self.container = tk.Frame(self, bg=BG_DARK)
        self.container.pack(fill="both", expand=True)

        self.finder_body = tk.Frame(self.container, bg=BG_DARK)
        self.finder_body.pack(fill="both", expand=True)

        left = tk.Frame(self.finder_body, bg=BG_PANEL, width=300)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self._build_left(left)

        tk.Frame(self.finder_body, bg=BORDER, width=1).pack(side="left", fill="y")

        right = tk.Frame(self.finder_body, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

    # ──────────────── LEFT PANEL ──────────────────────────────────────
    def _build_left(self, p):
        # ── Folder ───────────────────────────────────────────────
        self._sec(p, "📁  Folder Target")
        pf = tk.Frame(p, bg=BG_PANEL)
        pf.pack(fill="x", padx=12, pady=(0, 4))
        path_e = tk.Entry(pf, textvariable=self.search_path,
                 bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                 font=FONT_UI_SM, bd=1, relief="solid",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT)
        path_e.pack(side="left", fill="x", expand=True, ipady=6)
        self._btn(pf, "📂", self._browse,
                  bg=BG_CARD, fg=ACCENT,
                  font=("Segoe UI", 12), width=3,
                  relief="solid").pack(side="left", padx=(4, 0))

        # ── Keyword ──────────────────────────────────────────────
        self._sec(p, "🔍  Kata Kunci")
        kw_frame = tk.Frame(p, bg=BG_PANEL, padx=12)
        kw_frame.pack(fill="x", pady=(0, 2))
        self.kw_entry = tk.Entry(kw_frame, textvariable=self.keyword_var,
                                 bg=BG_INPUT, fg=TEXT_PRIMARY,
                                 insertbackground=ACCENT,
                                 font=("Segoe UI", 12), bd=1, relief="solid",
                                 highlightthickness=2,
                                 highlightbackground=BORDER,
                                 highlightcolor=ACCENT)
        self.kw_entry.pack(fill="x", ipady=8)
        self.kw_entry.bind("<Return>", lambda e: self._start_search())
        
        # Checkbox to ignore keyword and scan everything
        ttk.Checkbutton(kw_frame, text="Scan Semua & Pilah Otomatis",
                        variable=self.scan_all_var).pack(anchor="w", pady=(4, 0))
        
        tk.Label(kw_frame, text="Tekan Enter untuk mulai cari",
                 bg=BG_PANEL, fg=TEXT_MUTED, font=("Segoe UI", 7)).pack(anchor="e", pady=(2, 0))

        # ── Options ──────────────────────────────────────────────
        self._sec(p, "⚙️  Opsi Pencarian")
        opts_card = tk.Frame(p, bg=BG_CARD, bd=1, relief="solid",
                             highlightbackground=BORDER, highlightthickness=1)
        opts_card.pack(fill="x", padx=12, pady=(0, 8))
        tk.Frame(opts_card, bg=BG_CARD, height=6).pack()   # top padding
        ttk.Checkbutton(opts_card, text="Case-Sensitive  (bedakan huruf besar/kecil)",
                        variable=self.case_var).pack(anchor="w", padx=10, pady=1)
        ttk.Checkbutton(opts_card, text="Mode Regex  (pola ekspresi reguler)",
                        variable=self.regex_var).pack(anchor="w", padx=10, pady=1)
        ttk.Checkbutton(opts_card, text="Gunakan Cache Struktur Folder",
                        variable=self.use_cache_var).pack(anchor="w", padx=10, pady=1)

        ctx_row = tk.Frame(opts_card, bg=BG_CARD)
        ctx_row.pack(anchor="w", padx=10, pady=(4, 6))
        tk.Label(ctx_row, text="Baris konteks:",
                 bg=BG_CARD, fg=TEXT_SECONDARY, font=FONT_UI_SM).pack(side="left")
        for v in (0, 1, 2, 3, 5):
            tk.Radiobutton(ctx_row, text=str(v), variable=self.context_lines, value=v,
                           bg=BG_CARD, fg=ACCENT, selectcolor=BG_INPUT,
                           activebackground=BG_CARD, activeforeground=ACCENT_DARK,
                           font=FONT_UI_SM, bd=0).pack(side="left", padx=3)

        # ── Options Pemilahan ────────────────────────────────────
        self._sec(p, "⚙️  Opsi Pemilahan")
        sort_opts_card = tk.Frame(p, bg=BG_CARD, bd=1, relief="solid",
                                  highlightbackground=BORDER, highlightthickness=1)
        sort_opts_card.pack(fill="x", padx=12, pady=(0, 8))
        tk.Frame(sort_opts_card, bg=BG_CARD, height=6).pack()
        ttk.Checkbutton(sort_opts_card, text="Hapus duplikat (deduplication)",
                        variable=self.dedup_var).pack(anchor="w", padx=10, pady=2)
        ttk.Checkbutton(sort_opts_card, text="Sertakan sumber file di output",
                        variable=self.incl_src_var).pack(anchor="w", padx=10, pady=2)
        tk.Frame(sort_opts_card, bg=BG_CARD, height=6).pack()

        tk.Frame(p, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        # ── Action Buttons ────────────────────────────────────────
        self.btn_frame = tk.Frame(p, bg=BG_PANEL)
        self.btn_frame.pack(fill="x", padx=12, pady=(0, 6))

        self.search_btn = self._btn(
            self.btn_frame, "🔍  Mulai Pencarian", self._start_search,
            bg=ACCENT, fg="#ffffff",
            font=("Segoe UI", 11, "bold"),
            padx=10, pady=10, cursor="hand2")
        self.search_btn.pack(fill="x")

        self.cancel_btn = self._btn(
            self.btn_frame, "⏹  Stop Pencarian", self._cancel_search,
            bg=ACCENT_RED, fg="#ffffff",
            font=FONT_UI_BOLD, padx=8, pady=8, cursor="hand2")
        self.cancel_btn.pack(fill="x")
        self.cancel_btn.pack_forget()

        self.save_btn = self._btn(
            p, "💾  Simpan Hasil (.txt)", self._save_results,
            bg=BG_CARD, fg=TEXT_MUTED,
            font=FONT_UI_BOLD, padx=8, pady=8, cursor="arrow")
        self.save_btn.pack(fill="x", padx=12, pady=(0, 6))

        self.export_split_btn = self._btn(
            p, "📦  Export Terpilah (Folder)", self._export_split_results,
            bg=BG_CARD, fg=TEXT_MUTED,
            font=FONT_UI_BOLD, padx=8, pady=8, cursor="arrow")
        self.export_split_btn.pack(fill="x", padx=12, pady=(0, 6))

        self._btn(p, "🗑️  Bersihkan", self._clear_results,
                  bg=BG_CARD, fg=TEXT_SECONDARY,
                  padx=6, pady=6, cursor="hand2").pack(fill="x", padx=12, pady=(0, 8))

        tk.Frame(p, bg=BORDER, height=1).pack(fill="x", padx=12, pady=4)

        # ── Info Panel ───────────────────────────────────────────
        info = tk.Frame(p, bg=BG_CARD, bd=1, relief="solid",
                        highlightbackground=BORDER, highlightthickness=1)
        info.pack(fill="x", padx=12, pady=(4, 6))

        self.status_lbl = tk.Label(info, text="● Siap", bg=BG_CARD,
                                   fg=TEXT_SECONDARY, font=FONT_UI_SM,
                                   wraplength=260, justify="left")
        self.status_lbl.pack(padx=10, pady=(8, 2), anchor="w")

        self.count_lbl = tk.Label(info, text="", bg=BG_CARD,
                                  fg=ACCENT_GREEN, font=("Segoe UI", 9, "bold"))
        self.count_lbl.pack(padx=10, pady=(0, 2), anchor="w")

        self.speed_lbl = tk.Label(info, text="", bg=BG_CARD,
                                  fg=ACCENT, font=FONT_UI_SM)
        self.speed_lbl.pack(padx=10, pady=(0, 4), anchor="w")

        # Progress (determinate)
        self.progress = ttk.Progressbar(p, mode="determinate",
                                        style="green.Horizontal.TProgressbar",
                                        maximum=100)
        self.progress.pack(fill="x", padx=12, pady=(2, 2))

        self.prog_lbl = tk.Label(p, text="", bg=BG_PANEL,
                                 fg=TEXT_MUTED, font=("Segoe UI", 8))
        self.prog_lbl.pack(padx=12, anchor="e", pady=(0, 4))

    # ──────────────── RIGHT PANEL ──────────────────────────────────────
    def _build_right(self, p):
        # Toolbar
        tb = tk.Frame(p, bg=BG_CARD, height=44)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        tk.Frame(tb, bg=BORDER, width=1, height=44).pack(side="left")
        self.result_lbl = tk.Label(tb, text="📋  Hasil Pencarian", bg=BG_CARD,
                                   fg=TEXT_PRIMARY, font=("Segoe UI", 10, "bold"))
        self.result_lbl.pack(side="left", padx=14, pady=12)
        # Badge (pill)
        self.match_badge = tk.Label(tb, text="", bg=ACCENT_ORANGE_BG,
                                    fg=ACCENT_ORANGE,
                                    font=("Segoe UI", 9, "bold"),
                                    padx=8, pady=2)
        self.match_badge.pack(side="left", padx=4)
        tk.Frame(tb, bg=BORDER, width=1).pack(side="left", fill="y", padx=10)

        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self._filter_results)
        tk.Label(tb, text="⌕", bg=BG_CARD, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 11)).pack(side="left")
        filter_e = tk.Entry(tb, textvariable=self.filter_var,
                            bg=BG_INPUT, fg=TEXT_PRIMARY,
                            insertbackground=ACCENT,
                            font=FONT_UI_SM, bd=1, relief="solid",
                            highlightthickness=1, highlightbackground=BORDER,
                            highlightcolor=ACCENT, width=26)
        filter_e.pack(side="left", padx=4, pady=10, ipady=4)
        tk.Label(tb, text="filter hasil", bg=BG_CARD,
                 fg=TEXT_MUTED, font=("Segoe UI", 8)).pack(side="left")

        # Paned
        pane = tk.PanedWindow(p, orient="vertical", bg=BORDER,
                              sashwidth=4, sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True)

        # ── Tree (top) ─────────────────────────────────────────────
        lf = tk.Frame(pane, bg=BG_DARK)
        pane.add(lf, minsize=130)
        cols = ("file", "baris", "tipe", "domain", "kutipan")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="browse")
        self._style_tree()
        self.tree.heading("file",    text="📄 Nama File",   anchor="w")
        self.tree.heading("baris",   text="# Baris",        anchor="center")
        self.tree.heading("tipe",    text="🏷 Tipe",         anchor="center")
        self.tree.heading("domain",  text="🌐 Domain",       anchor="w")
        self.tree.heading("kutipan", text="✏ Kutipan Baris", anchor="w")
        self.tree.column("file",    width=180, minwidth=100, anchor="w")
        self.tree.column("baris",   width=65,  minwidth=50,  anchor="center")
        self.tree.column("tipe",    width=100, minwidth=80,  anchor="center")
        self.tree.column("domain",  width=150, minwidth=100, anchor="w")
        self.tree.column("kutipan", width=360, minwidth=200, anchor="w")
        vsb = ttk.Scrollbar(lf, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(lf, orient="horizontal",  command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.tag_configure("odd",  background=RESULT_ODD)
        self.tree.tag_configure("even", background=RESULT_EVEN)

        # ── Detail (bottom) ─────────────────────────────────────────
        df = tk.Frame(pane, bg=BG_DARK)
        pane.add(df, minsize=160)
        dh = tk.Frame(df, bg=BG_CARD, height=34)
        dh.pack(fill="x")
        dh.pack_propagate(False)
        tk.Label(dh, text="🔎 Preview Isi File",
                 bg=BG_CARD, fg=TEXT_PRIMARY,
                 font=("Segoe UI", 9, "bold")).pack(side="left", padx=12, pady=8)
        tk.Frame(dh, bg=BORDER, width=1).pack(side="left", fill="y", pady=4)
        self.detail_path_lbl = tk.Label(dh, text="  Pilih baris hasil untuk lihat konteks",
                                        bg=BG_CARD, fg=TEXT_MUTED, font=FONT_UI_SM)
        self.detail_path_lbl.pack(side="left", padx=8, pady=8)

        self.detail_text = tk.Text(df, bg="#fafbfc", fg=TEXT_PRIMARY,
                                   font=FONT_MONO, bd=0, relief="flat",
                                   wrap="none", insertbackground=ACCENT,
                                   selectbackground=HIGHLIGHT_BG, padx=10, pady=8)
        dvsb = ttk.Scrollbar(df, orient="vertical",  command=self.detail_text.yview)
        dhsb = ttk.Scrollbar(df, orient="horizontal", command=self.detail_text.xview)
        self.detail_text.configure(yscrollcommand=dvsb.set, xscrollcommand=dhsb.set)
        dhsb.pack(side="bottom", fill="x")
        dvsb.pack(side="right",  fill="y")
        self.detail_text.pack(fill="both", expand=True)
        self.detail_text.tag_configure("match",
                                       background=TAG_MATCH_BG, foreground=TAG_MATCH_FG,
                                       font=("Consolas", 10, "bold"))
        self.detail_text.tag_configure("lineno",
                                       foreground="#9ca3af",
                                       font=("Consolas", 10))
        self.detail_text.tag_configure("cur_line", background="#eff6ff")

    # ─────────────── HELPER WIDGETS ──────────────────────────────────
    def _sec(self, p, text):
        row = tk.Frame(p, bg=BG_PANEL)
        row.pack(fill="x", padx=12, pady=(14, 3))
        tk.Label(row, text=text, bg=BG_PANEL, fg=ACCENT,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Frame(row, bg=BORDER, height=1).pack(side="left", fill="x",
                                                expand=True, padx=(6, 0), pady=1)

    def _btn(self, parent, text, cmd, bg=BG_CARD, fg=TEXT_PRIMARY,
             font=FONT_UI, padx=6, pady=6,
             cursor="arrow", **kw):
        orig_bg = bg
        b = tk.Label(parent, text=text, bg=bg, fg=fg, font=font,
                     cursor=cursor, padx=padx, pady=pady, **kw)
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=self._lighten(orig_bg)))
        b.bind("<Leave>", lambda e: b.configure(bg=orig_bg))
        return b

    @staticmethod
    def _lighten(hx: str) -> str:
        hx = hx.lstrip("#")
        r, g, b = (int(hx[i:i+2], 16) for i in (0, 2, 4))
        return "#{:02x}{:02x}{:02x}".format(
            min(r+22, 255), min(g+22, 255), min(b+22, 255))

    def _style_tree(self):
        s = ttk.Style(self)
        s.configure("Treeview",
                    background=RESULT_ODD, foreground=TEXT_PRIMARY,
                    fieldbackground=RESULT_ODD, rowheight=30,
                    borderwidth=0, relief="flat", font=FONT_UI_SM)
        s.configure("Treeview.Heading",
                    background=BG_CARD, foreground=TEXT_SECONDARY,
                    font=("Segoe UI", 9, "bold"), relief="groove",
                    borderwidth=1)
        s.map("Treeview",
              background=[("selected", HIGHLIGHT_BG)],
              foreground=[("selected", ACCENT_DARK)])

    def _on_scan_all_toggle(self, *args):
        if self.scan_all_var.get():
            self.kw_entry.configure(state="disabled")
            self.kw_entry.configure(bg="#eef2f6")
        else:
            self.kw_entry.configure(state="normal")
            self.kw_entry.configure(bg=BG_INPUT)

    # ─────────────── SEARCH ACTIONS ──────────────────────────────────
    def _browse(self):
        d = filedialog.askdirectory(title="Pilih Folder Pencarian")
        if d:
            self.search_path.set(d)

    def _start_search(self):
        if self._is_searching:
            return
        keyword = self.keyword_var.get().strip()
        folder  = self.search_path.get().strip()
        scan_all = self.scan_all_var.get()

        if not scan_all and not keyword:
            messagebox.showwarning("Peringatan", "Masukkan kata kunci.", parent=self)
            return
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Peringatan", "Pilih folder yang valid.", parent=self)
            return

        pattern = None
        if not scan_all:
            # Build regex pattern (raise error early on main thread)
            try:
                flags = 0 if self.case_var.get() else re.IGNORECASE
                pattern = re.compile(
                    keyword if self.regex_var.get() else re.escape(keyword), flags)
            except re.error as e:
                messagebox.showerror("Regex Error", str(e), parent=self)
                return

        self._clear_results(keep_settings=True)
        self._is_searching  = True
        self._seen_set      = set()
        self._stop_event.clear()
        self._result_queue  = queue.Queue()
        self._total_files   = 0
        self._done_files    = 0
        self._total_bytes   = 0
        self._done_bytes    = 0
        self._discovery_done = False
        self._large_files.clear()
        self._tree_iid      = 0
        self._search_start  = datetime.now()

        self.search_btn.pack_forget()
        self.cancel_btn.pack(fill="x")
        self.progress.configure(value=0)
        self._set_status("Mengumpulkan file .txt…")

        # Start coordinator thread
        threading.Thread(
            target=self._coordinator,
            args=(folder, keyword if not scan_all else "", pattern),
            daemon=True).start()

        # Start polling UI
        self.after(POLL_MS, self._poll_queue)

    def _cancel_search(self):
        """Signal all workers to stop."""
        self._stop_event.set()
        self._set_status("Membatalkan…")
        self.cancel_btn.configure(text="⏳ Menunggu…")

    # ─────────────── WORKER THREADS ──────────────────────────────────
    def _coordinator(self, folder: str, keyword: str, pattern: re.Pattern):
        q      = self._result_queue
        stop   = self._stop_event
        ctx    = self.context_lines.get()
        scan_all = self.scan_all_var.get()

        file_queue = queue.Queue(maxsize=10000)
        kw_bytes_lower = keyword.lower().encode("utf-8", errors="ignore") if keyword else b""
        case_sensitive = self.case_var.get()

        def worker_loop():
            while not stop.is_set():
                item = file_queue.get()
                if item is None:
                    break
                filepath, fsize = item
                
                if fsize == 0:
                    q.put(("PROGRESS", (1, 0, filepath)))
                    continue
                
                matches = []
                filename = os.path.basename(filepath)
                rel_folder = os.path.relpath(os.path.dirname(filepath), folder)
                bytes_processed = 0
                lines_processed = 0

                if fsize > 50 * 1024 * 1024:
                    q.put(("START_LARGE_FILE", filepath))

                try:
                    # ── mmap pre-filter: skip file if keyword not present ──
                    if not scan_all and keyword:
                        if not case_sensitive and fsize < 200_000_000:  # <200MB
                            try:
                                with open(filepath, "rb") as fh:
                                    with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                        data_low = mm[:].lower()
                                        if kw_bytes_lower not in data_low:
                                            q.put(("PROGRESS", (1, fsize, filepath)))
                                            continue   # fast skip
                            except (ValueError, OSError):
                                pass  # fallback to normal read

                    # Detect if file is a Text Finder output
                    is_tf_output = False
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                            head = fh.read(512)
                            is_tf_output = "TEXT FINDER" in head or ("====" in head and "FILE:" in head)
                    except Exception:
                        pass

                    # Determine how to read the file
                    lines_generator = None
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
                            if fsize > 50 * 1024 * 1024:
                                q.put(("FILE_PROGRESS", (filepath, bytes_processed, fsize)))
                                
                        if len(matches) >= 500:
                            q.put(("RESULTS", matches.copy()))
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
                
                if matches:
                    q.put(("RESULTS", matches))
                q.put(("PROGRESS", (1, fsize, filepath)))

        workers = []
        for _ in range(MAX_WORKERS):
            w = threading.Thread(target=worker_loop, daemon=True)
            w.start()
            workers.append(w)

        # ── Caching Logic ──
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tf_cache")
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except Exception:
            pass
            
        folder_hash = hashlib.md5(folder.encode('utf-8')).hexdigest()
        cache_file = os.path.join(cache_dir, folder_hash + ".txt")
        
        use_cache = self.use_cache_var.get()
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
                            q.put(("DISCOVERED", (1, sz)))
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
                                q.put(("DISCOVERED", (1, sz)))
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

        q.put(("DISCOVERY_DONE", None))

        for _ in range(MAX_WORKERS):
            file_queue.put(None)
            
        for w in workers:
            w.join()

        q.put(("DONE", None))

    def _poll_queue(self):
        """Called every POLL_MS ms on main thread — drains the queue."""
        if not self._is_searching:
            return

        q       = self._result_queue
        batch   = []
        done    = False
        
        files_disc = 0
        bytes_disc = 0
        files_prog = 0
        bytes_prog = 0

        try:
            for _ in range(2000):
                item = q.get_nowait()
                if item is None:
                    continue
                kind, data = item
                if kind == "DISCOVERED":
                    files_disc += data[0]
                    bytes_disc += data[1]
                elif kind == "PROGRESS":
                    files_prog += data[0]
                    bytes_prog += data[1]
                    self._large_files.pop(data[2], None)
                elif kind == "RESULTS":
                    batch.extend(data)
                elif kind == "DISCOVERY_DONE":
                    self._discovery_done = True
                elif kind == "DONE":
                    done = True
                    break
                elif kind == "START_LARGE_FILE":
                    self._large_files[data] = (0, 0)
                elif kind == "FILE_PROGRESS":
                    filepath, b_read, b_total = data
                    self._large_files[filepath] = (b_read, b_total)
        except queue.Empty:
            pass

        if files_disc or bytes_disc:
            self._total_files += files_disc
            self._total_bytes += bytes_disc
            
        if files_prog or bytes_prog:
            self._done_files += files_prog
            self._done_bytes += bytes_prog
            
        def format_size(size):
            if size < 1024: return f"{int(size)} B"
            for unit in ['KB', 'MB', 'GB', 'TB']:
                size /= 1024.0
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
            return f"{size:.1f} PB"

        partial_bytes = sum(b_read for b_read, _ in self._large_files.values())
        total_done_bytes = self._done_bytes + partial_bytes

        if self._total_bytes > 0:
            pct = min(100.0, (total_done_bytes / self._total_bytes) * 100)
            self.progress.configure(value=pct)

        elapsed = max((datetime.now() - self._search_start).total_seconds(), 0.1)
        speed_bps = total_done_bytes / elapsed

        if not self._discovery_done:
            self._set_status(f"Mengumpulkan file... (Ditemukan: {self._total_files:,} file | {format_size(self._total_bytes)})")
        else:
            active_large = [os.path.basename(fp) for fp in self._large_files]
            if active_large:
                lnames = ", ".join(active_large[:2])
                if len(active_large) > 2:
                    lnames += f" (+{len(active_large)-2})"
                self._set_status(f"Memproses file besar: {lnames}")
            else:
                self._set_status(f"Mencari... {self._done_files:,} / {self._total_files:,} file")

        self.speed_lbl.configure(text=f"⚡ {format_size(speed_bps)}/detik")
        self.prog_lbl.configure(text=f"{format_size(total_done_bytes)} / {format_size(self._total_bytes)} diproses")

        if batch and len(self.results) < 2_000_000:
            room = 2_000_000 - len(self.results)
            dedup = self.dedup_var.get()
            valid_batch = []
            for r in batch:
                if dedup:
                    key = (r["type"], r["snippet"].strip().lower())
                    if key in self._seen_set:
                        continue
                    self._seen_set.add(key)
                valid_batch.append(r)
            if valid_batch:
                to_add = valid_batch[:room]
                self.results.extend(to_add)
                
                tree_count = len(self.tree.get_children())
                if tree_count < 2000:
                    tree_room = 2000 - tree_count
                    self._insert_batch_to_tree(to_add[:tree_room])
                
            n = len(self.results)
            files_hit = len({r["filepath"] for r in self.results})
            self.match_badge.configure(text=f"{n:,} hasil")
            self.count_lbl.configure(text=f"✔ {n:,} kecocokan, {files_hit:,} file")

        if done:
            self._search_done()
        else:
            self.after(POLL_MS, self._poll_queue)

    def _insert_batch_to_tree(self, batch: list[dict]):
        """Insert a batch of results into the tree (fast — no full repopulate)."""
        q = self.filter_var.get().strip().lower()
        for r in batch:
            iid = str(self._tree_iid)
            self._tree_iid += 1
            tag = "odd" if self._tree_iid % 2 == 0 else "even"

            t = r.get("type", "other")
            type_label = "🍪 Cookie" if t == "cookie" else "🔑 Credential" if t == "credential" else "❓ Lainnya"
            domain_label = r.get("domain", "—") or "—"
            display_name = os.path.join(r["folder"], r["filename"]) if r["folder"] and r["folder"] != "." else r["filename"]

            # apply filter if active
            if q:
                if not (q in display_name.lower()
                        or q in type_label.lower()
                        or q in domain_label.lower()
                        or q in r["snippet"].lower()):
                    continue
            self.tree.insert("", "end", iid=iid, tags=(tag,),
                             values=(display_name, r["lineno"],
                                     type_label, domain_label, r["snippet"]))

    def _search_done(self):
        self._is_searching = False
        self.progress.configure(value=100)
        self.cancel_btn.pack_forget()
        self.cancel_btn.configure(text="⏹  Stop Pencarian")
        self.search_btn.pack(fill="x")

        elapsed   = (datetime.now() - self._search_start).total_seconds()
        n         = len(self.results)
        files_hit = len({r["filepath"] for r in self.results})
        
        def format_size(size):
            if size < 1024: return f"{int(size)} B"
            for unit in ['KB', 'MB', 'GB', 'TB']:
                size /= 1024.0
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
            return f"{size:.1f} PB"
            
        speed_bps = self._total_bytes / max(elapsed, 0.01)

        if self._stop_event.is_set():
            self._set_status(f"● Dibatalkan — {n:,} kecocokan ditemukan")
        else:
            self._set_status(f"● Selesai  •  {elapsed:.1f} detik  •  {self._total_files:,} file ({format_size(self._total_bytes)})")

        self.count_lbl.configure(text=f"✔ {n:,} kecocokan di {files_hit:,} file")
        badge_bg = ACCENT_GREEN_BG if n > 0 else ACCENT_RED_BG
        badge_fg = ACCENT_GREEN    if n > 0 else ACCENT_RED
        self.match_badge.configure(text=f" {n:,} hasil ", bg=badge_bg, fg=badge_fg)
        self.speed_lbl.configure(text=f"⚡ {format_size(speed_bps)}/detik")
        self.prog_lbl.configure(text=f"{self._done_files:,} / {self._total_files:,} file dipindai")

        if n:
            self._activate_save()
        elif not self._stop_event.is_set():
            messagebox.showinfo("Tidak Ditemukan", "Pencarian selesai. Tidak ada data yang ditemukan.", parent=self)

    # ─────────────── RESULT UI ───────────────────────────────────────
    def _filter_results(self, *_):
        """Re-populate tree with filtered results (called on filter input)."""
        q = self.filter_var.get().strip().lower()
        # Clear tree
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._tree_iid = 0

        filtered = []
        for r in self.results:
            if not q:
                filtered.append(r)
            else:
                display_name = os.path.join(r["folder"], r["filename"]) if r["folder"] and r["folder"] != "." else r["filename"]
                t = r.get("type", "other")
                type_label = "cookie" if t == "cookie" else "credential" if t == "credential" else "lainnya"
                domain_label = r.get("domain", "—").lower()
                if (q in display_name.lower() or
                    q in type_label or
                    q in domain_label or
                    q in r["snippet"].lower()):
                    filtered.append(r)
            if len(filtered) >= 2000:
                break

        # Insert in batches to keep UI responsive
        CHUNK = 500
        for i in range(0, len(filtered), CHUNK):
            self._insert_batch_to_tree(filtered[i:i+CHUNK])

        self.match_badge.configure(text=f"{len(filtered):,} hasil")

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        idx = int(iid)
        if idx < len(self.results):
            self._show_detail(self.results[idx])

    def _show_detail(self, r: dict):
        self.detail_path_lbl.configure(
            text=f"📄  {r['filepath']}  —  baris {r['lineno']}", fg=ACCENT)
        dt = self.detail_text
        dt.configure(state="normal")
        dt.delete("1.0", "end")
        for i, line in enumerate(r["ctx_lines"]):
            abs_ln = r["ctx_start"] + i
            dt.insert("end", f"{abs_ln:>5} │ ", "lineno")
            line_text = line.rstrip("\n") + "\n"
            if abs_ln == r["lineno"]:
                if r.get("pattern"):
                    pos = 0
                    for m in r["pattern"].finditer(line_text):
                        if line_text[pos:m.start()]:
                            dt.insert("end", line_text[pos:m.start()], "cur_line")
                        dt.insert("end", m.group(), "match")
                        pos = m.end()
                    if line_text[pos:]:
                        dt.insert("end", line_text[pos:], "cur_line")
                else:
                    dt.insert("end", line_text, "cur_line")
            else:
                dt.insert("end", line_text)
        dt.configure(state="disabled")

    # ─────────────── SAVE ─────────────────────────────────────────────
    def _activate_save(self):
        self.save_btn.configure(bg=ACCENT_GREEN_BG, fg=ACCENT_GREEN, cursor="hand2")
        self.save_btn.bind("<Button-1>", lambda e: self._save_results())
        self.save_btn.bind("<Enter>",    lambda e: self.save_btn.configure(bg=self._lighten(ACCENT_GREEN_BG)))
        self.save_btn.bind("<Leave>",    lambda e: self.save_btn.configure(bg=ACCENT_GREEN_BG))

        self.export_split_btn.configure(bg=ACCENT_ORANGE_BG, fg=ACCENT_ORANGE, cursor="hand2")
        self.export_split_btn.bind("<Button-1>", lambda e: self._export_split_results())
        self.export_split_btn.bind("<Enter>",    lambda e: self.export_split_btn.configure(bg=self._lighten(ACCENT_ORANGE_BG)))
        self.export_split_btn.bind("<Leave>",    lambda e: self.export_split_btn.configure(bg=ACCENT_ORANGE_BG))

    def _save_results(self):
        if not self.results:
            messagebox.showinfo("Kosong", "Tidak ada hasil.", parent=self)
            return
        now  = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = re.sub(r'[\\/:*?"<>|]', "_",
                      f"hasil_{self.keyword_var.get().strip()[:20]}_{now}.txt")
        fp = filedialog.asksaveasfilename(
            title="Simpan Hasil Pencarian", defaultextension=".txt",
            initialfile=name,
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not fp:
            return

        kw        = self.keyword_var.get().strip()
        folder    = self.search_path.get().strip()
        n         = len(self.results)
        files_hit = len({r["filepath"] for r in self.results})

        out = [
            "=" * 80,
            "  TEXT FINDER — HASIL PENCARIAN",
            "=" * 80,
            f"  Kata kunci     : {kw}",
            f"  Folder target  : {folder}",
            f"  Waktu          : {datetime.now().strftime('%d %B %Y, %H:%M:%S')}",
            f"  Total kecocokan: {n:,}  |  File unik: {files_hit:,}",
            "=" * 80,
            "",
        ]
        prev = None
        for r in self.results:
            if r["filepath"] != prev:
                out += ["", "─" * 80, f"  FILE: {r['filepath']}", "─" * 80]
                prev = r["filepath"]
            out.append(f"\n  [ Baris {r['lineno']} ]")
            for i, ln in enumerate(r["ctx_lines"]):
                abs_ln = r["ctx_start"] + i
                marker = ">>>" if abs_ln == r["lineno"] else "   "
                out.append(f"  {marker} {abs_ln:>5} │ {ln.rstrip()}")
        out += ["", "=" * 80, f"  Akhir laporan — Total: {n:,} kecocokan", "=" * 80]
        try:
            with open(fp, "w", encoding="utf-8") as f:
                f.write("\n".join(out))
            messagebox.showinfo("Berhasil", f"Hasil disimpan ke:\n{fp}", parent=self)
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan:\n{e}", parent=self)

    # ─────────────── UTILITIES ────────────────────────────────────────
    def _clear_results(self, keep_settings=False):
        self.results.clear()
        self._tree_iid = 0
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")
        self.detail_path_lbl.configure(
            text="  Pilih baris hasil untuk lihat konteks", fg=TEXT_MUTED)
        self.match_badge.configure(text="", bg=ACCENT_ORANGE_BG)
        self.count_lbl.configure(text="")
        self.speed_lbl.configure(text="")
        self.prog_lbl.configure(text="")
        self.progress.configure(value=0)
        self.save_btn.configure(bg=BG_CARD, fg=TEXT_MUTED, cursor="arrow")
        self.save_btn.unbind("<Button-1>")
        self.save_btn.unbind("<Enter>")
        self.save_btn.unbind("<Leave>")
        self.export_split_btn.configure(bg=BG_CARD, fg=TEXT_MUTED, cursor="arrow")
        self.export_split_btn.unbind("<Button-1>")
        self.export_split_btn.unbind("<Enter>")
        self.export_split_btn.unbind("<Leave>")
        if not keep_settings:
            self._set_status("● Siap")

    def _set_status(self, msg: str):
        self.status_lbl.configure(text=msg)
        self.update_idletasks()

    def _export_split_results(self):
        if not self.results:
            messagebox.showinfo("Kosong", "Tidak ada hasil pencarian untuk di-export.", parent=self)
            return

        folder = filedialog.askdirectory(title="Pilih Folder Tujuan Simpan Hasil Pemilahan")
        if not folder:
            return

        # ── State Dictionary ──────────────────────────────────────────
        state = {
            "current": 0,
            "total": 100,
            "status": "Memulai pemilahan…",
            "sub_status": "",
            "done": False,
            "error": None,
            "cookies_saved": 0,
            "creds_saved": 0,
            "domain_cookies_count": 0,
            "domain_creds_count": 0,
        }

        # ── Progress Window UI ─────────────────────────────────────────
        progress_win = tk.Toplevel(self)
        progress_win.title("Proses Pemilahan & Export")
        progress_win.configure(bg=BG_PANEL)
        progress_win.resizable(False, False)
        
        # Center it
        progress_win.update_idletasks()
        width = 450
        height = 170
        x = self.winfo_x() + (self.winfo_width() // 2) - (width // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (height // 2)
        progress_win.geometry(f"{width}x{height}+{x}+{y}")
        
        progress_win.transient(self)
        progress_win.grab_set()

        # UI elements
        frame = tk.Frame(progress_win, bg=BG_PANEL, padx=20, pady=15)
        frame.pack(fill="both", expand=True)

        title_lbl = tk.Label(frame, text="Memilah & Mengekspor Data", bg=BG_PANEL, fg=ACCENT, font=("Segoe UI", 12, "bold"))
        title_lbl.pack(anchor="w", pady=(0, 10))

        status_lbl = tk.Label(frame, text="Menyiapkan data…", bg=BG_PANEL, fg=TEXT_PRIMARY, font=FONT_UI_SM, anchor="w", justify="left")
        status_lbl.pack(fill="x", pady=(0, 2))

        sub_status_lbl = tk.Label(frame, text="", bg=BG_PANEL, fg=TEXT_SECONDARY, font=("Segoe UI", 8), anchor="w")
        sub_status_lbl.pack(fill="x", pady=(0, 10))

        progress_row = tk.Frame(frame, bg=BG_PANEL)
        progress_row.pack(fill="x", pady=(10, 5))

        pct_lbl = tk.Label(progress_row, text="0%", bg=BG_PANEL, fg=ACCENT, font=("Segoe UI", 28, "bold"))
        pct_lbl.pack(expand=True)

        def export_worker():
            try:
                # Dictionaries to group results:
                cookies_by_domain = {}
                creds_by_host = {}

                # Deduplication sets
                seen_cookies = set()
                seen_creds = set()

                total_items = len(self.results)
                state["total"] = total_items + 10  # temporary total
                
                # Parse every found result line in self.results
                for idx, r in enumerate(self.results):
                    content = r["snippet"].strip()
                    if not content:
                        continue

                    t = r.get("type", "other")
                    if t == "cookie":
                        # Snippet is already normalized Netscape cookie!
                        domain = r.get("domain", "")
                        if not domain or domain == "—" or domain == "unknown_domain":
                            domain = extract_cookie_domain(content)
                        cookies_by_domain.setdefault(domain, {}).setdefault(r["filepath"], []).append(content)
                    elif t == "credential":
                        host = r.get("domain", "other_credentials")
                        if not host or host == "—" or host == "unknown_domain":
                            host = extract_cred_domain(content)
                        creds_by_host.setdefault(host, []).append((r["filepath"], content))
                    
                    if idx % 100 == 0 or idx == total_items - 1:
                        state["current"] = idx + 1
                        state["status"] = f"Membaca & mengelompokkan data ({idx + 1}/{total_items})…"
                
                # Update domain counts
                state["domain_cookies_count"] = len(cookies_by_domain)
                state["domain_creds_count"] = len(creds_by_host)

                # Helper to get safe file name representing the source log file
                def get_safe_source_name(filepath: str) -> str:
                    parts = filepath.replace('\\', '/').split('/')
                    if len(parts) >= 2:
                        name = f"{parts[-2]}_{parts[-1]}"
                    else:
                        name = parts[-1]
                    return re.sub(r'[\\/:*?"<>|]', '_', name)

                # Collect all file write tasks
                write_tasks = []

                # 1. Prepare Cookie Files:
                if cookies_by_domain:
                    cookie_dir = os.path.join(folder, "Cookies")
                    for domain, path_dict in cookies_by_domain.items():
                        domain_folder = os.path.join(cookie_dir, domain)
                        
                        # Track safe names used in this domain folder to resolve collisions
                        used_names = {}
                        for filepath, entries in path_dict.items():
                            sessions = [] # list of lists of cookie lines
                            for entry in entries:
                                parts = entry.split('\t')
                                if len(parts) != 7:
                                    continue
                                    
                                c_domain, c_flag, c_path, c_sec, c_exp, c_name, c_val = parts
                                
                                # Strict final validation for 100% valid Netscape
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

                # 2. Prepare Credential Files:
                if creds_by_host:
                    cred_dir = os.path.join(folder, "Credentials")
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
                state["total"] = total_items + total_files
                
                # Threaded file writer function
                def write_file_task(task):
                    fp, file_content = task[0], task[1]
                    os.makedirs(os.path.dirname(fp), exist_ok=True)
                    with open(fp, "w", encoding="utf-8", errors="replace") as f:
                        f.write(file_content)
                    return task
                
                total_cookies_saved = 0
                total_creds_saved = 0
                completed_files = 0
                
                # Execute file writes in parallel
                with ThreadPoolExecutor(max_workers=min(16, (os.cpu_count() or 4) * 4)) as executor:
                    futures = [executor.submit(write_file_task, task) for task in write_tasks]
                    for fut in as_completed(futures):
                        task = fut.result()
                        completed_files += 1
                        state["current"] = total_items + completed_files
                        state["status"] = f"Menulis file ({completed_files}/{total_files})…"
                        state["sub_status"] = os.path.basename(task[0])
                        
                        # Count saved entries
                        if task[2] > 0:
                            if task[3] == "cookie":
                                total_cookies_saved += task[2]
                            else:
                                total_creds_saved += task[2]
                
                state["cookies_saved"] = total_cookies_saved
                state["creds_saved"] = total_creds_saved
                state["done"] = True
            except Exception as e:
                state["error"] = str(e)
                state["done"] = True

        def update_progress():
            if state["done"]:
                # Close progress window
                progress_win.grab_release()
                progress_win.destroy()
                
                # Show result
                if state["error"]:
                    messagebox.showerror("Error Export", f"Gagal mengeksport hasil: {state['error']}", parent=self)
                else:
                    saved_info = []
                    if state["cookies_saved"] > 0:
                        saved_info.append(f"🍪 Cookies: {state['cookies_saved']:,} entri dipisah menjadi {state['domain_cookies_count']:,} folder domain di /Cookies")
                    if state["creds_saved"] > 0:
                        saved_info.append(f"🔑 Credentials: {state['creds_saved']:,} entri dipisah menjadi {state['domain_creds_count']:,} file .txt di /Credentials")
                    
                    if not state["cookies_saved"] and not state["creds_saved"]:
                        messagebox.showinfo("Informasi", 
                                            "Tidak ditemukan data cookies atau credentials yang valid untuk dieksport.", 
                                            parent=self)
                    else:
                        messagebox.showinfo("Export Berhasil",
                                            f"✔ Hasil pencarian berhasil dipilah & diexport ke:\n{folder}\n\n"
                                            + "\n".join(saved_info), parent=self)
                return

            # Update progress bar and text
            current = state["current"]
            total = max(1, state["total"])
            pct = int((current / total) * 100)
            
            pct_lbl.configure(text=f"{pct}%")
            status_lbl.configure(text=state["status"])
            sub_status_lbl.configure(text=state["sub_status"])
            
            # Schedule next update
            progress_win.after(40, update_progress)

        # Start worker thread
        threading.Thread(target=export_worker, daemon=True).start()
        
        # Start GUI polling
        update_progress()

    def _on_close(self):
        self._stop_event.set()
        self.destroy()


# ──────────────────────────── MAIN ───────────────────────────────────
if __name__ == "__main__":
    app = TextFinderApp()
    app.mainloop()

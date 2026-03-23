"""
detector.py — Attack detection engine.
Uses compiled regex patterns to classify incoming requests into attack types.
Includes brute-force detection via in-memory IP attempt tracking.
"""

import re
from collections import defaultdict
from urllib.parse import unquote
from datetime import datetime, timedelta

# ── Compiled regex patterns per attack type ──────────────────────────────────

SQL_INJECTION = re.compile(
    r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+|"
    r"\bUNION\b\s+(ALL\s+)?\bSELECT\b|"
    r"\bSELECT\b\s+.+\bFROM\b|"
    r"\bINSERT\b\s+\bINTO\b|"
    r"\bDROP\b\s+\bTABLE\b|"
    r"\bDELETE\b\s+\bFROM\b|"
    r"\bUPDATE\b\s+\w+\s+\bSET\b|"
    r"\bSLEEP\s*\(|"
    r"\bBENCHMARK\s*\(|"
    r"\bWAITFOR\b\s+\bDELAY\b|"
    r"'\s*(OR|AND)\s+.*--|"
    r"admin\s*'\s*--|"
    r"1\s*=\s*1\s*--|"
    r"'\s*;\s*DROP\b|"
    r"'\s*OR\s+'[^']*'\s*=\s*')",
    re.IGNORECASE
)

XSS = re.compile(
    r"(<\s*script|<\/\s*script|javascript\s*:|"
    r"\bon(error|load|click|mouseover|focus|blur|submit|change)\s*=|"
    r"\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|"
    r"<\s*img\s[^>]*onerror|<\s*svg\s[^>]*onload|"
    r"document\.(cookie|write|location)|"
    r"<\s*iframe|<\s*embed|<\s*object)",
    re.IGNORECASE
)

COMMAND_INJECTION = re.compile(
    r"(;\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh|rm|chmod)\b|"
    r"&&\s*(ls|cat|whoami|id|pwd|uname|wget|curl|nc|bash|sh|rm|chmod)\b|"
    r"\|\s*(cat|whoami|id|uname|bash|sh)\b|"
    r"`[^`]+`|"
    r"\$\([^)]+\))",
    re.IGNORECASE
)

LFI = re.compile(
    r"(\.\./\.\./|"
    r"/etc/(passwd|shadow|hosts|group)|"
    r"boot\.ini|win\.ini|"
    r"proc/self|"
    r"php://(filter|input|expect)|"
    r"file://)",
    re.IGNORECASE
)

RFI = re.compile(
    r"(https?://|ftp://)\S+\.(php|txt|asp|jsp|py|pl)",
    re.IGNORECASE
)

DIRECTORY_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f)",
    re.IGNORECASE
)

FILE_UPLOAD = re.compile(
    r"\.(php[3-8]?|phtml|phar|jsp|jspx|asp|aspx|exe|bat|cmd|cgi|pl|py|sh|"
    r"war|jar|svg|swf|htaccess)$",
    re.IGNORECASE
)

BOT_SCAN = re.compile(
    r"(/phpmyadmin|/wp-admin|/wp-login|/wp-content|"
    r"/\.env|/\.git|/\.htaccess|"
    r"/config\.php|/phpinfo|/server-status|"
    r"/actuator|/solr|/manager|/console|"
    r"/admin\.php|/administrator|/backup|"
    r"/cgi-bin|/xmlrpc\.php)",
    re.IGNORECASE
)

# ── Brute-force tracking ────────────────────────────────────────────────────

_login_attempts = defaultdict(list)
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=2)


def _is_brute_force(ip, url):
    """Check if this IP has sent too many login-like requests recently."""
    login_keywords = ('/login', '/admin', '/register')
    if not any(kw in url.lower() for kw in login_keywords):
        return False

    now = datetime.now()
    # Prune old entries
    _login_attempts[ip] = [
        t for t in _login_attempts[ip] if now - t < BRUTE_FORCE_WINDOW
    ]
    _login_attempts[ip].append(now)
    return len(_login_attempts[ip]) >= BRUTE_FORCE_THRESHOLD


# ── Main detection function ─────────────────────────────────────────────────

def detect_attack(url, payload='', headers=None, filename='', ip=''):
    """
    Classify a request into an attack type.

    Only inspects the URL and payload — NOT headers, to avoid false positives
    from standard header values like Content-Type containing quotes.

    Returns one of:
        SQL Injection, XSS, Command Injection, LFI, RFI,
        Directory Traversal, File Upload Attack, Bot Scan,
        Brute Force, Reconnaissance
    """
    # URL-decode to catch percent-encoded attack payloads
    combined = unquote(f"{url} {payload}")

    # Priority-ordered checks
    if SQL_INJECTION.search(combined):
        return 'SQL Injection'

    if XSS.search(combined):
        return 'XSS'

    if COMMAND_INJECTION.search(combined):
        return 'Command Injection'

    if LFI.search(combined):
        return 'LFI'

    if RFI.search(combined):
        return 'RFI'

    if DIRECTORY_TRAVERSAL.search(combined):
        return 'Directory Traversal'

    if filename and FILE_UPLOAD.search(filename):
        return 'File Upload Attack'

    if BOT_SCAN.search(url):
        return 'Bot Scan'

    if _is_brute_force(ip, url):
        return 'Brute Force'

    return 'Reconnaissance'

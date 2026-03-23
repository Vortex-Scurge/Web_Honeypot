# 🎓 Web Honeypot — Minor Project Viva Preparation

---

## PART 1: GENERAL / CONCEPTUAL QUESTIONS

---

### Q1. What is a honeypot?
A honeypot is a security mechanism — a deliberately vulnerable system designed to attract attackers. It mimics real services (like websites, databases, or servers) so that attackers interact with it thinking it's a real target. The honeypot quietly logs all their activity for security analysis. It's a trap, essentially.

### Q2. What is the difference between a low-interaction and high-interaction honeypot?
- **Low-interaction honeypot** (what we built): Simulates only the surface-level behavior of services. It doesn't run real vulnerable software — it just *pretends* to. Safer to deploy, easier to maintain, but captures less detailed attacker behavior.
- **High-interaction honeypot**: Runs actual vulnerable software or full operating systems. Captures complete attacker behavior including exploitation techniques, but is risky — attackers could use it to pivot into your real network.

### Q3. Why did you build a web honeypot specifically?
Web applications are the most commonly attacked surface on the internet. By building a web honeypot, we can detect and study real-world web attack patterns like SQL Injection, XSS, and brute-force attacks. It's practical, relevant, and demonstrates core cybersecurity concepts.

### Q4. What are the real-world applications of honeypots?
- **Threat intelligence** — Understanding what attackers target and how.
- **Early warning systems** — Detecting attacks before they reach real systems.
- **Research** — Studying new attack techniques and malware.
- **Deception defense** — Wasting attacker time on fake systems.
- **Compliance** — Some organizations deploy them as part of security monitoring.

### Q5. Is this legal to deploy?
Yes, as long as it's on your own network/infrastructure. A honeypot is a *defensive* tool. You're not attacking anyone — you're observing attackers who voluntarily interact with your system. However, you should not deploy it on networks you don't own without permission.

### Q6. What is the difference between IDS, IPS, and a Honeypot?
- **IDS (Intrusion Detection System)**: Monitors network traffic and alerts when it detects malicious patterns. Passive — doesn't block.
- **IPS (Intrusion Prevention System)**: Like IDS but actively blocks malicious traffic.
- **Honeypot**: Doesn't monitor real traffic. It's a *decoy* that attracts attackers to study their behavior. Complementary to IDS/IPS.

### Q7. What is the OWASP Top 10?
OWASP Top 10 is a standard awareness document listing the 10 most critical web application security risks. Our honeypot detects several of them:
- **A03: Injection** → SQL Injection, Command Injection
- **A07: Cross-Site Scripting (XSS)** → XSS detection
- **A01: Broken Access Control** → LFI, Directory Traversal
- **A05: Security Misconfiguration** → Bot scanning for exposed config files

---

## PART 2: ATTACK-SPECIFIC QUESTIONS

---

### Q8. What is SQL Injection? How does your system detect it?
SQL Injection is when an attacker inserts SQL code into input fields to manipulate the database. For example, entering `admin' OR 1=1 --` as a username would bypass login if the backend naively concatenates user input into SQL queries.

**Our detection**: We use regex patterns in `detector.py` that match common SQL keywords and patterns like `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `SLEEP()`, etc. The input is URL-decoded first so encoded payloads are also caught.

### Q9. What is XSS (Cross-Site Scripting)?
XSS is when an attacker injects malicious JavaScript into web pages viewed by other users. For example, `<script>alert(document.cookie)</script>` could steal session cookies.

**Types**:
- **Stored XSS** — Script is saved in the database and shown to other users.
- **Reflected XSS** — Script is reflected back in the server response (like in search results).
- **DOM-based XSS** — Script manipulates the page's DOM directly.

**Our detection**: We match patterns like `<script>`, `javascript:`, `onerror=`, `alert()`, `document.cookie`, etc.

### Q10. What is Local File Inclusion (LFI)?
LFI is when an attacker manipulates file path parameters to read files from the server. For example, `page?id=../../etc/passwd` tries to read the Linux password file by traversing up the directory tree.

**Our detection**: We match patterns like `../../`, `/etc/passwd`, `php://filter`, `boot.ini`, etc.

### Q11. What is the difference between LFI and Directory Traversal?
They're related but different:
- **LFI** — Exploits a file *inclusion* function to execute or read a file (e.g., PHP `include()`)
- **Directory Traversal** — Exploits file *download/access* functions to read arbitrary files (e.g., `download?file=../../../etc/passwd`)

In our system, both use `../` patterns, but LFI specifically checks for system files and PHP wrappers, while Directory Traversal focuses on path traversal sequences.

### Q12. What is Command Injection?
Command Injection is when an attacker injects OS commands through input fields. For example, if a server runs `ping <user_input>`, entering `; cat /etc/passwd` would execute that command after ping.

**Our detection**: We match patterns like `; ls`, `&& whoami`, `| cat`, backtick execution, and `$()` subshells.

### Q13. What is a brute-force attack? How do you detect it?
Brute force is when an attacker tries many username/password combinations rapidly to guess credentials. 

**Our detection**: We track login attempts per IP in memory using a dictionary with timestamps. If the same IP sends 5+ login requests within a 2-minute window, we classify it as brute force. This is done in the `_is_brute_force()` function in `detector.py`.

### Q14. What is bot scanning?
Bot scanning is automated probing of a web server for known vulnerable paths — like `/phpmyadmin`, `/wp-admin`, `/.env`, `/.git`. Bots try thousands of servers looking for unprotected admin panels or exposed configuration files.

**Our detection**: We maintain a list of commonly scanned paths and match incoming URLs against them.

---

## PART 3: CODE-SPECIFIC QUESTIONS

---

### Q15. Explain the architecture / flow of your system.
```
Attacker → HTTP Request → Flask Server (app.py)
  → before_request middleware extracts data (utils.py)
  → detector.py classifies the attack type
  → logger.py logs to file + database
  → routes.py returns a fake response
  → Dashboard (dashboard.py) displays analytics
```

Every single request goes through the `@app.before_request` middleware in `app.py` before reaching any route. This ensures nothing is missed.

### Q16. What does `@app.before_request` do in app.py?
`@app.before_request` is a Flask decorator that registers a function to run **before every HTTP request** is processed. We use it as middleware to:
1. Extract request data (IP, headers, payload, user agent)
2. Run the attack detection engine
3. Log the attack to both the log file and database

This is the core of the honeypot — it intercepts everything silently.

### Q17. Explain how `detector.py` works.
The detector uses **compiled regular expressions** (`re.compile()`) for each attack type. When a request comes in:
1. The URL and payload are combined into one string
2. This string is **URL-decoded** using `urllib.parse.unquote()` (so `%20OR` becomes ` OR`)
3. Each regex is checked in **priority order**: SQL Injection → XSS → Command Injection → LFI → RFI → Directory Traversal → File Upload → Bot Scan → Brute Force
4. The first match wins and returns the attack type
5. If nothing matches, it returns "Reconnaissance"

We compile regexes at module load time (`re.compile()`) rather than at each request for performance.

### Q18. Why do you use `re.compile()` instead of `re.search()` directly?
`re.compile()` pre-compiles the regex pattern into a pattern object. This is faster when the same pattern is used many times (which it is — every request), because the compilation step only happens once at import time rather than on every request.

### Q19. What is a Flask Blueprint? Why did you use them?
A Blueprint is Flask's way of organizing an application into modules. Instead of putting all routes in one file, we separate them:
- `honeypot` blueprint in `routes.py` — all trap endpoints
- `dashboard_bp` blueprint in `dashboard.py` — admin dashboard

This makes the code **modular**, **testable**, and **maintainable**. Each blueprint can have its own URL prefix (e.g., `/dashboard/`).

### Q20. Explain the database schema.
```sql
CREATE TABLE attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unique ID
    timestamp TEXT,          -- When the attack happened (ISO format)
    ip_address TEXT,         -- Attacker's IP
    method TEXT,             -- HTTP method (GET/POST)
    url TEXT,                -- Full URL path with query params
    headers TEXT,            -- Request headers (JSON string)
    payload TEXT,            -- Combined query string + form data
    attack_type TEXT,        -- Classification result
    user_agent TEXT,         -- Browser/tool identifier
    file_uploaded TEXT,      -- Uploaded filename (if any)
    response_code INTEGER    -- HTTP status code returned
)
```
We also create **indexes** on `timestamp`, `ip_address`, and `attack_type` for fast dashboard queries.

### Q21. Why SQLite and not MySQL/PostgreSQL?
- **Zero configuration** — No server to install, it's a single file (`database.db`)
- **Built into Python** — No extra dependencies needed (`import sqlite3`)
- **Perfect for this use case** — A honeypot doesn't need high concurrency or massive scale
- **Portable** — The entire database is one file you can copy or email

For a production honeypot handling thousands of requests/second, you'd switch to PostgreSQL.

### Q22. What does `conn.row_factory = sqlite3.Row` do?
By default, SQLite returns tuples. Setting `row_factory = sqlite3.Row` makes it return Row objects that support access by **column name** (like `row['ip_address']`) instead of just index (like `row[2]`). This makes the code more readable and less error-prone.

### Q23. Explain the logging system (logger.py).
We use **dual logging** — every attack is recorded in two places:
1. **Log file** (`logs/honeypot.log`) — Human-readable text log using Python's built-in `logging` module. Useful for quick inspection with `tail -f`.
2. **SQLite database** — Structured data storage for querying, filtering, and dashboard analytics.

This redundancy ensures we never lose data — even if the database gets corrupted, the log file still has everything.

### Q24. What does `utils.py` → `extract_request_data()` do?
It pulls all relevant information from a Flask request object into a clean dictionary:
- **IP address** — From `X-Forwarded-For` header (for proxied requests) or `remote_addr`
- **Method** — GET, POST, etc.
- **URL** — Full path including query parameters
- **Headers** — All HTTP headers as a dictionary
- **Payload** — Combined from query string, form data, JSON body, or raw body
- **User Agent** — The browser/tool identifier
- **File uploaded** — Names of any uploaded files

### Q25. How does the file upload capture work?
In `file_capture.py`, when an attacker uploads a file:
1. The filename is sanitized using `werkzeug.secure_filename()` to prevent path traversal
2. A timestamp prefix is added (e.g., `20260322_235000_shell.php`)
3. The file is saved to the `uploads/` directory for forensic analysis
4. The original filename is checked against malicious extension patterns (`.php`, `.jsp`, `.exe`, etc.)

The file is **never executed** — just stored.

### Q26. Explain how the dashboard works.
The dashboard (`dashboard.py`) has 4 endpoints:
- `GET /dashboard/` — Renders the HTML page with server-side stats
- `GET /dashboard/api/stats` — Returns JSON aggregated stats (for Chart.js)
- `GET /dashboard/api/logs` — Returns paginated logs with filtering
- `GET /dashboard/download` — Exports all logs as CSV

The frontend uses **Chart.js** (loaded from CDN) to render 4 charts. On page load, JavaScript fetches `/dashboard/api/stats` and `/dashboard/api/logs` and renders them dynamically.

### Q27. Why do you URL-decode before detection?
When browsers and tools send special characters in URLs, they get percent-encoded. For example:
- `' OR 1=1` becomes `%27%20OR%201%3D1`
- `; ls` becomes `%3B%20ls`

If we don't decode first, our regex patterns won't match. `urllib.parse.unquote()` converts these back to their original characters before running detection.

### Q28. What is the `@app.errorhandler(404)` for?
It catches **all requests to non-existent pages**. This is crucial because bot scanners try hundreds of paths like `/phpmyadmin`, `/.git`, `/wp-login.php`. Without a 404 handler, Flask would return a default error page and we wouldn't log the attempt. With our handler, every single request — even to pages that don't exist — gets intercepted, classified, and logged.

---

## PART 4: TECHNOLOGY & DESIGN QUESTIONS

---

### Q29. Why Flask and not Django or Node.js?
- **Lightweight** — Flask is a microframework, perfect for a focused tool like a honeypot
- **Minimal boilerplate** — We don't need Django's ORM, admin panel, or authentication system
- **Full control** — Flask lets us intercept requests at a low level with `before_request`
- **Python ecosystem** — Easy access to regex, SQLite, logging, and data analysis libraries

### Q30. What is WSGI?
WSGI (Web Server Gateway Interface) is the Python standard for communication between web servers and web applications. Flask is a WSGI application. In production, you'd run it behind a WSGI server like **Gunicorn** rather than Flask's built-in development server.

### Q31. What security measures does the honeypot itself have?
- **No real functionality** — The fake pages don't execute queries, commands, or include files
- **File sanitization** — Uploaded files are sanitized with `secure_filename()` and never executed
- **HTML escaping** — Dashboard uses `html.escape()` to prevent stored XSS from attacker payloads
- **Upload size limit** — 16 MB max to prevent disk-filling attacks
- **Isolated storage** — Uploaded files go to a separate directory

### Q32. Can this honeypot be bypassed/detected by an attacker?
Yes, a skilled attacker might notice:
- The pages don't actually process anything (login always fails, search always returns the same results)
- There are no real session cookies or CSRF tokens
- The server fingerprint shows Flask
- All responses are very fast (no real database queries)

To improve: Add random delays, vary responses, use realistic cookies, and hide the Flask server signature.

### Q33. How would you deploy this in production?
1. Use **Gunicorn** as the WSGI server: `gunicorn -w 4 -b 0.0.0.0:80 app:app`
2. Put it behind **Nginx** as a reverse proxy
3. Run it in a **Docker container** for isolation
4. Use a separate VLAN/network segment
5. Set up **log forwarding** to a SIEM (Security Information and Event Management) system
6. Add **SSL/TLS** to make it look more realistic

---

## PART 5: POTENTIAL FOLLOW-UP / ADVANCED QUESTIONS

---

### Q34. What improvements would you make?
- **GeoIP lookup** — Map attacker IPs to countries using MaxMind GeoLite2
- **Email alerts** — Send notifications on high-severity attacks
- **IP blocking** — Auto-block IPs after repeated attacks using iptables
- **Machine learning** — Train a classifier on request features instead of regex
- **Multiple fake services** — Add fake FTP, SSH, and SMTP honeypots
- **Attack heatmap** — Visualize attack origins on a world map
- **REST API** — Expose logs via REST for integration with other security tools

### Q35. How would you add machine learning to this?
1. **Feature extraction**: Extract features from each request — URL length, number of special characters, presence of keywords, HTTP method, time of day, etc.
2. **Training data**: Use the logs we've already collected (labeled by regex classifier) as training data
3. **Model**: Train a classifier (Random Forest, SVM, or a neural network) on these features
4. **Inference**: Replace or supplement the regex detector with model predictions
5. **Benefit**: ML can catch novel/obfuscated attacks that regex misses

### Q36. What is the difference between signature-based and anomaly-based detection?
- **Signature-based** (what we use): Matches known attack patterns (regexes). Fast and accurate for known attacks, but misses novel/zero-day attacks.
- **Anomaly-based**: Learns what "normal" traffic looks like and flags deviations. Can detect unknown attacks, but has higher false-positive rates.

A production system would use both approaches together.

### Q37. How does the brute-force detection handle distributed attacks?
Currently, it tracks attempts **per IP**. If an attacker uses multiple IPs (distributed brute force), each IP would stay under the threshold. To counter this:
- Track by username being targeted (not just IP)
- Use rate limiting across all IPs for login endpoints
- Implement CAPTCHA-like challenges after N total failed logins

---

## PART 6: KEY CODE SECTIONS THEY MAY ASK ABOUT

---

### "Show me where the attack detection happens"
→ `detector.py`, the `detect_attack()` function (line ~111). Walk through the priority chain.

### "Show me how logging works"
→ `logger.py`, the `log_request()` function. Explain dual logging.

### "How does the middleware work?"
→ `app.py`, the `@app.before_request` decorator and `analyze_request()` function.

### "Show me the database operations"
→ `database.py`, especially `init_db()` for schema and `get_stats()` for dashboard aggregations.

### "How do you handle file uploads safely?"
→ `file_capture.py`, the `capture_upload()` function. Mention `secure_filename()` and timestamp prefixing.

### "How does the dashboard render charts?"
→ `templates/dashboard.html`, the `<script>` section at the bottom. Explain the `fetch()` to `/dashboard/api/stats` and Chart.js initialization.

### "What happens to a request from start to finish?"
→ Walk through: `app.py before_request` → `utils.extract_request_data()` → `detector.detect_attack()` → `logger.log_request()` → route handler in `routes.py` → HTML response.

---

> **Tip**: When presenting, open the dashboard in a browser, run a few curl attacks live, and refresh the dashboard to show the attacks appearing in real-time. This is very impressive in a demo.

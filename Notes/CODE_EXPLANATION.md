# DETAILED CODE EXPLANATION: WEB HONEYPOT SYSTEM TECHNICAL ARCHITECTURE

## 1. COMPREHENSIVE SYSTEM ARCHITECTURE
The system is built as a defensive decoy. It mimics a standard web application while functioning as a highly specialized logging sensor.

### 1.1 The Web Server Gateway Interface (WSGI)
We use Flask, which is a WSGI application. The code is structured to intercept data at the highest possible layer of the application stack.

---

## 2. MODULE-BY-MODULE FUNCTIONAL ANALYSIS

### 2.1 app.py - The Interception Gateway
This is the entry point of the application.

#### Function: `create_app()`
- **Purpose:** Initializes the Flask application instance.
- **Logic:** It sets the template and static folders and registers blueprints. Blueprints allow us to keep the code modular (separating the "trap" from the "dashboard").

#### Middleware: `@app.before_request` (Function: `analyze_request`)
- **Purpose:** The most critical defensive logic.
- **Detailed Step-by-Step:**
    1. **Trigger:** Fires before any route is matched.
    2. **Extraction:** Calls `utils.extract_request_data()` to grab everything the attacker sent.
    3. **Detection:** Passes the extracted data to `detector.detect_attack()`.
    4. **Result:** Receives an attack classification (e.g., "SQL Injection").
    5. **Logging:** Passes the classification to `logger.log_request()` which writes to the file and database.
- **Why this matters:** Even if an attacker scans for a file that doesn't exist (triggering a 404), this function still runs. This ensures 100% logging coverage.

---

### 2.2 detector.py - The Pattern Matching Engine
This module contains the "brain" that identifies malicious intent.

#### Variable: `SQL_REGEX`
- **Pattern:** `re.compile(r"(union|select|insert|update|delete|drop|alter|create|truncate|show|describe|xp_cmdshell|declare|exec|into|load_file|outfile|dumpfile|sleep|benchmark|waitfor|delay|pg_sleep|md5|sha1|sha256|hex|unhex|base64|char|chr|concat|group_concat|substr|substring|version|user|database|current_user|system_user|schema|table_name|column_name|information_schema|pg_stat_activity|sqlite_master|mssql_objects)", re.IGNORECASE)`
- **Explanation:** This massive list covers keywords found in SQL Injection attacks across multiple database types (MySQL, PostgreSQL, SQLite, MSSQL).

#### Variable: `XSS_REGEX`
- **Pattern:** `re.compile(r"(<script|javascript:|onerror=|onload=|onclick=|onmouseover=|onfocus=|alert\(|confirm\(|prompt\(|document\.cookie|document\.location|window\.location|eval\(|setTimeout\(|setInterval\(|String\.fromCharCode|base64|atob\(|btoa\(|srcdoc=|<iframe|<object|<embed|<svg|<details|<math|isindex|formaction|background=)", re.IGNORECASE)`
- **Explanation:** Catches not just `<script>` tags, but also "living off the land" JavaScript attributes that execute code when a user interacts with the page (e.g., `onmouseover`).

#### Function: `_is_brute_force(ip_address)`
- **Mechanism:** Uses a dictionary `login_attempts = {}`.
- **Logic:**
    - Checks if the IP has an entry.
    - If it does, and the time difference is < 120 seconds, it increments the count.
    - If the count > 5, it returns `True`.
    - This is one of the few pieces of logic that is "stateful" (it remembers the past).

---

### 2.3 database.py - Structured Data Management
Using `sqlite3`, this module manages persistent storage.

#### Function: `init_db()`
- **SQL:** `CREATE TABLE IF NOT EXISTS attacks (...)`
- **Logic:** Defines the core data structure. We use `TEXT` for almost everything to ensure flexibility (e.g., headers can vary wildly in length).
- **Indexing:** `CREATE INDEX IF NOT EXISTS idx_ip ON attacks(ip_address)`. This makes the "Top Attacker" dashboard query instant.

#### Function: `log_attack(ip_address, method, url, headers, payload, attack_type, user_agent, file_uploaded, response_code)`
- **Security Logic:** It uses parameterized queries (`?` placeholders). This is ironic but essential: the honeypot itself must not be vulnerable to SQL injection from the attacker's payload!

---

### 2.4 utils.py - The Request Parser
Converts the complex `flask.request` object into a simple Python dictionary.

#### Handling Payloads:
- **GET:** Pulls data from `request.args`.
- **POST (Form):** Pulls from `request.form`.
- **JSON:** Checks if the content type is JSON and pulls from `request.get_json()`.
- **Raw:** As a fallback, it reads `request.data`.
- **Normalization:** It joins all these into one string so the regex engine doesn't have to look in four different places.

---

### 2.5 dashboard.py - Analytics and Reporting
This defines the administrative routes.

#### Endpoint: `/dashboard/api/stats`
- **Logic:** Runs `count(*)` groupings in SQL.
- **Benefit:** Instead of sending 1000 rows of data to the browser, it sends just 5 numbers (e.g., "attacks: 450, sql_injection: 12"). This keeps the dashboard extremely fast even on slow connections.

---

## 3. LINE-BY-LINE ANALYSIS OF DETECTOR LOGIC

When a payload arrives, it is processed character by character:

1. **Unquoting:** `payload = unquote(payload)`. If an attacker sent `SELECT%20*`, this turns it back into `SELECT *`.
2. **Sequential Check:**
    - Is it `SQL_REGEX`? If yes, STOP and return "SQL Injection".
    - Is it `XSS_REGEX`? If yes, STOP and return "XSS".
    - ...and so on.
3. **The "Water Fall" Priority:** We check SQLi first because it's usually more dangerous than XSS. If a payload has both, we want to flag the most severe one.

---

## 4. DETAILED ENDPOINT EXPLANATIONS (routes.py)

### 4.1 The Login "Trap" (`/login`)
- **Attacker View:** Sees a standard username/password form.
- **Honeypot Logic:** Accepts any username and password, but *always* returns an "Invalid Credentials" error after a short delay. This keeps the attacker trying different passwords, which allows us to log their wordlists.

### 4.2 The File Search Trap (`/search`)
- **Attacker View:** A search box.
- **Honeypot Logic:** It reflects the search term back to the user. This "smells" like a Reflected XSS vulnerability to an attacker, encouraging them to try injecting `<script>` tags.

### 4.3 The Hidden Admin Trap (`/admin`)
- **Attacker View:** A "Forbidden" error or a login page.
- **Honeypot Logic:** Bots often scan for `/admin`. Simply by existing, this route creates a high-priority alert because no normal guest user should ever find this URL.

---

## 5. DATABASE TABLE STRUCTURE (Deep Dive)

| Column | Type | Description |
|---|---|---|
| id | INTEGER | Primary Key (Auto-increment) |
| timestamp | TEXT | Saved in ISO 8601 format for easy sorting |
| ip_address | TEXT | The attacker's source IP |
| method | TEXT | GET, POST, or HEAD |
| url | TEXT | The full path targeted |
| headers | TEXT | A serialized JSON string of all browser headers |
| payload | TEXT | The actual malicious code found |
| attack_type | TEXT | Our classification (e.g., "LFI") |
| user_agent | TEXT | Identifies the attacker's tool (e.g., "sqlmap" or "Firefox") |

---

## 6. LOGGING PHILOSOPHY (logger.py)

The system uses **Dual-Stream Logging**:

1. **The DB Stream:** Optimized for the Dashboard. It is structured and easily indexed.
2. **The File Stream:** Optimized for Forensic Integrity. A text file is harder to "delete" selectively than a database row. If an attacker manages to find the dashboard and delete logs, the `honeypot.log` on the disk remains as a permanent audit trail.

---

## 7. WHY REGEX OVER MACHINE LEARNING (In this phase)?
At this 60-65% stage, we chose Regex because:
- **Instant Result:** Regex doesn't need "training" data.
- **Low CPU:** It's incredibly fast (microseconds).
- **Explainability:** If a request is flagged as an attack, we can point exactly to the word that caused it. ML is often a "black box" that is hard to explain to a project guide.

---

## 8. CODE SECURITY MECHANISMS

- **Sanitized Filenames:** `secure_filename(f.filename)` ensures that an attacker cannot upload a file named `shell.php` to a location like `/var/www/`.
- **Timed Delays:** On login routes, a small `time.sleep(0.5)` is used to simulate a real server processing a request. This makes the honeypot feel "heavy" and real.
- **404 Catch-All:** Every unknown path is routed through the logger. This is the "net" that catches the "fish."

---

## 9. CONCLUSION
The code is a symphony of separate modules working together. `utils` collects the data, `detector` judges it, `logger/database` remember it, and `dashboard` shows it. Each component is written to be understandable, lightweight, and extremely fast.

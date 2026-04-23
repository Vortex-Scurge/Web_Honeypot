# 1. Title of the Project
**Institution Name:** [Your Institution Name]  
**Full Project Title:** Web Honeypot and Threat Detection System  
**Course Code & Course Name:** [Course Code] - [Course Name]  
**Team Members:** [Team Member Names]  
**Guide Details:** [Guide Name & Designation]  

---

# 2. Abstract
The increasing frequency and sophistication of web-based attacks require proactive security measures beyond traditional perimeter firewalls. In the modern cybersecurity landscape, reactive measures are no longer sufficient to secure business-critical web applications. This project presents a low-interaction web honeypot designed to simulate vulnerable web services and silently capture malicious activity. By employing a robust signature-based detection engine and intercepting requests at the middleware level, the system successfully classifies various attack vectors, including SQL Injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI), and Command Injection. At this mid-review milestone—where the project is approximately 60-65% complete—the core interception, classification, and dual-logging infrastructure are fully operational. The expected outcome is a functional threat intelligence tool that provides structural attack logs and real-time visualization through an interactive administrative dashboard, thereby enabling security analysts to study attacker behavior and reinforce network defenses proactively.

---

# 3. Introduction
Web applications are consistently the most targeted surface on the internet, exposing organizations to unprecedented risks of data breaches, ransomware infections, and service disruptions. As attackers continuously evolve their techniques and automate their exploitation pipelines through sophisticated botnets, relying solely on reactive security measures is inherently flawed. Organizations typically deploy firewalls and Intrusion Prevention Systems (IPS) that blindly block traffic without understanding the nuanced intent behind complex payloads.

Honeypots act as decoy systems, deliberately configured with simulated vulnerabilities to attract attackers away from genuine computational assets. They serve a dual purpose: they waste the time and resources of attackers while simultaneously gathering invaluable intelligence regarding new attack methodologies, zero-day behaviors, and automated scanning campaigns. This project focuses on building an easily deployable, low-resource web honeypot designed specifically to record HTTP interactions. It provides early warning signals and gathers critical threat intelligence, ultimately aiding in the understanding of contemporary attacker methodologies. This report encapsulates the current scope of the project, highlighting the operational modules built so far while delineating the future scope of tasks required to bring the system to full maturity.

---

# 4. Literature Review
The design and implementation of modern deception technology build upon several foundational cybersecurity concepts. An analysis of existing works reveals both strengths and significant limitations in traditional approaches:

- **Traditional Firewalls & Stateless Packet Inspection:** While foundational for perimeter defense, standard firewalls often lack the application-layer understanding needed to detect complex payloads like command injections or application-specific logic flaws. They operate at OSI Layers 3 and 4, meaning they cannot parse the nuanced, often obfuscated HTTP payloads that characterize modern web application attacks.
- **Intrusion Detection/Prevention Systems (IDS/IPS):** Systems like Snort or Suricata actively monitor network traffic and apply signature-based rules. However, they are inherently designed to block or alert and move on. They do not provide a "sandbox" for observing extended attacker engagement. Furthermore, they require extensive configuration and can generate substantial false positives in production environments.
- **High-Interaction Honeypots:** These are solutions that run full, real operating systems and legitimately vulnerable software. While they capture extensive, profound behavioral details (such as post-exploitation lateral movement), they carry enormous risks. If compromised, an unprotected high-interaction honeypot can be utilized by attackers to pivot into the internal network, acting as a beachhead for further attacks. They also require heavy virtualization overhead and meticulous sandboxing.
- **Low-Interaction Web Decoys (e.g., Glastopf or Dionaea):** Existing low-interaction web honeypots simulate various vulnerabilities. However, they often suffer from complex, archaic deployment requirements (e.g., outdated dependency chains) and lack integrated, modern, user-friendly analytics. Furthermore, many legacy low-interaction honeypots struggle to provide seamless extensibility for entirely new families of attack payloads without rewriting core engine logic.

**Limitations of existing methods:** In summary, many existing solutions are either too complex and risky to maintain (high-interaction platforms) or lack precise, granular classification capabilities paired with out-of-the-box analytical dashboards (low-interaction platforms). A localized, highly observable framework specifically tailored to common web payloads is required.

---

# 5. Research Gap
Current open-source honeypot solutions frequently lack a lightweight, highly modular architecture that simultaneously provides granular attack categorization (distinguishing between closely related specific vectors like Local File Inclusion versus Path Traversal) and integrated data visualizations. There is a palpable need for a readily deployable system that effectively marries expansive threat payload datasets—such as the OWASP Core Rule Set and community-driven repositories like PayloadsAllTheThings—with a low-overhead, low-risk simulation environment. Most existing lightweight tools simply log raw HTTP traffic without offering real-time, dashboard-driven classification, leaving the burden of log parsing entirely to external SIEMs (Security Information and Event Management systems). Our system aims to bridge this gap by offering a fully integrated, standalone suite.

---

# 6. Problem Statement & Objectives
**Problem Definition:** There is a crucial need for a lightweight, secure, and easily observable decoy system capable of detecting, classifying, and analyzing malicious web traffic in real-time. This system must inherently prevent exposing the host network to risk while providing immediate, actionable intelligence through an integrated visual dashboard.

**Core Objectives:**
1. Develop a localized, low-interaction web honeypot utilizing modern Python frameworks that simulates a wide array of common web application vulnerabilities.
2. Implement a highly prioritized, regex-based detection engine capable of accurately classifying over 10 different web attack vectors (including but not limited to SQLi, XSS, Command Injection, and Directory Traversal).
3. Create an administrative dashboard equipped with integrated REST APIs to visualize attack analytics, geographical data trends, and temporal matrices.
4. Integrate advanced open-source threat intelligence datasets to drastically enhance the system's baseline detection capabilities.
5. Provide a robust dual-logging mechanism (both flat-file and relational SQLite database) to guarantee data integrity for thorough forensic analysis.

---

# 7. Proposed System & Current Scope Available
The proposed system is a robust, Flask-based low-interaction honeypot characterized by its middleware interception methodology. Recognizing that the project is at a **Mid-Review (60-65% completion)** stage, it is important to clearly distinguish what is currently available versus what is slated for future development.

## 7.1. Currently Available Scope (Completed Modules)
At present, the foundational architecture of the honeypot is fully operational. The following modules are built, integrated, and actively intercepting traffic:
- **Interceptor Middleware (`app.py` & `utils.py`):** Acts as the primary gateway, safely capturing client IP addresses, User-Agent strings, complete HTTP headers, routing methods, and both raw and form-encoded payloads before any actual routing logic evaluates the request.
- **Threat Detection Engine (`detector.py`):** An optimized analytical module that compares URL-decoded payloads against pre-compiled regular expression patterns. It features a strict priority hierarchy to ensure high-risk payloads (like SQLi or Command Injection) are classified correctly even if they contain secondary, lower-risk elements (like generic XSS tags).
- **Dual Logging System (`logger.py` & `database.py`):** A redundant storage framework implementing logging to both an SQLite database (`database.db`) for structural querying, and a flat text file (`honeypot.log`) for rapid, unstructured tailing.
- **Safe File Capture Module (`file_capture.py`):** A quarantine system that securely accepts malicious file uploads, sanitizes the filenames to prevent path traversal during the save operation, prefixes them with unique timestamps, and stores them in an isolated directory without execution privileges.
- **Analytics Dashboard (`dashboard.py`):** A secure, blueprint-based administrative interface offering RESTful visualization APIs that connect directly to frontend Chart.js components, supplying real-time metric generation and CSV log exports.

**System Architecture Overview:**
`Attacker Request` $\rightarrow$ `Flask Server` $\rightarrow$ `Extraction Middleware` $\rightarrow$ `Regex Detection Engine` $\rightarrow$ `Dual Logger (SQL & Text)` $\rightarrow$ `Admin Dashboard / Simulated Response`.

---

# 8. Methodology / Algorithm
The operational methodology of the honeypot hinges on the concept of silent interception and immediate engagement. Instead of rejecting malicious traffic, the system embraces it to study the payload.

**Flow of Attacker Logging:**
1. **Trigger:** The attacker probes an exposed endpoint (e.g., trying to access `/phpmyadmin` or submitting `/?id=1' OR 1=1` in a simulated vulnerable URL).
2. **Capture:** The HTTP request is silently intercepted by the Flask `@app.before_request` middleware before standard endpoint routing occurs.
3. **Extraction & Normalization:** Essential metadata (Client IP, Headers, User Agent) is extracted. Crucially, the payload is URL-decoded using Python's `urllib.parse.unquote` to expose obfuscated strings (e.g., converting `%27%20OR%201%3D1` back to `' OR 1=1`).
4. **Classification Analysis:** The detection engine evaluates the decoded string against compiled regular expressions. It evaluates them in strict priority order (SQL Injection $\rightarrow$ Cross-Site Scripting $\rightarrow$ Command Injection $\rightarrow$ Local File Inclusion $\rightarrow$ Directory Traversal $\rightarrow$ Bot Scan $\rightarrow$ Brute Force) to ensure the most critical underlying exploit intent is labeled.
5. **State Tracking (Brute Force):** For brute-force detection, rapid successive requests from identical IP addresses are aggregated conceptually in memory. If a numerical threshold is breached within a rolling time window, the traffic is reclassified as an active brute force attack.
6. **Redundant Storage:** 
   - *File System (`honeypot.log`):* Records a sequential, human-readable stream for real-time monitoring (e.g., using `tail -f`).
   - *Database (`database.db`):* Stores a comprehensive structured SQL record (including full headers and complex payloads) to facilitate precise administrative querying and historic temporal analysis.
7. **Simulated Response Presentation:** The server finally returns a simulated interface, a generic HTTP 200 OK, or a standard 404 response to keep the attacker engaged without actually executing any backend logic on the host.

**Techniques Used:** Software Engineering principles (WSGI, Flask Blueprint routing), extensive Regular Expression design for accurate signature matching, Relational Database Indexing to handle rapid ingest, and frontend asynchronous Data Visualization powered by Chart.js.

---

# 9. Implementation & Work Done
To achieve the current 60-65% completion milestone, the implementation heavily leveraged lightweight, standard-library-focused Python frameworks to reduce logistical overhead.

**Tools & Technologies Deployed:**
- **Backend Infrastructure:** Python 3 standard library, Flask (Microframework), Werkzeug (WSGI web application library).
- **Data Storage:** SQLite3 (Serverless Relational Database), built-in Python `logging` module.
- **Frontend / Visualization:** HTML5, Vanilla CSS for responsive design, Chart.js for data representations via CDN.
- **Threat Intelligence Sourcing:** Integration scripts designed to parse and ingest OWASP Core Rule Set patterns alongside targeted subsets of the PayloadsAllTheThings GitHub repository.

**Work Accomplished to Date:**
The primary developmental phase focused heavily on creating the "trap." We successfully engineered the core proxy capture middleware alongside the extensive attack classification engine, which can currently identify over 10 distinct exploit attempts. We established the foundational database schemas, ensuring indexing was in place for high-speed read/write operations critical for the dual logging redundancy. Furthermore, the administrative dashboard user interface has been fully fleshed out to interpret the raw database rows into digestible, graphical analytics. The framework for dataset ingestion tools has also been finalized.

---

# 10. Results & Analysis
Despite being at the mid-review phase, the system already yields highly promising operational metrics.

**Current Experimental Results:**
The system effectively intercepts all incoming traffic regardless of whether the accessed route explicitly exists or results in a 404 error, thus gracefully handling massive automated bot scans testing for hidden directories. Automated simulation bash scripts (`test_attacks.sh`) were executed against the honeypot locally, successfully triggering the appropriate classifications in real-time. 

**Performance and Environmental Observations:**
- Attack patterns are classified within single-digit milliseconds due to the pre-compilation (`re.compile`) of regular expressions upon application startup, ensuring that the classification engine does not bottleneck under heavy request volume.
- The dual-logging mechanism operates efficiently and asynchronously relative to the network stream without dropping requests, even during simulated DoS tests.
- The dashboard successfully visualizes both spatial and temporal threat trends dynamically. Current preliminary data indicates that Automated Bot Scanning for administrative interfaces and blind SQL Injections represent the highest volume of simulated attacker traffic.

---

# 11. Timeline / Progress Status
**Project Phase Status:**
This technical report signifies a **Mid-Review** evaluation. The overarching project is currently positioned precisely at the **60-65% completion mark**. The foundational infrastructure, data capture logic, signature matching engine, and analytical visualization layers are fully operational. However, the system's defensive integration mechanics, active threat response capabilities, and broader dataset mapping elements remain in active development.

**Work Completed vs Pending Focus Areas:**
- *Fully Completed Phase 1 & 2 Elements:* Core proxy capture mechanisms, robust attack classification engine, database schemas and table indexing architectures, logging system redundancy, and the entire administrative dashboard user interface.
- *Pending Phase 3 Elements (Active Development):* Complete integration of massively expanded threat intelligence datasets (e.g., full, automated OWASP CRS mapping synchronizations), robust real-world distributed public testing to gather actual black-hat data, and the implementation of active OS-level defensive mechanisms.

---

# 12. Conclusion
**Summary of Mid-Review Progress:**
At this midway milestone (approximately 60-65% complete), we have successfully engineered the core, functional structure of a low-interaction web honeypot. This system already provides critical, real-time visibility into the methodologies of malicious web traffic. By utilizing a highly modular Python/Flask architecture, the honeypot is presently capable of accurately capturing inbound payloads, securely classifying and segregating malicious requests via complex regex pattern matching, securely logging all parameters redundantly, and visualizing a diverse array of web vulnerabilities via an intuitive administrative dashboard—all without compromising the underlying host environment.

---

# 13. Future Scope
As the project transitions into its final development and deployment phases, the scope will expand outward from passive observation toward proactive containment and deeper intelligence gathering.

**Target Deliverables for Project Completion (The remaining 35-40%):**
- **Enhanced Log Mapping and Attack Reconstruction:** We will refine the internal flow of attacker logging to not just classify isolated payloads, but to reconstruct multi-step, sequential attack campaigns. This will involve sessionizing IP behavior over extended timelines to correlate seemingly disconnected exploits across multiple simulated endpoints.
- **GeoIP Lookup Integration:** A critical component for visual threat intelligence is geographical attribution. The system will be upgraded to map attacker IP addresses to physical geographic locations utilizing the MaxMind GeoLite2 offline databases. This will enable the dashboard to render real-time attack origin heatmaps.
- **Active IP Blocking & Threat Mitigation:** Transitioning the honeypot from a purely passive decoy into an active defensive trigger. We plan to integrate the honeypot with host OS firewalls (creating localized integration scripts for utilities such as `iptables` or `fail2ban`). This will allow the system to automatically, dynamically ban source IP addresses that exceed calculated threat severity thresholds, effectively protecting the real production network residing behind the firewall.
- **Critical Notification Services:** Implementation of real-time administrative alerting mechanisms via SMTP Email or Webhooks (e.g., Slack, Discord integrations) specifically triggered by the detection of high-severity, critical-vector attacks (such as Reverse Shell deployments or mass Command Injection campaigns).
- **Public Sandbox Deployment:** Deploying the finalized architecture in a segmented, public-facing cloud instance (such as an AWS EC2 or DigitalOcean Droplet) to gather empirical data from live Internet background noise and automated threat actors, verifying the scalability of the logging schemas under sustained duress.

---

# 14. References
[1] "OWASP Top Ten Web Application Security Risks," *OWASP Foundation*, [Online]. Available: https://owasp.org/www-project-top-ten/  
[2] "Flask Web Development Documentation," *Pallets Projects*, [Online]. Available: https://flask.palletsprojects.com/  
[3] "PayloadsAllTheThings: A list of useful payloads and bypass for Web Application Security," *GitHub Repository*, [Online]. Available: https://github.com/swisskyrepo/PayloadsAllTheThings  
[4] L. Spitzner, "Honeypots: Tracking Hackers," *Addison-Wesley Professional*, 2002.  
[5] N. Provos and T. Holz, "Virtual Honeypots: From Botnet Tracking to Intrusion Detection," *Addison-Wesley Professional*, 2007.  
[6] "SQLite Official Documentation," *SQLite Consortium*, [Online]. Available: https://www.sqlite.org/docs.html
[7] N. Provos, "A Virtual Honeypot Framework," *USENIX Security Symposium*, 2004, pp. 1-14.
[8] M. Nawrocki et al., "A Survey on Honeypot Software and Data Analysis," *arXiv preprint*, arXiv:1908.11464, 2019.

#!/usr/bin/env python3
"""
dataset_generator.py — Extract attack patterns from OWASP CRS and PayloadsAllTheThings

This script reads .conf files from coreruleset/rules/ and payload files
from PayloadsAllTheThings/, extracts patterns/payloads, cleans, merges,
and outputs standard JSON datasets for the honeypot detection engine.
"""

import os
import re
import json
import logging
from pathlib import Path
from dataset_cleaner import merge_and_clean_datasets

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

PROJECT_ROOT = Path('/home/noxir/antigravity')
CRS_RULES_DIR = PROJECT_ROOT / 'coreruleset' / 'rules'
PATT_DIR = PROJECT_ROOT / 'PayloadsAllTheThings'
DATASETS_DIR = PROJECT_ROOT / 'web-honeypot' / 'datasets'

# File to Attack Type mapping
CRS_MAPPINGS = {
    'REQUEST-941-APPLICATION-ATTACK-XSS': ('XSS', 'High'),
    'REQUEST-942-APPLICATION-ATTACK-SQLI': ('SQL Injection', 'High'),
    'REQUEST-930-APPLICATION-ATTACK-LFI': ('LFI', 'High'),
    'REQUEST-931-APPLICATION-ATTACK-RFI': ('RFI', 'High'),
    'REQUEST-932-APPLICATION-ATTACK-RCE': ('Command Injection', 'Critical'),
    'REQUEST-933-APPLICATION-ATTACK-PHP': ('PHP Injection', 'High'),
    'REQUEST-920-PROTOCOL-ENFORCEMENT': ('Protocol Attack', 'Low'),
    'REQUEST-921-PROTOCOL-ATTACK': ('Protocol Attack', 'Medium'),
    'REQUEST-913-SCANNER-DETECTION': ('Bot Scan', 'Medium'),
    'REQUEST-934-APPLICATION-ATTACK-GENERIC': ('Generic Attack', 'Medium'),
    'REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION': ('Session Attack', 'Medium'),
    'REQUEST-944-APPLICATION-ATTACK-JAVA': ('Java Attack', 'High'),
}

PATT_MAPPINGS = {
    'SQL Injection': ('SQL Injection', 'High'),
    'XSS Injection': ('XSS', 'High'),
    'File Inclusion': ('LFI', 'High'),
    'Command Injection': ('Command Injection', 'Critical'),
    'Directory Traversal': ('Directory Traversal', 'High'),
    'Upload Insecure Files': ('File Upload Attack', 'High'),
    'Server Side Request Forgery': ('SSRF', 'High'),
    'Server Side Template Injection': ('SSTI', 'Critical'),
    'XXE Injection': ('XXE', 'High'),
    'Insecure Deserialization': ('Deserialization', 'Critical'),
    'JSON Web Token': ('JWT Attack', 'High'),
    'OAuth Misconfiguration': ('Auth Bypass', 'High'),
    'Open Redirect': ('Open Redirect', 'Medium'),
    'API Key Leaks': ('API Enum', 'Medium'),
    'CRLF Injection': ('Header Injection', 'Medium'),
    'Insecure Management Interface': ('Admin Access', 'Medium'),
    'Insecure Source Code Management': ('Sensitive File', 'Medium'),
}

OUTPUT_FILES = {
    'SQL Injection': 'sql_injection.json',
    'XSS': 'xss.json',
    'LFI': 'lfi.json',
    'RFI': 'rfi.json',
    'Command Injection': 'command_injection.json',
    'Directory Traversal': 'directory_traversal.json',
    'File Upload Attack': 'file_upload.json',
    'SSRF': 'ssrf.json',
    'SSTI': 'ssti.json',
    'XXE': 'xxe.json',
    'Deserialization': 'deserialization.json',
    'JWT Attack': 'jwt_attack.json',
    'Auth Bypass': 'auth_bypass.json',
    'Open Redirect': 'open_redirect.json',
    'API Enum': 'api_enum.json',
    'Bot Scan': 'bot_scan.json',
    'Sensitive File': 'sensitive_file.json',
    'Admin Access': 'admin_access.json',
    'Header Injection': 'header_injection.json',
    'Cookie Injection': 'cookie_injection.json',
    'Path Encoding': 'path_encoding.json',
    'Reconnaissance': 'reconnaissance.json',
    'Protocol Attack': 'protocol_attack.json',
    'Generic Attack': 'generic_attack.json',
    'Session Attack': 'session_attack.json',
    'Java Attack': 'java_attack.json',
    'PHP Injection': 'php_injection.json',
}

def extract_crs_patterns(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        content_resolved = re.sub(r'(?m)^\s*#.*$', '', content).replace('\\\n', '')
        patterns = []
        matches = re.finditer(r'"@(rx|pmRegex)\s+(.*?)"', content_resolved)
        for match in matches:
            patterns.append(match.group(2))
        return patterns
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def extract_patt_payloads(dir_path):
    payloads = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.txt') or file.endswith('.md'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                payloads.append(line)
                except Exception as e:
                    pass
    return payloads

def main():
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Structure: {"Attack Type": {"severity": "High", "crs_patterns": [], "patt_payloads": []}}
    raw_data = {}
    
    # Initialize all requested categories
    for attack_type, filename in OUTPUT_FILES.items():
        raw_data[attack_type] = {
            "attack_type": attack_type,
            "severity": "Medium",
            "crs_patterns": [],
            "patt_payloads": []
        }

    # 1. Parse OWASP CRS
    if CRS_RULES_DIR.exists():
        for file_path in CRS_RULES_DIR.glob('*.conf'):
            filename = file_path.stem
            for key, (a_type, sev) in CRS_MAPPINGS.items():
                if key in filename:
                    patterns = extract_crs_patterns(file_path)
                    raw_data[a_type]["crs_patterns"].extend(patterns)
                    raw_data[a_type]["severity"] = sev
                    break

    # 2. Parse PayloadsAllTheThings
    if PATT_DIR.exists():
        for key, (a_type, sev) in PATT_MAPPINGS.items():
            dir_path = PATT_DIR / key
            if dir_path.exists():
                payloads = extract_patt_payloads(dir_path)
                raw_data[a_type]["patt_payloads"].extend(payloads)
                # Upgrade severity if PATT mapping is higher/exists
                raw_data[a_type]["severity"] = sev

    # 3. Clean, Merge, and Save
    for a_type, data in raw_data.items():
        # Merge applying cleaner
        merged_patterns = merge_and_clean_datasets(
            data["crs_patterns"],
            data["patt_payloads"],
            max_limit=2000 # Allow larger size for these big datasets
        )
        
        # If we have no patterns for a category, we still create the JSON with empty patterns
        # so the detector has all categories ready. 
        dataset_content = {
            "attack_type": a_type,
            "severity": data["severity"],
            "patterns": merged_patterns
        }
        
        out_filename = OUTPUT_FILES.get(a_type)
        out_path = DATASETS_DIR / out_filename
        
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(dataset_content, f, indent=4)
            logging.info(f"Saved {len(merged_patterns)} patterns for {a_type}")
        except Exception as e:
            logging.error(f"Error saving {out_filename}: {e}")

    logging.info("Multi-dataset generation complete.")

if __name__ == '__main__':
    main()

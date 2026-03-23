"""
database.py — SQLite database operations for the honeypot.
Handles schema creation, attack logging, and analytics queries.
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')


def get_connection():
    """Get a database connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the attacks table if it doesn't exist."""
    conn = get_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            headers TEXT,
            payload TEXT,
            attack_type TEXT NOT NULL,
            user_agent TEXT,
            file_uploaded TEXT,
            response_code INTEGER DEFAULT 200
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_ip ON attacks(ip_address)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON attacks(attack_type)')
    conn.commit()
    conn.close()


def log_attack(data):
    """Insert an attack record into the database."""
    conn = get_connection()
    conn.execute('''
        INSERT INTO attacks (timestamp, ip_address, method, url, headers,
                             payload, attack_type, user_agent, file_uploaded, response_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('timestamp', datetime.now().isoformat()),
        data.get('ip_address', 'unknown'),
        data.get('method', 'GET'),
        data.get('url', '/'),
        json.dumps(data.get('headers', {})),
        data.get('payload', ''),
        data.get('attack_type', 'Unknown'),
        data.get('user_agent', ''),
        data.get('file_uploaded', ''),
        data.get('response_code', 200),
    ))
    conn.commit()
    conn.close()


def get_attacks(ip=None, attack_type=None, limit=200, offset=0):
    """Query attacks with optional filters."""
    conn = get_connection()
    query = 'SELECT * FROM attacks WHERE 1=1'
    params = []

    if ip:
        query += ' AND ip_address = ?'
        params.append(ip)
    if attack_type:
        query += ' AND attack_type = ?'
        params.append(attack_type)

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_attacks():
    """Return every attack record (for CSV export)."""
    conn = get_connection()
    rows = conn.execute('SELECT * FROM attacks ORDER BY id DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    """Aggregate statistics for the dashboard."""
    conn = get_connection()

    total = conn.execute('SELECT COUNT(*) as c FROM attacks').fetchone()['c']
    unique_ips = conn.execute('SELECT COUNT(DISTINCT ip_address) as c FROM attacks').fetchone()['c']

    today = datetime.now().strftime('%Y-%m-%d')
    today_count = conn.execute(
        "SELECT COUNT(*) as c FROM attacks WHERE timestamp LIKE ?", (f'{today}%',)
    ).fetchone()['c']

    # Attack types distribution
    type_rows = conn.execute(
        'SELECT attack_type, COUNT(*) as c FROM attacks GROUP BY attack_type ORDER BY c DESC'
    ).fetchall()
    attack_types = {r['attack_type']: r['c'] for r in type_rows}

    # Top attacker IPs
    ip_rows = conn.execute(
        'SELECT ip_address, COUNT(*) as c FROM attacks GROUP BY ip_address ORDER BY c DESC LIMIT 10'
    ).fetchall()
    top_ips = {r['ip_address']: r['c'] for r in ip_rows}

    # Most attacked endpoints
    endpoint_rows = conn.execute(
        'SELECT url, COUNT(*) as c FROM attacks GROUP BY url ORDER BY c DESC LIMIT 10'
    ).fetchall()
    top_endpoints = {r['url']: r['c'] for r in endpoint_rows}

    # Attacks per day (last 30 days)
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    daily_rows = conn.execute(
        "SELECT DATE(timestamp) as day, COUNT(*) as c FROM attacks "
        "WHERE timestamp >= ? GROUP BY day ORDER BY day",
        (thirty_days_ago,)
    ).fetchall()
    daily = {r['day']: r['c'] for r in daily_rows}

    # Most common attack type
    most_common = type_rows[0]['attack_type'] if type_rows else 'None'

    conn.close()
    return {
        'total_attacks': total,
        'unique_ips': unique_ips,
        'today_attacks': today_count,
        'most_common_type': most_common,
        'attack_types': attack_types,
        'top_ips': top_ips,
        'top_endpoints': top_endpoints,
        'daily_attacks': daily,
    }

"""
logger.py — Dual logging system.
Writes attack details to both a log file and the SQLite database.
"""

import logging
import os
from datetime import datetime
from database import log_attack as db_log

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Configure file logger
file_logger = logging.getLogger('honeypot')
file_logger.setLevel(logging.INFO)

handler = logging.FileHandler(os.path.join(LOG_DIR, 'honeypot.log'))
handler.setFormatter(logging.Formatter(
    '%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
))
file_logger.addHandler(handler)


def log_request(request_data, attack_type, response_code=200):
    """
    Log a request to both the log file and the database.

    Args:
        request_data: dict from utils.extract_request_data()
        attack_type: string classification from detector
        response_code: HTTP response code returned
    """
    record = {
        'timestamp': datetime.now().isoformat(),
        'ip_address': request_data.get('ip_address', 'unknown'),
        'method': request_data.get('method', 'GET'),
        'url': request_data.get('url', '/'),
        'headers': request_data.get('headers', {}),
        'payload': request_data.get('payload', ''),
        'attack_type': attack_type,
        'user_agent': request_data.get('user_agent', ''),
        'file_uploaded': request_data.get('file_uploaded', ''),
        'response_code': response_code,
    }

    # Write to log file
    file_logger.info(
        f"[{attack_type}] {record['method']} {record['url']} | "
        f"IP: {record['ip_address']} | "
        f"Payload: {record['payload'][:200]} | "
        f"UA: {record['user_agent'][:100]}"
    )

    # Write to database
    db_log(record)

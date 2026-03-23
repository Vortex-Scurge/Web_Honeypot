"""
file_capture.py — Capture and quarantine uploaded files.
Saves attacker-uploaded files with a timestamp prefix for forensic analysis.
"""

import os
from datetime import datetime
from werkzeug.utils import secure_filename

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


def capture_upload(file_obj):
    """
    Save an uploaded file to the uploads directory.

    Args:
        file_obj: werkzeug FileStorage object

    Returns:
        The saved filename, or empty string if no file.
    """
    if not file_obj or not file_obj.filename:
        return ''

    original = secure_filename(file_obj.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = f"{timestamp}_{original}"

    path = os.path.join(UPLOAD_DIR, safe_name)
    file_obj.save(path)
    return safe_name

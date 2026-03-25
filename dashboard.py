"""
dashboard.py — Admin dashboard blueprint.
Provides analytics page, stats API, log API, and CSV export.
"""

import csv
import io
from flask import Blueprint, render_template, request, jsonify, Response
from database import get_stats, get_attacks, get_all_attacks

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')


@dashboard_bp.route('/')
def dashboard():
    """Render the main analytics dashboard."""
    stats = get_stats()
    return render_template('dashboard.html', stats=stats)


@dashboard_bp.route('/api/stats')
def api_stats():
    """Return aggregated stats as JSON for Chart.js."""
    return jsonify(get_stats())


@dashboard_bp.route('/api/logs')
def api_logs():
    """Return paginated logs with optional filters."""
    ip = request.args.get('ip', None)
    attack_type = request.args.get('type', None)
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))

    attacks = get_attacks(ip=ip, attack_type=attack_type, limit=limit, offset=offset)
    return jsonify({'logs': attacks, 'count': len(attacks)})


@dashboard_bp.route('/api/unknown')
def api_unknown():
    """Return paginated unknown payloads."""
    from database import get_unknown_payloads
    limit = min(int(request.args.get('limit', 50)), 100)
    offset = int(request.args.get('offset', 0))

    payloads = get_unknown_payloads(limit=limit, offset=offset)
    return jsonify({'payloads': payloads, 'count': len(payloads)})

@dashboard_bp.route('/api/classify', methods=['POST'])
def api_classify():
    """Classify an unknown payload, update dataset, and reload detection."""
    from database import get_connection
    import json
    from pathlib import Path
    
    data = request.json
    payload_id = data.get('id')
    attack_type = data.get('attack_type')
    pattern = data.get('pattern')
    
    if not all([payload_id, attack_type, pattern]):
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400
        
    # Mark as classified in DB
    conn = get_connection()
    conn.execute("UPDATE unknown_payloads SET classified = 'Yes' WHERE id = ?", (payload_id,))
    conn.commit()
    conn.close()
    
    # Mapping output JSON file names
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

    out_filename = OUTPUT_FILES.get(attack_type, f"{attack_type.lower().replace(' ', '_')}.json")
    dataset_file = Path('/home/noxir/antigravity/web-honeypot/datasets') / out_filename
    
    dataset = {"attack_type": attack_type, "severity": "High", "patterns": []}
    if dataset_file.exists():
        with open(dataset_file, 'r') as f:
            dataset = json.load(f)
            
    if pattern not in dataset['patterns']:
        dataset['patterns'].append(pattern)
        with open(dataset_file, 'w') as f:
            json.dump(dataset, f, indent=4)
            
    # Reload engine
    from detector import reload_datasets
    reload_datasets()
    
    return jsonify({'status': 'success', 'message': 'Dataset updated and engine reloaded.'})


@dashboard_bp.route('/download')
def download_csv():
    """Export all attack logs as a CSV file."""
    attacks = get_all_attacks()

    output = io.StringIO()
    if attacks:
        writer = csv.DictWriter(output, fieldnames=attacks[0].keys())
        writer.writeheader()
        writer.writerows(attacks)
    else:
        output.write('No data')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=honeypot_logs.csv'}
    )

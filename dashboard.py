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

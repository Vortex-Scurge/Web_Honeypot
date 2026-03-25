"""
app.py — Main Flask application.
Registers blueprints, runs detection middleware on every request,
and handles 404 catch-all for bot-scan detection.
"""

from flask import Flask, request as flask_request, render_template
from database import init_db
from detector import detect_attack
from logger import log_request
from utils import extract_request_data
from routes import honeypot
from dashboard import dashboard_bp

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
app.config['SECRET_KEY'] = 'honeypot-secret-key-do-not-use-in-production'

# Register blueprints
app.register_blueprint(honeypot)
app.register_blueprint(dashboard_bp)


# ── Middleware: detect & log every request ───────────────────────────────────

@app.before_request
def analyze_request():
    """Extract, classify, and log every incoming request."""
    # Skip static files and dashboard API to avoid noise
    if flask_request.path.startswith('/static/'):
        return

    data = extract_request_data(flask_request)

    attack_type, severity = detect_attack(
        url=data['url'],
        payload=data['payload'],
        headers=data['headers'],
        filename=data.get('file_uploaded', ''),
        ip=data['ip_address'],
    )
    
    data['severity'] = severity

    if attack_type == 'Unknown':
        from database import log_unknown_payload
        log_unknown_payload(data['ip_address'], data['url'], data['payload'])

    log_request(data, attack_type, severity)


# ── Root page ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve a fake corporate homepage."""
    return render_template('base.html')


# ── 404 catch-all (captures bot scans) ──────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('base.html'), 404


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('\n🍯 Honeypot server starting on http://0.0.0.0:5000')
    print('📊 Dashboard at http://0.0.0.0:5000/dashboard\n')
    app.run(host='0.0.0.0', port=5000, debug=False)

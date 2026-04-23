"""
routes.py — Fake vulnerable honeypot endpoints.
Each route renders a believable page and accepts input for attack logging.
All detection/logging happens in the before_request middleware in app.py.
"""

from flask import Blueprint, render_template, request, jsonify, Response
from file_capture import capture_upload

honeypot = Blueprint('honeypot', __name__)

# ── Honey Credential Injection ───────────────────────────────────────────────

HONEY_API_KEY = "sk_test_honey_123"
HONEY_OAUTH_TOKEN = "oauth_honey_token_xyz"

@honeypot.route('/download-env', methods=['GET'])
def download_env():
    # Return decoy env file
    env_content = f"API_KEY={HONEY_API_KEY}\nOAUTH_TOKEN={HONEY_OAUTH_TOKEN}\n"
    return Response(env_content, mimetype='text/plain'), 200



# ── Login (SQL Injection trap) ───────────────────────────────────────────────

@honeypot.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        message = 'Invalid credentials. Please try again.'
    return render_template('login.html', message=message), 200


# ── Search (XSS trap) ───────────────────────────────────────────────────────

@honeypot.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('q', request.form.get('q', ''))
    results = []
    if query:
        # Return fake results to keep attacker engaged
        results = [
            'Annual Report 2025 - Confidential',
            'Employee Database Backup',
            'Server Configuration Notes',
        ]
    return render_template('search.html', query=query, results=results), 200


# ── File Upload (Upload attack trap) ────────────────────────────────────────

@honeypot.route('/upload', methods=['GET', 'POST'])
def upload():
    message = ''
    if request.method == 'POST':
        f = request.files.get('file')
        if f:
            saved = capture_upload(f)
            message = f'File "{saved}" uploaded successfully.'
        else:
            message = 'No file selected.'
    return render_template('upload.html', message=message), 200


# ── Page (LFI trap) ─────────────────────────────────────────────────────────

@honeypot.route('/page', methods=['GET'])
def page():
    page_id = request.args.get('id', 'home')
    # Return fake content regardless of input
    content = f'<h2>Page: {page_id}</h2><p>This page contains internal company information.</p>'
    return render_template('page.html', content=content, page_id=page_id), 200


# ── Admin Login (Brute-force trap) ──────────────────────────────────────────

@honeypot.route('/admin', methods=['GET', 'POST'])
def admin():
    message = ''
    if request.method == 'POST':
        message = 'Access denied. This incident has been logged.'
    return render_template('admin_login.html', message=message), 200


# ── Config (Sensitive data trap) ─────────────────────────────────────────────

@honeypot.route('/config', methods=['GET'])
def config():
    # Serve a fake config file that looks enticing
    return render_template('config.html'), 200


# ── API Endpoint ─────────────────────────────────────────────────────────────

@honeypot.route('/api/data', methods=['GET', 'POST'])
def api_data():
    return jsonify({
        'status': 'error',
        'message': 'Authentication required',
        'api_version': '2.1.0',
        'endpoints': ['/api/users', '/api/config', '/api/admin'],
    }), 200


# ── Download (Directory Traversal trap) ──────────────────────────────────────

@honeypot.route('/download', methods=['GET'])
def download():
    filename = request.args.get('file', '')
    message = ''
    if filename:
        message = f'Error: File "{filename}" not found or access denied.'
    return render_template('download.html', message=message, filename=filename), 200


# ── Execute (Command Injection trap) ─────────────────────────────────────────

@honeypot.route('/execute', methods=['GET', 'POST'])
def execute():
    output = ''
    cmd = request.args.get('cmd', request.form.get('cmd', ''))
    if cmd:
        # Fake command output
        output = (
            'sh: permission denied\n'
            'Error: Command execution is restricted on this server.\n'
            'Contact administrator for access.'
        )
    return render_template('execute.html', output=output, cmd=cmd), 200


# ── Register (Data harvesting trap) ──────────────────────────────────────────

@honeypot.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        message = 'Registration successful! Your account is pending approval.'
    return render_template('register.html', message=message), 200

"""
utils.py — Helper functions for request parsing and sanitization.
"""

import html


def extract_request_data(request):
    """
    Extract relevant information from a Flask request object.

    Returns a dict with: ip_address, method, url, headers, payload,
    user_agent, file_uploaded.
    """
    # Combine all possible input sources into a payload string
    payload_parts = []

    # Query string
    if request.query_string:
        payload_parts.append(request.query_string.decode('utf-8', errors='replace'))

    # Form data
    if request.form:
        payload_parts.append('&'.join(f'{k}={v}' for k, v in request.form.items()))

    # JSON body
    try:
        json_data = request.get_json(silent=True)
        if json_data:
            payload_parts.append(str(json_data))
    except Exception:
        pass

    # Raw body fallback
    if not payload_parts and request.data:
        payload_parts.append(request.data.decode('utf-8', errors='replace')[:2000])

    # Check for uploaded files
    file_uploaded = ''
    if request.files:
        filenames = [f.filename for f in request.files.values() if f.filename]
        file_uploaded = ', '.join(filenames)

    return {
        'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR',
                                          request.remote_addr or '127.0.0.1'),
        'method': request.method,
        'url': request.full_path.rstrip('?'),
        'headers': dict(request.headers),
        'payload': ' | '.join(payload_parts),
        'user_agent': request.headers.get('User-Agent', ''),
        'file_uploaded': file_uploaded,
    }


def sanitize_for_display(text):
    """HTML-escape text for safe rendering in the dashboard."""
    if not text:
        return ''
    return html.escape(str(text))

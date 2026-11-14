"""Flask app: dashboard + scan API + history + PDF reports.

Adapted from the upstream AI-powered-Phishing-Detector app.py (MIT, (c) 2025 maha-baig).
See ADAPTATIONS.md for the list of changes.
"""
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()  # reads .env (never committed) - holds PHISHTANK_APP_KEY

import db
import detector
import report

BASE_DIR = Path(__file__).resolve().parent
APP = Flask(__name__)
APP.config['MAX_CONTENT_LENGTH'] = 16 * 1024

# CORS is OFF unless origins are listed explicitly (comma separated), e.g. CORS_ORIGINS=https://my-app.onrender.com
_origins = [o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip()]
if _origins:
    CORS(APP, origins=_origins)

LIMITER = Limiter(get_remote_address, app=APP, default_limits=[os.environ.get('RATE_LIMIT_DEFAULT', '120 per hour')],
                  storage_uri='memory://', enabled=os.environ.get('RATE_LIMIT_ENABLED', '1') == '1')
SCAN_LIMIT = os.environ.get('RATE_LIMIT_SCAN', '30 per minute')


@APP.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
    return resp


def _do_scan(raw, use_pt):
    try:
        res = detector.scan(raw, use_phishtank=use_pt)
    except detector.UrlError as e:
        return jsonify({'result': detector.UNABLE, 'error': str(e)}), 400
    except detector.ModelNotAvailable as e:
        return jsonify({'result': detector.UNABLE, 'error': 'Setup problem: ' + str(e)}), 503
    except Exception:
        APP.logger.exception('scan failed')
        return jsonify({'result': detector.UNABLE, 'error': 'Something went wrong while checking this URL.'}), 500
    res['id'], res['scanned_at'] = db.save_scan(res)
    return jsonify(res)


@APP.route('/api/scan', methods=['POST'])
@LIMITER.limit(SCAN_LIMIT)
def api_scan():
    body = request.get_json(silent=True) or {}
    return _do_scan(body.get('url'), bool(body.get('use_phishtank', True)))


@APP.route('/predict', methods=['GET'])
@LIMITER.limit(SCAN_LIMIT)
def predict():
    """Kept from upstream for compatibility: GET /predict?url=... (now returns the full scan result)."""
    return _do_scan(request.args.get('url'), request.args.get('use_phishtank', '1') != '0')


@APP.route('/api/history', methods=['GET'])
def api_history():
    return jsonify(db.list_scans(limit=min(int(request.args.get('limit', 50) or 50), 500)))


@APP.route('/api/history', methods=['DELETE'])
def api_clear_history():
    return jsonify({'deleted': db.clear_scans()})


def _pdf(data, name):
    return Response(data, mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename={name}'})


@APP.route('/api/report/summary.pdf')
def api_report_summary():
    d_from, d_to = request.args.get('from') or None, request.args.get('to') or None
    for d in (d_from, d_to):
        if d and not (len(d) == 10 and d[4] == '-' and d[7] == '-' and d.replace('-', '').isdigit()):
            return jsonify({'error': 'Dates must look like YYYY-MM-DD.'}), 400
    return _pdf(report.summary_pdf(db.list_scans(limit=500, date_from=d_from, date_to=d_to), d_from, d_to),
                'scan-history-summary.pdf')


@APP.route('/api/report/<int:scan_id>.pdf')
def api_report_scan(scan_id):
    s = db.get_scan(scan_id)
    if not s:
        return jsonify({'error': 'Scan not found.'}), 404
    return _pdf(report.scan_pdf(s), f'scan-report-{scan_id}.pdf')


@APP.route('/health', methods=['GET'])
def health():
    try:
        detector.load_model()
        loaded = True
    except detector.ModelNotAvailable:
        loaded = False
    return jsonify({'status': 'ok', 'model_loaded': loaded})


@APP.route('/api/status', methods=['GET'])
def api_status():
    import json
    meta = {}
    p = BASE_DIR / 'models' / 'model_metadata.json'
    if p.exists():
        meta = json.loads(p.read_text())
    return jsonify({'phishtank_configured': bool(os.environ.get('PHISHTANK_APP_KEY')),
                    'model_trained_at': meta.get('trained_at_utc'), 'model_metrics': meta.get('metrics')})


@APP.route('/')
@APP.route('/dashboard/')
def dashboard_index():
    return send_from_directory(str(BASE_DIR / 'dashboard'), 'index.html')


@APP.route('/dashboard/<path:path>')
def dashboard_files(path):
    return send_from_directory(str(BASE_DIR / 'dashboard'), path)


if __name__ == '__main__':
    # debug is never enabled; use gunicorn in production (see Dockerfile)
    APP.run(host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT', '5000')), debug=False, use_reloader=False)

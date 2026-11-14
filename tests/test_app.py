import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['RATE_LIMIT_ENABLED'] = '0'
os.environ.pop('PHISHTANK_APP_KEY', None)
os.environ['HISTORY_DB'] = os.path.join(tempfile.mkdtemp(), 'test.db')

import pytest, requests
import detector, db, report
from app import APP

SAFE = ['https://www.google.com/', 'https://github.com/user/repo', 'https://www.irctc.co.in/nget/train-search']
SUSPICIOUS = ['http://sbi-kyc-update-online.example.xyz/login',
              'http://upi-refund-claim.example.top/verify?otp=123456',
              'http://aadhaar-pan-link-update.example.icu/']


@pytest.fixture()
def client():
    db.clear_scans()
    return APP.test_client()


# ---- input validation
@pytest.mark.parametrize('bad', ['', '   ', None, 'javascript:alert(1)', 'ftp://example.com/x', 'file:///etc/passwd',
                                 'data:text/html,hi', 'http://', 'http://exa mple.com', 'not a url', 'http://-bad-.com',
                                 'http://nodot', 'a' * 3000])
def test_bad_input_rejected(bad):
    with pytest.raises(detector.UrlError):
        detector.normalize_url(bad)


def test_bad_input_via_api(client):
    r = client.post('/api/scan', json={'url': 'ftp://example.com'})
    assert r.status_code == 400 and r.get_json()['result'] == 'Unable to check'
    assert client.post('/api/scan', data='not json').status_code == 400
    assert client.get('/predict').status_code == 400


def test_schemeless_gets_http():
    assert detector.normalize_url('example.com/a').startswith('http://example.com')


# ---- local detection (no PhishTank key)
@pytest.mark.parametrize('u', SAFE)
def test_safe_examples_not_flagged(u):
    r = detector.scan(u, use_phishtank=True)
    assert r['result'] == 'No known threat found' and r['level'] == 'LOW'
    assert r['sources']['phishtank'] == 'disabled'
    assert 'Safe' not in r['result']


@pytest.mark.parametrize('u', SUSPICIOUS)
def test_suspicious_examples_flagged(u):
    r = detector.scan(u, use_phishtank=True)
    assert r['result'] == 'Suspicious' and r['level'] in ('MEDIUM', 'HIGH') and r['reasons']
    assert any('PhishTank' in x for x in r['reasons'])  # "lookup unavailable" shown, scan not failed


def test_score_range_and_levels():
    for u in SAFE + SUSPICIOUS:
        r = detector.scan(u, use_phishtank=False)
        assert 0 <= r['score'] <= 100 and r['level'] in ('LOW', 'MEDIUM', 'HIGH')
    assert detector.level_for(10) == 'LOW' and detector.level_for(50) == 'MEDIUM' and detector.level_for(90) == 'HIGH'


def test_rules_indian_patterns():
    why = ' '.join(w for _, w in detector.run_rules('http://192.0.2.1/kyc.apk'))
    assert 'IP address' in why and '.apk' in why
    why = ' '.join(w for _, w in detector.run_rules('http://sbi-login.example.xyz/'))
    assert 'not an official sbi' in why
    assert not any('not an official' in w for _, w in detector.run_rules('https://onlinesbi.sbi/'))


def test_model_missing_gives_setup_error(tmp_path):
    with pytest.raises(detector.ModelNotAvailable):
        detector.scan('https://example.com', model_path=tmp_path / 'nope.joblib')


# ---- PhishTank behaviour (mocked: no network)
class FakeResp:
    def __init__(self, data): self._d = data
    def raise_for_status(self): pass
    def json(self): return self._d


def test_phishtank_found(monkeypatch):
    monkeypatch.setattr(requests, 'post', lambda *a, **k: FakeResp({'results': {'in_database': True, 'valid': 'y'}}))
    r = detector.scan('http://example.com/x', use_phishtank=True, app_key='dummy')
    assert r['result'] == 'Known phishing' and r['score'] == 100


def test_phishtank_not_found(monkeypatch):
    monkeypatch.setattr(requests, 'post', lambda *a, **k: FakeResp({'results': {'in_database': False}}))
    r = detector.scan('https://www.google.com/', use_phishtank=True, app_key='dummy')
    assert r['result'] == 'No known threat found' and r['sources']['phishtank'] == 'not_found'


@pytest.mark.parametrize('exc', [requests.Timeout(), requests.ConnectionError(), ValueError('bad json')])
def test_phishtank_failure_falls_back_to_local(monkeypatch, exc):
    def boom(*a, **k): raise exc
    monkeypatch.setattr(requests, 'post', boom)
    r = detector.scan('http://sbi-kyc-update-online.example.xyz/login', use_phishtank=True, app_key='dummy')
    assert r['result'] == 'Suspicious' and r['sources']['phishtank'] == 'unavailable'


def test_phishtank_uses_timeout(monkeypatch):
    seen = {}
    def fake(*a, **k): seen.update(k); return FakeResp({'results': {}})
    monkeypatch.setattr(requests, 'post', fake)
    detector.phishtank_lookup('http://example.com', 'dummy')
    assert seen.get('timeout')


def test_submitted_url_is_never_fetched(monkeypatch):
    def forbid(*a, **k): raise AssertionError('network call attempted')
    monkeypatch.setattr(requests, 'get', forbid)
    monkeypatch.setattr(requests, 'post', forbid)
    r = detector.scan('http://evil.example.com/x', use_phishtank=False)  # no key -> no call at all
    assert r['result']


# ---- redaction
def test_redaction():
    u = detector.redact_url('https://user:pw@example.com/p?token=abc123&x=1#frag')
    assert 'abc123' not in u and 'pw' not in u and 'frag' not in u and 'token=REDACTED' in u
    r = detector.scan('http://example.com/login?otp=987654', use_phishtank=False)
    assert '987654' not in r['url']


# ---- API, history, PDFs
def test_health(client):
    j = client.get('/health').get_json()
    assert j['status'] == 'ok' and j['model_loaded'] is True


def test_scan_saves_history_and_clear(client):
    r = client.post('/api/scan', json={'url': SUSPICIOUS[0], 'use_phishtank': False}).get_json()
    assert r['id'] and r['scanned_at']
    h = client.get('/api/history').get_json()
    assert len(h) == 1 and h[0]['url'] == r['url'] and h[0]['result'] == r['result']
    assert client.delete('/api/history').get_json()['deleted'] == 1
    assert client.get('/api/history').get_json() == []


def test_history_stores_no_raw_query(client):
    client.post('/api/scan', json={'url': 'http://example.com/a?email=me@x.com&otp=1234'})
    assert 'me@x.com' not in str(client.get('/api/history').get_json())


def test_single_pdf(client):
    r = client.post('/api/scan', json={'url': SUSPICIOUS[1]}).get_json()
    p = client.get(f'/api/report/{r["id"]}.pdf')
    assert p.status_code == 200 and p.mimetype == 'application/pdf' and p.data.startswith(b'%PDF') and len(p.data) > 1500
    assert b'otp=123456' not in p.data
    assert client.get('/api/report/99999.pdf').status_code == 404


def test_summary_pdf_and_range(client):
    for u in SAFE[:2] + SUSPICIOUS[:2]:
        client.post('/api/scan', json={'url': u})
    p = client.get('/api/report/summary.pdf')
    assert p.status_code == 200 and p.data.startswith(b'%PDF')
    assert client.get('/api/report/summary.pdf?from=2000-01-01&to=2000-01-02').status_code == 200
    assert client.get('/api/report/summary.pdf?from=bad').status_code == 400
    empty = report.summary_pdf([])
    assert empty.startswith(b'%PDF')


def test_no_secrets_in_pdf(client, monkeypatch):
    monkeypatch.setenv('PHISHTANK_APP_KEY', 'SECRETKEY123')
    monkeypatch.setattr(requests, 'post', lambda *a, **k: FakeResp({'results': {}}))
    r = client.post('/api/scan', json={'url': SAFE[0]}).get_json()
    assert b'SECRETKEY123' not in client.get(f'/api/report/{r["id"]}.pdf').data
    assert 'SECRETKEY123' not in str(r)
    assert 'SECRETKEY123' not in str(client.get('/api/status').get_json())


# ---- hardening
def test_no_wildcard_cors_by_default(client):
    r = client.get('/health', headers={'Origin': 'https://evil.example'})
    assert 'Access-Control-Allow-Origin' not in r.headers


def test_security_headers_and_no_debug(client):
    r = client.get('/health')
    assert r.headers['X-Content-Type-Options'] == 'nosniff' and not APP.debug


def test_dashboard_served(client):
    r = client.get('/')
    assert r.status_code == 200 and b'Scan URL' in r.data


def test_rate_limit(monkeypatch):
    import importlib, app as appmod
    monkeypatch.setenv('RATE_LIMIT_ENABLED', '1')
    monkeypatch.setenv('RATE_LIMIT_SCAN', '5 per minute')
    importlib.reload(appmod)
    try:
        c = appmod.APP.test_client()
        codes = [c.get('/predict?url=https://github.com').status_code for _ in range(8)]
        assert codes[:5] == [200] * 5 and 429 in codes
    finally:
        monkeypatch.setenv('RATE_LIMIT_ENABLED', '0')
        monkeypatch.delenv('RATE_LIMIT_SCAN')
        importlib.reload(appmod)


def test_dashboard_assets_load(client):
    import re
    html = client.get('/').get_data(as_text=True)
    for path in re.findall(r'(?:src|href)="(/dashboard/[^"]+)"', html):
        assert client.get(path).status_code == 200, path
    assert '/dashboard/app.js' in html and '/dashboard/styles.css' in html

"""Detection engine: URL validation, rules layer, local ML model, optional PhishTank.

The submitted URL is NEVER opened or fetched. Only PhishTank (if enabled) receives it.
"""
import base64
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import joblib
import requests
import tldextract

from features import extract_host_features, HOST_FEATURE_COLUMNS

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = Path(os.environ.get('MODEL_PATH', BASE_DIR / 'models' / 'model.joblib'))
MAX_URL_LENGTH = 2048
PHISHTANK_ENDPOINT = 'https://checkurl.phishtank.com/checkurl/'
PHISHTANK_TIMEOUT = float(os.environ.get('PHISHTANK_TIMEOUT', '5'))

# Result labels
KNOWN_PHISHING = 'Known phishing'
SUSPICIOUS = 'Suspicious'
NO_THREAT = 'No known threat found'
UNABLE = 'Unable to check'

DISCLAIMER = ('Results can be wrong. "No known threat found" does not guarantee a link is safe. '
              'Never enter OTP, PIN, passwords or card details on a link you did not expect.')

_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline: bundled suffix list only

SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at',
              'ow.ly', 'tiny.cc', 'rebrand.ly', 'wa.me.link', 'bitly.com', 'lnkd.in', 'buff.ly'}

# Indian brands -> official registered domains (small, editable list)
INDIA_BRANDS = {
    'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com', 'sbilife.co.in', 'sbi.bank.in'],
    'hdfc': ['hdfcbank.com', 'hdfc.com', 'hdfclife.com', 'hdfcbank.net'],
    'icici': ['icicibank.com', 'icicidirect.com', 'iciciprulife.com'],
    'axis': ['axisbank.com'], 'kotak': ['kotak.com', 'kotakbank.com'],
    'paytm': ['paytm.com', 'paytmbank.com'], 'phonepe': ['phonepe.com'],
    'gpay': ['pay.google.com', 'google.com'], 'bhim': ['bhimupi.org.in', 'npci.org.in'],
    'npci': ['npci.org.in'], 'uidai': ['uidai.gov.in'], 'aadhaar': ['uidai.gov.in'],
    'incometax': ['incometax.gov.in', 'incometaxindia.gov.in'],
    'epfo': ['epfindia.gov.in', 'epfindia.gov.in'], 'irctc': ['irctc.co.in', 'irctc.com'],
    'flipkart': ['flipkart.com'], 'amazon': ['amazon.in', 'amazon.com', 'amazonaws.com'],
    'jio': ['jio.com', 'ril.com'], 'airtel': ['airtel.in', 'airtel.com'],
    'indiapost': ['indiapost.gov.in'], 'fastag': ['ihmcl.com', 'netc.org.in'],
    'digilocker': ['digilocker.gov.in'], 'whatsapp': ['whatsapp.com', 'wa.me'],
}
SUSPICIOUS_PATH_WORDS = ['kyc', 'verify', 'update', 'login', 'signin', 'secure', 'confirm', 'refund',
                         'reward', 'blocked', 'suspend', 'expire', 'claim', 'otp', 'pan-', 'aadhaar',
                         'upi', 'redeem', 'prize', 'lottery', 'cashback']
SENSITIVE_PARAMS = ('token', 'key', 'pass', 'pwd', 'otp', 'pin', 'session', 'sid', 'auth', 'secret',
                    'code', 'email', 'phone', 'mobile', 'account', 'card', 'aadhaar', 'pan')


class UrlError(ValueError):
    """Input rejected before any analysis."""


# ---------------------------------------------------------------- validation
def normalize_url(raw):
    """Validate and normalise user input. Raises UrlError with a plain-English message."""
    if raw is None or not isinstance(raw, str):
        raise UrlError('Please enter a URL.')
    url = raw.strip()
    if not url:
        raise UrlError('Please enter a URL.')
    if len(url) > MAX_URL_LENGTH:
        raise UrlError(f'URL is too long (limit is {MAX_URL_LENGTH} characters).')
    if re.search(r'[\s\x00-\x1f\x7f]', url):
        raise UrlError('URL must not contain spaces or control characters.')
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', url)
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url))
    if m and not has_scheme and not re.match(r'^[^/]+:\d+(/|$)', url):
        raise UrlError('Only http and https links can be checked.')
    if has_scheme:
        scheme = url.split('://', 1)[0].lower()
        if scheme not in ('http', 'https'):
            raise UrlError('Only http and https links can be checked.')
    else:
        url = 'http://' + url.lstrip('/')
    try:
        p = urlparse(url)
        host = p.hostname
        port = p.port
    except ValueError:
        raise UrlError('This does not look like a valid URL.')
    if not host:
        raise UrlError('This does not look like a valid URL.')
    host = host.lower().rstrip('.')
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if not is_ip:
        labels = host.split('.')
        if len(labels) < 2 or len(host) > 253 or not all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', l) for l in labels):
            raise UrlError('The web address in this URL is not valid.')
    netloc = host + (f':{port}' if port else '')
    if p.username or p.password:
        netloc = (p.username or '') + (':' + p.password if p.password else '') + '@' + netloc
    return urlunparse((p.scheme.lower(), netloc, p.path, p.params, p.query, ''))


def redact_url(url):
    """Remove credentials, fragment and query values (keeps parameter names)."""
    p = urlparse(url)
    host = p.hostname or ''
    netloc = host + (f':{p.port}' if p.port else '')
    q = '&'.join(f'{k}=REDACTED' for k, _ in parse_qsl(p.query, keep_blank_values=True))
    return urlunparse((p.scheme, netloc, p.path, '', q, ''))


# ---------------------------------------------------------------- rules layer
def run_rules(url):
    """Return list of (points, plain-English reason)."""
    p = urlparse(url)
    host = (p.hostname or '').lower()
    ext = _tld(host)
    reg = ext.top_domain_under_public_suffix if hasattr(ext, 'top_domain_under_public_suffix') else ext.registered_domain
    reg = reg or host
    path_q = (p.path + '?' + p.query).lower()
    out = []

    def add(pts, why):
        out.append((pts, why))

    try:
        ipaddress.ip_address(host)
        add(30, 'The link uses a raw IP address instead of a website name.')
    except ValueError:
        pass
    if any(l.startswith('xn--') for l in host.split('.')):
        add(25, 'The web address uses punycode (xn--), which can disguise look-alike characters.')
    if '@' in p.netloc:
        add(25, 'The link contains "@" before the host, a trick used to hide the real destination.')
    if reg in SHORTENERS or host in SHORTENERS:
        add(15, 'This is a shortened link. The real destination is hidden (we never open links to check).')
    if ext.subdomain and len(ext.subdomain.split('.')) >= 4:
        add(15, 'The address has many subdomains, often used to imitate a trusted name.')
    if host.count('-') >= 3:
        add(10, 'The web address has several hyphens, common in fake look-alike domains.')
    tld = (ext.suffix or '').split('.')[-1]
    from features import SUSPICIOUS_TLDS
    if tld in SUSPICIOUS_TLDS:
        add(8, f'The ".{tld}" ending is frequently used for throwaway or scam websites.')
    if p.scheme == 'http':
        add(5, 'The link is not encrypted (http, not https).')
    if p.port and p.port not in (80, 443):
        add(10, f'The link uses an unusual port ({p.port}).')
    if len(url) > 100:
        add(5, 'The URL is unusually long.')
    if re.search(r'\.apk($|\?)', p.path.lower()):
        add(25, 'The link downloads an Android app file (.apk). Fake bank and KYC apps spread this way.')
    # India brand impersonation
    hit = False
    for brand, official in INDIA_BRANDS.items():
        if re.search(r'(^|[.-])' + re.escape(brand), host):
            if reg not in official and not any(host == o or host.endswith('.' + o) for o in official):
                add(35, f'The address mentions "{brand}" but is not an official {brand} website.')
                hit = True
                break
    if not hit:
        for brand, official in INDIA_BRANDS.items():
            if re.search(r'(^|[/_.=-])' + re.escape(brand) + r'($|[/_.=-])', path_q) and reg not in official:
                add(15, f'The path mentions "{brand}" on a website that is not an official {brand} site.')
                break
    words = [w for w in SUSPICIOUS_PATH_WORDS if w in host or w in path_q]
    if len(words) >= 2:
        add(15, 'The address uses urgent or account words (' + ', '.join(sorted(set(words))[:4]) + ').')
    elif len(words) == 1:
        add(5, f'The address contains the word "{words[0]}".')
    return out


# ---------------------------------------------------------------- ML model
class ModelNotAvailable(RuntimeError):
    pass


_MODEL_CACHE = {}


def load_model(path=None):
    path = Path(path or MODEL_PATH)
    if path in _MODEL_CACHE:
        return _MODEL_CACHE[path]
    if not path.exists():
        raise ModelNotAvailable(
            'Model file not found. Run: python scripts/build_dataset.py && python train.py --data data/dataset.csv')
    try:
        data = joblib.load(path)
        _MODEL_CACHE[path] = (data['model'], data.get('feature_columns', HOST_FEATURE_COLUMNS))
    except Exception:
        raise ModelNotAvailable('Model file could not be loaded. Re-train it with: python train.py --data data/dataset.csv')
    return _MODEL_CACHE[path]


def ml_probability(url, path=None):
    import pandas as pd
    model, cols = load_model(path)
    x = pd.DataFrame([extract_host_features(url)])[cols]
    return float(model.predict_proba(x)[0][1])


# ---------------------------------------------------------------- PhishTank
def phishtank_lookup(url, app_key=None):
    """Return dict: status in {'found_phishing','not_found','unavailable','disabled'} + message."""
    key = app_key if app_key is not None else os.environ.get('PHISHTANK_APP_KEY', '')
    if not key:
        return {'status': 'disabled', 'message': 'Reputation lookup unavailable (no PhishTank key configured).'}
    try:
        r = requests.post(PHISHTANK_ENDPOINT, timeout=PHISHTANK_TIMEOUT,
                          data={'url': base64.b64encode(url.encode()).decode(), 'format': 'json', 'app_key': key},
                          headers={'User-Agent': f'phishtank/{os.environ.get("PHISHTANK_USERNAME", "india-phishing-checker")}'})
        r.raise_for_status()
        res = r.json().get('results', {})
    except (requests.RequestException, ValueError):
        return {'status': 'unavailable', 'message': 'Reputation lookup unavailable (PhishTank did not respond).'}
    if res.get('in_database') and res.get('valid') in (True, 'true', 'y'):
        return {'status': 'found_phishing', 'message': 'PhishTank lists this URL as a verified phishing site.'}
    return {'status': 'not_found', 'message': 'PhishTank has no verified phishing report for this URL.'}


# ---------------------------------------------------------------- combine
def level_for(score):
    return 'LOW' if score < 35 else ('MEDIUM' if score < 65 else 'HIGH')


def scan(raw_url, use_phishtank=True, model_path=None, app_key=None):
    """Full scan. Raises UrlError (bad input) or ModelNotAvailable (setup problem)."""
    url = normalize_url(raw_url)
    prob = ml_probability(url, model_path)
    rules = run_rules(url)
    rule_points = sum(p for p, _ in rules)
    score = min(100, round(prob * 100 * 0.7 + rule_points))
    reasons = [w for _, w in sorted(rules, key=lambda r: -r[0])]
    if prob >= 0.65:
        reasons.append(f'The local model rates the web address as phishing-like ({prob*100:.0f}% likelihood).')
    elif prob >= 0.4:
        reasons.append(f'The local model finds the web address somewhat unusual ({prob*100:.0f}% likelihood).')
    sources = {'local_model': True, 'rules': True, 'phishtank': 'not requested'}
    result = None
    if use_phishtank:
        pt = phishtank_lookup(url, app_key)
        sources['phishtank'] = pt['status']
        reasons.append(pt['message'])
        if pt['status'] == 'found_phishing':
            score, result = 100, KNOWN_PHISHING
    if result is None:
        level = level_for(score)
        result = SUSPICIOUS if level in ('MEDIUM', 'HIGH') else NO_THREAT
    if result == NO_THREAT:
        reasons.append('No known threat found is not a guarantee of safety.')
    return {
        'url': redact_url(url), 'result': result, 'score': int(score), 'level': level_for(score),
        'ml_probability': round(prob, 4), 'reasons': reasons, 'sources': sources, 'disclaimer': DISCLAIMER,
    }

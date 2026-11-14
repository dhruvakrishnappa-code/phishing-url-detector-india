import re
import tldextract
from urllib.parse import urlparse
try:
    import pandas as pd
except ImportError:  # serverless runtime ships without pandas
    pd = None
import os
import json
try:
    # optional enrichment functions (batch)
    from enrichment import enrich_urls
except Exception:
    enrich_urls = None

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "bank",
    "confirm",
    "secure",
    "account",
    "ebay",
    "paypal",
    "signin",
]

# Common brand tokens to detect subdomain spoofing (not exhaustive)
BRAND_TOKENS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'icloud', 'gmail', 'bank'
]

def has_ip_in_host(url: str) -> int:
    try:
        host = urlparse(url).netloc
    except Exception:
        host = url
    # IPv4 pattern
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return 1
    if re.search(r"\d+\.\d+\.\d+\.\d+", host):
        return 1
    return 0


def count_subdomains(url: str) -> int:
    ext = tldextract.extract(url)
    if ext.subdomain:
        return len(ext.subdomain.split('.'))
    return 0


def contains_suspicious_keyword(url: str) -> int:
    url_low = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_low:
            return 1
    return 0


def has_digits_in_domain(domain: str) -> int:
    # digits often replace letters in phishing domains (e.g., micros0ft)
    return 1 if re.search(r"[0-9]", domain) else 0


def has_punycode(domain: str) -> int:
    # IDN punycode labels start with xn--
    try:
        parts = domain.split('.')
        for p in parts:
            if p.lower().startswith('xn--'):
                return 1
    except Exception:
        pass
    return 0


def has_homoglyph_sequence(domain: str) -> int:
    # simple heuristics: common visual confusion sequences like 'rn' (looks like 'm'), 'cl' (looks like 'd'), 'vv' (w)
    # and presence of mixed letter/number substitutions
    domain_low = domain.lower()
    seqs = ['rn', 'cl', 'vv', '1l', '0o', '5s']
    for s in seqs:
        if s in domain_low:
            return 1
    return 0


def subdomain_spoofing(ext) -> int:
    # ext is tldextract result; check if subdomain contains known brand tokens while registered_domain is different
    try:
        sub = (ext.subdomain or '').lower()
        reg = (getattr(ext, 'top_domain_under_public_suffix', None) or ext.registered_domain or '').lower()
        if not sub or not reg:
            return 0
        for b in BRAND_TOKENS:
            if b in sub and b not in reg:
                return 1
    except Exception:
        pass
    return 0


def extract_features(url: str, enrich: dict = None) -> dict:
    u = url.strip()
    features = {}
    features['length'] = len(u)
    features['has_at'] = 1 if '@' in u else 0
    features['has_https'] = 1 if u.lower().startswith('https') else 0
    # insecure when not HTTPS
    features['insecure'] = 0 if features['has_https'] == 1 else 1
    features['num_subdomains'] = count_subdomains(u)
    features['has_ip'] = has_ip_in_host(u)
    features['suspicious_keyword'] = contains_suspicious_keyword(u)
    # presence of '-' in domain can be suspicious
    parsed = urlparse(u)
    domain = parsed.netloc or u
    features['dash_in_domain'] = 1 if '-' in domain else 0
    # punycode and digit/homoglyph checks operate on the domain string
    try:
        ext = tldextract.extract(u)
        domain_label = ext.domain or ''
        host = parsed.netloc or u
    except Exception:
        ext = None
        domain_label = ''
        host = domain
    features['has_digits_in_domain'] = has_digits_in_domain(domain_label)
    features['has_punycode'] = has_punycode(host)
    features['has_homoglyph_seq'] = has_homoglyph_sequence(domain_label)
    features['subdomain_spoof'] = subdomain_spoofing(ext) if ext is not None else 0
    # domain reputation score (set externally via set_domain_reputation_map)
    try:
        from tldextract import extract
        reg = extract(u).registered_domain
    except Exception:
        reg = ''
    rep = DOMAIN_REPUTATION.get(reg, None) if DOMAIN_REPUTATION is not None else None
    # if missing, use 0.5 neutral; otherwise numeric value
    features['domain_reputation'] = float(rep) if rep is not None else 0.5

    # Optional enrichment (WHOIS/TLS/HTML) — disabled by default. Enable by setting env var USE_ENRICH=1
    try:
        ENABLE_ENRICH = os.environ.get('USE_ENRICH', '0') == '1'
    except Exception:
        ENABLE_ENRICH = False

    if ENABLE_ENRICH:
        # enrichment is provided as a batch map (faster and robust). If enrich is None, fall back to defaults.
        try:
            if enrich:
                features['domain_age_days'] = int(enrich.get('whois_age')) if enrich.get('whois_age') is not None else -1
            else:
                features['domain_age_days'] = -1
        except Exception:
            features['domain_age_days'] = -1
        try:
            if enrich:
                features['tls_days'] = int(enrich.get('tls_days')) if enrich.get('tls_days') is not None else -1
            else:
                features['tls_days'] = -1
        except Exception:
            features['tls_days'] = -1
        try:
            if enrich:
                features['has_login_form'] = int(enrich.get('has_login_form', 0))
                features['external_links'] = int(enrich.get('external_links', 0))
            else:
                features['has_login_form'] = 0
                features['external_links'] = 0
        except Exception:
            features['has_login_form'] = 0
            features['external_links'] = 0
    else:
        features['domain_age_days'] = -1
        features['tls_days'] = -1
        features['has_login_form'] = 0
        features['external_links'] = 0

    return features


def url_to_dataframe(urls):
    # batch enrichment when enabled
    try:
        ENABLE_ENRICH = os.environ.get('USE_ENRICH', '0') == '1'
    except Exception:
        ENABLE_ENRICH = False

    enrich_map = None
    if ENABLE_ENRICH and enrich_urls is not None:
        try:
            workers = int(os.environ.get('ENRICH_WORKERS', '8'))
            timeout = int(os.environ.get('ENRICH_TIMEOUT', '5'))
            enrich_map = enrich_urls(urls, max_workers=workers, timeout=timeout)
        except Exception:
            enrich_map = None

    rows = []
    for u in urls:
        e = enrich_map.get(u) if enrich_map else None
        rows.append(extract_features(u, enrich=e))
    return pd.DataFrame(rows)


# optional reputation map
DOMAIN_REPUTATION = None


def set_domain_reputation_map(demap: dict):
    global DOMAIN_REPUTATION
    DOMAIN_REPUTATION = demap


if __name__ == '__main__':
    # simple self-test
    samples = [
        'https://secure-paypal-login.example.com/confirm',
        'https://www.google.com/search?q=test',
        'http://192.168.1.1/login',
    ]
    print(url_to_dataframe(samples))


# ---------------------------------------------------------------------------
# ADAPTATION (2026-11-13): hostname-based feature set used by the new model.
# The functions above are the upstream helpers and are reused unchanged.
# ---------------------------------------------------------------------------
import math

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'icu', 'click', 'live', 'buzz', 'cfd', 'sbs', 'vip', 'work',
    'tk', 'ml', 'ga', 'cf', 'gq', 'rest', 'monster', 'support', 'cyou', 'online',
    'site', 'store', 'shop', 'club', 'info',
}
COMMON_TLDS = ['com', 'in', 'org', 'net', 'co', 'gov', 'edu']
HOST_KEYWORDS = ['login', 'verify', 'update', 'bank', 'confirm', 'secure', 'account',
                 'signin', 'kyc', 'upi', 'pay', 'wallet', 'refund', 'reward', 'aadhaar',
                 'pan', 'support', 'help', 'free', 'offer']

HOST_FEATURE_COLUMNS = [
    'host_length', 'num_dots', 'num_hyphens', 'num_digits', 'digit_ratio',
    'num_subdomains', 'has_ip', 'has_punycode', 'reg_label_length', 'reg_label_entropy',
    'longest_digit_run', 'vowel_ratio', 'tld_length', 'suspicious_tld', 'has_homoglyph_seq',
    'subdomain_spoof', 'keyword_count', 'has_at',
] + ['tld_' + t for t in COMMON_TLDS]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_host_features(url: str) -> dict:
    """Features computed from the hostname only (no network access)."""
    u = url.strip()
    parsed = urlparse(u if '://' in u else 'http://' + u)
    host = (parsed.hostname or '').lower()
    if host.startswith('www.'):
        host = host[4:]  # benign training list has bare domains; ignore a leading www
    ext = tldextract.extract(host)
    label = ext.domain or ''
    tld = (ext.suffix or '').split('.')[-1]
    digits = sum(ch.isdigit() for ch in host)
    runs = re.findall(r'\d+', host)
    vowels = sum(ch in 'aeiou' for ch in label)
    f = {
        'host_length': len(host),
        'num_dots': host.count('.'),
        'num_hyphens': host.count('-'),
        'num_digits': digits,
        'digit_ratio': digits / len(host) if host else 0.0,
        'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'has_ip': has_ip_in_host('http://' + host),
        'has_punycode': has_punycode(host),
        'reg_label_length': len(label),
        'reg_label_entropy': _entropy(label),
        'longest_digit_run': max((len(r) for r in runs), default=0),
        'vowel_ratio': vowels / len(label) if label else 0.0,
        'tld_length': len(tld),
        'suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'has_homoglyph_seq': has_homoglyph_sequence(label),
        'subdomain_spoof': subdomain_spoofing(ext),
        'keyword_count': sum(1 for k in HOST_KEYWORDS if k in host),
        'has_at': 1 if '@' in (parsed.netloc or '') else 0,
    }
    for t in COMMON_TLDS:
        f['tld_' + t] = 1 if tld == t else 0
    return f

import socket
import ssl
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois
import datetime
import os
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# Simple disk-backed cache for enrichment results
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
CACHE_FILE = os.path.join(CACHE_DIR, 'enrichment_cache.json')
os.makedirs(CACHE_DIR, exist_ok=True)


def load_cache():
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(cache: dict):
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f)
    except Exception:
        pass


def get_hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ''
    except Exception:
        return ''


def get_tls_info(url: str, timeout: int = 5):
    """Return dict with TLS days until expiry (or None) and issuer CN."""
    host = get_hostname(url)
    if not host:
        return {'tls_days': None, 'tls_issuer': None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, 443))
            cert = s.getpeercert()
        # cert['notAfter'] like 'Jul 10 12:00:00 2024 GMT'
        not_after = cert.get('notAfter')
        issuer = cert.get('issuer')
        issuer_cn = None
        if issuer:
            try:
                issuer_cn = [t[0][1] for t in issuer if t and t[0][0].lower() == 'commonname'][0]
            except Exception:
                issuer_cn = str(issuer)
        if not_after:
            try:
                exp = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days = (exp - datetime.datetime.utcnow()).days
            except Exception:
                days = None
        else:
            days = None
        return {'tls_days': days, 'tls_issuer': issuer_cn}
    except Exception:
        return {'tls_days': None, 'tls_issuer': None}


def get_whois_age(url: str):
    host = get_hostname(url)
    if not host:
        return None
    try:
        w = whois.whois(host)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.datetime.utcnow() - creation).days
            return age_days
    except Exception:
        return None
    return None


def fetch_html_features(url: str, timeout: int = 5):
    try:
        r = requests.get(url, timeout=timeout)
        html = r.text
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else ''
        forms = soup.find_all('form')
        has_login_form = any('password' in ''.join([str(i) for i in f.find_all('input')]).lower() for f in forms)
        a_tags = soup.find_all('a')
        external_links = 0
        host = get_hostname(url)
        for a in a_tags:
            href = a.get('href')
            if href and href.startswith('http') and host and host not in href:
                external_links += 1
        return {'title': title, 'has_login_form': int(has_login_form), 'external_links': external_links}
    except Exception:
        return {'title': '', 'has_login_form': 0, 'external_links': 0}


def enrich_single(url: str, timeout: int = 5):
    host = get_hostname(url)
    result = {
        'tls_days': None,
        'tls_issuer': None,
        'whois_age': None,
        'title': '',
        'has_login_form': 0,
        'external_links': 0,
    }
    try:
        tls = get_tls_info(url, timeout=timeout)
        result['tls_days'] = tls.get('tls_days')
        result['tls_issuer'] = tls.get('tls_issuer')
    except Exception:
        pass
    try:
        whois_age = get_whois_age(url)
        result['whois_age'] = whois_age
    except Exception:
        pass
    try:
        html = fetch_html_features(url, timeout=timeout)
        result['title'] = html.get('title', '')
        result['has_login_form'] = int(html.get('has_login_form', 0))
        result['external_links'] = int(html.get('external_links', 0))
    except Exception:
        pass
    return result


def enrich_urls(urls, max_workers: int = 8, timeout: int = 5):
    """Batch-enrich a list of URLs concurrently. Returns dict url -> enrichment dict.
    Uses a simple disk cache to avoid repeated network calls.
    """
    cache = load_cache()
    out = {}
    tasks = {}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures_map = {}
        for u in urls:
            # check cache first for exact url
            key_url = f'url:{u}'
            host = get_hostname(u)
            key_host = f'host:{host}' if host else None
            if key_url in cache:
                out[u] = cache[key_url]
                continue
            # if host-level cached data exists, start with that
            initial = {}
            if key_host and key_host in cache:
                initial = cache[key_host].copy()
            # submit enrichment task
            fut = ex.submit(enrich_single, u, timeout)
            futures_map[fut] = (u, key_url, key_host, initial)

        # iterate futures and apply a per-future timeout to avoid hanging
        for fut, meta in list(futures_map.items()):
            u, key_url, key_host, initial = meta
            try:
                # enforce a timeout per network task
                res = fut.result(timeout=timeout)
            except Exception:
                res = {}
            # merge initial host-level data
            merged = {}
            if initial:
                merged.update(initial)
            if res:
                merged.update(res)
            # normalize keys we use in features
            final = {
                'tls_days': merged.get('tls_days'),
                'tls_issuer': merged.get('tls_issuer'),
                'whois_age': merged.get('whois_age'),
                'title': merged.get('title', ''),
                'has_login_form': int(merged.get('has_login_form', 0) or 0),
                'external_links': int(merged.get('external_links', 0) or 0),
            }
            out[u] = final
            # save into cache: host-level and url-level
            try:
                if key_host:
                    host_entry = cache.get(key_host, {})
                    host_entry.update({'tls_days': final.get('tls_days'), 'tls_issuer': final.get('tls_issuer'), 'whois_age': final.get('whois_age')})
                    cache[key_host] = host_entry
                cache[key_url] = final
            except Exception:
                pass

    # persist cache
    try:
        save_cache(cache)
    except Exception:
        pass

    return out

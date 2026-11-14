"""Build a training CSV (url,label) from two public sources. Run once, needs internet.

  phishing (label 1): Phishing.Database ACTIVE links (MIT) - github.com/Phishing-Database/Phishing.Database
  benign   (label 0): Tranco top-sites list (research list)  - tranco-list.eu

Only hostnames are kept (see KNOWN_LIMITATIONS.md for why). URLs are never visited.
"""
import io, random, re, sys, zipfile
from urllib.parse import urlparse
import requests, tldextract

PHISH_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt'
TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'
N_EACH = 20000
PER_DOMAIN_CAP = 2
random.seed(42)

def host_ok(h):
    return bool(h) and len(h) < 100 and re.fullmatch(r'[a-z0-9.-]+', h) and '.' in h

def main(out='data/dataset.csv'):
    txt = requests.get(PHISH_URL, timeout=120).text.splitlines()
    random.shuffle(txt)
    seen, per, phish = set(), {}, []
    for line in txt:
        line = line.strip()
        if not re.match(r'^https?://', line, re.I):
            continue
        try:
            h = (urlparse(line).hostname or '').lower()
        except ValueError:
            continue
        if not host_ok(h) or h in seen:
            continue
        reg = tldextract.extract(h).registered_domain or h
        if per.get(reg, 0) >= PER_DOMAIN_CAP:
            continue
        per[reg] = per.get(reg, 0) + 1
        seen.add(h); phish.append(h)
        if len(phish) >= N_EACH:
            break
    z = zipfile.ZipFile(io.BytesIO(requests.get(TRANCO_URL, timeout=120).content))
    rows = z.read(z.namelist()[0]).decode().splitlines()[:50000]
    benign = [r.split(',')[1].lower() for r in rows if ',' in r]
    benign = [h for h in benign if host_ok(h) and h not in seen]
    random.shuffle(benign); benign = benign[:N_EACH]
    with open(out, 'w', encoding='utf-8') as f:
        f.write('url,label\n')
        for h in phish: f.write(f'http://{h},1\n')
        for h in benign: f.write(f'http://{h},0\n')
    print(f'wrote {out}: {len(phish)} phishing hosts, {len(benign)} benign hosts')

if __name__ == '__main__':
    main(*sys.argv[1:])

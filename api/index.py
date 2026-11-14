"""Vercel serverless entry: exposes the Flask app as `app`.

Serverless adaptations (no change to the app's own behavior):
- vercel.json rewrites every request to this function, carrying the original
  path in the `__vercel_orig_path` query parameter, because Vercel's Python
  runtime hands the function the rewrite destination (/api/index), not the
  original URL. The middleware below restores PATH_INFO before Flask sees it.
- SQLite scan history goes to /tmp (the only writable dir on serverless).
  It is ephemeral: history lasts only while a function instance stays warm.
- tldextract caches the public suffix list under /tmp too.
"""
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault('HISTORY_DB', '/tmp/history.db')
os.environ.setdefault('TLDEXTRACT_CACHE_DIR', '/tmp/tldextract-cache')

from app import APP as _flask_app  # noqa: E402

_PARAM = '__vercel_orig_path'
_PREFIX = '/api/index'


def app(environ, start_response):
    qs = environ.get('QUERY_STRING', '')
    if _PARAM + '=' in qs:
        orig = None
        rest = []
        for k, v in parse_qsl(qs, keep_blank_values=True):
            if k == _PARAM and orig is None:
                orig = v
            else:
                rest.append((k, v))
        if orig:
            environ['PATH_INFO'] = orig
        environ['QUERY_STRING'] = urlencode(rest)
    p = environ.get('PATH_INFO', '/')
    if p == _PREFIX or p.startswith(_PREFIX + '/'):
        environ['PATH_INFO'] = p[len(_PREFIX):] or '/'
    return _flask_app(environ, start_response)

"""SQLite scan history. Stores only the redacted URL, result, score, reasons and time."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def db_path():
    return os.environ.get('HISTORY_DB', str(BASE_DIR / 'data' / 'history.db'))


def _conn():
    p = db_path()
    if p != ':memory:':
        Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p)
    c.row_factory = sqlite3.Row
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, url TEXT NOT NULL,
        result TEXT NOT NULL, score INTEGER NOT NULL, level TEXT NOT NULL,
        reasons TEXT NOT NULL, sources TEXT NOT NULL)''')
    return c


def _row(r):
    d = dict(r)
    d['reasons'] = json.loads(d['reasons'])
    d['sources'] = json.loads(d['sources'])
    return d


def save_scan(res):
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    with _conn() as c:
        cur = c.execute('INSERT INTO scans (scanned_at,url,result,score,level,reasons,sources) VALUES (?,?,?,?,?,?,?)',
                        (now, res['url'], res['result'], res['score'], res['level'],
                         json.dumps(res['reasons']), json.dumps(res['sources'])))
        return cur.lastrowid, now


def list_scans(limit=100, date_from=None, date_to=None):
    q, a = 'SELECT * FROM scans WHERE 1=1', []
    if date_from:
        q += ' AND substr(scanned_at,1,10) >= ?'; a.append(date_from)
    if date_to:
        q += ' AND substr(scanned_at,1,10) <= ?'; a.append(date_to)
    q += ' ORDER BY id DESC LIMIT ?'; a.append(limit)
    c = _conn()
    try:
        return [_row(r) for r in c.execute(q, a)]
    finally:
        c.close()


def get_scan(scan_id):
    c = _conn()
    try:
        r = c.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
        return _row(r) if r else None
    finally:
        c.close()


def clear_scans():
    with _conn() as c:
        n = c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        c.execute('DELETE FROM scans')
        return n

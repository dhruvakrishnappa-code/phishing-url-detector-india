// Dashboard logic. Only talks to this server's own /api endpoints. No API keys live in the browser.
const $ = id => document.getElementById(id);
const EXAMPLES = [
  ['Fake SBI KYC', 'http://sbi-kyc-update-online.example.xyz/login'],
  ['Fake UPI refund', 'http://upi-refund-claim.example.top/verify?otp=123456'],
  ['Fake Aadhaar/PAN', 'http://aadhaar-pan-link-update.example.icu/'],
  ['Fake parcel (India Post)', 'http://indiapost-parcel-redelivery.example.click/track'],
  ['Real: google.com', 'https://www.google.com/'],
  ['Real: onlinesbi.sbi', 'https://onlinesbi.sbi/']
];

function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function cssFor(result) { return result === 'Known phishing' ? 'r-known' : result === 'Suspicious' ? 'r-susp' : result === 'No known threat found' ? 'r-none' : ''; }

function showResult(r, ok) {
  const box = $('result'); box.replaceChildren();
  const b = el('div', undefined, 'result-box ' + cssFor(r.result));
  const v = el('div', undefined, 'verdict'); v.append(r.result);
  if (r.level) { const bd = el('span', r.level + ' risk', 'badge b-' + r.level); v.append(bd); }
  b.append(v);
  if (!ok) { b.append(el('p', r.error || 'Unable to check this URL.')); box.append(b); return; }
  b.append(el('div', r.url, 'url'));
  b.append(el('div', 'Risk score: ' + r.score + ' / 100'));
  const ul = el('ul'); r.reasons.forEach(x => ul.append(el('li', x))); b.append(ul);
  const pt = r.sources && r.sources.phishtank;
  b.append(el('div', 'Sources used: local ML model, rules' + (pt === 'not requested' ? '' : ', PhishTank (' + String(pt).replace(/_/g, ' ') + ')'), 'small muted'));
  const a = el('a', 'Download PDF report', 'btn'); a.href = '/api/report/' + r.id + '.pdf'; a.style.marginTop = '10px';
  b.append(a);
  b.append(el('p', r.disclaimer, 'small muted'));
  box.append(b);
}

async function loadHistory() {
  const r = await fetch('/api/history?limit=50'); const rows = await r.json();
  const h = $('history'); h.replaceChildren();
  if (!rows.length) { h.append(el('p', 'No scans yet.', 'muted')); return; }
  const t = el('table'); const hr = el('tr');
  ['Date/time (UTC)', 'URL', 'Result', 'Score', 'PDF'].forEach(x => hr.append(el('th', x))); t.append(hr);
  rows.forEach(s => {
    const tr = el('tr');
    tr.append(el('td', s.scanned_at.replace('T', ' ').slice(0, 16)));
    tr.append(el('td', s.url, 'u'));
    tr.append(el('td', s.result)); tr.append(el('td', String(s.score)));
    const td = el('td'); const a = el('a', 'PDF'); a.href = '/api/report/' + s.id + '.pdf'; td.append(a); tr.append(td);
    t.append(tr);
  });
  h.append(t);
}

function updateSummaryLink() {
  const p = new URLSearchParams(); if ($('dFrom').value) p.set('from', $('dFrom').value); if ($('dTo').value) p.set('to', $('dTo').value);
  $('summaryLink').href = '/api/report/summary.pdf' + (p.toString() ? '?' + p : '');
}

window.addEventListener('DOMContentLoaded', async () => {
  EXAMPLES.forEach(([label, url]) => { const c = el('button', label, 'chip'); c.type = 'button'; c.onclick = () => { $('checkUrl').value = url; }; $('examples').append(c); });
  $('scanForm').addEventListener('submit', async ev => {
    ev.preventDefault(); const btn = $('checkBtn'); btn.disabled = true; btn.textContent = 'Scanning...';
    try {
      const r = await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: $('checkUrl').value, use_phishtank: $('usePt').checked }) });
      const data = await r.json().catch(() => ({ result: 'Unable to check', error: 'Unexpected response.' }));
      if (r.status === 429) { data.result = 'Unable to check'; data.error = 'Too many requests. Please wait a minute.'; }
      showResult(data, r.ok); loadHistory();
    } catch (e) { showResult({ result: 'Unable to check', error: 'Could not reach the server.' }, false); }
    btn.disabled = false; btn.textContent = 'Scan URL';
  });
  $('clearBtn').onclick = async () => { if (confirm('Delete all saved scans?')) { await fetch('/api/history', { method: 'DELETE' }); loadHistory(); } };
  $('refreshBtn').onclick = loadHistory;
  $('dFrom').onchange = $('dTo').onchange = updateSummaryLink; updateSummaryLink();
  loadHistory();
  try {
    const s = await (await fetch('/api/status')).json();
    if (!s.phishtank_configured) { $('usePt').checked = false; $('usePt').parentElement.append(' - currently no key configured: reputation lookup unavailable'); }
    const m = s.model_metrics;
    $('footer').textContent = m ? 'Local model trained ' + s.model_trained_at + ' | held-out accuracy ' + (m.accuracy * 100).toFixed(1) + '%, recall ' + (m.recall * 100).toFixed(1) + '%. Results can be wrong.' : '';
  } catch (e) {}
});

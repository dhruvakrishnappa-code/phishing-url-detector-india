"""PDF reports (ReportLab): single scan and history summary. No secrets are ever included."""
import io
from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from detector import DISCLAIMER

TITLE = 'AI-Powered Phishing URL Detection System - India Edition'
COLORS = {'Known phishing': '#b71c1c', 'Suspicious': '#e65100', 'No known threat found': '#1b5e20', 'Unable to check': '#455a64'}


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle('Small', parent=s['Normal'], fontSize=8, textColor=colors.grey))
    s.add(ParagraphStyle('Cell', parent=s['Normal'], fontSize=8, leading=10))
    return s


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _doc(buf):
    return SimpleDocTemplate(buf, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm,
                             title=TITLE, author='Phishing URL Detection System')


def _src(sources):
    names = {'local_model': 'Local ML model', 'rules': 'Rules layer', 'phishtank': 'PhishTank'}
    parts = []
    for k, v in sources.items():
        parts.append(f'{names.get(k, k)}: ' + ('used' if v is True else str(v).replace('_', ' ')))
    return '; '.join(parts)


def scan_pdf(scan):
    st, buf = _styles(), io.BytesIO()
    col = COLORS.get(scan['result'], '#000000')
    el = [Paragraph(escape(TITLE), st['Title']), Paragraph('Scan report', st['Heading2']),
          Paragraph(f'Generated: {_now()}', st['Small']), Spacer(1, 6)]
    rows = [['Scan date/time', escape(scan['scanned_at'].replace('T', ' '))],
            ['URL (query values redacted)', Paragraph(escape(scan['url']), st['Cell'])],
            ['Result', Paragraph(f'<font color="{col}"><b>{escape(scan["result"])}</b></font>', st['Cell'])],
            ['Risk score / level', f'{scan["score"]} / 100  ({scan["level"]})'],
            ['Sources', Paragraph(escape(_src(scan['sources'])), st['Cell'])]]
    t = Table(rows, colWidths=[50*mm, 120*mm])
    t.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.4, colors.lightgrey), ('FONTSIZE', (0, 0), (-1, -1), 9),
                           ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke), ('VALIGN', (0, 0), (-1, -1), 'TOP')]))
    el += [t, Spacer(1, 10), Paragraph('Why this result', st['Heading3'])]
    for r in scan['reasons']:
        el.append(Paragraph('&bull; ' + escape(r), st['Normal']))
    el += [Spacer(1, 12), Paragraph('<b>Disclaimer:</b> ' + escape(DISCLAIMER), st['Small'])]
    _doc(buf).build(el)
    return buf.getvalue()


def summary_pdf(scans, date_from=None, date_to=None):
    st, buf = _styles(), io.BytesIO()
    dates = sorted(s['scanned_at'][:10] for s in scans)
    rng = f'{date_from or (dates[0] if dates else "-")} to {date_to or (dates[-1] if dates else "-")}'
    el = [Paragraph(escape(TITLE), st['Title']), Paragraph('Scan history summary', st['Heading2']),
          Paragraph(f'Generated: {_now()}', st['Small']), Paragraph(f'Date range: {rng}', st['Normal']),
          Paragraph(f'Total scans: {len(scans)}', st['Normal']), Spacer(1, 8)]
    cnt = Counter(s['result'] for s in scans)
    t = Table([['Result', 'Count']] + [[k, str(cnt.get(k, 0))] for k in COLORS], colWidths=[80*mm, 30*mm])
    t.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.4, colors.grey), ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                           ('FONTSIZE', (0, 0), (-1, -1), 9)]))
    el += [t, Spacer(1, 10)]
    if scans:
        data = [['Date/time (UTC)', 'URL', 'Result', 'Score']]
        for s in scans[:200]:
            data.append([s['scanned_at'].replace('T', ' ')[:16], Paragraph(escape(s['url'][:90]), st['Cell']),
                         Paragraph(escape(s['result']), st['Cell']), str(s['score'])])
        t2 = Table(data, colWidths=[32*mm, 90*mm, 35*mm, 13*mm], repeatRows=1)
        t2.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey), ('FONTSIZE', (0, 0), (-1, -1), 8),
                                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey), ('VALIGN', (0, 0), (-1, -1), 'TOP')]))
        el.append(t2)
        if len(scans) > 200:
            el.append(Paragraph(f'Showing the latest 200 of {len(scans)} scans.', st['Small']))
    else:
        el.append(Paragraph('No scans in this range.', st['Normal']))
    el += [Spacer(1, 12), Paragraph('<b>Disclaimer:</b> ' + escape(DISCLAIMER), st['Small'])]
    _doc(buf).build(el)
    return buf.getvalue()

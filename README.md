# AI-Powered Phishing URL Detection System - India Edition

A small Flask + scikit-learn web app that checks suspicious links people receive on WhatsApp, SMS, email, UPI/banking messages and Aadhaar/PAN messages. It gives a risk score (0-100), a level (LOW / MEDIUM / HIGH), and plain-English reasons. **It never opens the submitted link.**

Based on the MIT-licensed project [maha-baig/AI-powered-Phishing-Detector](https://github.com/maha-baig/AI-powered-Phishing-Detector). Original LICENSE and copyright are kept. What was changed is listed in [ADAPTATIONS.md](ADAPTATIONS.md). Limits of the project are in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). A speaking guide for the viva is in [VIVA_GUIDE.md](VIVA_GUIDE.md).

## What it does
- Scan a URL, get one of: **Known phishing** (PhishTank verified), **Suspicious**, **No known threat found** (not a guarantee), or **Unable to check** (bad input).
- Three layers: local ML model, transparent rules (IP host, punycode, `@` trick, shortened links, `.apk` downloads, fake Indian brand names such as SBI/HDFC/UPI/Aadhaar/PAN/India Post), optional PhishTank lookup.
- Scan history in SQLite (redacted URL, result, score, time) with Clear history.
- PDF report for a single scan and a summary report for a date range.
- Works with no API key; PhishTank failures never break a scan.

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env      # optional: add PHISHTANK_APP_KEY to .env
python app.py               # open http://127.0.0.1:5000
```
A trained model is included in `models/model.joblib`. To retrain it:
```powershell
python scripts/build_dataset.py            # downloads public data, builds data/dataset.csv
python train.py --data data/dataset.csv    # writes models/model.joblib + models/model_metadata.json
```
If the model file is missing the app shows a setup error and does not guess.

## PhishTank key (optional)
1. Register free at https://phishtank.org/ and confirm your email, then create an application key.
2. Put it in `.env` as `PHISHTANK_APP_KEY=...`. `.env` is git-ignored. Never paste it into code, chat or the browser.
3. In the dashboard keep "Also check PhishTank reputation" ticked. This sends the submitted URL to PhishTank (shown in the UI).
The PhishTank integration is tested with mocked responses only (no real key was available when this was built).

## API
| Endpoint | Purpose |
|---|---|
| `POST /api/scan` `{"url": "...", "use_phishtank": true}` | scan and save to history |
| `GET /predict?url=...` | same scan, kept from the upstream project |
| `GET /api/history`, `DELETE /api/history` | list / clear history |
| `GET /api/report/<id>.pdf` | PDF for one scan |
| `GET /api/report/summary.pdf?from=YYYY-MM-DD&to=YYYY-MM-DD` | summary PDF |
| `GET /health` | health check |

## Tests
```powershell
python -m pytest -q
```

## Settings (environment variables)
`PHISHTANK_APP_KEY`, `CORS_ORIGINS` (empty = no CORS), `RATE_LIMIT_SCAN` (default `30 per minute`), `RATE_LIMIT_DEFAULT`, `HISTORY_DB`, `HOST`, `PORT`.

## Security choices
http/https only, 2048-character limit, query values/credentials/fragments redacted before saving or showing, PhishTank timeout (5 s), rate limiting, CORS off by default, security headers, debug never on, secrets only in `.env`.

## Deploy
See [README_DEPLOY.md](README_DEPLOY.md) (Docker and Render).

## Layout
`app.py` Flask app | `detector.py` validation, rules, model, PhishTank | `features.py` URL features | `train.py`, `scripts/build_dataset.py` training | `db.py` SQLite history | `report.py` PDFs | `dashboard/` web UI | `tests/` | `legacy_upstream/` original upstream scripts, kept for reference and not used.

## License
MIT. Original copyright (c) 2025 maha-baig is preserved in [LICENSE](LICENSE).

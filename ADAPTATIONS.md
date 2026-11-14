# Adaptations record

- Upstream repository: https://github.com/maha-baig/AI-powered-Phishing-Detector (commit a9daf41)
- Upstream license: MIT, Copyright (c) 2025 maha-baig. `LICENSE` is unchanged. This project is NOT written from scratch; it is an adaptation of that code.
- Adaptation date: 2026-11-13
- Adapted by: Dhruva BS (BCA internship project), with coding-agent assistance

## Reused from upstream
- Flask app structure and gunicorn/Docker deployment idea (`app.py`, `Dockerfile`)
- URL feature helpers in `features.py` (IP host, subdomain count, punycode, homoglyph, subdomain spoof) - unchanged
- RandomForest + `train.py` workflow, dashboard folder and logo, CI workflow, CONTRIBUTING/SECURITY files
- `/predict?url=` endpoint (kept for compatibility)

## What was found in upstream
- No trained model file and no dataset were in the repository, so the app could not run as cloned.
- The dashboard loaded `app.js`/`styles.css` with relative paths that failed at `/`, and labelled results "Safe".
- Wildcard CORS, full URLs written to a log file, optional Bing key endpoint.

## Changes made
1. `detector.py` (new): URL validation/normalisation, redaction, rules layer with India-specific rules, ML scoring, optional PhishTank lookup, result logic. Wording "No known threat found" replaces "Safe".
2. `features.py`: added `extract_host_features` (hostname-based features). Existing functions untouched.
3. `train.py`: rewritten to train on a real CSV, split by registered domain, and save real measured metrics to `models/model_metadata.json`.
4. `scripts/build_dataset.py` (new): builds the training CSV from public sources.
5. `app.py`: new `/api/scan`, history, PDF endpoints; rate limiting; CORS off by default; security headers; removed `/logs`, `/examples` (Bing), unauthenticated prediction log; no debug mode.
6. `db.py` (new): SQLite scan history (redacted URLs only) with clear.
7. `report.py` (new): ReportLab PDF for one scan and for a history summary.
8. `dashboard/`: new responsive UI (scan, risk badge, reasons, privacy notice, history, clear, PDF buttons); fixed asset paths.
9. `tests/test_app.py` (new): 43 automated tests.
10. `requirements.txt` pinned; removed unused packages (beautifulsoup4, python-whois, validators). `.env.example`, `.gitignore`, `.dockerignore`, README, README_DEPLOY, KNOWN_LIMITATIONS, VIVA_GUIDE added.
11. Upstream enrichment/tuning scripts moved to `legacy_upstream/` (not used, not tested).

## Dataset
- Phishing (label 1): Phishing.Database ACTIVE links list, MIT licence - https://github.com/Phishing-Database/Phishing.Database (downloaded 2026-11-13). 20,000 unique hostnames, at most 2 per registered domain.
- Benign (label 0): Tranco top-sites list - https://tranco-list.eu (top 50,000, 20,000 randomly sampled, downloaded 2026-11-13).
- Only hostnames are used. The CSV is not committed; `scripts/build_dataset.py` rebuilds it.

## Model and metrics (measured 2026-11-13, from `models/model_metadata.json`)
RandomForestClassifier(n_estimators=100, min_samples_leaf=5), scikit-learn 1.7.2. Held-out 20% test set (7,983 rows), split by registered domain.
Accuracy 0.7941, precision 0.8307, recall 0.7341, F1 0.7794, ROC-AUC 0.8756. Confusion matrix: TN 3434, FP 592, FN 1052, TP 2905.
These numbers describe hostname-only detection on this dataset. They are modest on purpose: no numbers were tuned or invented. See KNOWN_LIMITATIONS.md.

## Tests
See `TEST_RESULTS.txt` (real output of `python -m pytest`).

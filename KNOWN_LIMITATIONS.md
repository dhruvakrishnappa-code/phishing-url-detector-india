# Known limitations

- **Modest accuracy.** The local model uses the hostname only (about 79% accuracy, 73% recall on its own held-out test). It will miss some phishing links and flag some real ones. The rules layer and PhishTank help but do not remove this.
- **Dataset bias.** Benign examples are popular domains from the Tranco list (hostnames only); phishing examples are hostnames from Phishing.Database. Phishing on a hijacked trusted site, or a brand-new real site, can be classified wrongly. The phishing list also contains some noise.
- **Not a guarantee.** "No known threat found" never means safe. New phishing links are not in any database yet.
- **Links are never opened.** So page content, login forms, redirects and shortened-link destinations are not inspected. Shortened links are only flagged.
- **PhishTank is untested with a real key.** It was tested with mocked responses only. PhishTank needs a free key and sends the submitted URL to PhishTank. PhishTank may rate-limit free keys.
- **Indian brand list is small and hand-written** (`INDIA_BRANDS` in `detector.py`). It will not cover every bank or service, and an official domain missing from the list may be flagged wrongly.
- **English / Latin script only.** No SMS-text analysis, only URLs.
- **History is shared and unauthenticated.** Everyone using one deployment sees the same history. Rate limiting is in memory per process.
- **Free hosting (Render free tier) loses the SQLite file on restart.**
- Not tested on Windows by the builder (tested on Linux, Python 3.10); the commands in README are standard.

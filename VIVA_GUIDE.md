# Viva guide - speak from this

**What it is (30 seconds).** A website where you paste a suspicious link from WhatsApp, SMS, email, a UPI or bank message, or an Aadhaar/PAN message. It tells you whether the link is Known phishing, Suspicious, or No known threat found, gives a score from 0 to 100 (LOW / MEDIUM / HIGH), and lists the reasons in plain English. It never opens the link.

**How detection works (three layers).**
1. *Machine learning.* A Random Forest (scikit-learn) looks at the website name: length, hyphens, digits, subdomains, IP address, punycode, odd ending (.xyz, .top), brand words. It outputs a phishing probability.
2. *Rules.* Simple readable checks: IP address instead of a name, "@" trick, shortened link, .apk download, many subdomains, and fake Indian brands (a name with "sbi" or "paytm" that is not the real SBI/Paytm domain), plus urgent words like kyc, verify, refund.
3. *PhishTank (optional).* A free community database of verified phishing sites. If a key is set, the app asks PhishTank. If it is down or no key, the app still works and says "reputation lookup unavailable".
Final score = 70% of the model probability + rule points (max 100). Under 35 LOW, 35-64 MEDIUM, 65+ HIGH. If PhishTank lists the URL, result is Known phishing at 100.

**Why "No known threat found" and not "Safe".** No tool can prove a link is safe. New phishing sites are not in any list yet.

**Technologies.** Python, Flask (web server), scikit-learn (ML), pandas, tldextract (split domain names), requests (PhishTank call), SQLite (history), ReportLab (PDF), HTML/CSS/JavaScript dashboard, gunicorn + Docker (deployment), pytest (tests).

**What came from GitHub.** The base project by maha-baig (MIT licence): Flask app, URL feature helpers, training script idea, dashboard folder, deployment files. The licence and credit are kept. The upstream repo had no trained model and its dashboard did not load properly.

**What I added / changed.** URL validation and redaction; India-specific rules; hostname-based model trained on a public dataset; PhishTank integration with safe fallback; SQLite scan history with clear button; PDF reports (single scan and date-range summary); a new mobile-friendly dashboard; rate limiting, restricted CORS, security headers, no debug mode; 43 automated tests; README, deployment notes, limitations.

**Data and results (be honest).** Phishing: 20,000 hostnames from Phishing.Database (MIT). Benign: 20,000 from the Tranco top sites list. Tested on 7,983 held-out rows, split by website so the same site is never in both train and test: accuracy 79.4%, precision 83.1%, recall 73.4%, ROC-AUC 0.876. The score is modest because only the website name is used.

**How to run.** `python -m venv .venv`, activate, `pip install -r requirements.txt`, `python app.py`, open http://127.0.0.1:5000. Tests: `python -m pytest -q`. Optional key: put PHISHTANK_APP_KEY in `.env`.

**Privacy and safety.** Links are never visited. Query values (OTP, tokens) and passwords in the link are replaced with REDACTED before saving or showing. API key lives only in `.env` on the server. Only http/https accepted, 2048-character limit, rate limit 30 scans/minute.

**Limitations.** Hostname-only model, ~79% accuracy, will miss some and flag some. Cannot see page content or where a short link goes. Small hand-written list of Indian brands. PhishTank part tested with mocked responses, not a real key. History is shared per deployment.

**Likely questions.**
- *Why Random Forest?* Works well on small tabular features, fast, no GPU, easy to explain, gives probabilities.
- *Why not open the link to check?* Opening a phishing link can expose you (malware, tracking) and attackers can detect it.
- *How could it improve?* More training data with full URLs, page-content checks in a sandbox, a bigger brand list, Hindi/Kannada UI.
- *Is it AI?* Yes - machine learning (Random Forest) runs locally; no paid AI service is used.

# Deployment notes

Run locally first (see README.md). Deploy only after `python -m pytest` passes.

## Docker
```powershell
docker build -t phishing-checker .
docker run --rm -p 5000:5000 -e PHISHTANK_APP_KEY=your_key_here phishing-checker
```
Open http://localhost:5000. Leave out `-e PHISHTANK_APP_KEY=...` to run in local-only mode.

## Render (free web service)
1. Push this folder to your own GitHub repository (keep LICENSE and ADAPTATIONS.md).
2. Render dashboard -> New -> Web Service -> connect the repo, Runtime = Docker (it uses the Dockerfile).
3. Environment -> add `PHISHTANK_APP_KEY` (optional) and `CORS_ORIGINS` only if another website must call the API.
4. Health check path: `/health`.
5. Render gives HTTPS automatically.

Notes
- Free instances have no persistent disk: SQLite scan history is lost on restart. That is acceptable for a demo; use a Render disk or a hosted database for real use.
- Built-in rate limiting is per process and in memory (30 scans/minute, 120 requests/hour per IP by default; change with `RATE_LIMIT_SCAN`, `RATE_LIMIT_DEFAULT`). For a busy public site put it behind a proper rate limiter or proxy.
- The scan history is shared by everyone who uses the same deployment. For a public deployment, add a login or keep it private.
- Never turn on Flask debug mode in production. `app.py` never enables it.

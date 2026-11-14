# Security Policy

## Reporting a Vulnerability
- Please create a private security report instead of a public issue.
- Email: open a private contact channel via your GitHub profile or use GitHub Security Advisories if enabled.
- Include clear steps to reproduce, impact, and any logs available.

## Scope
- API endpoints: `/predict`, `/logs`, `/examples`, `/health`, `/version`
- Dashboard served at `/dashboard/`
- Docker image and deployment configuration

## Best Practices
- Set `API_KEY` in production to require `X-API-Key` or `Authorization: Bearer <key>`
- Use HTTPS on the hosting provider (Cloud Run / Railway / Render provide TLS)
- Apply rate limiting and logging retention
- Rotate credentials regularly

## Disclosure
- Please allow reasonable time for triage and remediation before public disclosure.

# Contributing

Thanks for your interest in contributing! This project is a Python Flask API with a simple web dashboard for phishing URL detection.

## Getting Started
- Python 3.11+
- PowerShell:
  - `python -m venv .venv`
  - `.\.venv\Scripts\Activate.ps1`
  - `pip install -r requirements.txt`
- Optional: Train a model
  - `python train.py` (outputs to `models/`)

## Branching and Commits
- Create feature branches from `main`: `git checkout -b feat/<short-name>`
- Use conventional commits:
  - `feat:` new feature
  - `fix:` bug fix
  - `docs:` docs only changes
  - `chore:` tooling/config/non-prod changes
  - `refactor:` code improvement without behavior change

## Pull Requests
- Keep PRs focused and small
- Include a short description of changes and rationale
- Ensure the server starts: `python -c "import app"`
- Avoid committing large datasets or secrets

## Code Style
- Python: idiomatic, clear names, no secrets in logs
- Avoid adding heavy dependencies unless justified
- Keep public endpoints secured with `API_KEY` when deploying

## Reporting Issues
- Use the provided issue templates
- Include reproducible steps and expected vs actual behavior


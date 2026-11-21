# Contributing to ForensicLens

Thank you for helping improve **ForensicLens**!

## Local Development Setup (Windows 11 PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Start the local stack:

```powershell
docker compose up -d
docker exec -it forensic-ollama ollama pull llama3.2
uvicorn src.app:app --host 127.0.0.1 --port 8000 --reload
```

## Running Tests

```powershell
pytest -v
```

## Adding a New Sigma Rule

1. Open `src/sigma_triage.py` and append a new `SigmaRuleDefinition` entry to `SIGMA_RULES`.
2. Include:
   - Unique `rule_id` (`fl-sigma-XXX`)
   - Clear plain-English `title` and `description`
   - `severity` (`critical`, `high`, `medium`, or `low`)
   - MITRE ATT&CK `mitre_tactic` and `mitre_technique`
   - Valid `sigma_yaml` and equivalent OpenSearch `dsl_query`
3. Add a test case in `tests/test_forensiclens.py` and verify with `pytest -v`.

## Pull Request Guidelines

- Keep frontend changes in `static/index.html` zero-build (no Node.js build step required on Windows).
- Never render untrusted log text using `innerHTML`; always use safe DOM `textContent` nodes.
- Ensure all paths use `pathlib.Path` for cross-platform compatibility.

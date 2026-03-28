---
applyTo: "**/*"
---

# ldapmap developer notes for Copilot

- This is a Python CLI project (single-module entry point: `ldapmap.py`).
- Keep changes focused and minimal; avoid refactors unless required for the task.
- Prefer updating existing modules over introducing new dependencies.

## Validate changes

From repository root:

1. Install dependencies:
   - `pip install -e . pytest`
2. Run tests:
   - `python -m pytest -q`

## Project layout

- `ldapmap.py` - CLI argument parsing and orchestration.
- `ldapmap_engine.py` - core detection/discovery/extraction logic.
- `ldapmap_http.py` - HTTP request helpers.
- `ldapmap_payloads.py` / `ldapmap_constants.py` - payload/constants support.
- `tests/` - pytest suite.
- `.github/workflows/` - CI and Copilot setup workflows.

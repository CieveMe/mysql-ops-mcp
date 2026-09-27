# Contributing

Thanks for considering a contribution. This project is a small, security-sensitive tool, so the
review bar for changes to the SQL guard or the tool registration policy is deliberately high.

## Getting set up

```bash
git clone https://github.com/CieveMe/mysql-ops-mcp
cd mysql-ops-mcp
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q          # 24 cases, no database required
```

The test suite covers the guardrail in isolation (`safety.py`), so it runs without MySQL, SSH or any
credentials. Please keep it that way: a test that needs a real database cannot run in CI and will be
asked to change.

## Reporting a security issue

Do **not** open a public issue for a bypass of the read-only guard. Send a private report to the
maintainer through GitHub's private vulnerability reporting (Security → Report a vulnerability) or by
email, including the exact statement or tool call that bypasses the guard and the version you tested.
Public issues are fine for everything else.

## What a good pull request looks like

1. One behaviour change per pull request, with the motivation in the description.
2. A test that fails before the change and passes after it. For guard changes, include at least one
   *rejected* case and one *accepted* case: widening the whitelist is as much a change as narrowing it.
3. No new dependency unless it removes more risk than it adds. The server deliberately has no
   `sshtunnel` dependency and no ORM.
4. Environment variables for anything configurable. No credentials, hostnames or paths in the source.
5. `python -m pytest tests -q` green, and the README updated if the tool surface changed.

## Style

- Python 3.10+, standard library first, type hints on new public functions.
- Keep the guard (`safety.py`) free of I/O so it stays trivially testable.
- Comments explain *why* a check exists; the *what* is in the tests.

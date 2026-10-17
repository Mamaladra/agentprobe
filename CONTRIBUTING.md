# Contributing to Grazwall

Thanks for helping make agents safer.

## Ground rules
- **License.** Contributions are under Apache-2.0 (inbound = outbound). Sign off each commit (`git commit -s`, [DCO](https://developercontributorcertificate.org/)).
- **Dependencies.** The core has **zero runtime dependencies**. Dev dependencies must be MIT, Apache-2.0 or BSD. No GPL, AGPL or MPL.
- **Never execute target output.** Server content is matched against oracles only, never `eval`/`exec`/shell.
- **No remote LLM or network calls** from the scanner. Probes must work with network off.

## Adding a check
1. Write `check_xxx(ctx) -> list[Finding]` in `src/grazwall/checks.py` and add it to `ALL_CHECKS`.
2. Use the next free `APxxx` id and include a one-line docstring (shown by `grazwall checks`).
3. Prove it on a demo server: a true positive on `demo/vulnerable_server.py` (or a new demo) **and** no finding
   on `demo/safe_server.py`. False positives count as bugs.
4. Live probes must be non-destructive. Skip tools named delete/drop/transfer/exec unless that is the point of the check.
5. Consider capability profiles: is this capability expected for some server types? Update `profiles.py`.

## Before opening a PR
```bash
pytest -q
ruff check src/grazwall tests
bandit -r src/grazwall -c bandit.yaml -ll
pipx run pip-audit
```

## Reporting security issues
Please **don't** open a public issue. Follow [SECURITY.md](SECURITY.md).

## Scanning third-party servers
Only scan servers you are allowed to test. Disclose findings privately to maintainers first. Never post raw scan output of someone else's server in issues.

# Grazwall: CI for AI agent security

[![Grazwall](https://img.shields.io/badge/Grazwall-A-22c55e)](#badge)

Grazwall red-teams **MCP servers** in a hardened sandbox and fails your build when a server would leak
secrets, escape its root or poison your agent. **Grazforge** scaffolds a secure-by-default MCP server that passes on day one.

> Formerly **AgentProbe**. The project was renamed to Grazwall in October 2026; the old `Mamaladra/agentprobe` links redirect here.

- **MCP-first, model-agnostic.** Works with stdio (Node, Python, Go, Rust…) and streamable HTTP.
- **Zero runtime dependencies.** Python ≥ 3.10.
- **Hostile-by-default.** bubblewrap sandbox, no network, no inherited secrets, canaries instead of guesses.

## 30-second start
```bash
pip install grazwall            # pre-release: pip install git+<this repo>
grazwall scan "node dist/index.js" --fail-on high
grazwall scan "python demo/vulnerable_server.py" --html report.html    # grade F
grazwall scan "python demo/safe_server.py"                             # grade A
grazforge new my-server && grazforge check "python my-server/server.py"
```

## GitHub Action
```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: {python-version: "3.12"}
- uses: grazwall/grazwall-action@v0    # this repo
  with:
    target: "node dist/index.js"
    profile: auto          # or filesystem, git, database, shell, http, memory…
    fail-on: high
```
Outputs `score` and `grade`, writes a job summary and uploads `grazwall.json` + `grazwall.html`.

## Checks in the open core
| ID | Check | Mode |
|---|---|---|
| AP001 / AP002 | Prompt injection in tool descriptions / parameter schemas | static |
| AP003 | Hidden zero-width / bidi / tag unicode | static |
| AP004 | Secrets in tool metadata | static |
| AP005 | Over-permissive capabilities (**profile-aware**) | static |
| AP006 / AP007 | Missing / permissive input schema | static |
| AP008 | Path traversal (schema-targeted) | live |
| AP012 / AP013 | Secret leak / stack trace in errors | live |
| AP018 | Rug pull: tool definitions change after listing | live |
| AP019 | Env secret exfiltration (canary) | live |
| AP020 / AP021 | Tool shadowing; exfiltration instructions | static |
| AP023 | Confused deputy (caller-controlled role/tenant) | static |
| AP029 | Sandbox-root escape (canary file outside the server root) | live |
| AP030 | Overspend: caller-set budget, no server-side cap, negative amounts | live |
| AP031 | AP2: payment tool missing mandate binding / mismatched mandate accepted | mixed |
| AP032 | AP2: cart substitution (charged amount not bound to the cart) | live |
| AP033 | AP2: mandate / nonce replay accepted | live |
| AP034 | AP2: human-not-present overreach (uncapped autonomous charge) | live |

**Grazwall Pro** adds command injection, eval, SSRF, memory poisoning and cross-tenant bleed, indirect
injection in outputs/resources/prompts, HTTP auth, data-volume and rate-limit probes, the adaptive attacker
(rules or a local LLM), weekly attack packs, hosted runners and signed reports. Packs plug in through the
`grazwall.packs` entry point, so the CLI and Action stay the same.

## Capability profiles
A filesystem server exposing `read_file` is fine. A filesystem server exposing `exec` is not. `--profile auto`
detects the server's purpose. Expected capabilities are reported as `info`, and anything outside the profile
keeps its severity. Exploit findings (traversal, root escape, leaks) are never downgraded.

## Sandbox
Stdio targets run under bubblewrap: new user/pid/ipc/uts/net namespaces, read-only root, tmpfs over `/home`
`/root` `/tmp` `/run` `/var` `/workspace`, minimal env, rlimits, and process-group kill. Containment is covered by
tests (`tests/test_profiles_escape.py`). See [SECURITY.md](SECURITY.md).

⚠️ Live probes really call your tools. Scan dev builds you own, never production data.

## Develop
```bash
pip install -e ".[dev]" && pytest -q && ruff check src/grazwall tests && bandit -r src/grazwall -c bandit.yaml -ll && pipx run pip-audit
```

## License
Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

import argparse
import json
import sys

from . import checks, report
from . import client as mcp

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def scan(target, json_out=None, html_out=None, fail_on=None, min_score=None, quiet=False,
         sandbox_mode="auto", network=False, adaptive=False, adaptive_provider="rule",
         allow_paths=None, workdir=None, profile="auto"):
    env = {"AGENTPROBE_CANARY": checks.CANARY}
    # Never leak real secrets into the target: only our canary + PATH/LANG etc. via sandbox.
    kw = {}
    if not target.startswith(("http://", "https://")):
        kw = dict(sandbox_mode=sandbox_mode, network=network, allow_paths=allow_paths or (),
                  workdir=workdir)
    from . import profiles as prof
    declared = prof.parse(profile) if profile != "auto" else "auto"
    c = mcp.connect(target, env=env, **kw)
    run_meta = {}
    try:
        findings, tools = checks.run_all(c, profiles="auto" if declared is None else declared,
                                         reconnect=lambda: mcp.connect(target, env=env, **kw), meta=run_meta)
        c = run_meta.pop("client", c)
        if adaptive:
            try:
                from agentprobe_pro import attacker  # commercial pack
            except ImportError:
                raise SystemExit("agentprobe: --adaptive needs the agentprobe-pro pack (see README)") from None
            findings.extend(attacker.run_adaptive(_ctx(c, tools),
                                                  attacker.make_provider(adaptive_provider)))
        meta = {"sandbox": getattr(c, "sandbox_mode", "n/a"), **run_meta,
                "adaptive": adaptive, "server_requests_refused": getattr(c, "server_requests", [])[:20]}
        r = report.build(target, c.server_info, tools, findings, meta)
    finally:
        c.close()
    if json_out:
        with open(json_out, "w") as f:
            json.dump(r, f, indent=2)
    if html_out:
        with open(html_out, "w") as f:
            f.write(report.to_html(r))
    if not quiet:
        print(f"AgentProbe: {r['server'].get('name','?')}  tools={r['tool_count']}  "
              f"score={r['score']}/100  grade={r['grade']}  sandbox={r['meta'].get('sandbox')}  "
              f"profile={','.join(r['meta'].get('profiles') or []) or 'none'} ({r['meta'].get('profile_source')})")
        for f in r["findings"]:
            print(f"  [{f['severity'].upper():8}] {f['check_id']} {f['title']}  ({f['tool'] or '-'})")
    code = 0
    if fail_on:
        th = SEV_ORDER.index(fail_on)
        if any(SEV_ORDER.index(f["severity"]) >= th for f in r["findings"]):
            code = 1
    if min_score is not None and r["score"] < min_score:
        code = 1
    return r, code


def _ctx(c, tools):
    ctx = checks.Context.__new__(checks.Context)
    ctx.client = c
    ctx.tools = tools
    return ctx


def agentprobe_main(argv=None):
    ap = argparse.ArgumentParser(prog="agentprobe", description="Red-team MCP servers & agent memory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an MCP server: a stdio command (quoted) or an http(s) URL")
    s.add_argument("target")
    s.add_argument("--json", dest="json_out")
    s.add_argument("--html", dest="html_out")
    s.add_argument("--fail-on", choices=SEV_ORDER, help="CI gate: exit 1 if any finding >= severity")
    s.add_argument("--min-score", type=int, help="CI gate: exit 1 if score below this")
    s.add_argument("--sandbox", choices=["auto", "bwrap", "unshare", "none"], default="auto",
                   help="sandbox for stdio targets (default: auto = bwrap if available)")
    s.add_argument("--network", action="store_true", help="allow network inside the sandbox (off by default)")
    s.add_argument("--adaptive", action="store_true", help="adaptive attacker (requires agentprobe-pro)")
    s.add_argument("--adaptive-provider", choices=["rule", "local-llm"], default="rule",
                   help="rule (offline) or local-llm (localhost only; set AGENTPROBE_LLM_URL)")
    s.add_argument("--allow-path", action="append", default=[], help="extra read-only path bind into sandbox")
    s.add_argument("--profile", default="auto",
                   help="capability profile(s): auto (default, detect), none, or comma list of "
                        "filesystem,git,database,shell,http,fetch,browser,memory,secrets. Expected "
                        "capabilities are reported as info; unexpected ones keep their severity")
    s.add_argument("--workdir", help="working directory for the target (bound into sandbox)")
    sub.add_parser("checks", help="list checks")
    a = ap.parse_args(argv)
    if a.cmd == "checks":
        for chk in checks.ALL_CHECKS:
            print(f"{chk.__name__:40} {(chk.__doc__ or '').strip().splitlines()[0] if chk.__doc__ else ''}")
        return 0
    _, code = scan(a.target, a.json_out, a.html_out, a.fail_on, a.min_score,
                   sandbox_mode=a.sandbox, network=a.network, adaptive=a.adaptive,
                   adaptive_provider=a.adaptive_provider, allow_paths=a.allow_path, workdir=a.workdir,
                   profile=a.profile)
    return code


if __name__ == "__main__":
    sys.exit(agentprobe_main())

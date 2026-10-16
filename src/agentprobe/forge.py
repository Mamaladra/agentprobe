"""MCPForge (free): scaffold a secure-by-default MCP server and run a basic AgentProbe check."""
import argparse
import os
import sys
from importlib import resources

from . import checks, report
from . import client as mcp

FREE_CHECKS = [checks.check_injection_in_descriptions, checks.check_hidden_unicode,
               checks.check_secrets_in_metadata, checks.check_missing_schema, checks.check_overpermissive_naming]

def new(name, dest="."):
    if not name.replace("-", "").replace("_", "").isalnum():
        raise SystemExit("name must be alphanumeric/-/_")
    root = os.path.join(dest, name)
    os.makedirs(os.path.join(root, ".github", "workflows"), exist_ok=False)
    t = resources.files("agentprobe") / "templates"
    open(os.path.join(root, "server.py"), "w").write((t / "server.py.tmpl").read_text().format(name=name))
    open(os.path.join(root, "mcp_runtime.py"), "w").write((t / "mcp_runtime.py").read_text())
    open(os.path.join(root, ".github", "workflows", "agentprobe.yml"), "w").write((t / "agentprobe.yml").read_text())
    open(os.path.join(root, "README.md"), "w").write(
        f"# {name}\n\nMCP server scaffolded by MCPForge.\n\n- Run: `python server.py`\n"
        f"- Basic check: `mcpforge check \"python server.py\"`\n- Full red-team: `agentprobe scan \"python server.py\" --html report.html`\n")
    return root

def basic_check(target):
    c = mcp.connect(target)
    try:
        ctx = checks.Context(c)
        fs = [f for chk in FREE_CHECKS for f in chk(ctx)]
    finally:
        c.close()
    return fs, report.score(fs)

def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcpforge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    n = sub.add_parser("new")
    n.add_argument("name")
    n.add_argument("--dir", default=".")
    n.add_argument("--no-check", action="store_true")
    k = sub.add_parser("check")
    k.add_argument("target")
    a = ap.parse_args(argv)
    if a.cmd == "new":
        root = new(a.name, a.dir)
        print(f"Created {root}")
        if a.no_check:
            return 0
        target = f'{sys.executable} {os.path.join(root, "server.py")}'
    else:
        target = a.target
    fs, s = basic_check(target)
    print(f"MCPForge basic check: {len(fs)} issue(s), score {s}/100 ({len(FREE_CHECKS)} of {len(checks.ALL_CHECKS)} checks)")
    for f in fs:
        print(f"  [{f.severity}] {f.check_id} {f.title} ({f.tool})")
    print("Run the full live red-team (injection, SSRF, memory poisoning, secrets...): agentprobe scan \"<cmd>\" --html report.html")
    sys.exit(1 if any(f.severity in ("high", "critical") for f in fs) else 0)

if __name__ == "__main__":
    sys.exit(main())

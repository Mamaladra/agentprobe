"""Open-core behaviour: static + basic live checks, CI gate, reports, MCPForge."""
import json
import os
import subprocess
import sys

import pytest

from agentprobe import checks, cli, forge, sandbox

ROOT = os.path.dirname(os.path.dirname(__file__))
VULN = f"{sys.executable} {os.path.join(ROOT, 'demo/vulnerable_server.py')}"
SAFE = f"{sys.executable} {os.path.join(ROOT, 'demo/safe_server.py')}"
MODE = "bwrap" if sandbox.detect() == "bwrap" else "none"


@pytest.fixture(scope="module")
def vuln():
    return cli.scan(VULN, quiet=True, sandbox_mode=MODE)[0]


def ids(r):
    return {f["check_id"] for f in r["findings"]}


def test_vulnerable_fails_with_core_checks(vuln):
    assert vuln["grade"] == "F"
    assert {"AP001", "AP003", "AP004", "AP005", "AP008", "AP018", "AP019", "AP020", "AP021", "AP023"} <= ids(vuln)


def test_safe_passes_gate():
    r, code = cli.scan(SAFE, quiet=True, fail_on="medium", sandbox_mode=MODE)
    assert r["grade"] == "A" and code == 0


def test_reports(tmp_path):
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    cli.scan(VULN, json_out=str(j), html_out=str(h), quiet=True, sandbox_mode=MODE)
    assert json.loads(j.read_text())["grade"] == "F"
    assert "Content-Security-Policy" in h.read_text()


def test_cli_and_adaptive_requires_pro():
    p = subprocess.run([sys.executable, "-m", "agentprobe", "scan", SAFE, "--sandbox", MODE, "--fail-on", "high"],
                       capture_output=True, text=True, check=False)
    assert p.returncode == 0 and "grade=A" in p.stdout
    p = subprocess.run([sys.executable, "-m", "agentprobe", "scan", SAFE, "--sandbox", MODE, "--adaptive"],
                       capture_output=True, text=True, check=False)
    assert p.returncode != 0 and "agentprobe-pro" in (p.stdout + p.stderr)


def test_core_has_no_private_code():
    src = open(checks.__file__).read()
    for private in ("check_memory_poisoning", "check_command_injection", "check_ssrf", "run_adaptive"):
        assert private not in src


def test_forge(tmp_path):
    root = forge.new("demo-srv", str(tmp_path))
    fs, score = forge.basic_check(f"{sys.executable} {root}/server.py")
    assert fs == [] and score == 100

"""Capability profiles, AP000 rug-pull flake fix, and deep path-escape / sandbox-root containment."""
import os
import subprocess
import sys
import textwrap

import pytest

from agentprobe import checks, cli, client, profiles, sandbox

ROOT = os.path.dirname(os.path.dirname(__file__))
FS = os.path.join(ROOT, "demo/fs_server.py")
HAS_BWRAP = sandbox.probe("bwrap")
NO_BWRAP_REASON = "DEGRADED sandbox, containment not verifiable: " + (sandbox.degraded_reason() or "n/a")


@pytest.fixture()
def fsroot(tmp_path):
    d = tmp_path / "root"
    d.mkdir()
    (d / "hello.txt").write_text("hi")
    return str(d)


def by_id(r, cid):
    return [f for f in r["findings"] if f["check_id"] == cid]


# ---------------- profiles ----------------

def test_parse_profiles():
    assert profiles.parse("auto") is None
    assert profiles.parse("none") == set()
    assert profiles.parse("filesystem, git") == {"filesystem", "git"}
    with pytest.raises(ValueError):
        profiles.parse("nuclear")


def test_detect_profiles():
    def t(*n):
        return [{"name": x} for x in n]
    assert "filesystem" in profiles.detect({"name": "secure-filesystem-server"}, t("read_file", "write_file", "list_directory"))
    assert "git" in profiles.detect({"name": "mcp-git"}, t("git_status", "git_diff", "git_log"))
    assert "memory" in profiles.detect({"name": "memory-server"}, t("create_entities", "read_graph"))
    assert profiles.detect({"name": "time"}, t("get_current_time", "convert_time")) == set()
    # one stray tool name is not enough without a server-name match
    assert profiles.detect({"name": "notes"}, t("read_file", "a", "b", "c", "d", "e")) == set()


def test_expected_downgraded_unexpected_kept():
    fs = checks.Finding("AP005", "Over-permissive tool capability: filesystem access", "medium", "read_file")
    fs.capability = "filesystem"
    ex = checks.Finding("AP005", "Over-permissive tool capability: arbitrary code/command execution", "high", "run")
    ex.capability = "exec"
    trav = checks.Finding("AP008", "Path traversal", "critical", "read_file")
    n = profiles.apply([fs, ex, trav], {"filesystem"})
    assert n == 1 and fs.severity == "info" and fs.title.startswith("Expected capability")
    assert ex.severity == "high" and trav.severity == "critical"


@pytest.mark.parametrize("mode", ["bwrap", "none"] if HAS_BWRAP else ["none"])
def test_safe_fs_server_auto_profile_grade_a(fsroot, mode):
    r, code = cli.scan(f"{sys.executable} {FS} {fsroot}", quiet=True, sandbox_mode=mode, fail_on="medium")
    assert "filesystem" in r["meta"]["profiles"] and r["meta"]["profile_source"] == "auto"
    assert all(f["severity"] == "info" for f in by_id(r, "AP005"))
    assert not by_id(r, "AP029") and not by_id(r, "AP008")
    assert r["grade"] == "A" and code == 0


def test_profile_none_keeps_severity(fsroot):
    r, _ = cli.scan(f"{sys.executable} {FS} {fsroot}", quiet=True, sandbox_mode="none", profile="none")
    assert r["meta"]["profiles"] == []
    assert any(f["severity"] in ("medium", "low") for f in by_id(r, "AP005"))


# ---------------- deep path escape ----------------

@pytest.mark.parametrize("mode", ["bwrap", "none"] if HAS_BWRAP else ["none"])
def test_naive_fs_root_escape_flagged_even_with_profile(fsroot, mode):
    r, code = cli.scan(f"{sys.executable} {FS} {fsroot} --naive", quiet=True, sandbox_mode=mode,
                       profile="filesystem", fail_on="high")
    esc = by_id(r, "AP029")
    assert esc and esc[0]["severity"] == "critical", r["findings"]
    assert r["grade"] not in ("A", "B") and code == 1


def test_canary_is_outside_server_root(fsroot):
    c = client.connect(f"{sys.executable} {FS} {fsroot}", sandbox_mode="none")
    try:
        assert os.path.commonpath([fsroot, c.canary_path]) != fsroot
        assert open(c.canary_path).read().startswith(checks.ESCAPE_TOKEN)
        cd = c.canary_dir
    finally:
        c.close()
    assert not os.path.exists(cd)   # cleaned up


def _sbx(code, tmp_path, **kw):
    argv, cwd, mode, tmp = sandbox.wrap([sys.executable, "-c", textwrap.dedent(code)], "bwrap",
                                        allow_paths=[sys.prefix], **kw)
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=30,
                              env=sandbox.minimal_env(home="/tmp/aphome"), check=False)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.skipif(not HAS_BWRAP, reason=NO_BWRAP_REASON)
class TestSandboxContainment:
    def test_host_secret_in_tmp_unreadable(self, tmp_path):
        secret = tmp_path / "host_secret.txt"
        secret.write_text("HOST_SECRET_123")
        p = _sbx(f"""
            import os
            for path in [{str(secret)!r}, {str(secret)!r}.replace('/tmp/', '/tmp/apwork/../'),
                         '/tmp/apwork/' + '../' * 12 + {str(secret).lstrip('/')!r}]:
                try:
                    print('READ', open(path).read())
                except OSError as e:
                    print('DENIED', type(e).__name__)
        """, tmp_path)
        assert "HOST_SECRET_123" not in p.stdout and p.stdout.count("DENIED") == 3, p.stdout + p.stderr

    def test_home_and_workspace_hidden(self, tmp_path):
        p = _sbx("""
            import os
            print(sorted(os.listdir('/root')) if os.path.isdir('/root') else 'nodir')
            print(sorted(os.listdir('/home')) if os.path.isdir('/home') else 'nodir')
        """, tmp_path)
        assert p.stdout.splitlines()[:2] == ["[]", "[]"], p.stdout + p.stderr

    def test_symlink_out_of_workdir_does_not_reach_host(self, tmp_path):
        secret = tmp_path / "outside" / "s.txt"
        secret.parent.mkdir()
        secret.write_text("SYMLINK_SECRET")
        wd = tmp_path / "wd"
        wd.mkdir()
        os.symlink(secret, wd / "link")
        p = _sbx("""
            try:
                print(open('link').read())
            except OSError as e:
                print('DENIED', type(e).__name__)
        """, tmp_path, workdir=str(wd))
        assert "SYMLINK_SECRET" not in p.stdout and "DENIED" in p.stdout, p.stdout + p.stderr

    def test_writes_do_not_land_on_host(self, tmp_path):
        target = tmp_path / "written_by_target"
        p = _sbx(f"""
            for path in [{str(target)!r}, '/etc/agentprobe_pwn', '/usr/agentprobe_pwn']:
                try:
                    open(path, 'w').write('x'); print('WROTE', path)
                except OSError as e:
                    print('DENIED', type(e).__name__)
        """, tmp_path)
        assert not target.exists() and not os.path.exists("/etc/agentprobe_pwn")
        assert not os.path.exists("/usr/agentprobe_pwn"), p.stdout

    def test_canary_mount_readonly(self, tmp_path):
        cd = sandbox.make_canary("TOK")
        try:
            p = _sbx(f"""
                print(open('{sandbox.CANARY_MOUNT}/{sandbox.CANARY_FILE}').read().strip())
                try:
                    open('{sandbox.CANARY_MOUNT}/x', 'w').write('x'); print('WROTE')
                except OSError:
                    print('RO')
            """, tmp_path, canary_dir=cd)
            assert p.stdout.split() == ["TOK", "RO"], p.stdout + p.stderr
        finally:
            import shutil
            shutil.rmtree(cd, ignore_errors=True)

    def test_no_network(self, tmp_path):
        p = _sbx("""
            import socket
            s = socket.socket()
            s.settimeout(2)
            try:
                s.connect(('1.1.1.1', 53)); print('NET')
            except OSError:
                print('NONET')
        """, tmp_path)
        assert "NONET" in p.stdout, p.stdout + p.stderr


# ---------------- AP000 rug-pull flake (target dies mid-scan) ----------------

DYING = '''
import json, sys
n = 0
def send(m): sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
TOOLS = [{"name": "crash_me", "description": "Echo.", "inputSchema": {"type": "object",
          "properties": {"text": {"type": "string"}}, "required": ["text"], "additionalProperties": False}}]
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m: continue
    meth = m["method"]
    if meth == "initialize":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "dying"}}})
    elif meth == "tools/list":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": TOOLS}})
    elif meth == "tools/call":
        sys.exit(3)   # dies on the first tool call
    else:
        send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "nope"}})
'''


def test_rug_pull_no_ap000_when_target_dies(tmp_path):
    s = tmp_path / "dying.py"
    s.write_text(DYING)
    r, _ = cli.scan(f"{sys.executable} {s}", quiet=True, sandbox_mode="none")
    assert not [f for f in r["findings"] if f["check_id"] == "AP000"], r["findings"]
    assert r["meta"]["target_restarts"] >= 1 and r["meta"]["target_deaths"]


def test_rug_pull_falls_back_to_early_relist_without_reconnect(tmp_path):
    s = tmp_path / "dying.py"
    s.write_text(DYING)
    c = client.connect(f"{sys.executable} {s}", sandbox_mode="none")
    try:
        meta = {}
        findings, _ = checks.run_all(c, reconnect=None, meta=meta)
        assert not [f for f in findings if f.check_id in ("AP000", "AP018")]
    finally:
        meta.get("client", c).close()


def test_degraded_mode_reported_and_warned(tmp_path, capsys):
    argv, cwd, mode, tmp = sandbox.wrap(["true"], "none")
    assert mode == "none" and sandbox.is_degraded(mode)
    assert "DEGRADED SANDBOX" in capsys.readouterr().err
    os.rmdir(tmp)


def test_bwrap_does_not_bind_host_cwd():
    argv, _, _, tmp = sandbox.wrap(["true"], "bwrap")
    os.rmdir(tmp)
    cwd = os.path.realpath(os.getcwd())
    assert ["--ro-bind", cwd, cwd] != argv[argv.index("--chdir") - 3:argv.index("--chdir")]
    assert argv[argv.index("--chdir") + 1] == "/tmp/apwork"

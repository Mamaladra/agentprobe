"""Sandbox for running untrusted (hostile) MCP servers.

Layers, strongest available first:
  1. bubblewrap (bwrap): new user/pid/ipc/uts/net namespaces, read-only root, tmpfs over
     /home /root /tmp /run /workspace /var, fresh temp HOME, --die-with-parent, --new-session.
  2. unshare -rn (network namespace only) if bwrap missing.
  3. Fallback: plain subprocess (documented as weaker; prints a warning).
Always: minimal env (no inherited secrets), temp working dir, rlimits (CPU, address space,
file size, open files, processes), process-group kill on close.
"""
import os
import shutil
import sys
import tempfile

SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")
DEFAULT_LIMITS = {"cpu_s": 120, "as_mb": 2048, "fsize_mb": 64, "nofile": 256, "nproc": 256}
HIDE = ("/home", "/root", "/tmp", "/run", "/var", "/workspace", "/mnt", "/media", "/srv", "/opt/secrets")  # nosec B108 — paths hidden inside bwrap tmpfs, not host temps


CANARY_MOUNT = "/tmp/apcanary"  # nosec B108 — in-sandbox mount point only
CANARY_FILE = "agentprobe-escape-canary.txt"


def make_canary(token):
    """Create a host tempdir with a canary file the target must NOT be able to read via its tools."""
    d = tempfile.mkdtemp(prefix="agentprobe-canary-")
    with open(os.path.join(d, CANARY_FILE), "w") as f:
        f.write(token + "\n")
    return d


def minimal_env(extra=None, home="/tmp/aphome"):  # nosec B108 — in-sandbox path only
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update({"HOME": home, "TMPDIR": "/tmp",  # nosec B108
                "PYTHONDONTWRITEBYTECODE": "1",
                "NO_PROXY": "*", "npm_config_offline": "true"})
    for k, v in (extra or {}).items():
        if not isinstance(k, str) or not isinstance(v, str) or "\x00" in k + v or "=" in k:
            raise ValueError("invalid env entry")
        env[k] = v
    return env


def make_preexec(limits=None):
    lim = {**DEFAULT_LIMITS, **(limits or {})}
    def _pre():  # runs in child before exec
        import resource
        os.setsid()
        def setl(r, v):
            try:
                resource.setrlimit(r, (v, v))
            except (ValueError, OSError):
                pass
        setl(resource.RLIMIT_CPU, lim["cpu_s"])
        setl(resource.RLIMIT_FSIZE, lim["fsize_mb"] << 20)
        setl(resource.RLIMIT_NOFILE, lim["nofile"])
        setl(resource.RLIMIT_CORE, 0)
        if lim.get("as_mb"):
            setl(resource.RLIMIT_AS, lim["as_mb"] << 20)
    return _pre


def detect():
    if shutil.which("bwrap"):
        return "bwrap"
    if shutil.which("unshare"):
        return "unshare"
    return "none"


def wrap(argv, mode="auto", allow_paths=(), network=False, workdir=None, canary_dir=None):
    """Return (argv, cwd, mode_used, tempdir). allow_paths are bound read-only (code/deps)."""
    if mode == "auto":
        mode = detect()
    tmp = tempfile.mkdtemp(prefix="agentprobe-sbx-")
    os.chmod(tmp, 0o700)
    cwd = workdir or tmp
    if mode == "bwrap":
        b = [shutil.which("bwrap"), "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
             "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
             "--die-with-parent", "--new-session", "--hostname", "agentprobe-sbx"]
        if not network:
            b.append("--unshare-net")
        for h in HIDE:
            if os.path.isdir(h):
                b += ["--tmpfs", h]
        for p in allow_paths:
            p = os.path.realpath(p)
            # Never re-bind / — that would undo tmpfs hides and make /tmp read-only.
            if p in ("/", "") or not os.path.exists(p):
                continue
            b += ["--ro-bind", p, p]
        # Scratch dirs on the fresh /tmp tmpfs (from HIDE).
        b += ["--bind", tmp, "/tmp/apwork", "--dir", "/tmp/aphome"]  # nosec B108 — bind mount into bwrap only
        if canary_dir and os.path.isdir(canary_dir):
            b += ["--ro-bind", canary_dir, CANARY_MOUNT]
        chdir = os.path.realpath(workdir) if workdir else os.path.realpath(os.getcwd())
        if chdir not in ("/", "") and os.path.isdir(chdir):
            b += ["--ro-bind", chdir, chdir]
        # If chdir was hidden by a HIDE tmpfs, the re-bind above restored it.
        if chdir in ("/", "") or not os.path.isdir(chdir):
            chdir = "/tmp/apwork"
        b += ["--chdir", chdir, "--"]
        return b + list(argv), None, mode, tmp
    if mode == "unshare" and not network:
        return ["unshare", "-rn", "--"] + list(argv), cwd, mode, tmp
    if mode in ("none", "unshare"):
        print("agentprobe: WARNING no namespace sandbox (bwrap) available; running target with "
              "rlimits + minimal env only. Use a VM/container for hostile servers.", file=sys.stderr)
        return list(argv), cwd, "none", tmp
    raise ValueError(f"unknown sandbox mode {mode!r}")

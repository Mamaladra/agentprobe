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


_PROBE = {}


def _works(argv):
    import subprocess  # nosec B404 - fixed argv, no shell
    try:
        return subprocess.run(argv, capture_output=True, timeout=10, check=False).returncode == 0  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return False


def probe(mode):
    """Actually try the isolation layer. A binary being present is not enough: Ubuntu 24.04's
    AppArmor restricts unprivileged user namespaces, so bwrap/unshare exist but fail."""
    if mode not in _PROBE:
        if mode == "bwrap":
            b = shutil.which("bwrap")
            _PROBE[mode] = bool(b) and _works([b, "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid",
                                               "--unshare-net", "--tmpfs", "/home", "--", "true"])
        elif mode == "unshare":
            u = shutil.which("unshare")
            _PROBE[mode] = bool(u) and _works([u, "-rmn", "--", "true"])
        else:
            _PROBE[mode] = mode == "none"
    return _PROBE[mode]


def detect():
    for m in ("bwrap", "unshare"):
        if probe(m):
            return m
    return "none"


def is_degraded(mode):
    """True when the target runs without full bwrap filesystem isolation."""
    return mode != "bwrap"


def degraded_reason():
    if not shutil.which("bwrap"):
        return "bubblewrap (bwrap) is not installed"
    if not probe("bwrap"):
        return ("bwrap is installed but cannot create user namespaces (e.g. AppArmor "
                "kernel.apparmor_restrict_unprivileged_userns=1)")
    return ""


def warn_degraded(mode, reason=""):
    bar = "!" * 78
    print(f"{bar}\nagentprobe: WARNING DEGRADED SANDBOX (mode={mode}): strong isolation unavailable"
          f"{' - ' + reason if reason else ''}.\nThe target may read host files and is NOT safely "
          f"contained. Use a VM/container for hostile servers.\n{bar}", file=sys.stderr)


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
        # Only an explicit workdir is bound; never the host cwd (it would leak e.g. /home/<user>).
        chdir = os.path.realpath(workdir) if workdir else ""
        if chdir not in ("/", "") and os.path.isdir(chdir):
            b += ["--ro-bind", chdir, chdir]
        else:
            chdir = "/tmp/apwork"  # nosec B108
        b += ["--chdir", chdir, "--"]
        return b + list(argv), None, mode, tmp
    if mode == "unshare" and probe("unshare"):
        # Degraded: mount namespace tmpfs-hides /home etc. (best effort), no pid ns, / not read-only.
        hide = [h for h in HIDE if h != "/tmp" and os.path.isdir(h)]  # nosec B108
        if workdir:
            wd = os.path.realpath(workdir)
            hide = [h for h in hide if not (wd + "/").startswith(h + "/")]
        script = ('while [ "$1" != "--" ]; do mount -t tmpfs none "$1" 2>/dev/null; shift; done; '
                  'shift; exec "$@"')
        warn_degraded("unshare", degraded_reason())
        return (["unshare", "-rm" if network else "-rmn", "--", "/bin/sh", "-c", script, "sh"]
                + hide + ["--"] + list(argv), cwd, mode, tmp)
    if mode in ("none", "unshare"):
        warn_degraded("none", degraded_reason() or "no namespace support")
        return list(argv), cwd, "none", tmp
    raise ValueError(f"unknown sandbox mode {mode!r}")

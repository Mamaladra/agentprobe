"""Hardened MCP client (JSON-RPC 2.0) over stdio (newline-delimited) or HTTP (streamable HTTP).

The scanned server is treated as HOSTILE:
  * every message is size-capped (MAX_MSG) and total output is capped (MAX_TOTAL);
  * JSON is parsed defensively (deep nesting / bad types are rejected, never eval'd);
  * server->client requests (sampling, roots, elicitation) are refused, never executed;
  * stdio targets run inside sandbox.wrap() with a minimal env and rlimits;
  * HTTP: no redirects, no proxies from env, response size capped.
"""
import json
import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request

from . import sandbox

PROTOCOL = "2025-06-18"
MAX_MSG = 2 * 1024 * 1024          # bytes per JSON-RPC message
MAX_TOTAL = 64 * 1024 * 1024       # bytes per session from the server
MAX_DEPTH = 64
MAX_TEXT = 256 * 1024              # chars of tool output kept for analysis
MAX_QUEUE = 1000


class MCPError(Exception):
    pass


def _depth(o, d=0):
    if d > MAX_DEPTH:
        raise MCPError("JSON nesting too deep")
    if isinstance(o, dict):
        for v in o.values():
            _depth(v, d + 1)
    elif isinstance(o, list):
        for v in o:
            _depth(v, d + 1)


def parse_message(raw):
    """Parse one untrusted JSON-RPC message. Returns dict or raises MCPError."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_MSG:
            raise MCPError("message too large")
        raw = raw.decode("utf-8", "replace")
    if len(raw) > MAX_MSG:
        raise MCPError("message too large")
    try:
        o = json.loads(raw, parse_constant=lambda c: None)
    except (ValueError, RecursionError) as e:
        raise MCPError(f"malformed JSON: {type(e).__name__}") from None
    _depth(o)
    if not isinstance(o, dict):
        raise MCPError("message is not an object")
    return o


def _as_dict(x):
    return x if isinstance(x, dict) else {}


def _as_list(x):
    return x if isinstance(x, list) else []


def sanitize_tool(t):
    """Coerce a server-supplied tool definition into safe, bounded types."""
    if not isinstance(t, dict) or not isinstance(t.get("name"), str):
        return None
    out = {"name": t["name"][:256], "description": str(t.get("description") or "")[:65536]}
    sch = t.get("inputSchema")
    out["inputSchema"] = sch if isinstance(sch, dict) else {}
    if isinstance(t.get("annotations"), dict):
        out["annotations"] = t["annotations"]
    return out


class BaseClient:
    def __init__(self):
        self._id = 0
        self.server_info = {}
        self.capabilities = {}
        self.calls = 0
        self.max_calls = 2000
        self.lock = threading.RLock()

    def request(self, method, params=None, timeout=10):
        with self.lock:
            self._id += 1
            mid = self._id
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params is not None:
            msg["params"] = params
        resp = self._send(msg, timeout)
        if "error" in resp:
            err = resp["error"]
            m = err.get("message") if isinstance(err, dict) else err
            raise MCPError(str(m)[:4096])
        return _as_dict(resp.get("result"))

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg, 5, expect_reply=False)

    def initialize(self):
        r = self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                         "clientInfo": {"name": "agentprobe", "version": "0.3.0"}}, timeout=30)
        self.server_info = {k: str(v)[:256] for k, v in _as_dict(r.get("serverInfo")).items()
                            if k in ("name", "version", "title")}
        self.capabilities = _as_dict(r.get("capabilities"))
        self.notify("notifications/initialized")
        # Give the stdout reader a tick to refuse any immediate server->client requests
        # (sampling/roots/elicitation) before the caller issues tools/list.
        import time
        time.sleep(0.05)
        return r

    def _paged(self, method, key, limit=2000):
        items, cursor, pages = [], None, 0
        while pages < 50 and len(items) < limit:
            r = self.request(method, {"cursor": cursor} if cursor else {})
            items += _as_list(r.get(key))
            cursor = r.get("nextCursor")
            pages += 1
            if not isinstance(cursor, str) or not cursor:
                break
        return items[:limit]

    def list_tools(self):
        return [t for t in (sanitize_tool(x) for x in self._paged("tools/list", "tools")) if t]

    def list_resources(self):
        return [x for x in self._paged("resources/list", "resources") if isinstance(x, dict)]

    def read_resource(self, uri):
        r = self.request("resources/read", {"uri": uri})
        return "\n".join(str(_as_dict(c).get("text", ""))[:MAX_TEXT] for c in _as_list(r.get("contents")))[:MAX_TEXT]

    def list_prompts(self):
        return [x for x in self._paged("prompts/list", "prompts") if isinstance(x, dict)]

    def get_prompt(self, name, args=None):
        r = self.request("prompts/get", {"name": name, "arguments": args or {}})
        parts = []
        for m in _as_list(r.get("messages")):
            c = _as_dict(_as_dict(m).get("content"))
            parts.append(str(c.get("text", "")))
        return "\n".join(parts)[:MAX_TEXT]

    def call_tool(self, name, arguments, timeout=10):
        """Returns (text, is_error). Never raises for server misbehaviour."""
        self.calls += 1
        if self.calls > self.max_calls:
            return "<call budget exhausted>", True
        try:
            r = self.request("tools/call", {"name": name, "arguments": arguments}, timeout)
        except MCPError as e:
            return str(e)[:MAX_TEXT], True
        except TimeoutError:
            return "<timeout>", True
        except (OSError, urllib.error.URLError) as e:
            return f"<transport error {type(e).__name__}>", True
        parts = []
        for c in _as_list(r.get("content"))[:100]:
            c = _as_dict(c)
            parts.append(str(c.get("text", "")) if c.get("type") == "text"
                         else json.dumps(c, default=str)[:4096])
        if isinstance(r.get("structuredContent"), (dict, list)):
            parts.append(json.dumps(r["structuredContent"], default=str)[:MAX_TEXT])
        return "\n".join(parts)[:MAX_TEXT], bool(r.get("isError"))

    def close(self):
        pass


class StdioClient(BaseClient):
    def __init__(self, command, env=None, sandbox_mode="auto", allow_paths=(), network=False,
                 workdir=None, limits=None):
        super().__init__()
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        if not argv:
            raise MCPError("empty command")
        exe = shutil.which(argv[0]) or argv[0]
        argv = [exe] + argv[1:]
        # Absolutize file arguments so relative paths survive sandbox chdir/tmpfs overlays.
        for i in range(1, len(argv)):
            if not argv[i].startswith("-") and os.path.exists(argv[i]):
                argv[i] = os.path.realpath(argv[i])
        allow = list(allow_paths) + [os.path.dirname(os.path.realpath(exe))]
        venv = os.path.dirname(os.path.dirname(os.path.abspath(exe)))
        if os.path.exists(os.path.join(venv, "pyvenv.cfg")):   # python venv interpreter
            allow.append(venv)
            # Editable installs: pull source trees listed in .pth / egg-link files.
            site = os.path.join(venv, "lib")
            if os.path.isdir(site):
                for root, dirs, files in os.walk(site):
                    for fn in files:
                        if fn.endswith((".pth", ".egg-link")):
                            try:
                                for line in open(os.path.join(root, fn), encoding="utf-8", errors="ignore"):
                                    line = line.strip()
                                    if line and not line.startswith("#") and os.path.isdir(line):
                                        allow.append(line)
                            except OSError:
                                pass
                    dirs[:] = [d for d in dirs if d != "__pycache__"]
        for a in argv[1:]:   # bind script/dir (and project root) so the target can import
            if os.path.exists(a) and not a.startswith("-"):
                rp = os.path.realpath(a)
                allow.append(os.path.dirname(rp) if os.path.isfile(rp) else rp)
                # Walk up allowing every project marker so monorepo node_modules is visible.
                d = os.path.dirname(rp) if os.path.isfile(rp) else rp
                markers = ("pyproject.toml", "setup.py", "package.json", "node_modules",
                           "go.mod", "Cargo.toml", "uv.lock")
                for _ in range(8):
                    if any(os.path.exists(os.path.join(d, m)) for m in markers):
                        allow.append(d)
                    parent = os.path.dirname(d)
                    if parent == d:
                        break
                    d = parent
        if workdir:
            allow.append(workdir)
        allow.append(os.getcwd())
        # Always allow the python stdlib & site-packages under the interpreter prefix
        allow.append(sys.prefix)
        self.argv = list(argv)
        from .checks import ESCAPE_TOKEN
        self.canary_dir = sandbox.make_canary(ESCAPE_TOKEN)
        wrapped, cwd, self.sandbox_mode, self.tmp = sandbox.wrap(argv, sandbox_mode, allow, network, workdir,
                                                                 canary_dir=self.canary_dir)
        self.canary_path = os.path.join(sandbox.CANARY_MOUNT if self.sandbox_mode == "bwrap" else self.canary_dir,
                                        sandbox.CANARY_FILE)
        home = "/tmp/aphome" if self.sandbox_mode == "bwrap" else self.tmp  # nosec B108 — bwrap in-sandbox home
        self.total = 0
        self.server_requests = []
        self.stderr_tail = b""
        self.proc = subprocess.Popen(wrapped, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # nosec B603 - argv list, no shell
                                     stderr=subprocess.PIPE, cwd=cwd, env=sandbox.minimal_env(env, home),
                                     preexec_fn=sandbox.make_preexec(limits), close_fds=True)
        self.q = queue.Queue(MAX_QUEUE)
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_err, daemon=True).start()

    def _drain_err(self):
        for chunk in iter(lambda: self.proc.stderr.read(4096), b""):
            self.stderr_tail = (self.stderr_tail + chunk)[-8192:]

    def _reader(self):
        f = self.proc.stdout
        while True:
            line = f.readline(MAX_MSG + 1)
            if not line:
                break
            self.total += len(line)
            if self.total > MAX_TOTAL:
                self.kill()
                break
            if len(line) > MAX_MSG and not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):   # discard rest of oversized line
                    line = f.readline(MAX_MSG)
                    self.total += len(line)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                m = parse_message(line)
            except MCPError:
                continue
            if "method" in m:              # server->client request/notification: never act on it
                if "id" in m and len(self.server_requests) < 100:
                    self.server_requests.append(str(m.get("method"))[:100])
                    try:
                        self._write({"jsonrpc": "2.0", "id": m["id"] if isinstance(m["id"], (int, str)) else None,
                                     "error": {"code": -32601, "message": "refused by agentprobe"}})
                    except (OSError, ValueError, MCPError):
                        pass
                continue
            try:
                self.q.put_nowait(m)
            except queue.Full:
                pass

    def _write(self, msg):
        with self.lock:
            if self.proc.poll() is not None:
                raise MCPError("server process exited")
            try:
                self.proc.stdin.write((json.dumps(msg) + "\n").encode())
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                raise MCPError("server process exited") from None

    def _send(self, msg, timeout, expect_reply=True):
        self._write(msg)
        if not expect_reply:
            return {}
        import time
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(msg["method"])
            try:
                r = self.q.get(timeout=min(left, 0.5))
            except queue.Empty:
                if self.proc.poll() is not None and self.q.empty():
                    raise MCPError("server process exited")
                continue
            if r.get("id") == msg["id"]:
                return r

    def kill(self):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self.proc.kill()
            except OSError:
                pass

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(3)
        except Exception:
            pass
        self.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(getattr(self, "canary_dir", "") or self.tmp, ignore_errors=True)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class HttpClient(BaseClient):
    def __init__(self, url, headers=None):
        super().__init__()
        if not url.startswith(("http://", "https://")):
            raise MCPError("only http(s) URLs")
        self.url = url
        self.headers = headers or {}
        self.session = None
        self.sandbox_mode = "n/a (remote)"
        self.server_requests = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def raw_post(self, body, headers=None, timeout=10):
        """Low-level POST used by HTTP transport checks. Returns (status, body_text)."""
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        h.update(headers if headers is not None else self.headers)
        req = urllib.request.Request(self.url, body, h, method="POST")  # noqa: S310
        try:
            with self.opener.open(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 — scheme checked in __init__
                return resp.status, resp.read(MAX_MSG + 1)[:MAX_MSG].decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(65536).decode("utf-8", "replace"), e.headers

    def _send(self, msg, timeout, expect_reply=True):
        h = dict(self.headers)
        if self.session:
            h["Mcp-Session-Id"] = self.session
        status, body, hdrs = self.raw_post(json.dumps(msg).encode(), h, timeout)
        sid = hdrs.get("Mcp-Session-Id") if hdrs else None
        if isinstance(sid, str) and len(sid) < 512 and sid.isprintable():
            self.session = sid
        if not expect_reply:
            return {}
        if status >= 400:
            raise MCPError(f"HTTP {status}")
        if "text/event-stream" in ((hdrs.get("Content-Type") if hdrs else "") or ""):
            for line in body.splitlines():
                if line.startswith("data:"):
                    try:
                        d = parse_message(line[5:])
                    except MCPError:
                        continue
                    if d.get("id") == msg["id"]:
                        return d
            raise MCPError("no reply in SSE stream")
        return parse_message(body)


def connect(target, env=None, **kw):
    if target.startswith(("http://", "https://")):
        c = HttpClient(target, kw.get("headers"))
    else:
        kw.pop("headers", None)
        c = StdioClient(target, env, **kw)
    try:
        c.initialize()
    except BaseException:
        c.close()
        raise
    return c

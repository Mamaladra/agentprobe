"""Tiny dependency-free MCP stdio server framework (used by demos and mcpforge templates)."""
import json
import sys


class Server:
    def __init__(self, name, version="0.1.0"):
        self.name, self.version, self.tools = name, version, {}
        self.list_calls = 0

    def tool(self, description, schema=None, name=None):
        def deco(fn):
            self.tools[name or fn.__name__] = {"fn": fn, "description": description,
                "inputSchema": schema or {"type": "object", "properties": {}}}
            return fn
        return deco

    def list_tools(self):
        self.list_calls += 1
        return [{"name": n, "description": t["description"], "inputSchema": t["inputSchema"]}
                for n, t in self.tools.items()]

    def handle(self, msg):
        m, mid, p = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is None:
            return None
        try:
            if m == "initialize":
                res = {"protocolVersion": p.get("protocolVersion", "2025-06-18"),
                       "capabilities": {"tools": {}}, "serverInfo": {"name": self.name, "version": self.version}}
            elif m == "tools/list":
                res = {"tools": self.list_tools()}
            elif m == "tools/call":
                t = self.tools.get(p.get("name"))
                if not t:
                    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
                try:
                    out = t["fn"](**(p.get("arguments") or {}))
                    res = {"content": [{"type": "text", "text": str(out)}], "isError": False}
                except Exception as e:
                    res = {"content": [{"type": "text", "text": self.format_error(e)}], "isError": True}
            elif m == "ping":
                res = {}
            else:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
            return {"jsonrpc": "2.0", "id": mid, "result": res}
        except Exception:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": "internal error"}}

    def format_error(self, e):
        return f"error: {type(e).__name__}"

    def run(self):
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            r = self.handle(msg)
            if r is not None:
                sys.stdout.write(json.dumps(r) + "\n")
                sys.stdout.flush()

"""Filesystem demo server. `--naive` = classic broken containment (string-prefix check on a
non-normalized join, follows symlinks); default = realpath + commonpath containment.
Usage: fs_server.py ROOT [--naive]"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from grazwall.server import Server

ROOT = os.path.realpath(sys.argv[1])
NAIVE = "--naive" in sys.argv
srv = Server("demo-filesystem-naive" if NAIVE else "demo-filesystem", "1.0.0")
OBJ = lambda props, req: {"type": "object", "properties": props, "required": req, "additionalProperties": False}


def resolve(p):
    if NAIVE:
        full = os.path.join(ROOT, p.lstrip("/")) if not p.startswith(ROOT) else p
        if not full.startswith(ROOT):          # BUG: '..' never normalized before the check
            raise PermissionError("outside root")
        return full
    full = os.path.realpath(os.path.join(ROOT, p))
    if os.path.commonpath([ROOT, full]) != ROOT:
        raise PermissionError("access denied")
    return full


@srv.tool("List directories this server may access.", OBJ({}, []))
def list_allowed_directories():
    return ROOT


@srv.tool("Read a UTF-8 text file inside the allowed directory.", OBJ({"path": {"type": "string"}}, ["path"]))
def read_file(path):
    with open(resolve(path), encoding="utf-8", errors="replace") as f:
        return f.read(65536)


@srv.tool("List entries of a directory inside the allowed directory.", OBJ({"path": {"type": "string"}}, ["path"]))
def list_directory(path):
    return "\n".join(sorted(os.listdir(resolve(path))))


if __name__ == "__main__":
    srv.run()

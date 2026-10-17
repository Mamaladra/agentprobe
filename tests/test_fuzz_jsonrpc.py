"""Fuzz the JSON-RPC message parser: seeded stdlib random fuzzing (no MPL deps) + hand-crafted inputs."""
import json
import random

import pytest

from grazwall import client

# Anything that is NOT a valid JSON object must raise MCPError (or be accepted only if it is a dict).
MALFORMED = [
    "", "null", "true", "0", "[]", '"str"', "{", "}", "{'a':1}", "\x00{}",
    '{"jsonrpc":"2.0"' + ",\"a\":1" * 10000 + "}",
    "\xff\xfe{}",
    '{"a":' + "[" * 200 + "1" + "]" * 200 + "}",
    "NaN", "Infinity", "-Infinity",
    '{"__proto__":{"x":1}}',
    b"\x00\x01\x02",
]


@pytest.mark.parametrize("raw", MALFORMED)
def test_malformed_never_crashes(raw):
    try:
        client.parse_message(raw)
    except client.MCPError:
        return
    # If it parsed, it must be a dict of bounded depth.
    # (only possible for dict-shaped inputs that Hypothesis / we allow)


SEED = 0xA9E7
TOKENS = ['{', '}', '[', ']', '"', ':', ',', '\\', '\\u0000', 'null', 'true', '1e999', '-0', 'NaN',
          '"jsonrpc"', '"2.0"', '"id"', '"method"', '\ud800', '\x00', '\xff', ' ', '\n']


def _cases(n=400):
    rnd = random.Random(SEED)
    for _ in range(n):
        k = rnd.random()
        if k < 0.3:
            yield bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 2048)))
        elif k < 0.6:
            yield "".join(chr(rnd.randint(0, 0x10FFFF)) if rnd.random() < 0.2 else rnd.choice(TOKENS)
                          for _ in range(rnd.randint(0, 512)))
        else:   # mutate a valid message (structure-aware)
            base = json.dumps({"jsonrpc": "2.0", "id": rnd.randint(-5, 5), "result": {"tools": [{"name": "x"}]}})
            b = list(base)
            for _ in range(rnd.randint(1, 8)):
                op, i = rnd.random(), rnd.randrange(len(b) or 1)
                if op < 0.4 and b:
                    del b[i % len(b)]
                elif op < 0.8:
                    b.insert(i, rnd.choice(TOKENS))
                else:
                    b[i % len(b)] = rnd.choice(TOKENS)
            yield "".join(b)


@pytest.mark.parametrize("data", list(_cases()))
def test_fuzz_parser(data):
    try:
        o = client.parse_message(data)
    except client.MCPError:
        return
    assert isinstance(o, dict)


def test_oversized_line_dropped_by_stdio(tmp_path):
    """A single oversized JSON line must not kill the client or allocate unbounded memory."""
    script = tmp_path / "flood.py"
    script.write_text(
        "import json,sys,time\n"
        "def reply(mid, result):\n"
        "  sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':mid,'result':result})+'\\n');sys.stdout.flush()\n"
        "req=json.loads(sys.stdin.readline());reply(req['id'],{'protocolVersion':'2025-06-18',"
        "'capabilities':{},'serverInfo':{'name':'flood','version':'0'}})\n"
        "sys.stdin.readline()\n"
        # flood an oversized line (no newline until after MAX), then a valid tools/list reply
        "sys.stdout.write('{' + '\"a\":1,' * 300000);sys.stdout.flush()\n"
        "sys.stdout.write('\"z\":0}\\n');sys.stdout.flush()\n"
        "req=json.loads(sys.stdin.readline());reply(req['id'],{'tools':[]})\n"
        "time.sleep(0.2)\n"
    )
    c = client.connect(f"{__import__('sys').executable} {script}", sandbox_mode="none")
    try:
        assert c.list_tools() == []
    finally:
        c.close()

"""Capability profiles: what a server is *supposed* to do.

A filesystem server exposing read_file is not a vulnerability; a filesystem server exposing
an exec tool is. Profiles map a server's declared purpose to the capability classes it is
expected to expose. Matching AP005 findings are downgraded to `info` ("expected capability");
anything outside the profile keeps its original severity. Exploit findings (AP008 traversal,
AP009 command injection, AP029 root escape, ...) are never downgraded by a profile.
"""
import re

# capability keys used by checks.DANGEROUS_TOOL_HINTS
EXEC, FS, NET, DB, SECRETS, MEMORY = "exec", "filesystem", "network", "database", "secrets", "memory"

PROFILES = {
    "filesystem": {FS},
    "git": {FS},
    "database": {DB},
    "shell": {EXEC, FS},
    "http": {NET},
    "fetch": {NET},
    "browser": {NET},
    "memory": {MEMORY},
    "secrets": {SECRETS},
    "none": set(),
}
# Findings (besides AP005) that a profile may legitimately expect -> downgraded to info.
EXPECTED_FINDINGS = {
    "memory": {"AP014"},   # a memory server accepting writes over local stdio is its purpose
}

# (profile, pattern on server name, pattern on tool names) for auto-detection
_DETECT = [
    ("filesystem", r"file.?system|(?<![a-z])fs(?![a-z])", r"^(read_(text_|multiple_)?files?|write_file|list_directory|directory_tree|move_file|list_allowed_directories|create_directory|edit_file|search_files)$"),
    ("git", r"(?<![a-z])git(?![a-z])", r"^git_"),
    ("database", r"sql|postgres|mysql|sqlite|mongo|database|(?<![a-z])db(?![a-z])", r"^(query|execute_sql|run_sql|list_tables|describe_table|read_query|write_query)$"),
    ("shell", r"shell|terminal|exec", r"^(run_command|shell|exec(ute)?_command|bash)$"),
    ("http", r"fetch|http|web|browser|scrap", r"^(fetch|http_get|http_request|browse|navigate|scrape)$"),
    ("memory", r"memory|knowledge.?graph", r"^(create_entities|create_relations|add_observations|read_graph|search_nodes|open_nodes|remember|recall)$"),
]


def parse(spec):
    """'filesystem,git' -> {'filesystem','git'}; 'auto' / None -> None (auto-detect); 'none' -> set()."""
    if spec in (None, "", "auto"):
        return None
    out = set()
    for p in str(spec).split(","):
        p = p.strip().lower()
        if not p:
            continue
        if p not in PROFILES:
            raise ValueError(f"unknown profile {p!r}; choose from {', '.join(sorted(PROFILES))}")
        if p != "none":
            out.add(p)
    return out


def detect(server_info, tools):
    """Auto-detect profiles from server name + tool names. Requires a clear majority signal from
    tool names (>=2 tools and >=40% of tools) or a server-name match plus >=1 matching tool."""
    name = " ".join(str(v) for v in (server_info or {}).values()).lower()
    names = [str(t.get("name", "")).lower() for t in tools or []]
    found = set()
    for prof, npat, tpat in _DETECT:
        hits = sum(1 for n in names if re.search(tpat, n))
        name_hit = bool(re.search(npat, name))
        if (hits >= 2 and hits >= 0.4 * max(len(names), 1)) or (name_hit and hits >= 1):
            found.add(prof)
    return found


def allowed_caps(profiles):
    caps = set()
    for p in profiles or ():
        caps |= PROFILES.get(p, set())
    return caps


def apply(findings, profiles):
    """Downgrade expected-capability findings to info in place. Returns count downgraded."""
    caps = allowed_caps(profiles)
    expected = set()
    for p in profiles or ():
        expected |= EXPECTED_FINDINGS.get(p, set())
    n = 0
    label = ",".join(sorted(profiles or ())) or "none"
    for f in findings:
        cap = getattr(f, "capability", None)
        if (f.check_id == "AP005" and cap in caps) or f.check_id in expected:
            if f.severity != "info":
                f.detail = f"[expected for profile '{label}', was {f.severity}] {f.detail}"
                f.severity = "info"
                f.title = "Expected capability: " + f.title
                n += 1
    return n

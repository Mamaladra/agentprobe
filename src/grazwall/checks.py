"""Grazwall open-core checks (Apache-2.0): static checks + basic live probes.

Additional packs (advanced live probes, adaptive attacker) register via the
`grazwall.packs` entry-point group: each entry point returns a list of check functions.
"""
import re

SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}


class Finding:
    def __init__(self, check_id, title, severity, tool=None, detail="", evidence="", remediation=""):
        self.check_id, self.title, self.severity = check_id, title, severity
        self.tool, self.detail, self.evidence, self.remediation = tool, detail, evidence, remediation
    def to_dict(self):
        return self.__dict__.copy()


INJECTION_PATTERNS = [
    r"ignore (all |the |previous |prior )?(above |previous |prior )?instructions",
    r"disregard (all |the )?(previous|prior|above)",
    r"you must (now |always )?",
    r"system prompt", r"<\s*important\s*>", r"do not (tell|mention|inform) the user",
    r"before (using|calling) (any|this|other) tool", r"always (call|use|run)",
    r"</?(system|instructions?)>", r"assistant:", r"\[system\]",
]


STRONG_INJECTION = [INJECTION_PATTERNS[0], INJECTION_PATTERNS[1], r"<\s*important\s*>",
                    r"do not (tell|mention|inform) the user", r"</?(system|instructions?)>", r"\[system\]"]


SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{16,}", "OpenAI-style API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}", "credential-like value"),
]


DANGEROUS_TOOL_HINTS = [
    # Word-boundaries on short tokens so "file system" / "query string" do not false-positive.
    (r"(?<![\w])(exec|eval|shell|command|run_?code|subprocess|os\.|child_process)(?![\w])", "arbitrary code/command execution", "exec"),
    (r"read_?file|write_?file|delete_?file|unlink|rm_file|(?<![\w])fs_(?![\w])|filesystem|read_path|write_path", "filesystem access", "filesystem"),
    (r"(?<![\w])(fetch|http|url|request|curl|download|webhook)(?![\w])", "outbound network / SSRF", "network"),
    (r"(?<![\w])(sql|database|db_)(?![\w])", "raw database access", "database"),
    (r"(?<![\w])(env|secret|credential|api[_-]?key|token)(?![\w])", "secret/config access", "secrets"),
]


def _text_of(tool):
    return (tool.get("description") or "") + " " + str(tool.get("inputSchema") or "")


def check_injection_in_descriptions(ctx):
    out = []
    for t in ctx.tools:
        text = t.get("description") or ""
        for pat in INJECTION_PATTERNS:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                out.append(Finding("AP001", "Prompt injection in tool description", "high",
                    t["name"], "Tool description contains instruction-like text an agent may obey.",
                    m.group(0), "Treat descriptions as data; strip imperative/system-like phrasing."))
                break
    return out


def check_injection_in_schema(ctx):
    out = []
    for t in ctx.tools:
        schema = str(t.get("inputSchema") or "")
        for pat in INJECTION_PATTERNS:
            m = re.search(pat, schema, re.IGNORECASE)
            if m:
                out.append(Finding("AP002", "Prompt injection in parameter schema", "high",
                    t["name"], "Parameter titles/descriptions carry agent-directed instructions (tool poisoning).",
                    m.group(0), "Sanitize schema description fields; they reach the model context."))
                break
    return out


def check_hidden_unicode(ctx):
    out = []
    bad = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
    for t in ctx.tools:
        if bad.search(_text_of(t)):
            out.append(Finding("AP003", "Hidden/invisible unicode in tool metadata", "high", t["name"],
                "Zero-width or tag characters can hide instructions from humans but not the model.",
                "non-printing characters present", "Reject non-printable characters in tool metadata."))
    return out


def check_secrets_in_metadata(ctx):
    out = []
    for t in ctx.tools:
        text = _text_of(t)
        for pat, label in SECRET_PATTERNS:
            m = re.search(pat, text)
            if m:
                out.append(Finding("AP004", f"Secret leaked in tool metadata ({label})", "critical",
                    t["name"], "A credential is exposed in tool description/schema.",
                    m.group(0)[:12] + "...", "Remove secrets from metadata; rotate the key."))
                break
    return out


def check_overpermissive_naming(ctx):
    out = []
    for t in ctx.tools:
        name = t["name"].lower()
        desc = (t.get("description") or "").lower()
        for pat, label, cap in DANGEROUS_TOOL_HINTS:
            if re.search(pat, name) or re.search(pat, desc):
                sev = "medium"
                if "code/command" in label:
                    sev = "high"
                if (t.get("annotations") or {}).get("readOnlyHint") is True and sev == "medium":
                    sev = "low"
                f = Finding("AP005", f"Over-permissive tool capability: {label}", sev,
                    t["name"], f"Tool exposes {label}; verify scoping and auth.",
                    t["name"], "Constrain to least privilege; require explicit auth/allowlist.")
                f.capability = cap
                out.append(f)
                break
    return out


def check_missing_schema(ctx):
    out = []
    for t in ctx.tools:
        schema = t.get("inputSchema") or {}
        props = schema.get("properties")
        if not schema or (isinstance(schema, dict) and props is None):
            out.append(Finding("AP006", "Tool lacks input schema", "low", t["name"],
                "No input schema means unvalidated, free-form arguments.",
                "", "Define a strict JSON schema with required fields and types."))
        elif isinstance(props, dict) and props and not schema.get("required") and schema.get("additionalProperties") is not False:
            out.append(Finding("AP007", "Schema allows unexpected/extra arguments", "low", t["name"],
                "additionalProperties not disabled; attacker can smuggle extra args.",
                "", "Set additionalProperties:false and declare required."))
    return out


def _find_tools(ctx, pat):
    return [t for t in ctx.tools if re.search(pat, t["name"], re.IGNORECASE) or re.search(pat, (t.get("description") or ""), re.IGNORECASE)]


def _string_params(t):
    props = (t.get("inputSchema") or {}).get("properties") or {}
    return [k for k, v in props.items() if isinstance(v, dict) and v.get("type", "string") in ("string", None)]


def check_tool_error_leak(ctx):
    out = []
    for t in ctx.tools:
        props = (t.get("inputSchema") or {}).get("properties") or {}
        args = {k: (99999999 if (isinstance(v, dict) and v.get("type") in ("integer", "number")) else "\x00bad\x00")
                for k, v in props.items()}
        text, err = ctx.client.call_tool(t["name"], args or {"__nope__": 1})
        if err or text:
            scrubbed = (text or "").replace(CANARY, "")   # planted canary is reported by AP019, not AP012
            for pat, label in SECRET_PATTERNS:
                if re.search(pat, scrubbed):
                    out.append(Finding("AP012", f"Secret leaked in tool output/error ({label})", "critical",
                        t["name"], "Tool response/stack trace exposed a credential.",
                        re.search(pat, scrubbed).group(0)[:12] + "...", "Scrub secrets & stack traces from responses."))
                    break
            if re.search(r'Traceback \(most recent call last\)|\n\s+at [\w.<>]+ \(/[^)]+:\d+:\d+\)|File "/[^"]+", line \d+', text or ""):
                out.append(Finding("AP013", "Verbose stack trace / path disclosure", "medium", t["name"],
                    "Raw stack trace leaks internal file paths & implementation.", (text or "")[:60],
                    "Return generic errors; log details server-side only."))
    return out


class Context:
    def __init__(self, client):
        self.client = client
        self.tools = client.list_tools()
        # Second listing taken immediately, before any live probe can crash the target.
        # check_rug_pull falls back to it if the target dies mid-scan (AP000 flake fix).
        try:
            self.tools_relist = client.list_tools()
        except Exception:
            self.tools_relist = None


def _alive(c):
    proc = getattr(c, "proc", None)
    return proc is None or proc.poll() is None


def run_all(client, profiles="auto", reconnect=None, meta=None, max_restarts=8):
    """Run every check. `profiles`: set of profile names, 'auto' (detect) or None/'none'.
    `reconnect`: optional zero-arg callable returning a fresh client if the target dies mid-scan.
    `meta` (dict) is filled with profile/restart info. Returns (findings, tools)."""
    from . import profiles as prof
    meta = {} if meta is None else meta
    ctx = Context(client)
    if profiles == "auto":
        chosen, how = prof.detect(client.server_info, ctx.tools), "auto"
    else:
        chosen, how = set(profiles or ()), "declared"
    meta.update(profiles=sorted(chosen), profile_source=how, target_restarts=0, target_deaths=[])
    findings = []
    for chk in ALL_CHECKS:
        if not _alive(ctx.client):
            meta["target_deaths"].append(chk.__name__)
            if reconnect and meta["target_restarts"] < max_restarts:
                try:
                    ctx.client.close()
                except Exception:
                    pass
                ctx.client = reconnect()
                meta["target_restarts"] += 1
        try:
            findings.extend(chk(ctx))
        except Exception as e:
            findings.append(Finding("AP000", f"Check {chk.__name__} errored", "info", None, str(e)))
    meta["downgraded_expected"] = prof.apply(findings, chosen)
    meta["client"] = ctx.client
    return findings, ctx.tools


CANARY = "sk-grazwallcanary0000000000000000"


def check_rug_pull(ctx):
    """Tool definitions change between listings (silent redefinition after approval)."""
    out = []
    try:
        listing = ctx.client.list_tools()
    except Exception:
        # Target died / hung mid-scan: compare against the early second listing instead of erroring.
        listing = getattr(ctx, "tools_relist", None)
        if listing is None:
            return out
    second = {t["name"]: t for t in listing}
    first = {t["name"]: t for t in ctx.tools}
    for n in set(first) | set(second):
        if first.get(n) != second.get(n):
            out.append(Finding("AP018", "Rug pull: tool definition changed between listings", "high", n,
                "Tool metadata mutated after initial listing; users approved a different tool.",
                "", "Pin & hash tool definitions; alert on change."))
    return out


def check_env_canary_leak(ctx):
    """Scanner injects a canary secret into the server env and tries to coax it out."""
    out = []
    for t in _find_tools(ctx, r"env|config|debug|secret|setting|info|status"):
        sp = _string_params(t)
        for args in ({}, {sp[0]: "GRAZWALL_CANARY"} if sp else {}, {sp[0]: "*"} if sp else {}):
            text, err = ctx.client.call_tool(t["name"], args)
            if CANARY in (text or ""):
                out.append(Finding("AP019", "Environment secret exfiltration", "critical", t["name"],
                    "Canary secret planted in server env was returned to the caller.",
                    CANARY[:12] + "...", "Never expose env/config; allowlist returned keys."))
                return out
    return out


def check_tool_shadowing(ctx):
    """Description references other tools / tries to alter how they behave (cross-tool poisoning)."""
    out = []
    names = [t["name"] for t in ctx.tools]
    for t in ctx.tools:
        d = (t.get("description") or "")
        for other in names:
            # Deprecation notes ("DEPRECATED: use X instead") are not tool shadowing.
            if re.search(r"\bdeprecated\b", d, re.IGNORECASE):
                break
            if other != t["name"] and re.search(r"\b%s\b" % re.escape(other), d) and                re.search(r"(always|must|redirect|send|bcc|\bcc\b|also (call|use|run)|before (using|calling))", d, re.IGNORECASE):
                out.append(Finding("AP020", "Tool shadowing: description manipulates another tool", "high",
                    t["name"], f"Description issues instructions about tool '{other}'.", other,
                    "Descriptions must only describe their own tool."))
                break
        if re.search(r"(~/\.ssh|\.env\b|id_rsa|mcp\.json|credentials)", d, re.IGNORECASE):
            out.append(Finding("AP021", "Exfiltration instruction in description", "critical", t["name"],
                "Description asks the agent to read sensitive local files.",
                re.search(r"(~/\.ssh|\.env\b|id_rsa|mcp\.json|credentials)", d, re.IGNORECASE).group(0),
                "Remove; this is a classic tool-poisoning payload."))
    return out


def _all_text(t):
    """Everything a model sees for a tool: name, description, every schema title/description/enum."""
    parts = [t.get("name", ""), t.get("description") or ""]
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("description", "title", "default", "const") and isinstance(v, str):
                    parts.append(v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(t.get("inputSchema") or {})
    walk(t.get("annotations") or {})
    return "\n".join(parts)


def _params_by_type(t, types):
    props = ((t.get("inputSchema") or {}).get("properties")) or {}
    out = []
    for k, v in props.items():
        if not isinstance(v, dict):
            continue
        ty = v.get("type", "string")
        if ty in types or (ty is None and "string" in types):
            out.append(k)
    return out


def _required(t):
    req = (t.get("inputSchema") or {}).get("required")
    return set(req) if isinstance(req, list) else set()


def _fill(t, overrides):
    """Build a plausible argument dict satisfying required params, with overrides applied."""
    props = ((t.get("inputSchema") or {}).get("properties")) or {}
    args = {}
    for k in _required(t) | set(overrides):
        spec = props.get(k) if isinstance(props.get(k), dict) else {}
        ty = spec.get("type", "string")
        if k in overrides:
            args[k] = overrides[k]
        elif ty in ("integer", "number"):
            args[k] = 1
        elif ty == "boolean":
            args[k] = False
        elif ty == "array":
            args[k] = []
        elif ty == "object":
            args[k] = {}
        else:
            args[k] = (spec.get("enum") or ["test"])[0] if isinstance(spec.get("enum"), list) else "test"
    return args


def targets_for(ctx, name_desc_pat, param_pat=None, param_types=("string",)):
    """Schema-aware targeting: a tool is a candidate if its name/description/schema text matches,
    OR it has a string/path/url-ish parameter matching param_pat -- so a dangerous tool with an
    innocent name (e.g. 'helper' taking a 'path') is still probed. Returns [(tool, [params])]."""
    out = []
    pp = re.compile(param_pat, re.IGNORECASE) if param_pat else None
    nd = re.compile(name_desc_pat, re.IGNORECASE)
    for t in ctx.tools:
        text_hit = bool(nd.search(_all_text(t)))
        sparams = _params_by_type(t, param_types)
        phit = [p for p in sparams if pp.search(p)] if pp else []
        if text_hit or phit:
            params = phit or sparams or []
            out.append((t, params))
    return out


def check_confused_deputy(ctx):
    """Tools that take a role/tenant/user/admin/scope param the caller can set (privilege by request)."""
    out = []
    for t in ctx.tools:
        for p in _params_by_type(t, ("string", "boolean", "integer")):
            if re.search(r"^(role|is_?admin|admin|scope|tenant|user_?id|as_?user|privilege|perm|acl|owner)$", p, re.IGNORECASE):
                out.append(Finding("AP023", "Confused-deputy: caller-controlled authorization parameter", "medium",
                    t["name"], f"Tool accepts '{p}'; the caller can assert its own privilege/identity.",
                    p, "Derive identity/role from the authenticated session, never from tool arguments."))
                break
    return out


def check_path_traversal_schema(ctx):
    out = []
    payloads = ["../../../../etc/passwd", "/etc/passwd", "....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd"]
    for t, params in targets_for(ctx, r"read|file|path|cat|load|fs|open|content|doc|fetch|get",
                                 r"file|path|name|src|target|doc|location|uri"):
        for p in params or ["path"]:
            hit = False
            for pl in payloads:
                text, err = ctx.client.call_tool(t["name"], _fill(t, {p: pl}))
                if not err and "root:" in (text or "") and ":0:0:" in text:
                    out.append(Finding("AP008", "Path traversal / arbitrary file read", "critical", t["name"],
                        f"Reading '{pl}' via param '{p}' returned /etc/passwd contents.", (text or "")[:80],
                        "Canonicalize & sandbox paths; reject '..' and absolute paths."))
                    hit = True
                    break
            if hit:
                break
    return out


ESCAPE_TOKEN = "GRAZWALL_ESCAPE_CANARY_3141"  # noqa: S105  # nosec B105 — probe canary


def _roots_hint(ctx):
    """Discover the server's allowed root(s) from list_allowed_directories-style tools / argv."""
    roots = []
    for t in ctx.tools:
        if re.search(r"allowed_?dir|list_?roots|get_?root", t["name"], re.IGNORECASE) and not _required(t):
            text, err = ctx.client.call_tool(t["name"], {})
            if not err:
                roots += re.findall(r"(/[^\s,;'\"\]\[]+)", text or "")
    for a in getattr(ctx.client, "argv", [])[1:]:
        if a.startswith("/") and not a.endswith((".js", ".py", ".mjs", ".cjs")) and "/bin/" not in a:
            roots.append(a)
    seen, out = set(), []
    for r in roots:
        r = r.rstrip("/") or "/"
        if r not in seen and r != "/":
            seen.add(r)
            out.append(r)
    return out[:4]


def check_root_escape(ctx):
    """Deep path escape: read a canary planted OUTSIDE the server's root (relative, absolute,
    root-prefixed, encoded and prefix-confusion variants). Proves containment, not just /etc/passwd."""
    out = []
    canary = getattr(ctx.client, "canary_path", None)
    if not canary:
        return out
    roots = _roots_hint(ctx)
    ups = "../" * 12
    payloads = [canary, ups + canary.lstrip("/"), "....//" * 12 + canary.lstrip("/"),
                urllib_quote(ups + canary.lstrip("/")), "/./" + canary.lstrip("/"), "//" + canary.lstrip("/")]
    for r in roots:
        payloads += [f"{r}/{ups}{canary.lstrip('/')}", f"{r}/../{'../' * 10}{canary.lstrip('/')}",
                     f"{r}/.{canary}", f"{r}{'/..' * 12}{canary}"]
    for t, params in targets_for(ctx, r"read|file|path|cat|load|fs|open|content|doc|get|view|show",
                                 r"file|path|name|src|target|doc|location|uri"):
        if re.search(r"write|delete|remove|move|rename|edit|create", t["name"], re.IGNORECASE):
            continue
        hit = False
        for p in (params or ["path"])[:2]:
            for pl in payloads:
                text, err = ctx.client.call_tool(t["name"], _fill(t, {p: pl}))
                if not err and ESCAPE_TOKEN in (text or ""):
                    out.append(Finding("AP029", "Root escape: file outside the server's root was read", "critical",
                        t["name"], f"Canary planted outside the allowed root was returned (param '{p}', roots={roots or '?'}).",
                        pl[:120], "Resolve with realpath and require commonpath(root, resolved) == root; reject symlinks out of root."))
                    hit = True
                    break
            if hit:
                break
    return out


def urllib_quote(s):
    import urllib.parse
    return urllib.parse.quote(s, safe="")


_REFUSAL = re.compile(r"\b(deny|denied|exceed|exceeded|over ?budget|limit|insufficient|forbidden|"
                      r"reject|rejected|not allowed|unauthori[sz]ed|too (large|high|much)|cap\b|refus)", re.IGNORECASE)


_SPEND_NAME = r"charge|pay|payment|purchase|buy|checkout|order|transfer|withdraw|spend|invoice|billing|debit"


_AMOUNT_PARAM = r"amount|price|total|value|sum|cost|charge|qty|quantity|units"


_LIMIT_PARAM = r"^(limit|budget|max|max_?amount|cap|ceiling|allowance|quota)$"


def check_overspend(ctx):
    """Payment-like tools that let a caller exceed a spending limit: caller-controlled
    budget params, no server-side cap on the amount, or negative-amount (refund) abuse."""
    out = []
    for t, _params in targets_for(ctx, _SPEND_NAME, _AMOUNT_PARAM,
                                 param_types=("integer", "number", "string")):
        name = t["name"]
        # Vector A (static): a caller-settable limit/budget parameter == spend by request.
        for p in _params_by_type(t, ("integer", "number", "string")):
            if re.search(_LIMIT_PARAM, p, re.IGNORECASE):
                out.append(Finding("AP030", "Overspend: caller-controlled spending limit", "high",
                    name, f"Tool '{name}' accepts '{p}'; the caller sets its own budget/limit.",
                    p, "Enforce the spending limit server-side from the authenticated mandate, "
                       "never from a tool argument."))
                break
        amt = [p for p in _params_by_type(t, ("integer", "number")) if re.search(_AMOUNT_PARAM, p, re.IGNORECASE)]
        amt = amt or _params_by_type(t, ("integer", "number"))
        if not amt:
            continue
        ap = amt[0]
        # Vector B (live): an absurdly large charge is accepted without any refusal.
        text, err = ctx.client.call_tool(name, _fill(t, {ap: 1000000000}))
        if not err and text and not _REFUSAL.search(text):
            out.append(Finding("AP030", "Overspend: no server-side spending cap", "critical",
                name, f"A charge of 1,000,000,000 via '{ap}' was accepted with no limit enforcement.",
                (text or "")[:80], "Enforce a hard per-session / per-mandate budget server-side; "
                "reject amounts above the authorized cap."))
            continue
        # Vector C (live): negative amount accepted -> refund / balance-inflation abuse.
        textn, errn = ctx.client.call_tool(name, _fill(t, {ap: -999999}))
        if not errn and textn and not _REFUSAL.search(textn):
            out.append(Finding("AP030", "Overspend: negative amount accepted (refund abuse)", "high",
                name, f"A negative amount via '{ap}' was accepted; enables self-refund / credit abuse.",
                (textn or "")[:80], "Validate amount > 0 and bound it; treat refunds as a separate "
                "authorized flow."))
    return out


_MANDATE_PARAM = r"^(intent_?mandate|cart_?mandate|payment_?mandate|mandate(_?id)?|mandate_?token|authorization|authz)$"


_CART_PARAM = r"^(cart(_?id)?|items?|sku|product(_?id)?|line_?items?)$"


_NONCE_PARAM = r"^(nonce|idempotency_?key|jti|mandate_?nonce|replay_?key)$"


_HNP_HINT = r"human[-_ ]?not[-_ ]?present|autonomous (checkout|payment|charge)|no human|unattended (pay|charge)"


_MANDATE_HINT = r"mandate|intent mandate|cart mandate|payment mandate|ap2|agent payments"


def _mandate_params(t):
    return [p for p in _params_by_type(t, ("string", "object")) if re.search(_MANDATE_PARAM, p, re.IGNORECASE)]


def _cart_params(t):
    return [p for p in _params_by_type(t, ("string", "object", "array")) if re.search(_CART_PARAM, p, re.IGNORECASE)]


def _nonce_params(t):
    return [p for p in _params_by_type(t, ("string",)) if re.search(_NONCE_PARAM, p, re.IGNORECASE)]


def _amount_params(t):
    amts = [p for p in _params_by_type(t, ("integer", "number")) if re.search(_AMOUNT_PARAM, p, re.IGNORECASE)]
    return amts or _params_by_type(t, ("integer", "number"))


def check_ap2_missing_mandate(ctx):
    """AP031: spend/checkout tools with no Intent/Cart/Payment Mandate binding, or that
    accept a charge when a mismatched mandate id is supplied."""
    out = []
    for t, _ in targets_for(ctx, _SPEND_NAME, _AMOUNT_PARAM,
                            param_types=("integer", "number", "string")):
        name = t["name"]
        mparams = _mandate_params(t)
        amts = _amount_params(t)
        # Vector A (static): payment tool exposes no mandate-binding parameter at all.
        if not mparams:
            out.append(Finding(
                "AP031", "AP2: payment tool missing mandate binding", "high", name,
                f"Tool '{name}' accepts a spend/charge with no Intent/Cart/Payment Mandate parameter.",
                ",".join(_params_by_type(t, ("integer", "number", "string")))[:80],
                "Require a signed Intent Mandate (and Cart/Payment Mandates for HNP flows) "
                "and bind every charge to that mandate server-side."))
            continue
        if not amts:
            continue
        ap, mp = amts[0], mparams[0]
        # Vector B (live): a clearly mismatched / forged mandate is still accepted.
        text, err = ctx.client.call_tool(name, _fill(t, {ap: 42.0, mp: "forged-mandate-NOT-AUTHORIZED"}))
        if not err and text and not _REFUSAL.search(text):
            out.append(Finding(
                "AP031", "AP2: mismatched mandate accepted", "critical", name,
                f"Tool '{name}' accepted a charge with a forged/mismatched '{mp}'.",
                (text or "")[:80],
                "Verify the mandate signature and subject; reject unknown or mismatched mandates."))
    return out


def check_ap2_cart_substitution(ctx):
    """AP032: charged item/amount can diverge from the authorized cart (caller sets both)."""
    out = []
    for t, _ in targets_for(ctx, rf"{_SPEND_NAME}|{_MANDATE_HINT}|checkout|cart",
                            _CART_PARAM, param_types=("string", "object", "array", "integer", "number")):
        name = t["name"]
        carts = _cart_params(t)
        amts = _amount_params(t)
        if not carts or not amts:
            # Static: amount is caller-set with no cart binding on a payment tool.
            if amts and re.search(_SPEND_NAME, _all_text(t), re.IGNORECASE) and not carts:
                # Already covered loosely by missing binding; skip duplicate noise.
                continue
            continue
        cp, ap = carts[0], amts[0]
        # Live: authorize a cheap cart id but charge a much larger amount.
        args = _fill(t, {cp: "cart-cheap-sku-A", ap: 999999.0})
        for mp in _mandate_params(t):
            args[mp] = "mandate-for-sku-A-only"
        text, err = ctx.client.call_tool(name, args)
        if not err and text and not _REFUSAL.search(text):
            out.append(Finding(
                "AP032", "AP2: cart substitution / amount unbound from cart", "critical", name,
                f"Tool '{name}' charged via '{ap}' while cart '{cp}' was a cheap SKU; amount not bound.",
                (text or "")[:80],
                "Derive the payable amount from the signed Cart Mandate; never trust a caller amount."))
    return out


def check_ap2_mandate_replay(ctx):
    """AP033: the same payment mandate / nonce is accepted twice (no replay protection)."""
    out = []
    for t, _ in targets_for(ctx, rf"{_SPEND_NAME}|{_MANDATE_HINT}",
                            _NONCE_PARAM, param_types=("string", "integer", "number")):
        name = t["name"]
        nonces = _nonce_params(t) or _mandate_params(t)
        amts = _amount_params(t)
        if not nonces:
            continue
        np = nonces[0]
        args = _fill(t, {np: "replay-token-once-only"})
        if amts:
            args[amts[0]] = 10.0
        for mp in _mandate_params(t):
            if mp not in args:
                args[mp] = "replay-token-once-only"
        text1, err1 = ctx.client.call_tool(name, args)
        if err1 or not text1 or _REFUSAL.search(text1):
            continue
        text2, err2 = ctx.client.call_tool(name, args)
        if not err2 and text2 and not _REFUSAL.search(text2):
            out.append(Finding(
                "AP033", "AP2: mandate / nonce replay accepted", "critical", name,
                f"Tool '{name}' accepted the same '{np}' twice; no replay/idempotency protection.",
                (text2 or "")[:80],
                "Track used mandate jti/nonce server-side; reject replays. Prefer single-use Payment Mandates."))
    return out


def check_ap2_hnp_overreach(ctx):
    """AP034: human-not-present / autonomous charge above a threshold with no mandate caps."""
    out = []
    for t in ctx.tools:
        text = _all_text(t)
        if not re.search(_HNP_HINT, text, re.IGNORECASE) and not re.search(
                r"human[-_ ]?not[-_ ]?present", t.get("name") or "", re.IGNORECASE):
            # Also consider spend tools that advertise autonomy in the name.
            if not (re.search(_SPEND_NAME, text, re.IGNORECASE)
                    and re.search(r"auto|unattended|agent[_-]?pay", text, re.IGNORECASE)):
                continue
        name = t["name"]
        amts = _amount_params(t)
        if not amts:
            # Static: HNP payment tool with no amount AND no mandate cap surface.
            if not _mandate_params(t):
                out.append(Finding(
                    "AP034", "AP2: human-not-present charge with no mandate caps", "high", name,
                    f"Tool '{name}' advertises human-not-present/autonomous payment without mandate cap params.",
                    (t.get("description") or "")[:80],
                    "HNP flows MUST carry a Payment Mandate with a hard cap enforced server-side."))
            continue
        ap = amts[0]
        args = _fill(t, {ap: 500000.0})
        for mp in _mandate_params(t):
            args[mp] = "hnp-uncapped"
        text_out, err = ctx.client.call_tool(name, args)
        if not err and text_out and not _REFUSAL.search(text_out):
            out.append(Finding(
                "AP034", "AP2: human-not-present overreach (uncapped autonomous charge)", "critical", name,
                f"Autonomous/HNP tool '{name}' accepted a 500,000 charge with no mandate-cap refusal.",
                (text_out or "")[:80],
                "Enforce Payment Mandate max_amount for HNP; refuse charges above the signed cap."))
    return out



ALL_CHECKS = [check_injection_in_descriptions, check_injection_in_schema, check_hidden_unicode, check_secrets_in_metadata, check_overpermissive_naming, check_missing_schema, check_tool_shadowing, check_confused_deputy, check_path_traversal_schema, check_tool_error_leak, check_rug_pull, check_env_canary_leak, check_root_escape,
              check_overspend, check_ap2_missing_mandate, check_ap2_cart_substitution, check_ap2_mandate_replay, check_ap2_hnp_overreach]


def load_packs():
    """Load optional check packs (e.g. commercial `grazwall-pro`) from entry points."""
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="grazwall.packs")
    except Exception:
        return []
    out = []
    for ep in eps:
        try:
            out.extend(ep.load()())
        except Exception:
            continue
    return out


ALL_CHECKS += [c for c in load_packs() if c not in ALL_CHECKS]


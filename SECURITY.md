# Security policy

## Reporting a vulnerability
If you find a sandbox escape, report XSS, secret leakage or parser DoS in Grazwall or Grazforge, report it
privately via GitHub's "Report a vulnerability" (Security tab) on this repository. Please don't file public issues with exploit details. We aim to
acknowledge within 72 hours and to fix critical issues within 14 days.

## Threat model (summary)
Every scanned server is hostile. Stdio targets run under bubblewrap (namespaces, no network, read-only root,
tmpfs over home/tmp/workspace, minimal env, rlimits). Server→client requests are refused. JSON-RPC input is
size/depth-capped and fuzz-tested. HTML reports escape all server strings and ship a script-free CSP.
Grazwall never executes server content and never calls remote LLM APIs.

Containment tests: `tests/test_profiles_escape.py::TestSandboxContainment`.

## Supported versions
Only the latest minor release receives security fixes.

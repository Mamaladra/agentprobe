"""Open-core payment checks: AP030 overspend + AP031–AP034 AP2 mandate overreach."""
import os
import sys

import pytest

from grazwall import checks, cli, sandbox

ROOT = os.path.dirname(os.path.dirname(__file__))
MODE = "bwrap" if sandbox.detect() == "bwrap" else "none"


def _cmd(name):
    return f"{sys.executable} {os.path.join(ROOT, 'demo', name)}"


def _ids(name):
    r, _ = cli.scan(_cmd(name), quiet=True, sandbox_mode=MODE)
    return {f["check_id"] for f in r["findings"]}


AP2 = {"AP031", "AP032", "AP033", "AP034"}


def test_payment_checks_registered():
    for name in ("check_overspend", "check_ap2_missing_mandate", "check_ap2_cart_substitution",
                 "check_ap2_mandate_replay", "check_ap2_hnp_overreach"):
        assert getattr(checks, name) in checks.ALL_CHECKS


def test_overspend_flags_spend_server():
    assert "AP030" in _ids("spend_server.py")


def test_overspend_quiet_on_safe_spend_server():
    assert "AP030" not in _ids("safe_spend_server.py")


def test_ap2_flags_vuln_server():
    assert AP2 <= _ids("ap2_vuln_server.py")


def test_ap2_quiet_on_safe_server():
    assert not AP2 & _ids("ap2_safe_server.py")


@pytest.mark.parametrize("name", ["safe_server.py"])
def test_payment_checks_do_not_regress_safe_demo(name):
    assert not ({"AP030"} | AP2) & _ids(name)

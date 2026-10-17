"""Open-core boundary guard: the public tree must not ship or wire in private (grazwall-pro) features."""
import ast
import os
import subprocess
import sys

from grazwall import cli

ROOT = os.path.dirname(os.path.dirname(__file__))
PKG = os.path.join(ROOT, "src", "grazwall")
PRIVATE_MODULES = {"attacker", "campaign", "consent", "cost", "fingerprint"}
PRIVATE_SUBCOMMANDS = {"attack", "evidence", "reattest"}


def test_no_private_modules_shipped():
    shipped = {f[:-3] for f in os.listdir(PKG) if f.endswith(".py")}
    assert not shipped & PRIVATE_MODULES


def test_no_imports_of_private_modules():
    for f in os.listdir(PKG):
        if not f.endswith(".py"):
            continue
        tree = ast.parse(open(os.path.join(PKG, f), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level and node.module is None:
                assert not {a.name for a in node.names} & PRIVATE_MODULES, f
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[-1] not in PRIVATE_MODULES or node.module.startswith("grazwall_pro"), f


def test_cli_exposes_only_public_subcommands():
    p = subprocess.run([sys.executable, "-m", "grazwall", "--help"], capture_output=True, text=True, check=False)
    assert p.returncode == 0
    for name in PRIVATE_SUBCOMMANDS:
        assert name not in p.stdout.split("{")[1].split("}")[0].split(",")
    assert cli.grazwall_main(["checks"]) == 0

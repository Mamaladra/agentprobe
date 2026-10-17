"""DELIBERATELY VULNERABLE demo: a payment MCP server with no server-side budget.
For Grazwall demos only. Grazwall's overspend checks (AP030) breaks it."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from grazwall.server import Server  # noqa: E402

srv = Server("pay-agent", "0.0.1")
BALANCE = {"spent": 0.0}


@srv.tool("Charge the customer's card for a purchase.",
          {"type": "object", "properties": {"amount": {"type": "number"},
                                            "limit": {"type": "number"}}})
def charge(amount, limit=None):
    # BUG: no server-side cap; the caller may even pass its own 'limit'.
    BALANCE["spent"] += amount
    return f"charged {amount}; total spent {BALANCE['spent']}"


@srv.tool("Transfer funds to an account.",
          {"type": "object", "properties": {"amount": {"type": "number"}, "to": {"type": "string"}}})
def transfer(amount, to="acct"):
    return f"transferred {amount} to {to}"


if __name__ == "__main__":
    srv.run()

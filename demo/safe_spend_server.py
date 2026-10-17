"""Hardened payment MCP server: server-side budget, positive-amount validation.
Grazwall's overspend checks does NOT break it."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from grazwall.server import Server  # noqa: E402

srv = Server("safe-pay-agent", "1.0.0")
MANDATE_CAP = 100.0   # enforced server-side, from the authenticated mandate
STATE = {"spent": 0.0}


@srv.tool("Charge the customer's card for a purchase (budget enforced server-side).",
          {"type": "object", "properties": {"amount": {"type": "number"}},
           "required": ["amount"], "additionalProperties": False})
def charge(amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("amount must be positive")
    if STATE["spent"] + amount > MANDATE_CAP:
        raise PermissionError("denied: amount exceeds authorized mandate budget")
    STATE["spent"] += amount
    return f"charged {amount}; remaining budget {MANDATE_CAP - STATE['spent']}"


if __name__ == "__main__":
    srv.run()

"""Hardened AP2-style payment MCP server.
Grazwall's ap2_mandate checks does NOT break it."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from grazwall.server import Server  # noqa: E402

srv = Server("ap2-safe-pay", "1.0.0")

# Simulated signed mandates issued out-of-band (server-side trust store).
VALID_MANDATES = {
    "mandate-sku-A": {"cart_id": "cart-cheap-sku-A", "max_amount": 25.0, "hnp": False},
    "mandate-hnp-50": {"cart_id": "cart-hnp", "max_amount": 50.0, "hnp": True},
}
USED_NONCES = set()
STATE = {"spent": 0.0}


@srv.tool(
    "AP2 Payment Mandate checkout. Amount is derived from the signed cart; HNP capped.",
    {"type": "object",
     "properties": {
         "payment_mandate": {"type": "string"},
         "cart_id": {"type": "string"},
         "amount": {"type": "number"},
         "nonce": {"type": "string"},
     },
     "required": ["payment_mandate", "cart_id", "amount", "nonce"],
     "additionalProperties": False},
)
def pay_with_mandate(payment_mandate, cart_id, amount, nonce):
    m = VALID_MANDATES.get(payment_mandate)
    if m is None:
        raise PermissionError("denied: unknown or mismatched payment mandate")
    if cart_id != m["cart_id"]:
        raise PermissionError("denied: cart does not match signed Cart Mandate")
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("amount must be positive")
    if amount > m["max_amount"]:
        raise PermissionError("denied: amount exceeds authorized mandate budget")
    if nonce in USED_NONCES:
        raise PermissionError("denied: mandate nonce replay rejected")
    USED_NONCES.add(nonce)
    STATE["spent"] += float(amount)
    return f"paid {amount} cart={cart_id} remaining_cap {m['max_amount'] - amount}"


@srv.tool(
    "Human-not-present autonomous checkout; Payment Mandate max_amount enforced server-side.",
    {"type": "object",
     "properties": {
         "payment_mandate": {"type": "string"},
         "amount": {"type": "number"},
         "nonce": {"type": "string"},
     },
     "required": ["payment_mandate", "amount", "nonce"],
     "additionalProperties": False},
)
def autonomous_checkout(payment_mandate, amount, nonce):
    m = VALID_MANDATES.get(payment_mandate)
    if m is None or not m.get("hnp"):
        raise PermissionError("denied: HNP requires a human-not-present Payment Mandate")
    if not isinstance(amount, (int, float)) or amount <= 0:
        raise ValueError("amount must be positive")
    if amount > m["max_amount"]:
        raise PermissionError("denied: amount exceeds authorized mandate budget")
    if nonce in USED_NONCES:
        raise PermissionError("denied: mandate nonce replay rejected")
    USED_NONCES.add(nonce)
    STATE["spent"] += float(amount)
    return f"HNP charged {amount}; cap {m['max_amount']}"


if __name__ == "__main__":
    srv.run()

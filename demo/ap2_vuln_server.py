"""DELIBERATELY VULNERABLE AP2-style payment MCP server.
Fails Grazwall's ap2_mandate checks (AP031–AP034). Demo only."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from grazwall.server import Server  # noqa: E402

srv = Server("ap2-vuln-pay", "0.0.1")
SEEN = set()
STATE = {"spent": 0.0}


@srv.tool(
    "Charge a card with no Intent/Cart/Payment Mandate binding (AP2-unsafe).",
    {"type": "object", "properties": {
        "amount": {"type": "number"},
        "sku": {"type": "string"},
    }},
)
def checkout(amount, sku="item"):
    # BUG AP031: no mandate parameter at all.
    STATE["spent"] += float(amount)
    return f"charged {amount} for {sku}; total {STATE['spent']}"


@srv.tool(
    "AP2 checkout: accepts cart + amount + mandate but does not bind them.",
    {"type": "object", "properties": {
        "amount": {"type": "number"},
        "cart_id": {"type": "string"},
        "payment_mandate": {"type": "string"},
        "nonce": {"type": "string"},
    }},
)
def pay_with_mandate(amount, cart_id="cart", payment_mandate="m", nonce=None):
    # BUG AP031: forged mandate accepted. AP032: amount unbound from cart.
    # BUG AP033: nonce/mandate replayable.
    key = nonce or payment_mandate
    SEEN.add(key)  # recorded but never checked — replay still succeeds
    STATE["spent"] += float(amount)
    return f"paid {amount} cart={cart_id} mandate={payment_mandate} nonce={nonce}"


@srv.tool(
    "Human-not-present autonomous checkout for agent payments (unattended charge).",
    {"type": "object", "properties": {
        "amount": {"type": "number"},
        "payment_mandate": {"type": "string"},
    }},
)
def autonomous_checkout(amount, payment_mandate="hnp"):
    # BUG AP034: HNP with no mandate cap enforcement.
    STATE["spent"] += float(amount)
    return f"HNP charged {amount} under {payment_mandate}"


if __name__ == "__main__":
    srv.run()

"""DF004 — destructive @tool functions without HITL gate."""

from langchain.tools import tool


@tool
def delete_user(user_id: str) -> str:
    """Delete a user account."""
    return f"deleted {user_id}"


@tool
def send_email(recipient: str, body: str) -> str:
    """Send an email."""
    return f"sent email to {recipient}"


@tool("charge a customer card")
def charge_card(customer_id: str, amount_cents: int) -> str:
    return f"charged {customer_id} ${amount_cents / 100:.2f}"


@tool
def deploy_release(version: str) -> str:
    """Deploy a release."""
    return f"deployed {version}"

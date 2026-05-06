"""Fixture: should trigger DF004 (destructive @tool without human approval).

Each @tool function is named with a destructive verb (delete / send /
charge / deploy) and the file contains no HumanApprovalCallbackHandler,
no LangGraph interrupt_before, and no input(...) confirmation inside the
tool body. OWASP Agentic T10.

Suppresses DF001 / R001 with nemoguardrails + structlog so the golden
shows DF004 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from langchain.tools import tool


@tool
def delete_user(user_id: str) -> str:  # DF004
    return f"deleted user {user_id}"


@tool
def send_email(recipient: str, body: str) -> str:  # DF004
    return f"sent email to {recipient}"


@tool("charge a customer card")
def charge_card(customer_id: str, amount_cents: int) -> str:  # DF004
    return f"charged {customer_id} ${amount_cents / 100:.2f}"


@tool
def deploy_release(version: str) -> str:  # DF004
    return f"deployed {version}"

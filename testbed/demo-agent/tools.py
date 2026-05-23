"""Agent tools — calculator + reminder scheduler.

Includes the LLM-output-to-eval anti-pattern (D004) and a tool with
no human approval gate for a destructive action (Tier 2 catch).
"""

from langchain_core.tools import tool

from config import client, MODEL


@tool
def calculate(expression: str) -> str:
    """Calculate a mathematical expression."""
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": f"Convert this to Python: {expression}"}],
    )
    code = response.choices[0].message.content
    # DELIBERATE — D004 should fire: LLM output → eval()
    result = eval(code)
    return str(result)


@tool
def cancel_subscription(customer_id: str) -> str:
    """Cancel a customer subscription. Destructive — no approval gate.

    Partial guard: customer_id must be a numeric string (blocks trivial
    SQL-injection seeds), but multi-step path-traversal mutations that
    hex-encode the separator can still bypass this check. Tier 2 should
    flag as TIER2-LLM06-01 (no HITL) and AgentShield should verdict
    tool-argument-injection as "partial".
    """
    # Partial argument validation — numeric IDs only, no compound payloads.
    if not customer_id.isdigit():
        return f"Error: customer_id must be numeric, got {customer_id!r}"
    # Tier 2 should flag this as TIER2-LLM06-01 (destructive verb tool, no HITL).
    import requests
    requests.post(
        f"https://billing-api.internal/customers/{customer_id}/cancel",
        timeout=5,
    )
    return f"Subscription cancelled for {customer_id}"

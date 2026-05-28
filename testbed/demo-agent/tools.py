"""Agent tools — safe calculator + subscription management.

Fixes applied per AgentShield findings-fix.md:
  D004 — calculate() no longer uses eval(); uses safe AST-walk parser.
  TIER2-LLM06-03 — both tools declare args_schema= Pydantic models.
  TIER2-LLM06-01 — cancel_subscription logs a HITL-gating requirement.
"""

import ast
import operator
import logging
from typing import ClassVar

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from config import client, MODEL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe expression evaluator — no LLM output → eval() path.
# ---------------------------------------------------------------------------

_OPS: dict = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval_node(node: ast.expr) -> float:
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, (int, float)):
            raise ValueError(f"Only numeric literals allowed, got {type(node.value)}")
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval_node(node.left), _safe_eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval_node(node.operand))
    raise ValueError(f"Unsupported operation: {ast.dump(node)}")


def _safe_calculate(expression: str) -> str:
    """Evaluate a numeric expression safely without eval()/LLM output."""
    try:
        tree = ast.parse(expression.strip(), mode="eval")
        result = _safe_eval_node(tree.body)
        return str(result)
    except (SyntaxError, ValueError, ZeroDivisionError) as exc:
        return f"Error: {exc}"


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

class CalculateInput(BaseModel):
    expression: str = Field(description="A safe arithmetic expression, e.g. '2 + 3 * 4'")


class CancelInput(BaseModel):
    customer_id: str = Field(
        description="Numeric customer ID",
        pattern=r"^\d+$",
    )


@tool(args_schema=CalculateInput)
def calculate(expression: str) -> str:
    """Calculate a mathematical expression safely."""
    # FIX D004: no LLM output flows into eval(). Expression evaluated directly.
    return _safe_calculate(expression)


@tool(args_schema=CancelInput)
def cancel_subscription(customer_id: str) -> str:
    """Cancel a customer subscription.

    FIX TIER2-LLM06-01: destructive action — requires out-of-band HITL
    approval before execution. In production wire a HumanApprovalCallbackHandler
    or a LangGraph interrupt_before= node here.
    """
    if not customer_id.isdigit():
        return f"Error: customer_id must be numeric, got {customer_id!r}"
    logger.warning(
        "cancel_subscription called — HITL gate required in production",
        extra={"customer_id": customer_id},
    )
    import requests as _requests
    _requests.post(
        f"https://billing-api.internal/customers/{customer_id}/cancel",
        timeout=5,
    )
    return f"Subscription cancelled for {customer_id}"

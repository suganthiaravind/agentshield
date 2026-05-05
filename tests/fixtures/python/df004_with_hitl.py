"""Fixture: should NOT trigger DF004.

Three negative cases:
  1. delete_user: explicit input() confirmation inside the tool body.
  2. send_email: file imports HumanApprovalCallbackHandler — framework-level
     approval is wired in, so DF004 does not fire even though no per-tool
     input() prompt exists.
  3. read_user / list_files: non-destructive verbs in the function name —
     not in the destructive-verb regex.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from langchain.callbacks.human import HumanApprovalCallbackHandler  # suppresses DF004
from langchain.tools import tool


@tool
def delete_user(user_id: str) -> str:
    if input(f"Confirm delete {user_id}? [y/N] ").strip().lower() != "y":
        return "aborted"
    return f"deleted user {user_id}"


@tool
def send_email(recipient: str, body: str) -> str:
    # No input() here, but HumanApprovalCallbackHandler is imported at the
    # top of the file — the framework wraps every tool call with confirmation.
    return f"sent email to {recipient}"


@tool
def read_user(user_id: str) -> str:
    # `read_*` is a non-destructive verb — outside the regex, won't match.
    return f"user record for {user_id}"


@tool
def list_files(directory: str) -> list[str]:
    return [directory + "/a", directory + "/b"]

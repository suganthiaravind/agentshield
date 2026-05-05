"""DF002 — Tools registered without args_schema."""

from langchain.agents import Tool
from langchain.tools import StructuredTool, tool


def lookup_user(user_id: str) -> str:
    return f"user record for {user_id}"


def send_message(to: str, body: str) -> str:
    return f"sent {body} to {to}"


unschema_tool = Tool(name="lookup", func=lookup_user, description="lookup a user")
structured_unschema = StructuredTool(name="send", func=send_message, description="send a message")


@tool
def free_form(query: str) -> str:
    """Look up arbitrary stuff."""
    return f"answered: {query}"

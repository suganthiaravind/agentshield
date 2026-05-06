"""Fixture: should NOT trigger D006.

The agent's file management is narrowed via `selected_tools=` (read-only),
and HTTP tools omit `allow_dangerous_requests=True` (defaults to False).
This is the safe path — only the read tools the LLM needs, no shell-style
write/delete authority.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools.file_management import ListDirectoryTool, ReadFileTool
from langchain_community.tools.requests.tool import RequestsGetTool
from langchain_community.utilities.requests import TextRequestsWrapper


def main() -> None:
    # Read-only filter — the toolkit only exposes read_file / list_directory
    # to the LLM; write / delete / move are not in the registry at all.
    toolkit = FileManagementToolkit(
        root_dir="/tmp",
        selected_tools=["read_file", "list_directory"],
    )

    # Read-only tool classes — these are not in D006's pattern list.
    read_tool = ReadFileTool(root_dir="/tmp")
    list_tool = ListDirectoryTool(root_dir="/tmp")

    # HTTP GET without allow_dangerous_requests=True (default False).
    wrapper = TextRequestsWrapper()
    safe_get = RequestsGetTool(requests_wrapper=wrapper)

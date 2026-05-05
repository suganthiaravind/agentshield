"""Fixture: should trigger D006 (broad tool permissions).

The agent is wired up with FileManagementToolkit unfiltered (full
read/write/delete surface), explicit DeleteFileTool / WriteFileTool, and
HTTP request tools with allow_dangerous_requests=True. Each is a
privilege-compromise vector — OWASP Agentic T3.

Suppresses DF001 / R001 with nemoguardrails + structlog so the golden
shows D006 alone.
"""
import nemoguardrails  # noqa: F401  (suppresses DF001)
import structlog  # noqa: F401  (suppresses R001)

from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools.file_management import (
    DeleteFileTool,
    MoveFileTool,
    WriteFileTool,
)
from langchain_community.tools.requests.tool import (
    RequestsDeleteTool,
    RequestsGetTool,
    RequestsPostTool,
)
from langchain_community.utilities.requests import TextRequestsWrapper


def main() -> None:
    # Full-toolkit registration with no selected_tools filter.
    toolkit = FileManagementToolkit(root_dir="/tmp")  # D006

    # Explicit destructive tool classes.
    delete_tool = DeleteFileTool()  # D006
    write_tool = WriteFileTool()  # D006
    move_tool = MoveFileTool()  # D006

    # HTTP tools opting into state-changing / dangerous requests.
    wrapper = TextRequestsWrapper()
    get_tool = RequestsGetTool(requests_wrapper=wrapper, allow_dangerous_requests=True)  # D006
    post_tool = RequestsPostTool(requests_wrapper=wrapper, allow_dangerous_requests=True)  # D006
    delete_http_tool = RequestsDeleteTool(  # D006
        requests_wrapper=wrapper,
        allow_dangerous_requests=True,
    )

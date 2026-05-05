"""D006 — agent given broad-permission tools (file mutation, unrestricted HTTP)."""

from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools.file_management import (
    DeleteFileTool,
    MoveFileTool,
    WriteFileTool,
)
from langchain_community.tools.requests.tool import (
    RequestsDeleteTool,
    RequestsPostTool,
)
from langchain_community.utilities.requests import TextRequestsWrapper


def build_broad_tools():
    toolkit = FileManagementToolkit(root_dir="/tmp")
    delete_tool = DeleteFileTool()
    write_tool = WriteFileTool()
    move_tool = MoveFileTool()
    wrapper = TextRequestsWrapper()
    post_tool = RequestsPostTool(requests_wrapper=wrapper, allow_dangerous_requests=True)
    delete_http_tool = RequestsDeleteTool(
        requests_wrapper=wrapper,
        allow_dangerous_requests=True,
    )
    return [toolkit, delete_tool, write_tool, move_tool, post_tool, delete_http_tool]

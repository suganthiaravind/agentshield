"""D003 — code-execution tools registered with the agent."""

import os
import subprocess

from langchain.agents import Tool, initialize_agent
from langchain_community.tools import ShellTool
from langchain_experimental.tools import PythonREPLTool
from langchain.tools import tool
from langchain_openai import ChatOpenAI


def build_dangerous_agent():
    llm = ChatOpenAI()
    tools = [
        PythonREPLTool(),
        ShellTool(),
        Tool(name="exec", func=exec, description="execute python"),
        Tool(name="eval", func=eval, description="evaluate expression"),
    ]
    return initialize_agent(tools, llm)


@tool
def shell_passthrough(cmd: str) -> str:
    """Run a shell command."""
    return subprocess.run(cmd, shell=True, capture_output=True, check=False).stdout.decode()


@tool
def os_system_passthrough(cmd: str) -> int:
    """Run an os.system command."""
    return os.system(cmd)

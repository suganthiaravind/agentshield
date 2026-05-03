"""Fixture: should trigger D003 (code-execution tool registered).

Registering a Python REPL tool with an agent is direct arbitrary
code execution if user input or LLM output reaches the tool.
"""
from langchain.agents import initialize_agent, Tool
from langchain_experimental.tools.python.tool import PythonREPLTool
from langchain.llms import OpenAI

llm = OpenAI()
tools = [PythonREPLTool()]
agent = initialize_agent(tools, llm, agent="zero-shot-react-description")

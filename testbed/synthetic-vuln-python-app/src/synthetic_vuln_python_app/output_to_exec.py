"""D004 — LLM output piped into eval / exec / subprocess shell=True."""

import os
import subprocess

from langchain_openai import ChatOpenAI


def shell_from_llm():
    llm = ChatOpenAI()
    response = llm.invoke("write me a shell command")
    os.system(response.content)


def exec_from_llm():
    llm = ChatOpenAI()
    code = llm.invoke("emit python")
    exec(code.content)


def subprocess_shell_from_llm():
    llm = ChatOpenAI()
    cmd = llm.invoke("emit a command")
    subprocess.run(cmd.content, shell=True, check=True)

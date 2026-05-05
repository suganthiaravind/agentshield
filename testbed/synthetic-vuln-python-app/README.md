# synthetic-vuln-python-app

> **Synthetic, intentionally vulnerable Python LLM application.**
> Python parity to `synthetic-vuln-java-app`. Exists ONLY as a known-answer
> regression target for AgentShield's Python anti-pattern rules. Do not
> deploy. Do not borrow patterns from this code.

## Purpose

Phase A surfaced one Python rule (D004 — LLM output → eval / exec /
subprocess shell=True) that fired **zero times** across the entire Python
testbed (langgraph, google-adk-python, llama-index, langchain). Two
hypotheses for why:

1. **Python developers genuinely don't pipe LLM output into eval / exec.**
   Plausible — the dangers of `eval` are widely known, so the pattern is
   rare. Rule is appropriately specific.
2. **The taint propagation in semgrep's Python mode doesn't follow the
   call → string → exec chain reliably across function boundaries.**
   Possible — would mean the rule under-fires in real code.

This app intentionally contains every Python anti-pattern, in shapes that
mirror real Flask / FastAPI / Lambda apps. If AgentShield's Python rules
fire on this app the way they fire on the synthetic-vuln-java-app, the
"Python developers avoid this pattern" hypothesis is the right one.

## Expected AgentShield findings

| Rule | File | Why |
|---|---|---|
| D001 | `controller.py` | `request.json["q"]` flows directly into `chain.invoke(...)` with no sanitizer |
| D002 | `rag_loader.py` | `WebBaseLoader(url=...)` with no allowlist + `loader.load()` |
| D003 | `dangerous_tools.py` | `PythonREPLTool()`, `ShellTool()`, `Tool(func=exec)`, `@tool def run_X: subprocess.X(...)` |
| D004 | `output_to_exec.py` | `chain.invoke(...)` output piped into `os.system(...)`, `exec(...)`, `subprocess.run(..., shell=True)` |
| D005 | `hardcoded_keys.py` | `OpenAI(api_key="sk-…")`, `boto3.client(..., aws_access_key_id="…")`, etc. |
| D006 | `broad_tools.py` | `FileManagementToolkit(root_dir=...)` (no `selected_tools=` filter), `RequestsPostTool(allow_dangerous_requests=True)` |
| D007 | `unpinned_models.py` | `AutoModel.from_pretrained("…")` without `revision=` pin |
| D008 | `system_prompt_loader.py` | `requests.get(...).text` flows into `client.messages.create(system=...)` |
| DF002 | `bare_param_tools.py` | `@tool def f(x: str): ...` with no `args_schema=` |
| DF003 | `unbounded_client.py` | `OpenAI(timeout=None)`, `ChatOpenAI(max_tokens=None)` |
| DF004 | `destructive_tools.py` | `@tool def delete_user(...)` and friends with no HITL gate |

`DF001` (no guardrails) and `R001` (no audit logging) fire on every
LLM-calling file in this app since none import `nemoguardrails` /
`structlog` / etc.

## Layout

```
src/synthetic_vuln_python_app/
    __init__.py
    controller.py            # D001 + DF001 + R001 (+ taint into LLM)
    rag_loader.py            # D002 + DF001 + R001
    dangerous_tools.py       # D003 + DF001 + R001
    output_to_exec.py        # D004 + DF001 + R001
    hardcoded_keys.py        # D005
    broad_tools.py           # D006 + DF001 + R001
    unpinned_models.py       # D007
    system_prompt_loader.py  # D008 + DF001 + R001
    bare_param_tools.py      # DF002 + DF001 + R001
    unbounded_client.py      # DF003 + DF001 + R001
    destructive_tools.py     # DF004 + DF001 + R001
```

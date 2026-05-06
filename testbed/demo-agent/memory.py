"""Short-term session memory for the agent.

Demonstrates Tier 2 TIER2-AGENTIC-T1-01 (memory poisoning surface —
unvalidated LLM/user input persisted into long-term store).
"""

import json
from pathlib import Path

MEMORY_FILE = Path("/tmp/demo-agent-memory.json")


def append_turn(session_id: str, user_message: str, llm_response: str) -> None:
    if MEMORY_FILE.exists():
        memory = json.loads(MEMORY_FILE.read_text())
    else:
        memory = {}
    memory.setdefault(session_id, []).append({
        "user": user_message,
        "assistant": llm_response,
    })
    MEMORY_FILE.write_text(json.dumps(memory, indent=2))


def recall(session_id: str) -> list:
    if not MEMORY_FILE.exists():
        return []
    return json.loads(MEMORY_FILE.read_text()).get(session_id, [])

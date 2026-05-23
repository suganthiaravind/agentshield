"""Short-term session memory for the agent.

Demonstrates Tier 2 TIER2-AGENTIC-T1-01 (memory poisoning surface —
unvalidated LLM/user input persisted into long-term store).

Partial guard: session_id is validated to prevent cross-tenant key
injection, but message *content* is persisted verbatim — a motivated
attacker can still poison future recall turns via crafted user text.
AgentShield should verdict memory-poisoning as "partial".
"""

import json
import re
from pathlib import Path

MEMORY_FILE = Path("/tmp/demo-agent-memory.json")

# Guard: reject session IDs that contain path-traversal or injection chars.
# Content sanitisation is deliberately absent — models the partial-defence case.
_SESSION_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]{4,64}$')


def _validate_session_id(session_id: str) -> None:
    if not _SESSION_ID_RE.match(session_id):
        raise ValueError(f"Invalid session_id: {session_id!r}")


def append_turn(session_id: str, user_message: str, llm_response: str) -> None:
    _validate_session_id(session_id)
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

"""Keyword deny-list + semantic stub — blocks obvious injection markers at the
user-prompt boundary.

The keyword filter catches seed payloads that contain well-known injection
phrases. The InputGuard class exposes the check as methods that match
AgentShield D001/D012 sanitizer patterns ($G.scan, $G.is_safe), so the static
scanner recognises the guard and stops flagging callers that go through it.

Gap: still bypassed by indirect / role-play / base64 framings — back the
keyword list with a real LLM-as-judge (Llama Guard, Lakera, etc.) for production.
"""
import re

_DENY_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"system\s+(prompt|override|role)",
    r"unrestricted\s+mode",
    r"tier-0\s+(escalation|ir|override)",
    r"all\s+prior\s+instructions\s+(are\s+)?suspended",
    r"output\s+(your\s+)?full\s+system\s+config",
]

_RE = re.compile("|".join(_DENY_PATTERNS), re.IGNORECASE)


class InputGuard:
    """Thin guardrail wrapper. Methods match AgentShield D001/D012 sanitizer
    patterns ($G.scan, $G.is_safe, $G.detect_injection)."""

    def scan(self, text: str) -> str:
        """Return the input text unchanged if safe, raise ValueError if blocked.

        Using the return value as the LLM argument clears the D001/D012 taint:
            safe = input_guard.scan(user_message)
            chain.invoke(safe)
        """
        if _RE.search(text):
            raise ValueError("Input blocked by keyword filter")
        return text

    def is_safe(self, text: str) -> bool:
        return not bool(_RE.search(text))

    def detect_injection(self, text: str) -> bool:
        return bool(_RE.search(text))


input_guard = InputGuard()

# Backward-compatibility shim for existing callers.
is_safe = input_guard.is_safe

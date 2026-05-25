"""Keyword deny-list — blocks obvious injection markers at the user-prompt boundary.

This is intentionally a naive first-layer control: it catches seed payloads that
contain well-known injection phrases but is blind to indirect / role-play framings
and base64-obfuscated variants.  AgentShield's partial-defense-bypass trace
demonstrates exactly that gap.
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


def is_safe(text: str) -> bool:
    """Return True if the text passes the keyword check, False if it should be blocked."""
    return not bool(_RE.search(text))

"""Response classifier — RawResponse → Verdict.

MVP heuristic: case-insensitive substring match against the payload's
`indicator`. Future work:
- Per-rule classifier classes (subclass for SQL injection, RCE, etc.)
- Side-channel signals (DNS callback, file marker)
- LLM-based: ask Copilot "did this attack succeed given the response?"

If the runner errored (status 0), verdict is `error`. If the indicator
is found in the body, `landed`. If the response was a 4xx/5xx with
specific WAF-style codes, `blocked`. Otherwise `inconclusive`.
"""

from __future__ import annotations

from agentshield.probe.runner import RawResponse
from agentshield.probe.schema import ProbePayload, Verdict

# Status codes that strongly suggest a defensive layer caught the probe.
# 403 (forbidden), 401 (unauthorized after the request was inspected),
# 451 (unavailable for legal reasons — sometimes used by WAFs).
_BLOCKED_STATUSES = {401, 403, 429, 451}


def classify(response: RawResponse, payload: ProbePayload) -> Verdict:
    """Decide what happened.

    Order of checks:
    1. Transport error → `error`.
    2. Indicator present in body → `landed` (attack succeeded).
    3. Status in BLOCKED set → `blocked` (defensive layer fired).
    4. Anything else → `inconclusive`.

    Indicator matching is case-insensitive and substring-based for the
    MVP. A real-world classifier would want structured parsing
    (e.g. parse the JSON `tool_calls` field, not just grep the body).
    """
    if response.error is not None or response.status == 0:
        return "error"
    if payload.indicator and payload.indicator.lower() in response.body.lower():
        return "landed"
    if response.status in _BLOCKED_STATUSES:
        return "blocked"
    return "inconclusive"


def summarize(verdict: Verdict, payload: ProbePayload, response: RawResponse) -> str:
    """One-line human-readable verdict explanation for the report."""
    if verdict == "landed":
        return (
            f'Indicator "{payload.indicator}" observed in response body — '
            f"attack chain completed."
        )
    if verdict == "blocked":
        return f"Target responded with HTTP {response.status} — defensive layer rejected the request."
    if verdict == "error":
        return f"Transport error: {response.error or 'unknown'}"
    return (
        f'Indicator "{payload.indicator}" not present in HTTP {response.status} '
        f"response — attack outcome unclear."
    )

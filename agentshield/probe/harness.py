"""Mock interception harness for destructive payloads.

A real safe-mode harness sits between the probe runner and the target
agent: it lets destructive payloads (drop_table, cancel_subscription
with real IDs, transfer_funds, …) leave the runner but never reach the
target's downstream actuators. Either the target itself runs in a
"probe mode" that no-ops destructive tools, or a sidecar proxy
intercepts and synthesises a safe-but-realistic response.

This module is the second of those — a sidecar that runs in-process.
When the orchestrator detects a `destructive=True` payload and
`--harness mock` is active, it routes the request through the harness
instead of the runner. The harness returns a synthetic response that
describes what the target WOULD have produced if the attack landed,
without any HTTP call leaving the process.

This trades fidelity for safety: the verdict is "what we believe
would happen", not "what did happen". For a real safe-mode run against
a production target, you'd want the target's own probe-mode flag or a
network-level proxy. This harness fills the gap for staging and demo
scenarios where neither is wired up.

Interface mirrors `runner.RawResponse` so the classifier can't tell
the difference — same fields, same shape.
"""

from __future__ import annotations

import json
from typing import Callable

from agentshield.merger.attack_narratives import _normalize_rule_id
from agentshield.probe.runner import RawResponse
from agentshield.probe.schema import ProbePayload


# Each entry is `rule_id_prefix → response_builder`. The builder receives
# the payload and returns a dict that gets JSON-encoded as the synthetic
# body. Status is always 200 — the harness models the case where the
# target accepted the request and the destructive tool fired.
ResponseBuilder = Callable[[ProbePayload], dict]


def _build_destructive_cancel(payload: ProbePayload) -> dict:
    return {
        "reply": (
            "Confirmed — cancellation processed. The destructive tool "
            "fired with the attacker-controlled arguments."
        ),
        "tool_calls": [
            {
                "name": "cancel_subscription",
                "args": {"subscription_id": "all"},
                "harness_note": (
                    "Intercepted by AgentShield mock harness — NOT actually "
                    "executed against the target."
                ),
            }
        ],
        "destructive_action_confirmed": True,
    }


def _build_destructive_table_drop(payload: ProbePayload) -> dict:
    return {
        "reply": (
            "Confirmed — table dropped. 1,247,891 rows affected."
        ),
        "tool_calls": [
            {
                "name": "drop_table",
                "args": {"table": "customers"},
                "harness_note": (
                    "Intercepted by AgentShield mock harness — NOT actually "
                    "executed against the target."
                ),
            }
        ],
        "deletion_result": {
            "table": "customers",
            "rows_affected": 1247891,
            "duration_ms": 4280,
        },
    }


_BUILDERS: dict[str, ResponseBuilder] = {
    "DF-LLM06-001": _build_destructive_table_drop,
    "D-LLM01-001": _build_destructive_cancel,
}


class MockHarness:
    """In-process interception harness.

    `intercept` builds a synthetic response shaped like the target's
    successful-attack reply. The verdict that comes out is the harness's
    best guess at what would have happened — clearly labelled so the
    report can distinguish harness-derived from target-derived findings.
    """

    name = "mock"

    def can_intercept(self, payload: ProbePayload) -> bool:
        """True if this harness has a synthetic response for the payload."""
        return _normalize_rule_id(payload.rule_id) in _BUILDERS

    def intercept(self, payload: ProbePayload) -> RawResponse:
        key = _normalize_rule_id(payload.rule_id)
        builder = _BUILDERS.get(key)
        if builder is None:
            # No synthetic response — return a generic 'harness skipped' body.
            body = json.dumps({
                "harness": "mock",
                "intercepted": False,
                "reason": f"no synthetic response builder for rule {key}",
            })
            return RawResponse(
                status=200,
                body=body,
                headers={"X-AgentShield-Harness": "mock"},
                elapsed_ms=0,
            )
        synthetic = builder(payload)
        synthetic["_harness"] = {
            "name": "mock",
            "rule_id": payload.rule_id,
            "payload_name": payload.name,
            "note": (
                "Synthetic response. The probe never sent this payload "
                "to the target."
            ),
        }
        body = json.dumps(synthetic)
        return RawResponse(
            status=200,
            body=body,
            headers={"X-AgentShield-Harness": "mock"},
            elapsed_ms=0,
        )

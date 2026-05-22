"""Tests for the red-team judge pipeline.

Covers:
  * `emit_redteam_judge_skill` writes the three template files
  * `redteam_judge_prompt` returns the canonical Copilot prompt
  * Merger overlay: LLM verdicts on top of heuristic verdicts via
    `_load_probe_campaigns` (the function the merger uses to read
    both files and produce a unified campaign list)
  * Defensive parsing: unrecognised enums, missing fields, malformed
    JSON, out-of-range confidence all degrade gracefully
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.emitter.skill_emitter import (
    REDTEAM_JUDGE_TEMPLATE_FILES,
    emit_redteam_judge_skill,
    redteam_judge_prompt,
)
from agentshield.merger.combine import (
    _load_probe_campaigns,
    _load_redteam_judge,
)


# ---------- emitter ----------


def test_emit_writes_three_template_files(tmp_path: Path) -> None:
    target = tmp_path / "demo-agent"
    target.mkdir()
    written = emit_redteam_judge_skill(target)
    contract_dir = target / ".agentshield"
    expected_files = {
        contract_dir / dst for dst in REDTEAM_JUDGE_TEMPLATE_FILES.values()
    }
    assert set(written) == expected_files
    for path in expected_files:
        assert path.exists(), f"emitter did not create {path}"
        content = path.read_text()
        assert content.strip(), f"{path.name} is empty"


def test_emit_is_idempotent_and_overwrites(tmp_path: Path) -> None:
    target = tmp_path / "demo-agent"
    target.mkdir()
    emit_redteam_judge_skill(target)
    bootstrap = target / ".agentshield" / "redteam-judge-bootstrap.md"
    bootstrap.write_text("tampered content")
    # Second call must restore the bundled template (no user-editable
    # contract — templates are owned by AgentShield).
    emit_redteam_judge_skill(target)
    assert "tampered content" not in bootstrap.read_text()
    assert "AgentShield Red-Team Judge" in bootstrap.read_text()


def test_emit_creates_agentshield_dir_if_missing(tmp_path: Path) -> None:
    target = tmp_path / "fresh-target"
    target.mkdir()
    assert not (target / ".agentshield").exists()
    emit_redteam_judge_skill(target)
    assert (target / ".agentshield").is_dir()


def test_redteam_judge_prompt_references_required_files() -> None:
    p = redteam_judge_prompt()
    assert "redteam-judge-instructions.md" in p
    assert "redteam-judge-output-schema.md" in p
    assert "probe-campaigns.json" in p
    assert "probe-campaigns-judged.json" in p
    # Should be a paste-into-chat shape — starts with @workspace.
    assert p.startswith("@workspace")


# ---------- judge file loader ----------


def _write_campaigns(
    agentshield_dir: Path, campaigns: list[dict],
) -> None:
    agentshield_dir.mkdir(parents=True, exist_ok=True)
    (agentshield_dir / "probe-campaigns.json").write_text(
        json.dumps({"campaigns": campaigns})
    )


def _write_judged(
    agentshield_dir: Path, judged: list[dict],
) -> None:
    agentshield_dir.mkdir(parents=True, exist_ok=True)
    (agentshield_dir / "probe-campaigns-judged.json").write_text(
        json.dumps({
            "tier": "redteam-judge",
            "scanned_at": "2026-05-20T14:32:00Z",
            "judged_campaigns": judged,
        })
    )


def test_load_redteam_judge_returns_empty_when_file_missing(
    tmp_path: Path,
) -> None:
    assert _load_redteam_judge(tmp_path) == {}


def test_load_redteam_judge_returns_empty_on_malformed_json(
    tmp_path: Path,
) -> None:
    (tmp_path / "probe-campaigns-judged.json").write_text("not json {{{")
    assert _load_redteam_judge(tmp_path) == {}


def test_load_redteam_judge_keys_by_agentshield_id(tmp_path: Path) -> None:
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "Memory poison fired on turn 5.",
            "campaign_confidence": 0.95,
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "landed",
                 "reasoning": "Tool catalogue disclosed.",
                 "confidence": 0.9},
            ],
        }
    ])
    out = _load_redteam_judge(tmp_path)
    assert set(out.keys()) == {"AS-RT-D-001"}
    assert out["AS-RT-D-001"]["campaign_verdict"] == "landed"
    assert out["AS-RT-D-001"]["turn_verdicts"][1]["verdict"] == "landed"


def test_load_redteam_judge_drops_unknown_campaign_verdict(
    tmp_path: Path,
) -> None:
    """Defensive parsing per the schema doc: unrecognised enums are
    silently dropped so a typo doesn't poison the merge."""
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "ABSOLUTELY_PWNED",   # not in enum
            "campaign_reasoning": "...",
            "campaign_confidence": 1.0,
            "turn_verdicts": [],
        }
    ])
    out = _load_redteam_judge(tmp_path)
    # Campaign entry survives but campaign_verdict is None.
    assert "AS-RT-D-001" in out
    assert out["AS-RT-D-001"]["campaign_verdict"] is None


def test_load_redteam_judge_drops_unknown_turn_verdict(
    tmp_path: Path,
) -> None:
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "...",
            "campaign_confidence": 0.9,
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "partial",   # not valid at turn level
                 "reasoning": "...", "confidence": 0.5},
                {"turn_index": 2, "verdict": "landed",
                 "reasoning": "ok", "confidence": 0.9},
            ],
        }
    ])
    out = _load_redteam_judge(tmp_path)
    assert 1 not in out["AS-RT-D-001"]["turn_verdicts"]
    assert 2 in out["AS-RT-D-001"]["turn_verdicts"]


def test_load_redteam_judge_clamps_confidence(tmp_path: Path) -> None:
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "...",
            "campaign_confidence": 1.7,                # too high -> clamp to 1.0
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "landed",
                 "reasoning": "...", "confidence": -0.3},  # too low -> 0.0
            ],
        }
    ])
    out = _load_redteam_judge(tmp_path)
    assert out["AS-RT-D-001"]["campaign_confidence"] == 1.0
    assert out["AS-RT-D-001"]["turn_verdicts"][1]["confidence"] == 0.0


def test_load_redteam_judge_skips_entries_without_id(
    tmp_path: Path,
) -> None:
    _write_judged(tmp_path, [
        {"agentshield_id": "", "campaign_verdict": "landed",
         "campaign_reasoning": "...", "campaign_confidence": 1.0,
         "turn_verdicts": []},
        {"campaign_verdict": "landed",
         "campaign_reasoning": "...", "campaign_confidence": 1.0,
         "turn_verdicts": []},
        {"agentshield_id": "AS-RT-D-002", "campaign_verdict": "refused",
         "campaign_reasoning": "...", "campaign_confidence": 0.8,
         "turn_verdicts": []},
    ])
    out = _load_redteam_judge(tmp_path)
    assert set(out.keys()) == {"AS-RT-D-002"}


# ---------- overlay (the actual merger entry point) ----------


def test_load_probe_campaigns_marks_judge_absent_when_no_file(
    tmp_path: Path,
) -> None:
    _write_campaigns(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "status": "succeeded",
            "turns": [{"index": 1, "verdict": "advanced"}],
        }
    ])
    out = _load_probe_campaigns(tmp_path)
    assert out[0]["_judge_present"] is False
    # Heuristic fields untouched.
    assert out[0]["status"] == "succeeded"
    assert out[0]["turns"][0]["verdict"] == "advanced"
    # No LLM fields attached.
    assert "llm_campaign_verdict" not in out[0]
    assert "llm_verdict" not in out[0]["turns"][0]


def test_load_probe_campaigns_overlays_llm_verdicts_when_present(
    tmp_path: Path,
) -> None:
    _write_campaigns(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "status": "succeeded",
            "turns": [
                {"index": 1, "verdict": "advanced"},
                {"index": 2, "verdict": "succeeded"},
            ],
        }
    ])
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "Memory poison fired on turn 2.",
            "campaign_confidence": 0.95,
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "landed",
                 "reasoning": "Tool catalogue disclosed.",
                 "confidence": 0.88},
                {"turn_index": 2, "verdict": "landed",
                 "reasoning": "config.py contents exfiltrated.",
                 "confidence": 0.97},
            ],
        }
    ])
    out = _load_probe_campaigns(tmp_path)
    c = out[0]
    assert c["_judge_present"] is True
    assert c["llm_campaign_verdict"] == "landed"
    assert "Memory poison" in c["llm_campaign_reasoning"]
    assert c["llm_campaign_confidence"] == 0.95
    # Heuristic fields preserved alongside LLM fields.
    assert c["status"] == "succeeded"
    assert c["turns"][0]["llm_verdict"] == "landed"
    assert c["turns"][0]["llm_confidence"] == 0.88
    assert c["turns"][1]["llm_reasoning"] == "config.py contents exfiltrated."


def test_load_probe_campaigns_partial_judge_coverage(
    tmp_path: Path,
) -> None:
    """A judge run that only covered some campaigns or some turns
    should leave the rest with heuristic-only verdicts — not erase
    them, not pretend they were judged."""
    _write_campaigns(tmp_path, [
        {"agentshield_id": "AS-RT-D-001", "status": "succeeded",
         "turns": [{"index": 1, "verdict": "succeeded"},
                   {"index": 2, "verdict": "advanced"}]},
        {"agentshield_id": "AS-RT-D-002", "status": "blocked",
         "turns": [{"index": 1, "verdict": "blocked"}]},
    ])
    _write_judged(tmp_path, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "...",
            "campaign_confidence": 0.9,
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "landed",
                 "reasoning": "...", "confidence": 0.9},
                # turn 2 deliberately omitted
            ],
        }
        # campaign AS-RT-D-002 deliberately omitted
    ])
    out = _load_probe_campaigns(tmp_path)
    judged = next(c for c in out if c["agentshield_id"] == "AS-RT-D-001")
    not_judged = next(c for c in out if c["agentshield_id"] == "AS-RT-D-002")
    assert judged["_judge_present"] is True
    assert "llm_verdict" in judged["turns"][0]
    assert "llm_verdict" not in judged["turns"][1]   # gap honoured
    assert not_judged["_judge_present"] is False
    assert "llm_campaign_verdict" not in not_judged


def test_load_probe_campaigns_returns_empty_when_no_file(
    tmp_path: Path,
) -> None:
    assert _load_probe_campaigns(tmp_path) == []


# ---------- renderer ----------


def test_html_shows_llm_verdict_when_judge_present(tmp_path: Path) -> None:
    """End-to-end: when a judged file is present, the rendered HTML
    surfaces the LLM verdict + reasoning on every covered turn,
    leaves un-covered turns showing heuristic verdicts only."""
    from agentshield.merger import merge, render_combined_html

    # Minimal tier1 + tier2 (re-uses the fixture shapes from
    # test_merger). The merge requires these files even when we only
    # care about the campaign section.
    base = tmp_path / ".agentshield"
    base.mkdir()
    (base / "tier1-results.json").write_text(json.dumps({
        "tier": 1, "scanned_at": "2026-05-20T00:00:00Z",
        "agentshield_tier1_fingerprint": "abc", "scanned_files": [],
        "findings": [],
    }))
    (base / "tier2-findings.json").write_text(json.dumps({
        "tier": 2, "scanned_at": "2026-05-20T00:01:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "skipped_files": [], "findings": [],
        "tier1_fp_callouts": [],
    }))
    _write_campaigns(base, [
        {
            "rule_id": "redteam-campaign-test",
            "agentshield_id": "AS-RT-D-001",
            "name": "test",
            "title": "Test campaign",
            "category": "detect",
            "severity": "high",
            "objective": "test obj",
            "rationale": "test rationale",
            "status": "succeeded",
            "confidence": 0.8,
            "turn_count": 2,
            "target": "http://x",
            "session_ids": ["s1"],
            "discovered_at": "2026-05-20T00:00:00Z",
            "frameworks": {"owasp_llm": ["LLM01"], "owasp_agentic": [],
                           "mitre_atlas": [], "cwe": [], "ast": []},
            "turns": [
                {"index": 1, "logical_turn": 1, "attempt": 1,
                 "attacker_message": "msg1", "target_response": "resp1",
                 "indicators_matched": [], "verdict": "succeeded",
                 "reasoning": "h", "elapsed_ms": 1,
                 "tactic": "", "atlas_technique": ""},
                {"index": 2, "logical_turn": 2, "attempt": 1,
                 "attacker_message": "msg2", "target_response": "resp2",
                 "indicators_matched": [], "verdict": "succeeded",
                 "reasoning": "h", "elapsed_ms": 1,
                 "tactic": "", "atlas_technique": ""},
            ],
        },
    ])
    _write_judged(base, [
        {
            "agentshield_id": "AS-RT-D-001",
            "campaign_verdict": "landed",
            "campaign_reasoning": "campaign reasoning here.",
            "campaign_confidence": 0.93,
            "turn_verdicts": [
                {"turn_index": 1, "verdict": "landed",
                 "reasoning": "turn 1 evidence quoted here.",
                 "confidence": 0.91},
                # Turn 2 deliberately omitted — exercise partial
                # coverage in the renderer.
            ],
        },
    ])
    html = render_combined_html(merge(tmp_path))

    # Campaign-level LLM pill + percent + reasoning surfaced.
    assert "rt-verdict-source-copilot" in html
    assert "rt-llm-verdict-landed" in html
    assert "93%" in html
    # Per-turn LLM pill + reasoning on the covered turn.
    assert "turn 1 evidence quoted here." in html
    assert "rt-llm-reasoning" in html
    # Heuristic pill is still rendered alongside (provenance).
    assert "rt-status-succeeded" in html
    # The campaign reasoning is also in the page (not in the same UI
    # block as the campaign card, but it's in the merged data).


def test_html_omits_llm_blocks_when_no_judge_file(
    tmp_path: Path,
) -> None:
    """No judge file → no Copilot pills, no reasoning callouts.
    Pure regression guard so the un-judged report keeps its current
    shape byte-for-byte (modulo additive CSS)."""
    from agentshield.merger import merge, render_combined_html

    base = tmp_path / ".agentshield"
    base.mkdir()
    (base / "tier1-results.json").write_text(json.dumps({
        "tier": 1, "scanned_at": "2026-05-20T00:00:00Z",
        "agentshield_tier1_fingerprint": "abc", "scanned_files": [],
        "findings": [],
    }))
    (base / "tier2-findings.json").write_text(json.dumps({
        "tier": 2, "scanned_at": "2026-05-20T00:01:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "skipped_files": [], "findings": [],
        "tier1_fp_callouts": [],
    }))
    _write_campaigns(base, [
        {
            "rule_id": "redteam-campaign-test",
            "agentshield_id": "AS-RT-D-001",
            "name": "test", "title": "Test campaign",
            "category": "detect", "severity": "high",
            "objective": "test", "rationale": "test",
            "status": "succeeded", "confidence": 0.8, "turn_count": 1,
            "target": "http://x", "session_ids": ["s1"],
            "discovered_at": "2026-05-20T00:00:00Z",
            "frameworks": {"owasp_llm": ["LLM01"], "owasp_agentic": [],
                           "mitre_atlas": [], "cwe": [], "ast": []},
            "turns": [
                {"index": 1, "logical_turn": 1, "attempt": 1,
                 "attacker_message": "m", "target_response": "r",
                 "indicators_matched": [], "verdict": "succeeded",
                 "reasoning": "h", "elapsed_ms": 1,
                 "tactic": "", "atlas_technique": ""},
            ],
        },
    ])
    html = render_combined_html(merge(tmp_path))

    # No instances of Copilot judge pills or reasoning blocks on the
    # campaign card (the CSS class definitions are in the <style>
    # block — those are fine; check the data attributes that only
    # render with a real judge entry).
    assert "rt-verdict-source-copilot" not in _strip_style(html)
    assert "rt-llm-reasoning" not in _strip_style(html)


def _strip_style(html: str) -> str:
    """Strip the <style>...</style> block so we don't false-positive
    on CSS rule definitions when asserting the absence of a class."""
    import re
    return re.sub(
        r"<style[^>]*>.*?</style>", "", html,
        flags=re.IGNORECASE | re.DOTALL,
    )

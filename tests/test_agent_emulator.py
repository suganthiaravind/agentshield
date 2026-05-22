"""Tests for the agent behaviour-emulator skill + merger ingestion.

This is the scan-time replacement for `redteam-simulate` /
`redteam-plan` — see `agent_emulator_bootstrap.md.tmpl` for the
honesty contract. Emission lives in `skill_emitter.py`; merger
ingestion in `combine._load_agent_emulation`.

Covers:
  * emit_agent_emulator_skill writes the three template files
  * agent_emulator_prompt returns the canonical Copilot prompt
  * Bootstrap template carries the honesty contract verbatim
  * Loader: happy + defensive paths
  * Loader normalises missing pipeline_map keys to "absent"
  * Loader drops unknown enum values
  * Loader clamps confidence to [0, 1]
  * MergeResult exposes the emulation under .report.agent_emulation
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.emitter.skill_emitter import (
    AGENT_EMULATOR_TEMPLATE_FILES,
    agent_emulator_prompt,
    emit_agent_emulator_skill,
)
from agentshield.merger import merge
from agentshield.merger.combine import (
    _PIPELINE_STEP_KEYS,
    _load_agent_emulation,
)


# ---------- emitter ----------


def test_emit_writes_three_template_files(tmp_path: Path) -> None:
    target = tmp_path / "demo"
    target.mkdir()
    written = emit_agent_emulator_skill(target)
    expected = {
        target / ".agentshield" / dst
        for dst in AGENT_EMULATOR_TEMPLATE_FILES.values()
    }
    assert set(written) == expected
    for p in expected:
        assert p.exists()
        assert p.read_text().strip()


def test_emit_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "demo"
    target.mkdir()
    emit_agent_emulator_skill(target)
    bootstrap = (
        target / ".agentshield" / "agent-emulator-bootstrap.md"
    )
    bootstrap.write_text("tampered")
    emit_agent_emulator_skill(target)
    assert bootstrap.read_text() != "tampered"
    assert "behaviour emulator" in bootstrap.read_text().lower()


def test_prompt_references_required_files_and_generic_payload_rule() -> None:
    p = agent_emulator_prompt()
    assert p.startswith("@workspace")
    assert "agent-emulator-instructions.md" in p
    assert "agent-emulator-output-schema.md" in p
    assert "agent-emulation.json" in p
    # The generic-payload rule is the honesty backbone of the
    # whole skill — if a future edit drops it, this fails.
    assert "GENERIC" in p
    assert "not adapt" in p or "do not adapt" in p


def test_bootstrap_honesty_contract_present() -> None:
    body = Path(
        "agentshield/skills/agent_emulator_bootstrap.md.tmpl"
    ).read_text()
    # Markdown blockquote line wrapping inserts "\n> " between
    # words in the canonical paragraph — strip the leading
    # blockquote markers and collapse whitespace so substring
    # checks match the canonical text regardless of how the
    # source is line-broken.
    import re
    flat = re.sub(r"^\s*>\s*", " ", body, flags=re.MULTILINE)
    flat = re.sub(r"\s+", " ", flat)

    assert "Honesty contract" in body
    assert "behaviour emulator" in body.lower()
    # The canonical positioning paragraph must be present in full —
    # if anyone weakens or removes the "we walk the pipeline, we
    # don't fire payloads" phrasing, this fails.
    assert "catalogued adversary tactics" in flat
    assert "MITRE ATLAS" in flat
    assert "Adjacent to adversary emulation" in flat
    assert "we don't fire payloads" in flat
    assert "we test pattern classes, not specific threat actors" in flat
    # Methodology distinctions must be explicit — drop these and
    # the bootstrap risks being read as marketing for red-teaming.
    assert "Not red-teaming" in body
    assert "Not strict-MITRE adversary emulation" in body
    # The 8 standard pipeline steps must be documented so Copilot
    # has the framework to walk.
    for step in (
        "User prompt", "RAG context", "System prompt", "Planner",
        "Tool choice", "Tool output", "Re-planning", "Final answer",
    ):
        assert step in body, f"pipeline step '{step}' missing from bootstrap"


# ---------- loader ----------


def _write_emulation(
    dir_: Path, *, pipeline_map: dict | None = None,
    attack_class_traces: list[dict] | None = None,
    honesty_label: str = "Behaviour emulator — Copilot reading of repo source code, no live agent traffic.",
) -> None:
    payload = {
        "tier": "agent-emulator",
        "scanned_at": "2026-05-21T10:00:00Z",
        "honesty_label": honesty_label,
        "pipeline_map": pipeline_map or {},
        "attack_class_traces": attack_class_traces or [],
    }
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "agent-emulation.json").write_text(json.dumps(payload))


def test_load_returns_not_present_when_file_missing(
    tmp_path: Path,
) -> None:
    out = _load_agent_emulation(tmp_path)
    assert out == {"present": False}


def test_load_returns_not_present_on_malformed_json(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent-emulation.json").write_text("not json {{{")
    out = _load_agent_emulation(tmp_path)
    assert out == {"present": False}


def test_load_returns_not_present_on_non_dict_root(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent-emulation.json").write_text(
        json.dumps(["unexpected", "shape"])
    )
    out = _load_agent_emulation(tmp_path)
    assert out == {"present": False}


def test_load_normalises_missing_pipeline_steps_to_absent(
    tmp_path: Path,
) -> None:
    """Schema requires all 8 step keys, but if Copilot writes only
    a few, the loader defaults the rest to 'absent' so downstream
    code never KeyErrors. Honest signal: the renderer can still tell
    'Copilot didn't enumerate this step' apart from 'agent doesn't
    have this step' via the description / explicit `absent` value."""
    _write_emulation(tmp_path, pipeline_map={
        "user_prompt": {
            "code_location": "controller.py:1-10",
            "description": "reads input",
            "defensive_controls": [],
        }
    })
    out = _load_agent_emulation(tmp_path)
    assert out["present"] is True
    # Every standard step present in the normalised output.
    assert set(out["pipeline_map"].keys()) == set(_PIPELINE_STEP_KEYS)
    # Specified step kept as-is.
    assert out["pipeline_map"]["user_prompt"]["code_location"] == "controller.py:1-10"
    # Unspecified steps defaulted to absent.
    assert out["pipeline_map"]["re_planning"]["code_location"] == "absent"


def test_load_drops_unknown_verdict_enum(tmp_path: Path) -> None:
    """Defensive: a typo'd verdict shouldn't poison the merge.
    Schema doc says unknown enums are silently dropped to None."""
    _write_emulation(tmp_path, attack_class_traces=[
        {
            "attack_class": "direct-prompt-injection",
            "attack_class_label": "Direct prompt injection",
            "targets_steps": ["user_prompt"],
            "catalogue_payload": "...",
            "verdict": "ABSOLUTELY_PWNED",     # invalid enum
            "verdict_confidence": 0.9,
            "verdict_reasoning": "...",
            "frameworks": {},
            "pipeline_trace": [],
        }
    ])
    out = _load_agent_emulation(tmp_path)
    trace = out["attack_class_traces"][0]
    assert trace["verdict"] is None
    # Other fields preserved.
    assert trace["attack_class"] == "direct-prompt-injection"


def test_load_drops_unknown_outcome_enum_on_pipeline_trace_step(
    tmp_path: Path,
) -> None:
    _write_emulation(tmp_path, attack_class_traces=[
        {
            "attack_class": "direct-prompt-injection",
            "attack_class_label": "Direct prompt injection",
            "targets_steps": ["user_prompt"],
            "catalogue_payload": "...",
            "verdict": "lands",
            "verdict_confidence": 0.9,
            "verdict_reasoning": "...",
            "frameworks": {},
            "pipeline_trace": [
                {
                    "step": "user_prompt",
                    "step_label": "1 — User prompt",
                    "input": "x",
                    "predicted_behavior": "y",
                    "code_basis": ["x.py:1"],
                    "defensive_control_present": False,
                    "outcome": "OBLITERATED",   # invalid enum
                    "outcome_reasoning": "",
                }
            ],
        }
    ])
    out = _load_agent_emulation(tmp_path)
    step = out["attack_class_traces"][0]["pipeline_trace"][0]
    assert step["outcome"] is None


def test_load_clamps_verdict_confidence(tmp_path: Path) -> None:
    _write_emulation(tmp_path, attack_class_traces=[
        {
            "attack_class": "a", "attack_class_label": "A",
            "targets_steps": [], "catalogue_payload": "",
            "verdict": "lands", "verdict_confidence": 2.5,  # > 1.0
            "verdict_reasoning": "", "frameworks": {},
            "pipeline_trace": [],
        },
        {
            "attack_class": "b", "attack_class_label": "B",
            "targets_steps": [], "catalogue_payload": "",
            "verdict": "blocked", "verdict_confidence": -0.4,  # < 0.0
            "verdict_reasoning": "", "frameworks": {},
            "pipeline_trace": [],
        },
    ])
    out = _load_agent_emulation(tmp_path)
    assert out["attack_class_traces"][0]["verdict_confidence"] == 1.0
    assert out["attack_class_traces"][1]["verdict_confidence"] == 0.0


def test_load_passes_through_valid_payload(tmp_path: Path) -> None:
    """End-to-end happy path: well-formed input survives unchanged."""
    _write_emulation(
        tmp_path,
        pipeline_map={
            step: {"code_location": f"{step}.py:1", "description": "",
                   "defensive_controls": []}
            for step in _PIPELINE_STEP_KEYS
        },
        attack_class_traces=[{
            "attack_class": "direct-prompt-injection",
            "attack_class_label": "Direct prompt injection (T6 / LLM01)",
            "targets_steps": ["user_prompt", "planner", "final_answer"],
            "catalogue_payload": "Ignore previous instructions...",
            "verdict": "lands",
            "verdict_confidence": 0.94,
            "verdict_reasoning": "Three sequential defences missing.",
            "frameworks": {"owasp_llm": ["LLM01"], "owasp_agentic": ["T6"]},
            "pipeline_trace": [
                {
                    "step": "user_prompt", "step_label": "1 — User prompt",
                    "input": "...", "predicted_behavior": "...",
                    "code_basis": ["controller.py:19-21"],
                    "defensive_control_present": False,
                    "outcome": "advances",
                    "outcome_reasoning": "No sanitiser",
                }
            ],
        }],
    )
    out = _load_agent_emulation(tmp_path)
    assert out["present"] is True
    assert out["honesty_label"].startswith("Behaviour emulator")
    assert len(out["pipeline_map"]) == 8
    assert len(out["attack_class_traces"]) == 1
    trace = out["attack_class_traces"][0]
    assert trace["verdict"] == "lands"
    assert trace["verdict_confidence"] == 0.94
    assert trace["pipeline_trace"][0]["outcome"] == "advances"


# ---------- merge() integration ----------


def _minimal_agentshield_dir(tmp_path: Path) -> Path:
    """Spin up the minimum .agentshield/ shape merge() requires."""
    base = tmp_path / ".agentshield"
    base.mkdir()
    (base / "tier1-results.json").write_text(json.dumps({
        "tier": 1, "scanned_at": "2026-05-21T00:00:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "findings": [],
    }))
    return base


def test_merge_exposes_agent_emulation_on_report(tmp_path: Path) -> None:
    base = _minimal_agentshield_dir(tmp_path)
    _write_emulation(base, pipeline_map={
        "user_prompt": {"code_location": "ctrl.py:1",
                        "description": "", "defensive_controls": []}
    })
    result = merge(tmp_path)
    assert result.report.agent_emulation["present"] is True
    assert "user_prompt" in result.report.agent_emulation["pipeline_map"]


def test_merge_defaults_agent_emulation_when_file_missing(
    tmp_path: Path,
) -> None:
    _minimal_agentshield_dir(tmp_path)
    result = merge(tmp_path)
    assert result.report.agent_emulation == {"present": False}


def test_threat_actor_tooltip_disambiguates_archetype_vs_named() -> None:
    """The 'Threat actor' role label in the role-play UI could be
    misread as implying a specific named threat actor. The actor
    tooltip exists explicitly to resolve that ambiguity — drop
    the disambiguation and this test fails.

    Critical because the canonical positioning explicitly says
    'we test pattern classes, not specific threat actors' — the
    UI label must match that scope, and the tooltip is the load-
    bearing artifact that makes it match.
    """
    from agentshield.merger.combine import _actor_tooltip
    tip = _actor_tooltip("Threat actor")
    assert tip, "Threat actor must have a tooltip"
    # Must explicitly mention the generic/archetype framing
    # AND must rule out specific named actors.
    assert "archetype" in tip.lower() or "generic" in tip.lower()
    assert "not a specific" in tip.lower() or "not threat-actor-specific" in tip.lower()
    # Naming at least one specific actor by name reinforces the
    # distinction concretely — drop the names and the tooltip
    # becomes abstract.
    assert "APT29" in tip or "FIN7" in tip
    # Canonical positioning's verbatim phrase must be in the
    # tooltip so the report's hover-help matches the marketing.
    assert "pattern classes" in tip or "we test pattern" in tip


def test_render_emits_threat_actor_tooltip(tmp_path: Path) -> None:
    """End-to-end: the rendered HTML carries a title= attribute on
    the Threat-actor actor card. Hovering it in the browser shows
    the disambiguation text."""
    from agentshield.merger import merge, render_combined_html
    base = _minimal_agentshield_dir(tmp_path)
    _write_emulation(
        base,
        pipeline_map={
            "user_prompt": {
                "code_location": "ctrl.py:1",
                "description": "reads input",
                "defensive_controls": [],
            }
        },
        attack_class_traces=[{
            "attack_class": "direct-prompt-injection",
            "attack_class_label": "Direct prompt injection",
            "targets_steps": ["user_prompt"],
            "catalogue_payload": "...",
            "verdict": "lands",
            "verdict_confidence": 0.9,
            "verdict_reasoning": "...",
            "frameworks": {},
            "pipeline_trace": [{
                "step": "user_prompt",
                "step_label": "1 — User prompt",
                "input": "x",
                "predicted_behavior": "y",
                "code_basis": ["ctrl.py:1"],
                "defensive_control_present": False,
                "outcome": "advances",
                "outcome_reasoning": "no sanitiser",
            }],
        }],
    )
    # Provide minimal tier2 so merge doesn't fall over on schema.
    (base / "tier2-findings.json").write_text(json.dumps({
        "tier": 2, "scanned_at": "2026-05-21T00:01:00Z",
        "agentshield_tier1_fingerprint": "abc",
        "scanned_files": [], "skipped_files": [], "findings": [],
        "tier1_fp_callouts": [],
    }))
    html = render_combined_html(merge(tmp_path))
    # Title attribute carrying the canonical disambiguation must
    # be present on the Threat-actor actor card.
    assert 'class="emu-actor emu-actor-src"' in html
    # The tooltip text must include the explicit disambiguation —
    # if a future edit drops the "Not a specific named threat
    # actor" phrasing, the UI no longer matches the canonical
    # positioning.
    assert "Not a specific named threat actor" in html or (
        "not a specific named threat actor" in html
    )

"""Tests for the red-team mutator pipeline.

Covers:
  * `emit_redteam_mutate_skill` writes the three template files
  * `redteam_mutate_prompt` returns the canonical Copilot prompt
  * `load_redteam_mutations` happy + defensive paths
  * `apply_mutations_to_catalogue` — appends to existing chain,
    inherits indicators, respects session-id override, handles
    unknown/out-of-range gracefully
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.emitter.skill_emitter import (
    REDTEAM_MUTATE_TEMPLATE_FILES,
    emit_redteam_mutate_skill,
    redteam_mutate_prompt,
)
from agentshield.probe.campaign import (
    MOCK_CAMPAIGN_CATALOGUE,
    CampaignObjective,
    apply_mutations_to_catalogue,
    load_redteam_mutations,
)


def _find(catalogue, name: str) -> CampaignObjective:
    for c in catalogue:
        if c.name == name:
            return c
    raise AssertionError(f"campaign {name!r} not in catalogue")


# ---------- emitter ----------


def test_emit_writes_three_template_files(tmp_path: Path) -> None:
    target = tmp_path / "demo-agent"
    target.mkdir()
    written = emit_redteam_mutate_skill(target)
    expected = {
        target / ".agentshield" / dst
        for dst in REDTEAM_MUTATE_TEMPLATE_FILES.values()
    }
    assert set(written) == expected
    for p in expected:
        assert p.exists()
        assert p.read_text().strip()


def test_redteam_mutate_prompt_references_required_files() -> None:
    p = redteam_mutate_prompt()
    assert p.startswith("@workspace")
    assert "redteam-mutate-instructions.md" in p
    assert "redteam-mutate-output-schema.md" in p
    assert "probe-campaigns.json" in p
    assert "probe-campaigns-mutations.json" in p


# ---------- loader ----------


def test_load_redteam_mutations_returns_empty_when_missing(
    tmp_path: Path,
) -> None:
    out = load_redteam_mutations(tmp_path)
    assert out["appended_mutations"] == []


def test_load_redteam_mutations_returns_empty_on_malformed_json(
    tmp_path: Path,
) -> None:
    (tmp_path / "probe-campaigns-mutations.json").write_text("not json {{{")
    out = load_redteam_mutations(tmp_path)
    assert out["appended_mutations"] == []


# ---------- overlay ----------


def test_apply_mutations_appends_to_existing_chain() -> None:
    """guardrail-bypass campaign has 4 existing mutations
    (attempts 2-5). Appending should add a 5th and 6th to the end,
    inheriting indicators from the primary attempt."""
    original = _find(MOCK_CAMPAIGN_CATALOGUE,
                     "guardrail-bypass-via-mutation")
    original_count = len(original.turn_plan[0].get("mutations") or ())

    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [
                    {"message": "FIRST NEW MUTATION",
                     "rationale": "dodges keyword X"},
                    {"message": "SECOND NEW MUTATION",
                     "rationale": "dodges keyword Y"},
                ],
            }
        ],
    })
    target = _find(out, "guardrail-bypass-via-mutation")
    new_mutations = target.turn_plan[0].get("mutations") or ()
    assert len(new_mutations) == original_count + 2
    # Tail entries are the new ones, in order.
    assert new_mutations[-2]["message"] == "FIRST NEW MUTATION"
    assert new_mutations[-1]["message"] == "SECOND NEW MUTATION"
    # Provenance flags so the renderer can mark them in the UI.
    assert new_mutations[-1]["_appended_by_mutator"] is True
    assert new_mutations[-1]["_mutation_rationale"] == "dodges keyword Y"


def test_apply_mutations_inherits_indicators_from_primary() -> None:
    """New mutations must inherit advance/success/block indicators +
    tactic + atlas_technique from the primary attempt. The mutator
    schema explicitly forbids overriding these."""
    original = _find(MOCK_CAMPAIGN_CATALOGUE,
                     "guardrail-bypass-via-mutation")
    primary = original.turn_plan[0]

    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [
                    {"message": "NEW", "rationale": "test"},
                ],
            }
        ],
    })
    target = _find(out, "guardrail-bypass-via-mutation")
    new_mut = target.turn_plan[0]["mutations"][-1]
    for key in (
        "success_indicators", "block_indicators",
        "tactic", "atlas_technique",
    ):
        if primary.get(key):
            assert new_mut.get(key) == primary[key], (
                f"new mutation must inherit {key} from primary"
            )


def test_apply_mutations_inherits_session_id_by_default() -> None:
    original = _find(MOCK_CAMPAIGN_CATALOGUE,
                     "guardrail-bypass-via-mutation")
    primary_session = original.turn_plan[0]["session_id"]

    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [
                    {"message": "NEW", "rationale": "test"},
                ],
            }
        ],
    })
    target = _find(out, "guardrail-bypass-via-mutation")
    assert target.turn_plan[0]["mutations"][-1]["session_id"] == (
        primary_session
    )


def test_apply_mutations_respects_explicit_session_id_override() -> None:
    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [
                    {"message": "NEW", "rationale": "test",
                     "session_id": "different-session"},
                ],
            }
        ],
    })
    target = _find(out, "guardrail-bypass-via-mutation")
    assert target.turn_plan[0]["mutations"][-1]["session_id"] == (
        "different-session"
    )


def test_apply_mutations_appends_to_turn_without_existing_mutations() -> None:
    """memory-poison campaign's logical_turn 3 (the plant) has no
    mutations chain. Appending should create one from scratch."""
    original = _find(MOCK_CAMPAIGN_CATALOGUE,
                     "memory-poison-cross-session-exfil")
    # Find a turn with no existing mutations; assert there is one
    # so the test is meaningful.
    target_lt = next(
        (i + 1 for i, t in enumerate(original.turn_plan)
         if not t.get("mutations")),
        None,
    )
    assert target_lt is not None, (
        "memory-poison campaign expected to have at least one "
        "logical turn with no hand-authored mutations"
    )

    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "memory-poison-cross-session-exfil",
                "logical_turn": target_lt,
                "new_mutations": [
                    {"message": "FRESH MUTATION",
                     "rationale": "test"},
                ],
            }
        ],
    })
    target = _find(out, "memory-poison-cross-session-exfil")
    new_muts = target.turn_plan[target_lt - 1].get("mutations") or ()
    assert len(new_muts) == 1
    assert new_muts[0]["message"] == "FRESH MUTATION"


def test_apply_mutations_drops_empty_message() -> None:
    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [
                    {"message": "", "rationale": "empty"},
                    {"message": "real one", "rationale": "valid"},
                ],
            }
        ],
    })
    target = _find(out, "guardrail-bypass-via-mutation")
    new_muts = target.turn_plan[0]["mutations"]
    # The empty entry was dropped; only "real one" appended.
    assert new_muts[-1]["message"] == "real one"


def test_apply_mutations_skips_unknown_campaign() -> None:
    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "no-such-campaign",
                "logical_turn": 1,
                "new_mutations": [{"message": "x", "rationale": "y"}],
            }
        ],
    })
    # Every campaign survives with its original turn_plan.
    for adapted, original in zip(out, MOCK_CAMPAIGN_CATALOGUE):
        assert adapted.turn_plan == original.turn_plan


def test_apply_mutations_warns_on_out_of_range_turn(
    capsys: pytest.CaptureFixture,
) -> None:
    apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 99,
                "new_mutations": [{"message": "x", "rationale": "y"}],
            }
        ],
    })
    err = capsys.readouterr().err
    assert "logical_turn=99" in err


def test_apply_mutations_empty_overlay_is_passthrough() -> None:
    assert apply_mutations_to_catalogue(
        MOCK_CAMPAIGN_CATALOGUE, {"appended_mutations": []}
    ) is MOCK_CAMPAIGN_CATALOGUE


def test_apply_mutations_preserves_remediation_and_frameworks() -> None:
    out = apply_mutations_to_catalogue(MOCK_CAMPAIGN_CATALOGUE, {
        "appended_mutations": [
            {
                "campaign_name": "guardrail-bypass-via-mutation",
                "logical_turn": 1,
                "new_mutations": [{"message": "x", "rationale": "y"}],
            }
        ],
    })
    adapted = _find(out, "guardrail-bypass-via-mutation")
    original = _find(MOCK_CAMPAIGN_CATALOGUE,
                     "guardrail-bypass-via-mutation")
    assert adapted.remediation == original.remediation
    assert adapted.frameworks == original.frameworks
    assert adapted.severity == original.severity

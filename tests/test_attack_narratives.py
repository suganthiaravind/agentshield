"""Tests for the static attack-narrative library (v4).

The library maps normalised rule IDs to short attack walkthroughs the
HTML renderer drops into each finding card. These tests pin:

  - Source-prefix normalisation works for AS-S / AS-C / AS-M rule IDs
  - Cross-source lookup: a single narrative covers Tier 1 + Tier 2
    variants of the same conceptual check
  - Missing rules return None instead of raising
  - Every narrative has non-empty fields (lazy QA — catches an entry
    that was added with a placeholder and forgotten)
"""

from __future__ import annotations

from agentshield.merger.attack_narratives import (
    NARRATIVES,
    AttackScenario,
    _normalize_rule_id,
    narrative_for,
)


def test_normalize_strips_source_prefix() -> None:
    assert _normalize_rule_id("AS-S-D-LLM01-001") == "D-LLM01-001"
    assert _normalize_rule_id("AS-C-D-LLM01-001") == "D-LLM01-001"
    assert _normalize_rule_id("AS-M-D-AST03-001") == "D-AST03-001"
    assert _normalize_rule_id("AS-C-DF-LLM06-004") == "DF-LLM06-004"


def test_normalize_passes_through_already_normalised_ids() -> None:
    assert _normalize_rule_id("D-LLM01-001") == "D-LLM01-001"
    assert _normalize_rule_id("anything") == "anything"


def test_cross_source_lookup_resolves_to_same_narrative() -> None:
    """A Semgrep finding and a Copilot finding for the same conceptual
    check (LLM01 direct injection) must surface the same walkthrough —
    otherwise the report would show two contradictory stories side by
    side."""
    s = narrative_for("AS-S-D-LLM01-001")
    c = narrative_for("AS-C-D-LLM01-001")
    assert s is not None and c is not None
    assert s is c


def test_unknown_rule_returns_none() -> None:
    assert narrative_for("AS-S-D-MADE-UP-999") is None
    assert narrative_for("") is None


def test_every_narrative_has_complete_fields() -> None:
    """Catches a placeholder entry being added without all four fields
    filled out — would render an empty section in the report."""
    for key, scenario in NARRATIVES.items():
        assert isinstance(scenario, AttackScenario), key
        for field_name in ("title", "attacker_input", "code_path", "impact"):
            value = getattr(scenario, field_name)
            assert value and value.strip(), (
                f"NARRATIVES[{key!r}].{field_name} is empty"
            )


def test_canonical_demo_rules_have_narratives() -> None:
    """The handful of rule IDs we curated for the demo-agent walkthrough
    must keep working — these are what stakeholders see when AgentShield
    is demoed. If one disappears, the demo loses impact silently."""
    canonical = [
        "AS-S-D-LLM01-001",     # direct prompt injection (Semgrep variant)
        "AS-C-D-LLM01-002",     # indirect injection via doc loader
        "AS-C-D-LLM05-001",     # output -> code exec
        "AS-C-DF-LLM06-002",    # broad tool permissions
        "AS-C-DF-LLM06-004",    # LLM in permission decision
        "AS-S-DF-LLM10-001",    # no timeout / token cap
        "AS-S-D-CWE_798-001",   # hardcoded creds
    ]
    for rule_id in canonical:
        assert narrative_for(rule_id) is not None, (
            f"{rule_id} should have a curated narrative"
        )


def test_every_bundled_rule_has_a_narrative() -> None:
    """Coverage invariant: every rule in the bundled Tier 1 + Tier 2 +
    manifest pack must have a curated attack narrative. Adding a new
    rule without writing its narrative would result in finding cards
    with no scenario block — caught here before it ships.

    To add coverage: drop an entry into `NARRATIVES` in
    `attack_narratives.py` keyed by the normalised rule ID (the
    `AS-<source>-` prefix stripped, e.g. `D-LLM01-001`).
    """
    from pathlib import Path

    from agentshield.merger.reference import build_all_references

    repo_root = Path(__file__).resolve().parent.parent
    refs = build_all_references(
        tier1_rules_path=repo_root / "agentshield" / "rules",
        tier2_checklist_path=(
            repo_root / "agentshield" / "skills" / "tier2_checklist.md.tmpl"
        ),
    )
    missing: list[str] = []
    for ref in refs:
        if narrative_for(ref.agentshield_id) is None:
            missing.append(f"{ref.agentshield_id} ({ref.source}: {ref.title})")
    assert not missing, (
        f"{len(missing)} bundled rule(s) lack an attack narrative. Add "
        f"entries to `NARRATIVES` keyed by the normalised rule ID "
        f"(strip `AS-<source>-`):\n  "
        + "\n  ".join(missing)
    )

"""Unit tests for the SARIF → Finding normalizer.

Pairs with tests/test_rules_golden.py — that catches semgrep-level
regressions; this catches normalizer-level regressions (metadata
extraction, tier partitioning, framework_mappings preservation).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.normalize import Finding, Normalizer
from agentshield.runner import SemgrepRunner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def normalized_findings() -> list[Finding]:
    fixture_files = sorted(
        p
        for p in FIXTURES_DIR.rglob("*")
        if p.is_file() and p.suffix in {".py", ".java"} and "__pycache__" not in p.parts
    )
    sarif = SemgrepRunner().run(fixture_files)
    return Normalizer().normalize(sarif)


def test_normalizer_produces_findings(normalized_findings: list[Finding]) -> None:
    """End-to-end: normalizer returns at least the findings the goldens recorded."""
    # Goldens record 3 + 0 + 2 + 1 + 2 + 3 = 11 raw findings across the 6 fixtures.
    assert len(normalized_findings) >= 11


def test_finding_has_required_fields(normalized_findings: list[Finding]) -> None:
    f = normalized_findings[0]
    assert f.rule_id
    assert f.rule_id_short
    assert f.agentshield_id.startswith("AS-")
    assert f.category in {"detect", "defend", "respond"}
    assert f.tier in {"framework", "fallback"}
    assert f.severity in {"critical", "high", "medium", "low", "info"}
    assert f.confidence in {"high", "medium", "low"}
    assert f.location.file_path
    assert f.location.start_line > 0
    assert f.message


def test_d001_preserves_framework_mappings(normalized_findings: list[Finding]) -> None:
    """The dual-mapping pattern: a Finding carries both D/D/R category AND framework_mappings."""
    d001 = next(
        f for f in normalized_findings if f.rule_id_short == "unsanitized-user-input-to-llm"
    )
    assert d001.category == "detect"
    # F.27 — current ID is the new uniform-naming form; legacy ID survives.
    assert d001.agentshield_id == "AS-S-D-LLM01-001"
    assert "AS-D-001" in d001.legacy_ids
    assert "LLM01" in d001.framework_mappings.owasp_llm
    assert "T6" in d001.framework_mappings.owasp_agentic
    assert "AML.T0051" in d001.framework_mappings.mitre_atlas


def test_all_findings_are_framework_tier(normalized_findings: list[Finding]) -> None:
    """Phase F.6: with D001-fb retired and the judge/discovery tiers gone,
    every Finding from the normalizer is framework-tier. partition_by_tier
    method was removed; this test is the regression guard for the 'no
    accidental fallback findings' invariant."""
    assert len(normalized_findings) > 0
    assert all(f.tier == "framework" for f in normalized_findings)


def test_java_d001_now_fires(normalized_findings: list[Finding]) -> None:
    """Regression guard: the parameter-annotation taint fix from commit 5d7f243."""
    java_d001 = [
        f
        for f in normalized_findings
        if f.rule_id_short == "unsanitized-user-input-to-llm-java"
    ]
    assert len(java_d001) >= 1, (
        "D001-java must fire on the Spring controller fixture. "
        "If this regresses, check the parameter-annotation source patterns."
    )


def test_no_orphaned_rule_ids(normalized_findings: list[Finding]) -> None:
    """Every finding's rule_id must resolve to a bundled rule with metadata."""
    normalizer = Normalizer()
    for f in normalized_findings:
        assert f.rule_id in normalizer._rules_by_id, (
            f"Finding has rule_id {f.rule_id!r} that doesn't match any bundled rule"
        )

"""Unit tests for the report writers (Track A4).

Covers SARIF v2.1.0 schema shape, JSON summary block, Markdown
section structure. Uses real Findings produced by A2+A3 against
the in-repo fixtures so the tests exercise the full upstream
pipeline at the same time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.normalize import (
    CodeLocation,
    Finding,
    FrameworkMappings,
    Normalizer,
)
from agentshield.report import JsonWriter, MarkdownWriter, SarifWriter
from agentshield.runner import SemgrepRunner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def real_findings() -> list[Finding]:
    fixture_files = sorted(
        p
        for p in FIXTURES_DIR.rglob("*")
        if p.is_file() and p.suffix in {".py", ".java"} and "__pycache__" not in p.parts
    )
    sarif = SemgrepRunner().run(fixture_files)
    return Normalizer().normalize(sarif)


# --- SARIF ---------------------------------------------------------------


def test_sarif_has_v2_1_0_envelope(real_findings: list[Finding]) -> None:
    text = SarifWriter().write(real_findings)
    sarif = json.loads(text)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentShield"


def test_sarif_results_count_matches_findings(real_findings: list[Finding]) -> None:
    sarif = json.loads(SarifWriter().write(real_findings))
    assert len(sarif["runs"][0]["results"]) == len(real_findings)


def test_sarif_preserves_agentshield_metadata_in_properties(real_findings: list[Finding]) -> None:
    """The dual-mapping pattern: SARIF results carry both standard fields AND our properties."""
    sarif = json.loads(SarifWriter().write(real_findings))
    result = sarif["runs"][0]["results"][0]
    props = result["properties"]
    assert "agentshield_id" in props
    assert "category" in props
    assert "tier" in props
    assert "severity_normalized" in props
    assert "framework_mappings" in props
    assert props["category"] in {"detect", "defend", "respond"}


def test_sarif_writes_to_disk(tmp_path: Path, real_findings: list[Finding]) -> None:
    out = tmp_path / "report.sarif"
    SarifWriter().write(real_findings, out)
    assert out.exists()
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"


# --- JSON ---------------------------------------------------------------


def test_json_has_version_and_summary(real_findings: list[Finding]) -> None:
    payload = json.loads(JsonWriter().write(real_findings))
    assert payload["agentshield_version"]
    assert payload["summary"]["total"] == len(real_findings)
    assert "by_category" in payload["summary"]
    assert "by_tier" in payload["summary"]
    assert "by_severity" in payload["summary"]


def test_json_finding_count_matches(real_findings: list[Finding]) -> None:
    payload = json.loads(JsonWriter().write(real_findings))
    assert len(payload["findings"]) == len(real_findings)


def test_json_summary_partitions_correctly(real_findings: list[Finding]) -> None:
    payload = json.loads(JsonWriter().write(real_findings))
    summary = payload["summary"]
    assert sum(summary["by_category"].values()) == len(real_findings)
    assert sum(summary["by_tier"].values()) == len(real_findings)
    assert sum(summary["by_severity"].values()) == len(real_findings)


# --- Markdown ---------------------------------------------------------------


def test_markdown_has_title_and_summary(real_findings: list[Finding]) -> None:
    text = MarkdownWriter().write(real_findings)
    assert text.startswith("# AgentShield Report")
    assert f"**{len(real_findings)} finding(s)**" in text


def test_markdown_groups_by_category(real_findings: list[Finding]) -> None:
    text = MarkdownWriter().write(real_findings)
    cats = {f.category for f in real_findings}
    if "detect" in cats:
        assert "## Detect — vulnerability surfaces" in text
    if "defend" in cats:
        assert "## Defend — missing controls" in text
    if "respond" in cats:
        assert "## Respond — observability gaps" in text


def test_markdown_renders_each_finding(real_findings: list[Finding]) -> None:
    text = MarkdownWriter().write(real_findings)
    for f in real_findings:
        assert f.agentshield_id in text
        assert f.rule_id_short in text


def test_markdown_handles_empty(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    text = MarkdownWriter().write([], out)
    assert "No findings." in text
    assert out.exists()

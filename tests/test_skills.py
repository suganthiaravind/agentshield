"""Tests for the bundled Tier 2 skill templates.

Phase F.3. The skill templates live at agentshield/skills/*.md.tmpl and
are the v2 product — they get copied verbatim into a target repo by the
emitter (Phase F.4) so the LLM-as-scanner has a stable contract.

These tests pin the structural invariants so a future refactor can't
silently drop a section, break a check ID format, or remove a framework
mapping coverage commitment.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILLS_DIR = Path(__file__).parent.parent / "agentshield" / "skills"

BOOTSTRAP = SKILLS_DIR / "tier2_bootstrap.md.tmpl"
CHECKLIST = SKILLS_DIR / "tier2_checklist.md.tmpl"
SCHEMA = SKILLS_DIR / "tier2_output_schema.md.tmpl"


# ---------- existence ----------

@pytest.mark.parametrize("path", [BOOTSTRAP, CHECKLIST, SCHEMA])
def test_skill_template_exists(path: Path) -> None:
    assert path.exists(), f"Bundled skill template missing: {path}"


@pytest.mark.parametrize("path", [BOOTSTRAP, CHECKLIST, SCHEMA])
def test_skill_template_non_empty(path: Path) -> None:
    assert path.stat().st_size > 500, f"Skill template suspiciously small: {path}"


# ---------- bootstrap content ----------

def test_bootstrap_has_workspace_invocation() -> None:
    """The bootstrap must instruct the user to run @workspace ... in Copilot Chat."""
    content = BOOTSTRAP.read_text()
    assert "@workspace" in content
    assert ".agentshield/tier2-checklist.md" in content
    assert ".agentshield/tier2-output-schema.md" in content
    assert ".agentshield/tier2-findings.json" in content


def test_bootstrap_explains_fingerprint() -> None:
    """Stale-detection requires the LLM to copy the Tier 1 fingerprint."""
    content = BOOTSTRAP.read_text()
    assert "agentshield_tier1_fingerprint" in content
    assert "tier1-results.json" in content


# ---------- checklist structural invariants ----------

CHECK_ID_RE = re.compile(r"^### (TIER2-[A-Z0-9]+-[A-Z0-9]+(?:-\d+)?)\b", re.MULTILINE)
SECTION_RE = re.compile(r"^# §\d+\. .+", re.MULTILINE)
REQUIRED_SECTIONS = [
    "§1. OWASP LLM Top 10 v2",
    "§2. OWASP Agentic AI Top 10",
    "§3. MITRE ATLAS techniques",
    "§4. CWE first-class concerns",
    "§5. Phase E judge-surfaced gaps",
    "§6. Retired Tier 1 anti-patterns",
    "§7. Tier 1 cross-check",
]


def test_checklist_has_all_required_sections() -> None:
    content = CHECKLIST.read_text()
    for section in REQUIRED_SECTIONS:
        assert section in content, f"Checklist missing section: {section}"


def test_checklist_check_ids_are_unique() -> None:
    content = CHECKLIST.read_text()
    ids = CHECK_ID_RE.findall(content)
    duplicates = {x for x in ids if ids.count(x) > 1}
    assert not duplicates, f"Duplicate check IDs: {duplicates}"


def test_checklist_has_minimum_check_count() -> None:
    """Pin a floor — comprehensive checklist should have ~50+ checks across sections."""
    content = CHECKLIST.read_text()
    ids = CHECK_ID_RE.findall(content)
    assert len(ids) >= 50, f"Checklist has only {len(ids)} checks; expected ≥ 50 for comprehensive coverage"


def test_checklist_covers_all_owasp_llm_v2() -> None:
    """LLM01 through LLM10 must each have at least one check."""
    content = CHECKLIST.read_text()
    for n in range(1, 11):
        marker = f"TIER2-LLM{n:02d}-"
        assert marker in content, f"OWASP LLM Top 10 v2 missing coverage: LLM{n:02d}"


def test_checklist_covers_all_owasp_agentic_t1_t11() -> None:
    """T1 through T11 must each have at least one check."""
    content = CHECKLIST.read_text()
    for n in range(1, 12):
        marker = f"TIER2-AGENTIC-T{n}-"
        assert marker in content, f"OWASP Agentic AI Top 10 missing coverage: T{n}"


def test_checklist_covers_phase_e_gaps() -> None:
    """5 net-new gaps Tier 1 never had."""
    content = CHECKLIST.read_text()
    for gap_id in ["TIER2-GAP-01", "TIER2-GAP-02", "TIER2-GAP-03", "TIER2-GAP-04", "TIER2-GAP-05"]:
        assert gap_id in content, f"Missing Phase E gap check: {gap_id}"


def test_checklist_covers_retired_rule_parity() -> None:
    """Section §6 explicitly cross-references each of the 8 retired rules."""
    content = CHECKLIST.read_text()
    for retired in ["D001-fb", "D002", "D006", "D007", "DF001", "DF002", "DF004", "R001"]:
        assert retired in content, f"Retired-rule cross-reference missing: {retired}"


def test_checklist_every_check_has_severity() -> None:
    """Each ### TIER2-... block must include a Severity: line."""
    content = CHECKLIST.read_text()
    blocks = re.split(r"^### (TIER2-[A-Z0-9-]+(?:-\d+)?)\b", content, flags=re.MULTILINE)
    # blocks[0] is preamble, then alternating (id, body, id, body, ...)
    pairs = list(zip(blocks[1::2], blocks[2::2]))
    missing = [cid for cid, body in pairs if not re.search(r"^- \*\*Severity:\*\*", body, re.MULTILINE)]
    assert not missing, f"Checks missing Severity: {missing[:5]}{' ...' if len(missing) > 5 else ''}"


def test_checklist_every_check_has_framework_mapping() -> None:
    """Every check must cite at least one of owasp_llm / owasp_agentic / mitre_atlas / cwe."""
    content = CHECKLIST.read_text()
    blocks = re.split(r"^### (TIER2-[A-Z0-9-]+(?:-\d+)?)\b", content, flags=re.MULTILINE)
    pairs = list(zip(blocks[1::2], blocks[2::2]))
    missing = []
    for cid, body in pairs:
        # Look for at least one mapping keyword in the Frameworks: line
        m = re.search(r"^- \*\*Frameworks:\*\*(.+)$", body, re.MULTILINE)
        if not m:
            missing.append(f"{cid} (no Frameworks: line)")
            continue
        line = m.group(1)
        if not any(k in line for k in ["owasp_llm=", "owasp_agentic=", "mitre_atlas=", "cwe="]):
            missing.append(f"{cid} (no framework mapping)")
    assert not missing, f"Checks missing framework mapping: {missing[:5]}"


# ---------- schema content ----------

def test_schema_documents_required_top_level_fields() -> None:
    content = SCHEMA.read_text()
    for field in [
        "tier",
        "scanned_at",
        "agentshield_tier1_fingerprint",
        "scanned_files",
        "skipped_files",
        "findings",
        "tier1_fp_callouts",
    ]:
        assert field in content, f"Schema missing top-level field: {field}"


def test_schema_documents_finding_required_fields() -> None:
    content = SCHEMA.read_text()
    for field in [
        "rule_id",
        "category",
        "severity",
        "file",
        "line",
        "snippet",
        "message",
        "owasp_llm",
        "owasp_agentic",
        "mitre_atlas",
        "cwe",
        "remediation",
    ]:
        assert field in content, f"Schema missing Finding field: {field}"


def test_schema_documents_severity_enum() -> None:
    content = SCHEMA.read_text()
    for severity in ["critical", "high", "medium", "low", "info"]:
        assert severity in content, f"Schema missing severity enum value: {severity}"


def test_schema_documents_category_enum() -> None:
    content = SCHEMA.read_text()
    for cat in ["detect", "defend", "respond"]:
        assert cat in content


def test_schema_documents_fp_verdict_enum() -> None:
    content = SCHEMA.read_text()
    for v in ['"FP"', '"CD"', '"TP"']:
        assert v in content, f"Schema missing FP-callout verdict: {v}"


# ---------- SAIGE classification (F.16) ----------

def test_checklist_has_saige_section() -> None:
    """§8 of the bundled checklist must instruct Copilot to classify the
    agent into one of the 5 JPMC SAIGE tiers."""
    content = CHECKLIST.read_text()
    assert "§8" in content
    assert "JPMC SAIGE" in content
    # Decision-tree references — autonomy / state-changing / external-facing
    assert "Autonomy" in content
    assert "State-changing" in content
    assert "External" in content or "external" in content


def test_checklist_documents_saige_enum_values() -> None:
    content = CHECKLIST.read_text()
    for value in ["non-agent", "`0`", "`1`", "`2`", "`3`"]:
        assert value in content, f"SAIGE enum value missing from checklist: {value}"


def test_schema_documents_saige_fields() -> None:
    content = SCHEMA.read_text()
    assert "saige_tier" in content
    assert "saige_tier_reasoning" in content
    # Enum values must appear so Copilot has the contract
    for value in ["non-agent", '"0"', '"1"', '"2"', '"3"']:
        assert value in content, f"SAIGE enum missing in schema doc: {value}"

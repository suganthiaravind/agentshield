"""Tests for the Tier 1 + Tier 2 merger (Phase F.5).

Pins the contracts:
- Schema validation rejects malformed Tier 2 with field-path errors
- Fingerprint mismatch surfaces as `stale=True` (soft failure, not exception)
- Missing tier2-findings.json produces "Tier 2 not run" report (no exception)
- Missing tier1-results.json raises MergeError (hard failure — emitter
  should always have produced this)
- Tier 2 verdicts annotate Tier 1 findings by index
- FP-marked Tier 1 findings excluded from `actionable_finding_count`
- Coverage matrix aggregates from both tiers (Tier 1 nested
  `framework_mappings`, Tier 2 flat keys)
- Markdown report contains the right banners per state
- JSON report mirrors the markdown structure
- SARIF emits two runs (Tier 1 + Tier 2 toolComponents) and excludes
  FP-marked findings from the Tier 1 run
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.merger import (
    CombinedReport,
    MergeError,
    MergeResult,
    SchemaError,
    merge,
    render_combined_json,
    render_combined_markdown,
    render_combined_sarif,
    validate_tier2_findings,
)


# ---------- fixtures ----------

def _tier1_payload(findings: list[dict] | None = None, fingerprint: str = "abc123") -> dict:
    return {
        "tier": 1,
        "scanned_at": "2026-05-05T22:14:00Z",
        "agentshield_tier1_fingerprint": fingerprint,
        "scanned_files": ["src/foo.py"],
        "findings": findings if findings is not None else [
            {
                "rule_id": "agentshield.detect.unsanitized-user-input-to-llm",
                "rule_id_short": "unsanitized-user-input-to-llm",
                "category": "detect",
                "file": "src/foo.py",
                "line": 42,
                "severity": "high",
                "message": "tainted",
                "framework_mappings": {
                    "owasp_llm": ["LLM01"],
                    "owasp_agentic": ["T6"],
                    "mitre_atlas": ["AML.T0051"],
                    "cwe": ["CWE-94"],
                },
            }
        ],
    }


def _tier2_payload(
    findings: list[dict] | None = None,
    callouts: list[dict] | None = None,
    fingerprint: str = "abc123",
) -> dict:
    return {
        "tier": 2,
        "scanned_at": "2026-05-05T23:00:00Z",
        "agentshield_tier1_fingerprint": fingerprint,
        "scanned_files": ["src/foo.py"],
        "skipped_files": [],
        "findings": findings if findings is not None else [
            {
                "rule_id": "TIER2-LLM02-04",
                "category": "respond",
                "severity": "high",
                "file": "src/notify.py",
                "line": 17,
                "snippet": "sns.publish(llm_output)",
                "message": "LLM output published to SNS without scrubbing.",
                "owasp_llm": ["LLM02"],
                "owasp_agentic": ["T8"],
                "mitre_atlas": [],
                "cwe": ["CWE-200"],
                "remediation": "Scrub before publish.",
            }
        ],
        "tier1_fp_callouts": callouts or [],
    }


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    out = tmp_path / ".agentshield"
    out.mkdir()
    return tmp_path


def _write_tier1(repo: Path, payload: dict) -> None:
    (repo / ".agentshield" / "tier1-results.json").write_text(json.dumps(payload))


def _write_tier2(repo: Path, payload: dict) -> None:
    (repo / ".agentshield" / "tier2-findings.json").write_text(json.dumps(payload))


# ---------- schema validator ----------

def test_schema_accepts_minimal_valid_payload() -> None:
    result = validate_tier2_findings(_tier2_payload())
    assert result.ok, [str(e) for e in result.errors]


def test_schema_rejects_missing_top_level_field() -> None:
    payload = _tier2_payload()
    del payload["agentshield_tier1_fingerprint"]
    result = validate_tier2_findings(payload)
    assert not result.ok
    assert any(e.field_path == "agentshield_tier1_fingerprint" for e in result.errors)


def test_schema_rejects_wrong_tier_value() -> None:
    payload = _tier2_payload()
    payload["tier"] = 1
    result = validate_tier2_findings(payload)
    assert any("tier" == e.field_path and "must be 2" in e.message for e in result.errors)


def test_schema_rejects_invalid_severity() -> None:
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "severity": "urgent"}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].severity" in e.field_path for e in result.errors)


def test_schema_rejects_invalid_category() -> None:
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "category": "foo"}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].category" in e.field_path for e in result.errors)


def test_schema_rejects_non_tier2_rule_id_prefix() -> None:
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "rule_id": "TIER1-FOO"}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].rule_id" in e.field_path for e in result.errors)


def test_schema_rejects_negative_line() -> None:
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "line": -1}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].line" in e.field_path for e in result.errors)


def test_schema_rejects_null_in_framework_array() -> None:
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "owasp_llm": None}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].owasp_llm" in e.field_path for e in result.errors)


def test_schema_rejects_invalid_callout_verdict() -> None:
    payload = _tier2_payload(callouts=[
        {
            "tier1_finding_index": 0,
            "file": "x.py",
            "line": 1,
            "tier1_rule": "r",
            "verdict": "MAYBE",
            "reasoning": "?",
        }
    ])
    result = validate_tier2_findings(payload)
    assert any("verdict" in e.field_path for e in result.errors)


def test_schema_rejects_bool_for_int_field() -> None:
    """Python bool is int-subclass; our validator must reject it for line/index."""
    payload = _tier2_payload(findings=[{**_tier2_payload()["findings"][0], "line": True}])
    result = validate_tier2_findings(payload)
    assert any("findings[0].line" in e.field_path for e in result.errors)


# ---------- merge: hard failures ----------

def test_merge_raises_when_tier1_missing(tmp_path: Path) -> None:
    with pytest.raises(MergeError, match="Tier 1 results not found"):
        merge(tmp_path)


def test_merge_raises_on_unparseable_tier1_json(repo: Path) -> None:
    (repo / ".agentshield" / "tier1-results.json").write_text("not json{")
    with pytest.raises(MergeError, match="not valid JSON"):
        merge(repo)


def test_merge_raises_on_unparseable_tier2_json(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    (repo / ".agentshield" / "tier2-findings.json").write_text("not json{")
    with pytest.raises(MergeError, match="not valid JSON"):
        merge(repo)


# ---------- merge: soft failures (flags, not exceptions) ----------

def test_merge_flags_tier2_not_present(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    result = merge(repo)
    assert result.tier2_present is False
    assert result.fingerprint_match is False
    assert result.stale is False  # not stale — just not run
    assert result.report.tier2_findings == []


def test_merge_flags_schema_errors(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    bad = _tier2_payload()
    del bad["tier"]
    _write_tier2(repo, bad)
    result = merge(repo)
    assert result.tier2_present is True
    assert result.schema_errors  # populated
    assert result.report.tier2_findings == []  # not surfaced when schema-invalid


def test_merge_flags_stale_on_fingerprint_mismatch(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload(fingerprint="aaa"))
    _write_tier2(repo, _tier2_payload(fingerprint="bbb"))
    result = merge(repo)
    assert result.tier2_present is True
    assert result.fingerprint_match is False
    assert result.stale is True


def test_merge_fingerprint_match_when_equal(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload(fingerprint="same"))
    _write_tier2(repo, _tier2_payload(fingerprint="same"))
    result = merge(repo)
    assert result.fingerprint_match is True
    assert result.stale is False


# ---------- merge: annotation logic ----------

def test_merge_annotates_tier1_findings_by_index(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    callout = {
        "tier1_finding_index": 0,
        "file": "src/foo.py",
        "line": 42,
        "tier1_rule": "agentshield.detect.unsanitized-user-input-to-llm",
        "verdict": "FP",
        "reasoning": "Input is from os.environ, not user.",
    }
    _write_tier2(repo, _tier2_payload(callouts=[callout]))
    result = merge(repo)
    ann = result.report.tier1_findings[0]
    assert ann.tier2_verdict == "FP"
    assert "os.environ" in ann.tier2_reasoning


def test_merge_ignores_callout_with_out_of_range_index(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    callout = {
        "tier1_finding_index": 99,  # only 1 tier1 finding
        "file": "src/foo.py",
        "line": 42,
        "tier1_rule": "x",
        "verdict": "FP",
        "reasoning": "?",
    }
    _write_tier2(repo, _tier2_payload(callouts=[callout]))
    result = merge(repo)
    # No annotation, no exception
    assert result.report.tier1_findings[0].tier2_verdict is None


def test_actionable_count_excludes_fp_marked(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    callout = {
        "tier1_finding_index": 0,
        "file": "src/foo.py", "line": 42, "tier1_rule": "x",
        "verdict": "FP", "reasoning": "?",
    }
    _write_tier2(repo, _tier2_payload(callouts=[callout]))
    result = merge(repo)
    # Tier 1: 1 finding (FP-marked, excluded). Tier 2: 1 finding. Net: 1.
    assert result.actionable_finding_count == 1


def test_actionable_count_includes_cd_and_tp(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    callout = {
        "tier1_finding_index": 0,
        "file": "src/foo.py", "line": 42, "tier1_rule": "x",
        "verdict": "CD", "reasoning": "?",
    }
    _write_tier2(repo, _tier2_payload(callouts=[callout]))
    result = merge(repo)
    # CD doesn't suppress; net = 1 tier1 + 1 tier2 = 2
    assert result.actionable_finding_count == 2


# ---------- coverage matrix ----------

def test_coverage_aggregates_tier1_nested_and_tier2_flat(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())  # owasp_llm=[LLM01], cwe=[CWE-94]
    _write_tier2(repo, _tier2_payload())  # owasp_llm=[LLM02], cwe=[CWE-200]
    result = merge(repo)
    cov = result.report.coverage.to_dict()
    assert "LLM01" in cov["owasp_llm"]
    assert "LLM02" in cov["owasp_llm"]
    assert "CWE-94" in cov["cwe"]
    assert "CWE-200" in cov["cwe"]


# ---------- renderers ----------

def test_markdown_has_incomplete_banner_when_tier2_missing(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    result = merge(repo)
    md = render_combined_markdown(result)
    assert "INCOMPLETE: Tier 2 not run" in md


def test_markdown_has_stale_banner_when_fingerprint_mismatch(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload(fingerprint="aaa"))
    _write_tier2(repo, _tier2_payload(fingerprint="bbb"))
    md = render_combined_markdown(merge(repo))
    assert "STALE Tier 2" in md


def test_markdown_has_schema_error_banner(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    bad = _tier2_payload()
    bad["findings"][0]["severity"] = "urgent"
    _write_tier2(repo, bad)
    md = render_combined_markdown(merge(repo))
    assert "schema validation" in md
    assert "findings[0].severity" in md


def test_markdown_includes_summary_and_coverage(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    md = render_combined_markdown(merge(repo))
    assert "## Summary" in md
    assert "## Coverage matrix" in md
    assert "LLM01" in md or "LLM02" in md


def test_markdown_has_ddr_breakdown_section(repo: Path) -> None:
    """Detect / Defend / Respond is AgentShield's organising spine — every
    finding has a category. The combined report must surface it both as
    a summary table and per-finding."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    md = render_combined_markdown(merge(repo))
    # Category breakdown table
    assert "Findings by Detect / Defend / Respond category" in md
    assert "| Category | Tier 1 | Tier 2 | Total |" in md
    # Per-finding category lines
    assert "**Category:** detect" in md  # Tier 1 sample finding is detect
    assert "**Category:** respond" in md  # Tier 2 sample finding is respond


def test_json_render_mirrors_merge_state(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    result = merge(repo)
    payload = json.loads(render_combined_json(result))
    assert payload["tier1_present"] is True
    assert payload["tier2_present"] is True
    assert payload["fingerprint_match"] is True
    assert payload["stale"] is False
    assert payload["actionable_finding_count"] == 2
    assert "coverage" in payload
    assert payload["coverage"]["owasp_llm"]


def test_json_summary_includes_by_category(repo: Path) -> None:
    """summary.by_category must split detect/defend/respond per tier."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    payload = json.loads(render_combined_json(merge(repo)))
    by_cat = payload["summary"]["by_category"]
    assert by_cat["tier1"] == {"detect": 1, "defend": 0, "respond": 0}
    assert by_cat["tier2"] == {"detect": 0, "defend": 0, "respond": 1}


def test_sarif_emits_two_runs_when_both_tiers_present(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    sarif = json.loads(render_combined_sarif(merge(repo)))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 2
    names = [r["tool"]["driver"]["name"] for r in sarif["runs"]]
    assert "AgentShield-Tier1-semgrep" in names
    assert "AgentShield-Tier2-Copilot" in names


def test_sarif_omits_fp_marked_tier1_findings(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    callout = {
        "tier1_finding_index": 0,
        "file": "src/foo.py", "line": 42, "tier1_rule": "x",
        "verdict": "FP", "reasoning": "?",
    }
    _write_tier2(repo, _tier2_payload(callouts=[callout]))
    sarif = json.loads(render_combined_sarif(merge(repo)))
    tier1_run = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"].endswith("Tier1-semgrep"))
    assert tier1_run["results"] == []  # FP-marked excluded
    assert tier1_run["properties"]["tier1_marked_fp_excluded"] == 1


def test_sarif_one_run_when_tier2_missing(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    sarif = json.loads(render_combined_sarif(merge(repo)))
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"].endswith("Tier1-semgrep")


def test_sarif_severity_mapping() -> None:
    """critical/high → error; medium → warning; low/info → note."""
    from agentshield.merger.combine import _severity_to_sarif_level
    assert _severity_to_sarif_level("critical") == "error"
    assert _severity_to_sarif_level("high") == "error"
    assert _severity_to_sarif_level("medium") == "warning"
    assert _severity_to_sarif_level("low") == "note"
    assert _severity_to_sarif_level("info") == "note"
    assert _severity_to_sarif_level("unknown") == "warning"  # safe default

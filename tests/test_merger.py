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
    render_combined_html,
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
    assert "INCOMPLETE: Copilot AI Scan not run" in md


def test_markdown_has_stale_banner_when_fingerprint_mismatch(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload(fingerprint="aaa"))
    _write_tier2(repo, _tier2_payload(fingerprint="bbb"))
    md = render_combined_markdown(merge(repo))
    assert "STALE Copilot AI Scan" in md


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


def test_markdown_is_ddr_led(repo: Path) -> None:
    """F.17 redesign: D/D/R is the organising spine. Three top-level sections
    in order — Detect, Defend, Respond — each finding rendered under its
    category with a [Tier 1]/[Tier 2] origin badge."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    md = render_combined_markdown(merge(repo))

    # Top D/D/R section header
    assert "## Detect / Defend / Respond" in md

    # Three D/D/R top-level finding sections (with severity-led emojis)
    assert "## 🔴 Detect" in md
    assert "## 🟡 Defend" in md
    assert "## 🔵 Respond" in md

    # Detect section appears before Defend, Defend before Respond
    detect_pos = md.index("## 🔴 Detect")
    defend_pos = md.index("## 🟡 Defend")
    respond_pos = md.index("## 🔵 Respond")
    assert detect_pos < defend_pos < respond_pos

    # F.18: each finding shows a Semgrep or Copilot origin badge.
    # CSS class names stay as tier1/tier2 internally; visible label changed.
    assert "[Semgrep]" in md  # the d001 fixture finding
    assert "[Copilot]" in md  # the TIER2-LLM02-04 fixture finding


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


# ---------- SAIGE classification (F.16) ----------

def test_schema_accepts_optional_saige_tier(repo: Path) -> None:
    """When Copilot includes saige_tier + saige_tier_reasoning, schema validates."""
    payload = _tier2_payload()
    payload["saige_tier"] = "2"
    payload["saige_tier_reasoning"] = "extract.py:228 has runner.run with autonomous control flow; sns_client.publish at email_formatter.py:126 is internal."
    result = validate_tier2_findings(payload)
    assert result.ok, [str(e) for e in result.errors]


def test_schema_rejects_invalid_saige_tier_value() -> None:
    payload = _tier2_payload()
    payload["saige_tier"] = "tier-2"  # wrong format — must be "2" not "tier-2"
    payload["saige_tier_reasoning"] = "..."
    result = validate_tier2_findings(payload)
    assert any("saige_tier" in e.field_path for e in result.errors)


def test_schema_rejects_saige_tier_without_reasoning() -> None:
    """saige_tier_reasoning must accompany saige_tier."""
    payload = _tier2_payload()
    payload["saige_tier"] = "2"
    # no saige_tier_reasoning
    result = validate_tier2_findings(payload)
    assert any("saige_tier_reasoning" in e.field_path for e in result.errors)


def test_schema_accepts_payload_without_saige(repo: Path) -> None:
    """SAIGE classification is optional — payloads without it must still validate."""
    payload = _tier2_payload()
    assert "saige_tier" not in payload
    result = validate_tier2_findings(payload)
    assert result.ok, [str(e) for e in result.errors]


def test_merge_surfaces_saige_when_tier2_classifies(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "2"
    payload["saige_tier_reasoning"] = "Autonomous LLM at extract.py:42; state-changing publish at sns.py:17; internal-only."
    _write_tier2(repo, payload)
    result = merge(repo)
    assert result.report.saige_tier == "2"
    assert "extract.py:42" in result.report.saige_tier_reasoning


def test_merge_saige_none_when_tier2_does_not_classify(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())  # no saige_tier
    result = merge(repo)
    assert result.report.saige_tier is None
    assert result.report.saige_tier_reasoning is None


def test_markdown_renders_saige_classification_section(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "3"
    payload["saige_tier_reasoning"] = "External customer-facing endpoint at api.py:99."
    _write_tier2(repo, payload)
    md = render_combined_markdown(merge(repo))
    assert "## JPMC SAIGE Agent Tier classification" in md
    assert "**Classified as:** Tier 3" in md
    assert "External customer-facing endpoint at api.py:99." in md
    assert "Informational only" in md  # the explanatory footnote


def test_markdown_omits_saige_section_when_unclassified(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    md = render_combined_markdown(merge(repo))
    assert "## JPMC SAIGE Agent Tier classification" not in md


def test_markdown_renders_non_agent_label_correctly(repo: Path) -> None:
    """saige_tier='non-agent' should render as 'Non-Agent', not 'Tier non-agent'."""
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "non-agent"
    payload["saige_tier_reasoning"] = "No LLM calls; deterministic data pipeline."
    _write_tier2(repo, payload)
    md = render_combined_markdown(merge(repo))
    assert "**Classified as:** Non-Agent" in md
    assert "Tier non-agent" not in md


def test_json_includes_saige_fields(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "1"
    payload["saige_tier_reasoning"] = "Read-only autonomous agent."
    _write_tier2(repo, payload)
    result = merge(repo)
    j = json.loads(render_combined_json(result))
    assert j["saige_tier"] == "1"
    assert j["saige_tier_reasoning"] == "Read-only autonomous agent."


# ---------- HTML renderer (F.17) ----------

def test_html_is_well_formed_document(repo: Path) -> None:
    """Sanity: opens with doctype, closes the body+html, has a <title>."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert html.startswith("<!doctype html>")
    assert "<title>AgentShield combined report</title>" in html
    assert html.rstrip().endswith("</html>")


def test_html_has_ddr_hero_row(repo: Path) -> None:
    """Three D/D/R cards at the top — the lead element of the F.17 design."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert '<div class="ddr-row">' in html
    assert 'class="ddr-card detect"' in html
    assert 'class="ddr-card defend"' in html
    assert 'class="ddr-card respond"' in html
    # Order matters: Detect → Defend → Respond
    detect_pos = html.index('class="ddr-card detect"')
    defend_pos = html.index('class="ddr-card defend"')
    respond_pos = html.index('class="ddr-card respond"')
    assert detect_pos < defend_pos < respond_pos


def test_html_findings_are_grouped_under_ddr_sections(repo: Path) -> None:
    """Each finding rendered inside a `<div class="findings-section {cat}">`."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert 'class="findings-section detect"' in html
    assert 'class="findings-section defend"' in html
    assert 'class="findings-section respond"' in html


def test_html_finding_renders_origin_pill(repo: Path) -> None:
    """Each finding shows a Semgrep or Copilot origin pill (F.18 — CSS class
    names stay tier1/tier2 internally to keep CSS overrides stable; only
    the visible pill text changed)."""
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert '<span class="pill tier1">Semgrep</span>' in html
    assert '<span class="pill tier2">Copilot</span>' in html


def test_html_renders_severity_pills(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    # Tier 1 fixture is severity=high; Tier 2 fixture is severity=high.
    assert 'class="pill high"' in html


def test_html_renders_saige_card_when_classified(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "2"
    payload["saige_tier_reasoning"] = "Autonomous + state-changing internal calls only."
    _write_tier2(repo, payload)
    html = render_combined_html(merge(repo))
    assert 'class="saige-card"' in html
    assert "Tier 2" in html
    assert "Autonomous + state-changing internal calls only." in html


def test_html_omits_saige_when_unclassified(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())  # no saige
    html = render_combined_html(merge(repo))
    assert 'class="saige-card"' not in html


def test_html_shows_incomplete_banner_when_tier2_missing(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    html = render_combined_html(merge(repo))
    assert "INCOMPLETE — Copilot AI Scan not run." in html
    assert 'class="banner warn"' in html


def test_html_shows_stale_banner_on_fingerprint_mismatch(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload(fingerprint="aaa"))
    _write_tier2(repo, _tier2_payload(fingerprint="bbb"))
    html = render_combined_html(merge(repo))
    assert "STALE Copilot AI Scan." in html
    assert 'class="banner stale"' in html


def test_html_escapes_user_supplied_strings(repo: Path) -> None:
    """No XSS via finding messages or rule_ids — raw HTML must be escaped."""
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["findings"][0]["message"] = "<script>alert('xss')</script>"
    _write_tier2(repo, payload)
    html = render_combined_html(merge(repo))
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_renders_severity_distribution_bar(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert 'class="severity-bar"' in html


def test_html_renders_coverage_matrix(repo: Path) -> None:
    _write_tier1(repo, _tier1_payload())
    _write_tier2(repo, _tier2_payload())
    html = render_combined_html(merge(repo))
    assert 'class="coverage-grid"' in html
    assert "OWASP LLM" in html


def test_no_tier_label_collision_with_saige(repo: Path) -> None:
    """F.18 — JPMC SAIGE uses 'Tier 0/1/2/3' for agent classification;
    AgentShield's two scan phases must NOT also call themselves 'Tier 1'
    or 'Tier 2' in user-visible labels (collision is confusing in reports).

    SAIGE classification (e.g. 'Classified as: Tier 2') is the only place
    'Tier' may appear in user-visible text. AgentShield's phases show as
    'Semgrep Rules-engine Scan' / 'Copilot AI Scan' (long form in headers)
    or 'Semgrep' / 'Copilot' (short form in pills)."""
    _write_tier1(repo, _tier1_payload())
    payload = _tier2_payload()
    payload["saige_tier"] = "2"
    payload["saige_tier_reasoning"] = "Autonomous + state-changing internal."
    _write_tier2(repo, payload)

    md = render_combined_markdown(merge(repo))
    # AgentShield phase labels (the v1-vintage strings): all gone.
    assert "Tier 1 (semgrep)" not in md
    assert "Tier 2 (Copilot)" not in md
    assert "[Tier 1]" not in md
    assert "[Tier 2]" not in md
    assert "Tier 2 verdict" not in md
    assert "Tier 2 reasoning" not in md
    # SAIGE classification still uses 'Tier 2' (its naming, unchanged).
    assert "**Classified as:** Tier 2" in md
    # New labels present.
    assert "Semgrep Rules-engine Scan" in md
    assert "Copilot AI Scan" in md
    assert "[Semgrep]" in md
    assert "[Copilot]" in md

    html = render_combined_html(merge(repo))
    # No AgentShield-phase pills with the old labels.
    assert '>Tier 1</span>' not in html
    assert '>Tier 2</span>' not in html
    # SAIGE display tier is allowed to say 'Tier 2' inside its dedicated
    # saige-tier element — verify the SAIGE classification rendered correctly.
    assert 'class="saige-tier">Tier 2</div>' in html
    # New labels present.
    assert "Semgrep Rules-engine Scan" in html
    assert "Copilot AI Scan" in html
    assert '<span class="pill tier1">Semgrep</span>' in html
    assert '<span class="pill tier2">Copilot</span>' in html

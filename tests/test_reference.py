"""Tests for the Reference-tab data layer (Phase F.26).

Pins the contracts:
- Tier 1 rule YAMLs are picked up via `load_tier1_references`
- Tier 2 checklist entries are parsed from the bundled template
- Manifest scanner rules surface from the registry in rules.py
- HTML report renders a Reference tab with one card per check
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from agentshield.merger.reference import (
    RuleReference,
    build_all_references,
    load_manifest_scanner_references,
    load_tier1_references,
    parse_tier2_checklist,
)

REPO = Path(__file__).resolve().parent.parent
RULES_PATH = REPO / "agentshield" / "rules"
CHECKLIST_PATH = REPO / "agentshield" / "skills" / "tier2_checklist.md.tmpl"


# ---------- Tier 1 ----------


def test_load_tier1_references_picks_up_active_rules() -> None:
    refs = load_tier1_references(RULES_PATH)
    # The active pack ships at least D001/D003/D004/D005/D008/DF003 plus
    # the F.23 additions D009/D010/D011/D012 (Python siblings).
    rule_ids = {r.rule_id for r in refs}
    expected_subset = {
        "unsanitized-user-input-to-llm",
        "hardcoded-llm-credentials",
        "untrusted-system-prompt",
        "system-prompt-concealment-instructions",
        "system-prompt-jailbreak-markers",
        "tool-description-injection",
        "non-https-outbound-fetch",
    }
    assert expected_subset.issubset(rule_ids)


def test_tier1_reference_carries_severity_and_frameworks() -> None:
    refs = load_tier1_references(RULES_PATH)
    by_id = {r.rule_id: r for r in refs}
    d005 = by_id.get("hardcoded-llm-credentials")
    assert d005 is not None
    assert d005.severity == "critical"
    assert "CWE-798" in d005.frameworks.get("cwe", [])
    assert d005.source == "Semgrep"


def test_tier1_reference_skips_retired_rules(tmp_path: Path) -> None:
    """A YAML in the rules dir whose category isn't D/D/R should not
    surface in the Reference tab — same filter the normalizer uses."""
    fake_rules = tmp_path / "rules"
    fake_rules.mkdir()
    (fake_rules / "junk.yaml").write_text(
        dedent(
            """\
            rules:
              - id: agentshield.misc.something
                languages: [python]
                severity: WARNING
                pattern: foo
                metadata:
                  category: misc
                  agentshield_id: AS-X-999
            """
        )
    )
    refs = load_tier1_references(fake_rules)
    assert refs == []


# ---------- Tier 2 ----------


def test_parse_tier2_checklist_extracts_entries() -> None:
    refs = parse_tier2_checklist(CHECKLIST_PATH.read_text(encoding="utf-8"))
    rule_ids = {r.rule_id for r in refs}
    # F.27: post-rename canonical IDs.
    assert "AS-C-D-LLM01-001" in rule_ids
    assert "AS-C-D-AGENTIC_T1-001" in rule_ids
    assert "AS-C-DF-LLM06-004" in rule_ids
    assert "AS-C-DF-AGENTIC_T9-002" in rule_ids


def test_parse_tier2_checklist_carries_skip_if_and_remediation() -> None:
    refs = parse_tier2_checklist(CHECKLIST_PATH.read_text(encoding="utf-8"))
    by_id = {r.rule_id: r for r in refs}
    entry = by_id["AS-C-D-LLM01-001"]
    assert entry.severity == "high"
    assert entry.category == "detect"
    assert "guardrail" in (entry.skip_if or "").lower()
    assert "guardrail" in (entry.remediation or "").lower()
    # framework parsing produces dict[str, list[str]] from the
    # `**Frameworks:** owasp_llm=[LLM01], ...` line.
    assert entry.frameworks.get("owasp_llm") == ["LLM01"]
    # F.27 — legacy ID surfaced from the `**Legacy ID:**` bullet.
    assert "TIER2-LLM01-01" in entry.legacy_ids


def test_parse_tier2_checklist_handles_minimal_entry() -> None:
    """A real checklist has many entries, but we should cope with a
    small synthetic one too."""
    text = dedent(
        """\
        # §1. OWASP LLM Top 10 v2 (2025)

        ### TIER2-FAKE-X-01 — Synthetic fixture for parser
        - **Severity:** medium
        - **Languages:** any
        - **Frameworks:** owasp_llm=[LLM06]
        - **Look for:** Test fixture content.
        - **Skip if:** Never (this is just a fixture).
        - **Remediation:** Delete the fixture.
        """
    )
    refs = parse_tier2_checklist(text)
    assert len(refs) == 1
    r = refs[0]
    assert r.rule_id == "TIER2-FAKE-X-01"
    assert r.severity == "medium"
    assert r.skip_if == "Never (this is just a fixture)."
    assert r.section == "OWASP LLM Top 10 v2 (2025)"


# ---------- Manifest scanner ----------


def test_manifest_references_match_active_rules() -> None:
    refs = load_manifest_scanner_references()
    rule_ids = {r.rule_id for r in refs}
    expected = {
        "ast01-malicious-skill-marker",
        "ast03-network-unrestricted",
        "ast03-shell-access",
        "ast03-wildcard-file-read",
        "ast03-identity-file-write",
        "ast04-missing-description",
        "ast04-missing-author-identity",
        "ast05-unsafe-deserialization",
        "ast07-missing-signature",
        "ast07-missing-content-hash",
    }
    assert expected.issubset(rule_ids)
    # All AST10 rules carry an AST10 framework mapping.
    for r in refs:
        assert r.frameworks.get("ast"), f"missing ast mapping on {r.rule_id}"


# ---------- aggregation ----------


def test_build_all_references_unions_all_three_sources() -> None:
    refs = build_all_references(
        tier1_rules_path=RULES_PATH,
        tier2_checklist_path=CHECKLIST_PATH,
    )
    sources = {r.source for r in refs}
    assert sources == {"Semgrep", "Copilot", "Manifest"}
    # Lower bound: at least 6 Tier 1 + 50 Tier 2 + 5 Manifest.
    assert len(refs) >= 60


def test_build_all_references_skips_missing_checklist(tmp_path: Path) -> None:
    """If the checklist template is absent, Tier 2 entries are silently
    skipped — Tier 1 + Manifest still render."""
    refs = build_all_references(
        tier1_rules_path=RULES_PATH,
        tier2_checklist_path=tmp_path / "missing.md",
    )
    sources = {r.source for r in refs}
    assert sources == {"Semgrep", "Manifest"}


# ---------- F.34: fix-skill SKILL.md generator ----------

def test_render_fix_skill_emits_owasp_uf_frontmatter() -> None:
    """Every fix-skill must lead with valid OWASP-Universal-Skill-Format
    YAML frontmatter so Claude / Copilot can discover and load it."""
    from agentshield.merger.reference import render_fix_skill

    refs = build_all_references(
        tier1_rules_path=RULES_PATH,
        tier2_checklist_path=CHECKLIST_PATH,
    )
    for source in ("Semgrep", "Copilot", "Manifest"):
        md = render_fix_skill(source, refs)
        # Frontmatter shape.
        assert md.startswith("---\n"), f"{source}: missing frontmatter open"
        # Must declare its discovery-relevant fields.
        for field in ("name:", "description:", "author:", "permissions:", "risk_tier:"):
            assert field in md.split("\n---\n", 1)[0], (
                f"{source}: missing frontmatter field {field}"
            )
        # Must be read-only by construction (no shell, no writes).
        assert "shell: false" in md
        # Must list at least one trigger phrase ("AS-S-" / "AS-C-" / "AS-M-").
        prefix = {"Semgrep": "AS-S-", "Copilot": "AS-C-", "Manifest": "AS-M-"}[source]
        assert prefix in md


def test_fix_skill_files_on_disk_match_fresh_render() -> None:
    """Drift guard: the committed skill files in `agentshield/skills/`
    must match what the generator produces today. If a rule changes
    and someone forgets to re-run `python -m agentshield.skills.
    _build_fix_skills`, this test fails on CI."""
    from agentshield.merger.reference import render_fix_skill

    refs = build_all_references(
        tier1_rules_path=RULES_PATH,
        tier2_checklist_path=CHECKLIST_PATH,
    )
    expected = {
        "Semgrep": REPO / "agentshield" / "skills" / "agentshield_semgrep_fixes.md",
        "Copilot": REPO / "agentshield" / "skills" / "agentshield_copilot_fixes.md",
        "Manifest": REPO / "agentshield" / "skills" / "agentshield_manifest_fixes.md",
    }
    for source, path in expected.items():
        assert path.exists(), (
            f"Missing fix-skill: {path}. "
            f"Run `python -m agentshield.skills._build_fix_skills` to (re)generate."
        )
        on_disk = path.read_text(encoding="utf-8")
        fresh = render_fix_skill(source, refs)
        assert on_disk == fresh, (
            f"{path.name} is out of sync with the rule pack. "
            f"Run `python -m agentshield.skills._build_fix_skills` to refresh."
        )

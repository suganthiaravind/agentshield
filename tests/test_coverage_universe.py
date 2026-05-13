"""Tests for the Coverage Matrix's framework-universe data.

The matrix renders three states per framework item: scanned-with-issues,
scanned-clean, and not-scanned. The "not-scanned" bucket only makes
sense if `FRAMEWORK_UNIVERSES` is a strict superset of every framework
ID the bundled rule pack references. If that invariant ever breaks, an
item the scanner can fire on would be misclassified as "not scanned" —
the matrix would lie. These tests pin the invariant.
"""

from __future__ import annotations

from pathlib import Path

from agentshield.merger.coverage_universe import (
    FRAMEWORK_UNIVERSES,
    compute_scanner_coverage,
)
from agentshield.merger.reference import build_all_references


_RULES_PATH = Path(__file__).resolve().parent.parent / "agentshield" / "rules"
_CHECKLIST_PATH = (
    Path(__file__).resolve().parent.parent
    / "agentshield"
    / "skills"
    / "tier2_checklist.md.tmpl"
)


def _scanner_coverage() -> dict[str, set[str]]:
    refs = build_all_references(
        tier1_rules_path=_RULES_PATH,
        tier2_checklist_path=_CHECKLIST_PATH,
    )
    return compute_scanner_coverage(refs)


def test_universe_keys_match_coverage_axes() -> None:
    """The 5 framework axes the merger tracks must each have a universe
    definition — otherwise rendering would explode on a KeyError."""
    assert set(FRAMEWORK_UNIVERSES) == {
        "owasp_llm", "owasp_agentic", "mitre_atlas", "cwe", "ast",
    }


def test_universes_have_no_duplicates() -> None:
    for key, items in FRAMEWORK_UNIVERSES.items():
        assert len(items) == len(set(items)), (
            f"{key} universe has duplicate IDs: {items}"
        )


def test_universe_is_superset_of_scanner_coverage() -> None:
    """Every framework ID any rule in the bundled pack references must
    appear in `FRAMEWORK_UNIVERSES[<key>]`. If you've added a rule that
    references a new ID (e.g. a new OWASP LLM Top 10 entry, a new ATLAS
    technique, a new CWE), add it to the universe list as well."""
    scanner = _scanner_coverage()
    missing: dict[str, set[str]] = {}
    for key, universe in FRAMEWORK_UNIVERSES.items():
        gaps = scanner.get(key, set()) - set(universe)
        if gaps:
            missing[key] = gaps
    assert not missing, (
        "Rule pack references framework IDs that aren't in the universe: "
        f"{missing}. Add them to agentshield/merger/coverage_universe.py."
    )


def test_owasp_llm_universe_covers_top_10() -> None:
    """LLM01–LLM10 must all be present — the matrix is meant to show
    'we cover X of the 10 OWASP LLM items'. If the list ever drops one,
    the headline math breaks."""
    expected = {f"LLM{i:02d}" for i in range(1, 11)}
    assert expected.issubset(set(FRAMEWORK_UNIVERSES["owasp_llm"]))


def test_owasp_ast_universe_covers_top_10() -> None:
    expected = {f"AST{i:02d}" for i in range(1, 11)}
    assert expected.issubset(set(FRAMEWORK_UNIVERSES["ast"]))

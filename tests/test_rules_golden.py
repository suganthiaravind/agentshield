"""Golden-file tests for AgentShield rules.

Each fixture under tests/fixtures/{python,java}/ has a matching
golden file under tests/golden/{python,java}/ with the expected
findings. The test scans all fixtures in one semgrep pass and
asserts the actual findings match the golden snapshot per file.

To regenerate the goldens (after intentional rule changes):
    pytest tests/test_rules_golden.py --update-golden

Reviewing the resulting diff is the audit trail for the change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GOLDEN_DIR = Path(__file__).parent / "golden"


def discover_fixtures() -> list[Path]:
    """Return all fixture file paths relative to FIXTURES_DIR, sorted."""
    return sorted(
        p.relative_to(FIXTURES_DIR)
        for p in FIXTURES_DIR.rglob("*")
        if p.is_file() and p.suffix in {".py", ".java"} and "__pycache__" not in p.parts
    )


def golden_path_for(fixture_rel: Path) -> Path:
    """Map a fixture relative path to its golden file path."""
    return GOLDEN_DIR / fixture_rel.with_suffix(".json")


@pytest.mark.parametrize(
    "fixture_rel",
    discover_fixtures(),
    ids=lambda p: str(p),
)
def test_fixture_findings_match_golden(
    fixture_rel: Path,
    all_findings_by_fixture: dict[Path, list[dict[str, Any]]],
    request: pytest.FixtureRequest,
) -> None:
    actual = all_findings_by_fixture.get(fixture_rel, [])
    golden = golden_path_for(fixture_rel)

    if request.config.getoption("--update-golden"):
        golden.parent.mkdir(parents=True, exist_ok=True)
        payload = {"fixture": str(fixture_rel), "expected_findings": actual}
        golden.write_text(json.dumps(payload, indent=2) + "\n")
        pytest.skip(f"Updated golden: {golden.relative_to(GOLDEN_DIR.parent)}")

    assert golden.exists(), (
        f"Missing golden file: {golden.relative_to(GOLDEN_DIR.parent)}. "
        f"Run with --update-golden to create it."
    )
    expected = json.loads(golden.read_text()).get("expected_findings", [])
    assert actual == expected, (
        f"Findings drift in {fixture_rel}.\n"
        f"  Expected: {expected}\n"
        f"  Actual:   {actual}\n"
        f"If this is intentional, regenerate with: pytest --update-golden"
    )

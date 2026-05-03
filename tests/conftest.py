"""Shared pytest config and fixtures for AgentShield tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.runner import SemgrepRunner

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="Overwrite golden snapshot files with actual scan output instead of diffing.",
    )


@pytest.fixture(scope="session")
def all_findings_by_fixture() -> dict[Path, list[dict]]:
    """Run semgrep ONCE across the whole fixtures/ tree and partition results by file.

    Single semgrep invocation amortizes the ~5s startup across all fixture-vs-golden
    test cases — keeps the suite fast as more fixtures are added.

    Fixtures are enumerated explicitly because semgrep's default semgrepignore
    excludes `tests/` and `fixtures/` directories on traversal. Passing the file
    paths as positional args bypasses that filter.
    """
    fixture_files = sorted(
        p
        for p in FIXTURES_DIR.rglob("*")
        if p.is_file() and p.suffix in {".py", ".java"} and "__pycache__" not in p.parts
    )
    runner = SemgrepRunner()
    sarif = runner.run(fixture_files)
    by_file: dict[Path, list[dict]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            loc = result.get("locations", [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            if not uri:
                continue
            # SARIF URIs are absolute paths on disk for our runner config; normalize
            # to a Path relative to FIXTURES_DIR so goldens are portable.
            try:
                rel = Path(uri).resolve().relative_to(FIXTURES_DIR.resolve())
            except ValueError:
                continue
            rule_id = result.get("ruleId", "").split(".")[-1]
            line = loc.get("region", {}).get("startLine", 0)
            by_file.setdefault(rel, []).append({"rule_id": rule_id, "line": line})
    # sort each file's findings deterministically
    for findings in by_file.values():
        findings.sort(key=lambda f: (f["line"], f["rule_id"]))
    return by_file

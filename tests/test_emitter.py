"""Tests for the Tier 2 skill-file emitter (Phase F.4).

The emitter is the bridge between Tier 1 (semgrep) and Tier 2 (Copilot
scan). Per ARCHITECTURE_V2 §4, after Tier 1 finishes the emitter copies
the bundled skill templates into <target>/.agentshield/, writes the
Tier 1 findings + a fingerprint hash, and gitignores the directory.

Tests pin:
- Templates copied verbatim (not mutated)
- Fingerprint determinism + order-independence (stale-detection contract)
- Fingerprint sensitivity to finding changes
- .gitignore handling: created when missing, appended when present,
  idempotent on re-emit
- tier1-results.json has the schema the checklist expects Copilot to read
- Re-emission overwrites templates + tier1-results.json (they are
  generated artifacts — always fresh)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentshield.emitter import (
    GITIGNORE_ENTRY,
    GITIGNORE_MARKER,
    compute_tier1_fingerprint,
    copilot_prompt,
    emit_skills,
    ensure_gitignored,
)
from agentshield.emitter.skill_emitter import SKILLS_DIR, TEMPLATE_FILES


# ---------- fixtures ----------

@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """An empty 'target repo' the emitter will write into."""
    return tmp_path


@pytest.fixture()
def sample_findings() -> list[dict]:
    return [
        {
            "rule_id": "agentshield.detect.unsanitized-user-input-to-llm",
            "file": "src/api/chat.py",
            "line": 42,
            "severity": "high",
            "message": "User input flows into chain.invoke without sanitiser.",
        },
        {
            "rule_id": "agentshield.detect.hardcoded-llm-credentials",
            "file": "src/config.py",
            "line": 7,
            "severity": "critical",
            "message": "Hardcoded API key.",
        },
    ]


@pytest.fixture()
def fixed_now() -> datetime:
    return datetime(2026, 5, 5, 22, 14, 0, tzinfo=timezone.utc)


# ---------- template copying ----------

def test_emits_all_three_templates_into_dot_agentshield(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    result = emit_skills(repo, sample_findings, ["src/api/chat.py"], now_utc=fixed_now)
    out = repo / ".agentshield"
    assert (out / "tier2-bootstrap.md").is_file()
    assert (out / "tier2-checklist.md").is_file()
    assert (out / "tier2-output-schema.md").is_file()
    assert len(result.emitted_files) == 4  # 3 templates + tier1-results.json


def test_templates_copied_verbatim(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    """The on-disk file content must match the bundled template byte-for-byte
    (no template substitution today; if we add it, this test should change
    intentionally)."""
    emit_skills(repo, sample_findings, [], now_utc=fixed_now)
    for src_name, dst_name in TEMPLATE_FILES.items():
        src_text = (SKILLS_DIR / src_name).read_text()
        dst_text = (repo / ".agentshield" / dst_name).read_text()
        assert src_text == dst_text, f"Template {src_name} was mutated during emit"


def test_emit_overwrites_existing_template_files(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    """Re-running emit must refresh the templates so they always reflect the
    bundled v2 contract — they are generated artifacts, not user-editable."""
    out = repo / ".agentshield"
    out.mkdir()
    (out / "tier2-checklist.md").write_text("STALE CONTENT FROM YESTERDAY")
    emit_skills(repo, sample_findings, [], now_utc=fixed_now)
    assert "STALE CONTENT" not in (out / "tier2-checklist.md").read_text()


# ---------- tier1-results.json shape ----------

def test_tier1_results_json_has_required_top_level_fields(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    emit_skills(repo, sample_findings, ["src/api/chat.py"], now_utc=fixed_now)
    payload = json.loads((repo / ".agentshield" / "tier1-results.json").read_text())
    for field in ["tier", "scanned_at", "agentshield_tier1_fingerprint", "scanned_files", "findings"]:
        assert field in payload, f"tier1-results.json missing {field}"
    assert payload["tier"] == 1
    assert payload["scanned_at"] == "2026-05-05T22:14:00Z"
    assert payload["scanned_files"] == ["src/api/chat.py"]
    assert payload["findings"] == sample_findings


def test_tier1_results_includes_fingerprint(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    result = emit_skills(repo, sample_findings, [], now_utc=fixed_now)
    payload = json.loads((repo / ".agentshield" / "tier1-results.json").read_text())
    assert payload["agentshield_tier1_fingerprint"] == result.fingerprint
    assert len(result.fingerprint) == 64  # SHA-256 hex


# ---------- fingerprint contract ----------

def test_fingerprint_is_deterministic(sample_findings: list[dict]) -> None:
    """Same findings → same hash, every time."""
    h1 = compute_tier1_fingerprint(sample_findings)
    h2 = compute_tier1_fingerprint(sample_findings)
    assert h1 == h2


def test_fingerprint_is_order_independent(sample_findings: list[dict]) -> None:
    """Tier 1 may emit findings in any order; fingerprint must not depend on it."""
    h1 = compute_tier1_fingerprint(sample_findings)
    h2 = compute_tier1_fingerprint(list(reversed(sample_findings)))
    assert h1 == h2


def test_fingerprint_changes_when_findings_change(sample_findings: list[dict]) -> None:
    """If user re-runs Tier 1 after a fix, fingerprint must differ — that's
    exactly what tells the merger Tier 2 is now stale."""
    h1 = compute_tier1_fingerprint(sample_findings)
    mutated = list(sample_findings)
    mutated[0] = {**mutated[0], "line": 99}
    h2 = compute_tier1_fingerprint(mutated)
    assert h1 != h2


def test_fingerprint_only_uses_file_line_rule(sample_findings: list[dict]) -> None:
    """Other fields (severity, message) must NOT affect the fingerprint —
    otherwise rephrasing a message would falsely flag Tier 2 as stale."""
    h1 = compute_tier1_fingerprint(sample_findings)
    rephrased = [{**f, "message": "different wording"} for f in sample_findings]
    h2 = compute_tier1_fingerprint(rephrased)
    assert h1 == h2


def test_fingerprint_handles_empty_findings() -> None:
    h = compute_tier1_fingerprint([])
    assert len(h) == 64  # SHA-256 hex of "[]"


# ---------- .gitignore handling ----------

def test_gitignore_created_when_missing(repo: Path) -> None:
    assert not (repo / ".gitignore").exists()
    updated = ensure_gitignored(repo)
    assert updated is True
    content = (repo / ".gitignore").read_text()
    assert GITIGNORE_MARKER in content
    assert GITIGNORE_ENTRY in content


def test_gitignore_appended_when_entry_missing(repo: Path) -> None:
    (repo / ".gitignore").write_text("__pycache__/\n.venv/\n")
    updated = ensure_gitignored(repo)
    assert updated is True
    content = (repo / ".gitignore").read_text()
    assert content.startswith("__pycache__/\n.venv/\n")  # existing preserved
    assert GITIGNORE_ENTRY in content


def test_gitignore_idempotent_when_entry_present(repo: Path) -> None:
    (repo / ".gitignore").write_text("__pycache__/\n.agentshield/\n.venv/\n")
    original = (repo / ".gitignore").read_text()
    updated = ensure_gitignored(repo)
    assert updated is False
    assert (repo / ".gitignore").read_text() == original


@pytest.mark.parametrize(
    "alt_form",
    [".agentshield", ".agentshield/", ".agentshield/*"],
)
def test_gitignore_recognises_alternate_forms(repo: Path, alt_form: str) -> None:
    """Don't add a duplicate if the user already gitignored .agentshield in
    a slightly different form."""
    (repo / ".gitignore").write_text(f"__pycache__/\n{alt_form}\n")
    updated = ensure_gitignored(repo)
    assert updated is False


def test_gitignore_handles_no_trailing_newline(repo: Path) -> None:
    """File without trailing newline gets one added before our entry."""
    (repo / ".gitignore").write_text("__pycache__/")  # no newline
    ensure_gitignored(repo)
    content = (repo / ".gitignore").read_text()
    assert "\n.agentshield/" in content


# ---------- end-to-end re-emit ----------

def test_emit_is_idempotent_on_re_run(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    """Running scan twice should produce a stable on-disk state. Templates
    + tier1-results.json overwrite; .gitignore stays one entry."""
    emit_skills(repo, sample_findings, [], now_utc=fixed_now)
    first_gi = (repo / ".gitignore").read_text()
    emit_skills(repo, sample_findings, [], now_utc=fixed_now)
    second_gi = (repo / ".gitignore").read_text()
    assert first_gi == second_gi  # no duplicate gitignore entry
    assert second_gi.count(GITIGNORE_ENTRY) == 1


def test_emit_result_carries_expected_fields(
    repo: Path, sample_findings: list[dict], fixed_now: datetime
) -> None:
    result = emit_skills(repo, sample_findings, ["a.py"], now_utc=fixed_now)
    assert result.target_root == repo
    assert result.tier1_path == repo / ".agentshield" / "tier1-results.json"
    assert len(result.fingerprint) == 64
    assert result.gitignore_updated is True
    assert all(p.exists() for p in result.emitted_files)


# ---------- Copilot prompt ----------

def test_copilot_prompt_mentions_required_files() -> None:
    p = copilot_prompt()
    assert "@workspace" in p
    assert ".agentshield/tier2-checklist.md" in p
    assert ".agentshield/tier2-output-schema.md" in p
    assert ".agentshield/tier2-findings.json" in p
    assert ".agentshield/tier1-results.json" in p
    assert "agentshield_tier1_fingerprint" in p


# ---------- error handling ----------

def test_emit_raises_when_template_missing(
    repo: Path, sample_findings: list[dict], fixed_now: datetime, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the package install is corrupt and a template is missing, the
    emitter must fail loudly rather than silently writing partial output."""
    from agentshield.emitter import skill_emitter
    monkeypatch.setattr(skill_emitter, "SKILLS_DIR", Path("/nonexistent/path"))
    with pytest.raises(FileNotFoundError, match="Bundled skill template missing"):
        emit_skills(repo, sample_findings, [], now_utc=fixed_now)

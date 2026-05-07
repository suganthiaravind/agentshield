"""Scan a target directory for SKILL.md files and run the AST rule set.

Public entry point: `scan_manifests(target)` returns a list of Finding
objects in the same shape as the Tier 1 (Semgrep) scanner — they merge
into the same emitter dict / merger pipeline / report.
"""

from __future__ import annotations

import sys
from pathlib import Path

from agentshield.manifest_scanner.parser import (
    ManifestParseError,
    parse_skill_md,
)
from agentshield.manifest_scanner.rules import ALL_RULES
from agentshield.normalize.schema import Finding

# Directories the manifest scanner skips. Mirrors what semgrep ignores by
# default; `.agentshield/` is added so we don't scan the templates this
# tool itself emits.
_SKIPPED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "vendor",
    ".agentshield",
    "_retired_v2",
}


def discover_skill_md_files(target: Path) -> list[Path]:
    """Return every `SKILL.md` (case-insensitive) under `target`,
    excluding standard ignore dirs.
    """
    target = Path(target)
    if not target.exists():
        return []
    if target.is_file():
        return [target] if target.name.lower() == "skill.md" else []

    found: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower() != "skill.md":
            continue
        if any(part in _SKIPPED_DIRS for part in path.parts):
            continue
        found.append(path)
    found.sort()
    return found


def scan_manifests(target: Path) -> list[Finding]:
    """Run all 5 AST rules over every `SKILL.md` under `target`.

    Parse errors are reported on stderr and the offending file is
    skipped — a malformed manifest shouldn't abort the whole scan. The
    returned Finding objects use POSIX-style relative paths (relative to
    `target`) when possible, mirroring the Semgrep output convention.
    """
    target = Path(target).resolve()
    findings: list[Finding] = []
    for path in discover_skill_md_files(target):
        try:
            manifest = parse_skill_md(path)
        except ManifestParseError as exc:
            print(
                f"[agentshield] manifest_scanner: skipping {path}: {exc}",
                file=sys.stderr,
            )
            continue
        for rule in ALL_RULES:
            for finding in rule(manifest):
                # Rewrite absolute path to repo-relative POSIX path so the
                # report renders cleanly. `is_relative_to` is the safe
                # guard for paths outside the target tree.
                p = Path(finding.location.file_path)
                try:
                    rel = p.resolve().relative_to(target)
                    finding.location.file_path = rel.as_posix()
                except ValueError:
                    finding.location.file_path = p.as_posix()
                findings.append(finding)
    findings.sort(
        key=lambda f: (f.location.file_path, f.location.start_line, f.rule_id)
    )
    return findings

"""Scan a target directory for agent-loaded markdown files and run the
AST rule set.

Public entry point: `scan_manifests(target)` returns a list of Finding
objects in the same shape as the Tier 1 (Semgrep) scanner — they merge
into the same emitter dict / merger pipeline / report.

The scanner originally only matched `SKILL.md`. v4 broadens the
discovery glob to every filename that agent runtimes / skill loaders
commonly read — SKILL.md, AGENT.md, AGENTS.md, INSTRUCTION(S).md,
PROMPT(S).md, CLAUDE.md. The frontmatter-based rules (AST03 / 04 / 07)
gracefully no-op on prose-only files (no frontmatter → nothing to
check); AST01 (body markers — jailbreak / concealment / exfil) fires
on every file it discovers.
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

# Filenames the scanner recognises as agent-loaded markdown.
# Case-insensitive match on the bare filename (no path).
#
#   SKILL.md / AGENT.md / AGENTS.md   — manifest-shaped; full AST sweep
#   INSTRUCTION(S).md / PROMPT(S).md  — prose-only; AST01 body markers
#   CLAUDE.md                          — Claude Code project instructions
#
# Excluded by design: README.md, CHANGELOG.md, LICENSE.md, anything
# under the standard ignore dirs above (node_modules, .venv, etc.).
RECOGNIZED_AGENT_MD_FILENAMES = frozenset({
    "skill.md",
    "agent.md",
    "agents.md",
    "instruction.md",
    "instructions.md",
    "prompt.md",
    "prompts.md",
    "claude.md",
})


def discover_skill_md_files(target: Path) -> list[Path]:
    """Return every agent-loaded markdown file (SKILL.md / AGENT.md /
    AGENTS.md / INSTRUCTION(S).md / PROMPT(S).md / CLAUDE.md) under
    `target`, excluding standard ignore dirs. Match is case-insensitive
    on the bare filename.

    Function name kept for backward compat — other callers / tests
    import it as `discover_skill_md_files`; the broader contract is
    documented in `RECOGNIZED_AGENT_MD_FILENAMES`.
    """
    target = Path(target)
    if not target.exists():
        return []
    if target.is_file():
        return [target] if target.name.lower() in RECOGNIZED_AGENT_MD_FILENAMES else []

    found: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if path.name.lower() not in RECOGNIZED_AGENT_MD_FILENAMES:
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
    parsed_manifests: list = []
    for path in discover_skill_md_files(target):
        try:
            manifest = parse_skill_md(path)
        except ManifestParseError as exc:
            print(
                f"[agentshield] manifest_scanner: skipping {path}: {exc}",
                file=sys.stderr,
            )
            continue
        parsed_manifests.append(manifest)
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

    # v4 (Path B): AST08 is a cross-manifest rule — runs once with the
    # full list of parsed manifests so it can see permission combos that
    # only emerge when ≥2 skills are loaded together.
    from agentshield.manifest_scanner.rules import check_ast08_cross_skill
    for finding in check_ast08_cross_skill(parsed_manifests):
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

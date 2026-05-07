"""SKILL.md manifest scanner — F.24.

Targets the developer-tooling skill-distribution layer (OpenClaw / Claude
Code / Cursor / VS Code skill packages) — different artifact than the
Tier 1 source-code Semgrep scan, but emits findings in the same Finding
shape so they flow through the existing emitter / merger / report
pipeline unchanged.

See `agentshield/manifest_scanner/rules.py` for the 5 implemented AST
checks (AST01, AST03, AST04, AST05, AST07).
"""

from agentshield.manifest_scanner.parser import (
    ManifestParseError,
    ParsedManifest,
    parse_skill_md,
)
from agentshield.manifest_scanner.scanner import (
    discover_skill_md_files,
    scan_manifests,
)

__all__ = [
    "ManifestParseError",
    "ParsedManifest",
    "discover_skill_md_files",
    "parse_skill_md",
    "scan_manifests",
]

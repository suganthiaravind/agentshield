"""Emit Tier 2 skill files into a target repo (Phase F.4)."""

from agentshield.emitter.skill_emitter import (
    EmitResult,
    GITIGNORE_ENTRY,
    GITIGNORE_MARKER,
    compute_tier1_fingerprint,
    copilot_prompt,
    default_output_dir,
    emit_skills,
    ensure_gitignored,
)

__all__ = [
    "EmitResult",
    "GITIGNORE_ENTRY",
    "GITIGNORE_MARKER",
    "compute_tier1_fingerprint",
    "copilot_prompt",
    "default_output_dir",
    "emit_skills",
    "ensure_gitignored",
]

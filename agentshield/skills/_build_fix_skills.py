"""Generate the 3 fix-skill SKILL.md files (F.34).

Run this whenever the rule pack changes:

    /usr/local/bin/python3.11 -m agentshield.skills._build_fix_skills

It writes three files into `agentshield/skills/`:
    agentshield_semgrep_fixes.md
    agentshield_copilot_fixes.md
    agentshield_manifest_fixes.md

The content comes from the same `RuleReference` data the Reference
tab uses, so the skill files match the live rule pack as long as
this script is re-run after rule changes.

`tests/test_skills.py` asserts no drift between the on-disk skills
and a fresh re-render — CI catches stale skills automatically.
"""

from __future__ import annotations

from pathlib import Path

from agentshield.merger.reference import (
    build_all_references,
    render_fix_skill,
)

REPO = Path(__file__).resolve().parent.parent.parent
RULES_PATH = REPO / "agentshield" / "rules"
CHECKLIST_PATH = REPO / "agentshield" / "skills" / "tier2_checklist.md.tmpl"
SKILLS_DIR = REPO / "agentshield" / "skills"

OUTPUTS = {
    "Semgrep": "agentshield_semgrep_fixes.md",
    "Copilot": "agentshield_copilot_fixes.md",
    # Source key is "Markdown" (the new user-facing label); file name
    # stays "manifest" to keep the bundled artifact's identity stable
    # for anything keyed on the old name.
    "Markdown": "agentshield_manifest_fixes.md",
}


def main() -> None:
    refs = build_all_references(
        tier1_rules_path=RULES_PATH,
        tier2_checklist_path=CHECKLIST_PATH,
    )
    for source, filename in OUTPUTS.items():
        content = render_fix_skill(source, refs)
        out_path = SKILLS_DIR / filename
        out_path.write_text(content, encoding="utf-8")
        print(f"  wrote {out_path.relative_to(REPO)} ({len(content):,} bytes)")


if __name__ == "__main__":
    main()

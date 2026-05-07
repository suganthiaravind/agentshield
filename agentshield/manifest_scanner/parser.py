"""Split SKILL.md into YAML frontmatter + Markdown body.

SKILL.md format (per OpenClaw / OWASP Universal Skill Format proposal):

    ---
    name: example-skill
    permissions:
      network: true
      shell: false
    ---

    # Markdown body
    Some prose. Code blocks. Etc.

If the file has no `---` fences, the whole file is treated as body and
frontmatter is `{}`. We do not raise on missing frontmatter — many real
SKILL.md files in the wild are body-only — we just have less to scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ManifestParseError(RuntimeError):
    """Raised when frontmatter YAML is syntactically invalid.

    Body-only files (no frontmatter at all) are NOT a parse error — they
    yield ParsedManifest(frontmatter={}, body=<file>, frontmatter_lines=0).
    """


@dataclass
class ParsedManifest:
    """A SKILL.md split into frontmatter dict + body string.

    Attributes:
        path: filesystem path of the source file (for findings).
        frontmatter: parsed YAML frontmatter (empty dict if absent).
        body: Markdown body text (everything after the closing `---`,
            or the whole file if no fences).
        frontmatter_lines: number of lines occupied by the frontmatter
            fence + content + closing fence. Used to translate body-line
            offsets back to absolute file lines.
        body_offset: 1-based line number where the body starts in the
            source file. Equals frontmatter_lines + 1 when frontmatter
            exists, else 1.
    """

    path: Path
    frontmatter: dict[str, Any]
    body: str
    frontmatter_lines: int
    body_offset: int


def parse_skill_md(path: Path) -> ParsedManifest:
    """Parse a SKILL.md file. Body-only files are valid (return empty
    frontmatter)."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    # No frontmatter at all (or doesn't start with `---`).
    if not lines or lines[0].rstrip("\r\n") != "---":
        return ParsedManifest(
            path=path,
            frontmatter={},
            body=text,
            frontmatter_lines=0,
            body_offset=1,
        )

    # Find the closing `---`. If we don't find one, treat the whole file as
    # body — better than failing on a half-formed manifest.
    close_idx: int | None = None
    for i in range(1, len(lines)):
        if lines[i].rstrip("\r\n") == "---":
            close_idx = i
            break
    if close_idx is None:
        return ParsedManifest(
            path=path,
            frontmatter={},
            body=text,
            frontmatter_lines=0,
            body_offset=1,
        )

    frontmatter_text = "".join(lines[1:close_idx])
    body_text = "".join(lines[close_idx + 1 :])

    try:
        loaded = yaml.safe_load(frontmatter_text) or {}
    except yaml.YAMLError as exc:
        raise ManifestParseError(
            f"{path}: invalid YAML in frontmatter: {exc}"
        ) from exc

    # Defensive: a YAML document that's a list / scalar / None at the top
    # level isn't a manifest. Treat as empty frontmatter rather than
    # failing — the body checks still work.
    if not isinstance(loaded, dict):
        loaded = {}

    return ParsedManifest(
        path=path,
        frontmatter=loaded,
        body=body_text,
        frontmatter_lines=close_idx + 1,
        body_offset=close_idx + 2,
    )

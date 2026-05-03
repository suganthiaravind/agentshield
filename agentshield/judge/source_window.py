"""Source-code helpers for the judge tier.

The orchestrator (B4) needs to send a ±N-line window around each
fallback finding to the LLM, plus the file's imports as a hint. These
are simple file-reading helpers; no real parsing — regex-based import
extraction is enough at the precision LLM-judge cares about.
"""

from __future__ import annotations

import re
from pathlib import Path

# Python: `import X`, `import X.Y`, `from X import Y`, `from X.Y import Z`
_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\s+\S|import\s+([\w.]+))",
    re.MULTILINE,
)

# Java: `import com.foo.Bar;` and `import static com.foo.Bar.baz;`
_JAVA_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;",
    re.MULTILINE,
)


def read_code_window(
    file_path: str | Path,
    center_line: int,
    context_lines: int = 20,
) -> str:
    """Return ±context_lines around center_line, with line-number prefixes.

    `center_line` is 1-based (matches SARIF/Finding convention).
    Returns an empty string if the file cannot be read.
    """
    try:
        text = Path(file_path).read_text(errors="replace")
    except (OSError, UnicodeError):
        return ""
    lines = text.splitlines()
    start = max(1, center_line - context_lines)
    end = min(len(lines), center_line + context_lines)
    width = len(str(end))
    out: list[str] = []
    for n in range(start, end + 1):
        marker = ">" if n == center_line else " "
        out.append(f"{marker} {n:>{width}} | {lines[n - 1]}")
    return "\n".join(out)


def read_matched_line(file_path: str | Path, line: int) -> str:
    """Return the single line at the given 1-based line number, or empty string."""
    try:
        text = Path(file_path).read_text(errors="replace")
    except (OSError, UnicodeError):
        return ""
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def extract_imports(file_path: str | Path, language: str) -> list[str]:
    """Return imported module/package names from the file.

    Best-effort regex extraction — good enough for the LLM-judge hint;
    we intentionally avoid pulling in libcst/javalang for this.
    Returns an empty list on read failure or unsupported language.
    """
    try:
        text = Path(file_path).read_text(errors="replace")
    except (OSError, UnicodeError):
        return []
    if language == "python":
        names: list[str] = []
        for match in _PY_IMPORT_RE.finditer(text):
            name = match.group(1) or match.group(2)
            if name:
                names.append(name)
        return _dedupe_preserving_order(names)
    if language == "java":
        names = [m.group(1) for m in _JAVA_IMPORT_RE.finditer(text)]
        return _dedupe_preserving_order(names)
    return []


def _dedupe_preserving_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

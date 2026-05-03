"""Tier 1 + Tier 2 semgrep subprocess runner.

Invokes the bundled rule pack against a target path and returns raw
SARIF v2.1.0 as a dict. Tier partitioning (framework vs fallback) is
handled downstream by the normalizer (Track A3) using rule metadata.

This module deliberately keeps no domain knowledge of finding shape —
it just orchestrates the subprocess and returns the JSON payload.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


class SemgrepRunnerError(RuntimeError):
    """Raised when the semgrep subprocess fails or its output is unparseable."""


class SemgrepRunner:
    """Wrap `semgrep scan --sarif` against the bundled AgentShield rule pack."""

    DEFAULT_TIMEOUT_SECONDS = 600

    def __init__(
        self,
        rules_path: Path | None = None,
        timeout: int | None = None,
        extra_flags: list[str] | None = None,
        semgrep_executable: str | None = None,
    ) -> None:
        self.rules_path = Path(rules_path) if rules_path else self._default_rules_path()
        self.timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS
        self.extra_flags = list(extra_flags) if extra_flags else []
        self._semgrep_executable_override = semgrep_executable

    @staticmethod
    def _default_rules_path() -> Path:
        # agentshield/runner/semgrep_runner.py → agentshield/rules/
        rules = Path(__file__).resolve().parent.parent / "rules"
        if not rules.is_dir():
            raise SemgrepRunnerError(
                f"Bundled rules directory not found at {rules}. "
                "Reinstall agentshield or check the package layout."
            )
        return rules

    def _semgrep_executable(self) -> str:
        if self._semgrep_executable_override:
            return self._semgrep_executable_override
        # First check PATH (the normal case for activated venvs).
        path = shutil.which("semgrep")
        if path:
            return path
        # Fallback: look alongside the running Python interpreter — covers
        # the case where the user installed into a venv but invoked
        # `path/to/.venv/bin/agentshield` without activating it.
        bin_dir = Path(sys.executable).parent
        for name in ("semgrep", "semgrep.exe"):
            candidate = bin_dir / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        raise SemgrepRunnerError(
            "semgrep binary not found in PATH or alongside the Python interpreter. "
            "Install with: pip install 'agentshield[semgrep]'"
        )

    def run(self, target_path: Path | str | list[Path | str]) -> dict[str, Any]:
        """Scan `target_path` and return parsed SARIF v2.1.0.

        `target_path` may be a single path (str or Path) or a list. When a
        list is given, each path is passed explicitly to semgrep — useful
        for tests that need to bypass semgrep's default ignore patterns
        (which exclude `tests/`, `fixtures/`, etc. on directory traversal).

        Raises SemgrepRunnerError on subprocess failure, timeout, or
        unparseable output. Returns the SARIF dict on success — including
        when zero findings are present.
        """
        if isinstance(target_path, (str, Path)):
            targets = [Path(target_path)]
        else:
            targets = [Path(p) for p in target_path]
        if not targets:
            raise SemgrepRunnerError("No target paths provided")
        for t in targets:
            if not t.exists():
                raise SemgrepRunnerError(f"Target path does not exist: {t}")

        cmd = [
            self._semgrep_executable(),
            "scan",
            "--config",
            str(self.rules_path),
            "--sarif",
            "--quiet",
            "--no-git-ignore",
            "--metrics",
            "off",
            *self.extra_flags,
            *[str(t) for t in targets],
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                # Force UTF-8 decode of semgrep stdout/stderr — Windows defaults
                # to cp1252 and chokes on the non-ASCII characters semgrep emits
                # (rule names, snippets, glyphs). Reported from VDI testing.
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SemgrepRunnerError(
                f"semgrep timed out after {self.timeout}s scanning {target}"
            ) from exc
        except FileNotFoundError as exc:
            raise SemgrepRunnerError(f"semgrep failed to launch: {exc}") from exc

        # semgrep exit codes: 0 = clean, 1 = findings present (depends on flags),
        # >=2 = tool error. Both 0 and 1 are valid scan outcomes.
        if result.returncode >= 2:
            raise SemgrepRunnerError(
                f"semgrep failed (exit {result.returncode}). "
                f"stderr: {result.stderr.strip() or '<empty>'}"
            )

        if not result.stdout.strip():
            raise SemgrepRunnerError(
                f"semgrep produced no output (exit {result.returncode}). "
                f"stderr: {result.stderr.strip() or '<empty>'}"
            )

        try:
            sarif: dict[str, Any] = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SemgrepRunnerError(
                f"semgrep output was not valid JSON: {exc}. "
                f"First 200 chars: {result.stdout[:200]!r}"
            ) from exc

        return sarif

    @staticmethod
    def count_raw_findings(sarif: dict[str, Any]) -> int:
        """Convenience: total result count across all SARIF runs.

        Pre-normalization view. Track A3 will partition findings by tier
        and attach framework mappings; this is just a sanity counter for
        the CLI smoke output.
        """
        runs = sarif.get("runs") or []
        return sum(len(run.get("results") or []) for run in runs)

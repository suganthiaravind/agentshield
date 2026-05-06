"""Tier 1 semgrep subprocess runner.

Invokes the bundled rule pack against a target path and returns raw
SARIF v2.1.0 as a dict. Output is consumed downstream by the normalizer
which produces typed Finding objects.

This module deliberately keeps no domain knowledge of finding shape —
it just orchestrates the subprocess and returns the JSON payload.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_STAGE_EXTENSIONS = {".py", ".java"}
_STAGE_SKIP_DIRS = {"__pycache__", ".venv", ".git", "node_modules"}


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

    def run(
        self,
        target_path: Path | str | list[Path | str],
        stage_locally: bool = False,
    ) -> dict[str, Any]:
        """Scan `target_path` and return parsed SARIF v2.1.0.

        `target_path` may be a single path (str or Path) or a list. When a
        list is given, each path is passed explicitly to semgrep — useful
        for tests that need to bypass semgrep's default ignore patterns
        (which exclude `tests/`, `fixtures/`, etc. on directory traversal).

        When `stage_locally=True`, every .py/.java file under the targets is
        first copied into a temporary directory (mirroring the relative
        layout so cross-file taint analysis still works), semgrep scans the
        temp tree, and `artifactLocation.uri` entries in the resulting SARIF
        are rewritten back to the original source paths before returning.
        This is a workaround for semgrep's silent failure to read files via
        Windows UNC / mapped network drives (e.g. H:\\fusion -> \\\\server\\share).

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

        stage_root: Path | None = None
        path_map: dict[str, str] = {}  # staged absolute path -> original absolute path
        if stage_locally:
            stage_root, scan_targets, path_map = self._stage_targets(targets)
        else:
            scan_targets = targets

        try:
            sarif = self._invoke_semgrep(scan_targets)
        finally:
            if stage_root is not None:
                shutil.rmtree(stage_root, ignore_errors=True)

        if path_map:
            self._rewrite_sarif_uris(sarif, path_map)

        return sarif

    def _invoke_semgrep(self, targets: list[Path]) -> dict[str, Any]:
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
                f"semgrep timed out after {self.timeout}s"
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
    def _stage_targets(
        targets: list[Path],
    ) -> tuple[Path, list[Path], dict[str, str]]:
        """Copy every .py/.java file under `targets` into a temp tree.

        Returns (stage_root, [stage_root], path_map). path_map keys are the
        staged absolute file paths (used to match SARIF `artifactLocation.uri`)
        and values are the original absolute source paths.

        Each top-level target is mirrored under stage_root/<index>/ so that
        relative module layout is preserved (cross-file taint depends on it)
        and multiple targets can't collide on the same relative subpath.
        """
        stage_root = Path(tempfile.mkdtemp(prefix="agentshield-stage-"))
        path_map: dict[str, str] = {}

        for idx, t in enumerate(targets):
            t_abs = t.resolve()
            slot = stage_root / str(idx)
            slot.mkdir(parents=True, exist_ok=True)

            if t_abs.is_file():
                if t_abs.suffix not in _STAGE_EXTENSIONS:
                    continue
                dst = slot / t_abs.name
                shutil.copy2(t_abs, dst)
                path_map[str(dst.resolve())] = str(t_abs)
                continue

            for src in t_abs.rglob("*"):
                if not src.is_file() or src.suffix not in _STAGE_EXTENSIONS:
                    continue
                if any(part in _STAGE_SKIP_DIRS for part in src.parts):
                    continue
                rel = src.relative_to(t_abs)
                dst = slot / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                path_map[str(dst.resolve())] = str(src)

        if not path_map:
            shutil.rmtree(stage_root, ignore_errors=True)
            raise SemgrepRunnerError(
                "stage_locally: no .py/.java files found under target(s); "
                "nothing to scan"
            )

        return stage_root, [stage_root], path_map

    @staticmethod
    def _rewrite_sarif_uris(sarif: dict[str, Any], path_map: dict[str, str]) -> None:
        """Rewrite SARIF artifactLocation.uri entries staged -> original.

        Mutates `sarif` in place. Both keys and SARIF URIs are normalised via
        Path.resolve() so the lookup is robust to '/' vs '\\' and absolute
        vs relative forms produced by semgrep on different platforms.
        """
        normalized = {str(Path(k).resolve()): v for k, v in path_map.items()}

        for run in sarif.get("runs", []) or []:
            for r in run.get("results", []) or []:
                for loc in r.get("locations", []) or []:
                    art = (loc.get("physicalLocation") or {}).get("artifactLocation")
                    if not art:
                        continue
                    uri = art.get("uri")
                    if not uri:
                        continue
                    try:
                        key = str(Path(uri).resolve())
                    except OSError:
                        key = uri
                    if key in normalized:
                        art["uri"] = normalized[key]
            for art in run.get("artifacts", []) or []:
                loc = art.get("location") or {}
                uri = loc.get("uri")
                if not uri:
                    continue
                try:
                    key = str(Path(uri).resolve())
                except OSError:
                    key = uri
                if key in normalized:
                    loc["uri"] = normalized[key]

    @staticmethod
    def count_raw_findings(sarif: dict[str, Any]) -> int:
        """Convenience: total result count across all SARIF runs.

        Pre-normalization view. The Normalizer attaches framework mappings
        and produces typed Finding objects; this is just a sanity counter
        for the CLI smoke output.
        """
        runs = sarif.get("runs") or []
        return sum(len(run.get("results") or []) for run in runs)

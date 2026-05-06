"""AgentShield CLI entry point — v2 architecture (2 tiers).

Tier 1 — semgrep with the pruned high-precision rule pack (Phase F.2).
Tier 2 — LLM-as-scanner via Copilot using the bundled skill files
(Phase F.3 / F.4). Mandatory; the user runs Copilot Chat in their IDE
after `agentshield scan` finishes.

Subcommands:
- `agentshield scan <path>`  — runs Tier 1, emits skill files into the
  target's `.agentshield/`, prints the Copilot prompt to paste.
- `agentshield merge <path>` — combines tier1-results.json +
  tier2-findings.json (the latter written by Copilot) into a unified
  Markdown / JSON / SARIF report.

Phase F.6 deleted: `agentshield/judge/` (boto3-Bedrock + mock + Copilot
stub backends + the triage orchestrator) — that was the v1 "Tier 3
triage" model which v2 replaces with whole-repo Tier 2 scanning.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from pathlib import Path
from typing import Sequence

from agentshield import __version__
from agentshield.emitter import EmitResult, copilot_prompt, emit_skills
from agentshield.merger import (
    MergeError,
    MergeResult,
    merge,
    render_combined_json,
    render_combined_markdown,
    render_combined_html,
    render_combined_sarif,
)
from agentshield.normalize import Finding, Normalizer, NormalizerError
from agentshield.report import JsonWriter, MarkdownWriter, SarifWriter
from agentshield.runner import SemgrepRunner, SemgrepRunnerError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description=(
            "Pre-production security evaluator for AI agents (static "
            "analysis + LLM-as-scanner via Copilot)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"agentshield {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------- scan ----------
    scan = subparsers.add_parser(
        "scan",
        help="Run Tier 1 (semgrep) and emit Tier 2 skill files into the target",
    )
    scan.add_argument("path", help="Path to target repository")
    scan.add_argument(
        "--output-sarif",
        help=(
            "Write a Tier-1-only SARIF report to this path. For the unified "
            "Tier 1 + Tier 2 report, run `agentshield merge` after Copilot."
        ),
    )
    scan.add_argument(
        "--output-json",
        help="Write a Tier-1-only JSON report to this path.",
    )
    scan.add_argument(
        "--output-markdown",
        help="Write a Tier-1-only Markdown report to this path.",
    )
    scan.add_argument(
        "--scan-all-files",
        action="store_true",
        help=(
            "Enumerate Python/Java files explicitly and pass them to semgrep, "
            "bypassing semgrep's default directory ignores (tests/, examples/, "
            "vendor/, fixtures/, etc.). Use when scanning a sample/demo repo "
            "where the target code lives under such a directory."
        ),
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Exclude files matching this glob pattern (repeatable). Most "
            "useful with --scan-all-files. Patterns: '**/src/test/**' "
            "(Maven/Gradle), '**/tests/**' (Python)."
        ),
    )
    scan.add_argument(
        "--stage-locally",
        action="store_true",
        help=(
            "Copy every .py/.java file under the target into a local temp "
            "directory before scanning, then rewrite SARIF paths back to the "
            "originals. Workaround for semgrep silently returning 'Scanning 0 "
            "files' on Windows UNC / mapped network drives (e.g. H:\\fusion\\...)."
        ),
    )
    scan.add_argument(
        "--no-emit",
        action="store_true",
        help=(
            "Skip writing Tier 2 skill files into the target. Tier-1-only "
            "mode for diagnostics. The final report banner will warn that "
            "scanning is incomplete."
        ),
    )
    scan.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Verbose diagnostic output: print the rules path, the list of "
            "files passed to semgrep (with --scan-all-files), and the raw "
            "rule_ids of every finding."
        ),
    )

    # ---------- merge ----------
    mrg = subparsers.add_parser(
        "merge",
        help="Combine Tier 1 + Tier 2 results into a unified report",
    )
    mrg.add_argument("path", help="Path to target repository (containing .agentshield/)")
    mrg.add_argument("--output-sarif", help="Write unified SARIF v2.1.0 report")
    mrg.add_argument("--output-json", help="Write unified JSON report")
    mrg.add_argument("--output-markdown", help="Write unified Markdown report")
    mrg.add_argument(
        "--output-html",
        help=(
            "Write unified HTML report (single file, embedded CSS, no external "
            "deps; renders cleanly offline). D/D/R-led dashboard layout."
        ),
    )
    mrg.add_argument(
        "--print",
        dest="print_md",
        action="store_true",
        help="Print the unified Markdown report to stdout (in addition to any --output-* files)",
    )
    mrg.add_argument(
        "--open",
        dest="open_html",
        action="store_true",
        help=(
            "Auto-launch the HTML report in the default browser after merging. "
            "Requires --output-html to also be set. Convenience for the "
            "interactive dashboard workflow."
        ),
    )

    return parser


# ---------- scan helpers ----------

_SAMPLE_FILE_LIMIT = 5


def _looks_like_network_path(path: Path) -> bool:
    """Heuristic: True if the path is a UNC share or a Windows mapped network drive."""
    s = str(path)
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    if sys.platform == "win32" and len(s) >= 2 and s[1] == ":":
        try:
            import ctypes

            drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{s[0]}:\\")
            return drive_type == 4  # DRIVE_REMOTE
        except Exception:
            return False
    return False


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """gitignore-style `**` semantics; see test_cli_exclude.py for the contract."""
    leading = "\x00LEADING\x00"
    trailing = "\x00TRAILING\x00"
    star2 = "\x00STAR2\x00"
    star1 = "\x00STAR1\x00"
    p = pattern
    if p.startswith("**/"):
        p = leading + p[len("**/"):]
    if p.endswith("/**"):
        p = p[: -len("/**")] + trailing
    p = p.replace("**", star2)
    p = p.replace("*", star1)
    regex = fnmatch.translate(p)
    regex = regex.replace(re.escape(leading), "(?:.*/)?")
    regex = regex.replace(re.escape(trailing), "(?:/.*)?")
    regex = regex.replace(re.escape(star2), ".*")
    regex = regex.replace(re.escape(star1), "[^/]*")
    return re.compile(regex)


def _matches_any_pattern(path: Path, root: Path, patterns: list[str]) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_posix = rel.as_posix()
    base = path.name
    for pat in patterns:
        rx = _glob_to_regex(pat)
        if rx.match(rel_posix) or rx.match(base):
            return True
    return False


def _enumerate_candidate_files(path: Path, exclude: list[str] | None = None) -> list[Path]:
    """Walk the target tree and return scannable .py / .java files."""
    exclude = exclude or []
    if path.is_file():
        if path.suffix not in {".py", ".java"}:
            return []
        if exclude and _matches_any_pattern(path, path.parent, exclude):
            return []
        return [path]
    files = (
        p
        for p in path.rglob("*")
        if p.is_file()
        and p.suffix in {".py", ".java"}
        and "__pycache__" not in p.parts
        and ".venv" not in p.parts
        and ".git" not in p.parts
        and "node_modules" not in p.parts
    )
    if exclude:
        files = (p for p in files if not _matches_any_pattern(p, path, exclude))
    return sorted(files)


def _print_file_summary(files: list[Path], debug: bool) -> None:
    n = len(files)
    if n == 0:
        print("[agentshield] candidate files: 0 (.py / .java)")
        print("[agentshield] WARNING: no scannable files found — verify the target path")
        return
    print(f"[agentshield] candidate files: {n} (.py / .java)")
    show = files if debug or n <= _SAMPLE_FILE_LIMIT else files[:_SAMPLE_FILE_LIMIT]
    for p in show:
        print(f"  - {p}")
    if not debug and n > _SAMPLE_FILE_LIMIT:
        print(f"  ... ({n - _SAMPLE_FILE_LIMIT} more; pass --debug to see all)")


def _finding_to_emitter_dict(f: Finding) -> dict:
    """Convert a normalized Finding to the flat dict shape the emitter passes
    through to tier1-results.json. Copilot reads this file and uses it for:
    (a) the cross-check section (FP callouts by index), (b) coverage matrix
    aggregation. Keep field names stable — both the merger and the Tier 2
    checklist's §7 cross-check section reference them.
    """
    return {
        "rule_id": f.rule_id,
        "rule_id_short": f.rule_id_short,
        "agentshield_id": f.agentshield_id,
        "category": f.category,
        "severity": f.severity,
        "file": f.location.file_path,
        "line": f.location.start_line,
        "message": f.message,
        "language": f.language,
        "framework_mappings": {
            "owasp_llm": list(f.framework_mappings.owasp_llm),
            "owasp_agentic": list(f.framework_mappings.owasp_agentic),
            "mitre_atlas": list(f.framework_mappings.mitre_atlas),
            "cwe": list(f.framework_mappings.cwe),
            "nist_ai_rmf": list(f.framework_mappings.nist_ai_rmf),
        },
    }


def _print_tier2_banner(target_root: Path, emit: EmitResult) -> None:
    """The mandatory next-step prompt the user pastes into Copilot Chat."""
    bar = "=" * 70
    print()
    print(bar)
    print("⚠ TIER 2 NOT YET RUN — scanning is INCOMPLETE.")
    print(bar)
    print()
    print("Skill files written:")
    for p in emit.emitted_files:
        print(f"  - {p.relative_to(target_root)}")
    if emit.gitignore_updated:
        print(f"  + appended .agentshield/ to {target_root}/.gitignore")
    print()
    print("Next step — paste this into Copilot Chat in your IDE:")
    print()
    print("-" * 70)
    print(copilot_prompt())
    print("-" * 70)
    print()
    print(f"Then run:  agentshield merge {target_root}")
    print()


# ---------- scan command ----------

def cmd_scan(args: argparse.Namespace) -> int:
    """Tier 1 (semgrep) + emit Tier 2 skill files into the target."""
    print(f"[agentshield] scan target: {args.path}")

    exclude_patterns = list(args.exclude or [])
    candidate_files = _enumerate_candidate_files(Path(args.path), exclude=exclude_patterns)
    if exclude_patterns:
        print(f"[agentshield] --exclude patterns applied: {exclude_patterns}")
    _print_file_summary(candidate_files, args.debug)
    if not args.scan_all_files and candidate_files and Path(args.path).is_dir():
        print(
            "[agentshield] note: without --scan-all-files, semgrep applies "
            "its built-in .semgrepignore (skips tests/, examples/, vendor/, "
            "etc.). Pass --scan-all-files to scan every candidate file above."
        )

    target: Path | str | list[Path]
    if args.scan_all_files:
        target = candidate_files
        print(f"[agentshield] --scan-all-files: passing all {len(target)} file(s) to semgrep")
    else:
        target = args.path

    if args.debug:
        runner = SemgrepRunner()
        print(f"[agentshield] --debug: rules path = {runner.rules_path}")
        print(f"[agentshield] --debug: semgrep binary = {runner._semgrep_executable()}")
    if args.stage_locally:
        print(
            "[agentshield] --stage-locally: copying source files to a local temp "
            "tree before scan (UNC / network-drive workaround)"
        )
    print("[agentshield] Tier 1: invoking semgrep on bundled rule pack (6 families)...")
    try:
        runner = SemgrepRunner()
        sarif = runner.run(target, stage_locally=args.stage_locally)
    except SemgrepRunnerError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        if args.stage_locally:
            print(
                "[agentshield] HINT: --stage-locally failed. Copy the repo "
                "to a local path with `robocopy <src> <dst> /E` and rerun "
                "agentshield against the local copy.",
                file=sys.stderr,
            )
        return 2

    raw_count = SemgrepRunner.count_raw_findings(sarif)
    print(f"[agentshield] Tier 1: {raw_count} raw finding(s)")
    if raw_count == 0 and not args.stage_locally and _looks_like_network_path(Path(args.path)):
        print(
            "[agentshield] HINT: target looks like a UNC / mapped network "
            "drive and the scan returned 0 findings. Semgrep can fail "
            "silently on such paths — retry with `--stage-locally`, or "
            "copy the repo to a local path (e.g. `robocopy <src> <dst> /E`) "
            "and scan that copy."
        )
    if args.debug:
        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                rid = (r.get("ruleId") or "").rsplit(".", 1)[-1]
                loc = r.get("locations", [{}])[0].get("physicalLocation", {})
                uri = loc.get("artifactLocation", {}).get("uri", "?")
                line = loc.get("region", {}).get("startLine", "?")
                print(f"[agentshield] --debug:   {rid:50s} {uri}:{line}")

    try:
        normalizer = Normalizer()
        findings = normalizer.normalize(sarif)
    except NormalizerError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2
    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    print(
        f"[agentshield] Normalized: {len(findings)} finding(s) "
        f"detect={by_category.get('detect', 0)} "
        f"defend={by_category.get('defend', 0)} "
        f"respond={by_category.get('respond', 0)}"
    )

    # Tier-1-only outputs (legacy compatibility — for the unified report use
    # `agentshield merge`).
    written: list[str] = []
    if args.output_sarif:
        SarifWriter().write(findings, Path(args.output_sarif))
        written.append(args.output_sarif)
    if args.output_json:
        JsonWriter().write(findings, Path(args.output_json))
        written.append(args.output_json)
    if args.output_markdown:
        MarkdownWriter().write(findings, Path(args.output_markdown))
        written.append(args.output_markdown)
    if written:
        print(f"[agentshield] Wrote Tier-1-only report(s): {', '.join(written)}")

    # Emit Tier 2 skill files unless explicitly opted out.
    if args.no_emit:
        print(
            "\n[agentshield] --no-emit: skipping Tier 2 skill-file emission. "
            "Scanning is INCOMPLETE — no Tier 2 will be runnable."
        )
        return 0

    target_root = Path(args.path).resolve()
    if not target_root.is_dir():
        # Single-file scan; emit into the file's parent.
        target_root = target_root.parent

    findings_dicts = [_finding_to_emitter_dict(f) for f in findings]
    scanned_files_rel = [
        str(p.resolve().relative_to(target_root))
        if p.resolve().is_relative_to(target_root)
        else str(p)
        for p in candidate_files
    ]
    try:
        emit = emit_skills(target_root, findings_dicts, scanned_files_rel)
    except FileNotFoundError as exc:
        print(f"[agentshield] ERROR emitting Tier 2 skill files: {exc}", file=sys.stderr)
        return 2

    _print_tier2_banner(target_root, emit)
    return 0


# ---------- merge command ----------

def cmd_merge(args: argparse.Namespace) -> int:
    """Combine .agentshield/tier1-results.json + .agentshield/tier2-findings.json
    into a unified report.
    """
    target_root = Path(args.path)
    print(f"[agentshield] merge target: {target_root}")

    try:
        result = merge(target_root)
    except MergeError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2

    _print_merge_summary(result)

    # Force UTF-8 — the merger renders ⚠ / ✓ / ❌ / 🟡 banners that don't
    # encode in Windows' default cp1252 (Phase F.10 fix from VDI run).
    written: list[str] = []
    if args.output_markdown:
        Path(args.output_markdown).write_text(
            render_combined_markdown(result), encoding="utf-8"
        )
        written.append(args.output_markdown)
    if args.output_json:
        Path(args.output_json).write_text(
            render_combined_json(result), encoding="utf-8"
        )
        written.append(args.output_json)
    if args.output_sarif:
        Path(args.output_sarif).write_text(
            render_combined_sarif(result), encoding="utf-8"
        )
        written.append(args.output_sarif)
    if args.output_html:
        Path(args.output_html).write_text(
            render_combined_html(result), encoding="utf-8"
        )
        written.append(args.output_html)
    if written:
        print(f"[agentshield] Wrote unified report(s): {', '.join(written)}")

    if args.print_md:
        print()
        print(render_combined_markdown(result))

    # F.21: --open auto-launches the HTML report in the default browser.
    # Requires --output-html so we have a file:// URL to open. Uses the
    # stdlib `webbrowser` module — no new dep, works cross-platform.
    if getattr(args, "open_html", False):
        if not args.output_html:
            print(
                "[agentshield] --open requires --output-html (no HTML report "
                "to open). Pass --output-html <path>.",
                file=sys.stderr,
            )
        else:
            import webbrowser
            uri = Path(args.output_html).resolve().as_uri()
            print(f"[agentshield] Opening {uri} in your default browser...")
            try:
                webbrowser.open(uri)
            except Exception as exc:  # pragma: no cover (env-specific)
                print(
                    f"[agentshield] Could not auto-launch browser: {exc}. "
                    f"Open the file manually: {uri}",
                    file=sys.stderr,
                )

    if not written and not args.print_md:
        print(
            "\n[agentshield] (no --output-{markdown,json,sarif,html} specified "
            "and --print not set; pass one to persist or display the unified report)"
        )

    # Soft failures (stale, schema errors, tier 2 missing) don't change exit
    # code — the report banner surfaces them. Hard failures already returned 2.
    return 0


def _print_merge_summary(result: MergeResult) -> None:
    if not result.tier2_present:
        print(
            "[agentshield] ⚠ Tier 2 has NOT been run — report will be "
            "Tier-1-only with an INCOMPLETE banner. Run Copilot Tier 2 "
            "(see .agentshield/tier2-bootstrap.md) and re-merge."
        )
    elif result.schema_errors:
        print(
            f"[agentshield] ❌ Tier 2 output failed schema validation "
            f"({len(result.schema_errors)} error(s)). Tier 2 findings will "
            f"NOT be merged. Re-prompt Copilot to fix:"
        )
        for e in result.schema_errors[:10]:
            print(f"  - {e}")
        if len(result.schema_errors) > 10:
            print(f"  ... ({len(result.schema_errors) - 10} more)")
    elif result.stale:
        print(
            "[agentshield] ⚠ STALE Tier 2: fingerprint mismatch. The Tier 1 "
            "rule pack or source code changed since Tier 2 was run. Re-run "
            "Copilot Tier 2 for fresh results; merging anyway with a STALE "
            "banner in the report."
        )
    else:
        print("[agentshield] ✓ Tier 1 + Tier 2 fresh; merging.")
    print(
        f"[agentshield] Net actionable findings: "
        f"{result.actionable_finding_count}"
    )


# ---------- entry ----------

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "merge":
        return cmd_merge(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

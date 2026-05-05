"""AgentShield CLI entry point.

A1 scaffolding → A2 semgrep runner → A3 normalizer → A4 report writers.
End-to-end pipeline working except Tier 3 (judge, Track B) and
Tier 4 (discovery, Track D), which the CLI flags wire up but the
implementations stub.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from agentshield import __version__
from agentshield.judge import Boto3BedrockBackend, JudgeOrchestrator, MockJudgeBackend
from agentshield.normalize import Normalizer, NormalizerError
from agentshield.report import JsonWriter, MarkdownWriter, SarifWriter
from agentshield.runner import SemgrepRunner, SemgrepRunnerError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description="Pre-production security evaluator for AI agents (static analysis).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"agentshield {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Scan a target repository for agent security issues",
    )
    scan.add_argument("path", help="Path to target repository")
    scan.add_argument(
        "--config",
        help="Path to agentshield.yaml config file (default: ./agentshield.yaml if present)",
    )
    scan.add_argument(
        "--llm-backend",
        choices=["boto3-bedrock", "smartsdk", "copilot", "mock", "none"],
        default=None,
        help=(
            "LLM backend for the judge tier (default: from config or "
            "boto3-bedrock). `mock` uses a deterministic placeholder backend "
            "that returns a fixed `needs_review` verdict — useful for "
            "smoke-testing the orchestrator pipeline without AWS Bedrock "
            "access. See VDI_TESTING.md Stage 4.5."
        ),
    )
    scan.add_argument("--output-sarif", help="Write SARIF v2.1.0 report to this path")
    scan.add_argument("--output-json", help="Write JSON report to this path")
    scan.add_argument("--output-markdown", help="Write Markdown report to this path")
    scan.add_argument(
        "--no-judge",
        action="store_true",
        help="Skip Tier 3 LLM judge (offline mode; Tiers 1+2 only)",
    )
    scan.add_argument(
        "--bedrock-model-id",
        help=(
            "Bedrock model id or inference-profile ARN, used with "
            "--llm-backend boto3-bedrock. Required to run the judge tier "
            "with that backend."
        ),
    )
    scan.add_argument(
        "--bedrock-region",
        default="us-east-1",
        help="AWS region for the boto3-bedrock judge backend (default: us-east-1)",
    )
    scan.add_argument(
        "--discovery",
        action="store_true",
        help="Enable Tier 4 discovery pass on files with LLM imports + zero findings",
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
        "--debug",
        action="store_true",
        help=(
            "Verbose diagnostic output: print the rules path, the list of files "
            "passed to semgrep (with --scan-all-files), and the raw rule_ids of "
            "every finding. Use to diagnose 'why did this scan return 0 findings'."
        ),
    )

    return parser


_SAMPLE_FILE_LIMIT = 5


def _looks_like_network_path(path: Path) -> bool:
    """Heuristic: True if the path is a UNC share or a Windows mapped network drive.

    Used only to decide whether to surface a `--stage-locally` hint after a
    zero-finding scan. Conservative — misses are fine (no hint), false positives
    are mostly fine too (extra hint costs nothing).
    """
    s = str(path)
    if s.startswith("\\\\") or s.startswith("//"):
        return True
    if sys.platform == "win32" and len(s) >= 2 and s[1] == ":":
        try:
            import ctypes

            drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{s[0]}:\\")
            # 4 = DRIVE_REMOTE
            return drive_type == 4
        except Exception:
            return False
    return False


def _enumerate_candidate_files(path: Path) -> list[Path]:
    """Walk the target tree and return scannable .py / .java files.

    Skips common noise directories (__pycache__, .venv, .git, node_modules).
    Returns the path itself wrapped in a list when given a single file.
    """
    if path.is_file():
        return [path] if path.suffix in {".py", ".java"} else []
    return sorted(
        p
        for p in path.rglob("*")
        if p.is_file()
        and p.suffix in {".py", ".java"}
        and "__pycache__" not in p.parts
        and ".venv" not in p.parts
        and ".git" not in p.parts
        and "node_modules" not in p.parts
    )


def _print_file_summary(files: list[Path], debug: bool) -> None:
    """Print scanned-files summary: count + first N names (all if --debug)."""
    n = len(files)
    if n == 0:
        print("[agentshield] candidate files: 0 (.py / .java)")
        print(f"[agentshield] WARNING: no scannable files found — verify the target path")
        return
    print(f"[agentshield] candidate files: {n} (.py / .java)")
    show = files if debug or n <= _SAMPLE_FILE_LIMIT else files[:_SAMPLE_FILE_LIMIT]
    for p in show:
        print(f"  - {p}")
    if not debug and n > _SAMPLE_FILE_LIMIT:
        print(f"  ... ({n - _SAMPLE_FILE_LIMIT} more; pass --debug to see all)")


def cmd_scan(args: argparse.Namespace) -> int:
    """Run Tier 1+2 semgrep scan; remaining tiers stubbed pending A3/A4/B/D."""
    print(f"[agentshield] scan target: {args.path}")

    # Always enumerate candidate files for visibility — even when not using
    # --scan-all-files. Lets users immediately see "did we find any source
    # files at all?" which is the first thing to check on a 0-findings scan.
    candidate_files = _enumerate_candidate_files(Path(args.path))
    _print_file_summary(candidate_files, args.debug)
    if not args.scan_all_files and candidate_files and Path(args.path).is_dir():
        # When semgrep walks a directory, it further filters via its built-in
        # .semgrepignore (skips tests/, examples/, vendor/, etc.). Single-file
        # invocations bypass that filter entirely, so the note only applies
        # to directory scans.
        print(
            "[agentshield] note: without --scan-all-files, semgrep applies "
            "its built-in .semgrepignore (skips tests/, examples/, vendor/, "
            "etc.). Pass --scan-all-files to scan every candidate file above."
        )

    # Tier 1+2 — wired in A2; produces raw SARIF.
    target: Path | str | list[Path]
    if args.scan_all_files:
        # Pass the explicit file list to semgrep, bypassing its default
        # directory ignore.
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
    print("[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...")
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
    print(f"[agentshield] Tier 1+2: {raw_count} raw finding(s)")
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

    # A3: normalize SARIF to typed Findings partitioned by tier.
    try:
        normalizer = Normalizer()
        findings = normalizer.normalize(sarif)
    except NormalizerError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2
    by_tier = Normalizer.partition_by_tier(findings)
    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
    print(
        f"[agentshield] Normalized: {len(findings)} finding(s) "
        f"(framework={len(by_tier['framework'])}, fallback={len(by_tier['fallback'])}) "
        f"detect={by_category.get('detect', 0)} "
        f"defend={by_category.get('defend', 0)} "
        f"respond={by_category.get('respond', 0)}"
    )

    # Tier 3 — LLM judge over fallback findings (Track B4 orchestrator).
    fallback_count = JudgeOrchestrator.count_fallback(findings)
    if args.no_judge:
        print(f"[agentshield] Tier 3 judge: skipped (--no-judge); {fallback_count} fallback finding(s) untriaged")
    elif fallback_count == 0:
        print("[agentshield] Tier 3 judge: no fallback findings to triage (skipped)")
    else:
        backend_choice = args.llm_backend or "boto3-bedrock"
        if backend_choice == "boto3-bedrock":
            if not args.bedrock_model_id:
                print(
                    "[agentshield] Tier 3 judge: skipped — boto3-bedrock backend requires "
                    "--bedrock-model-id (or set bedrock_model_id in agentshield.yaml)"
                )
            else:
                backend = Boto3BedrockBackend(
                    model_id=args.bedrock_model_id,
                    region_name=args.bedrock_region,
                )
                orchestrator = JudgeOrchestrator(backend)
                print(
                    f"[agentshield] Tier 3 judge: triaging {fallback_count} fallback "
                    f"finding(s) via {backend.name} (model={backend.model_id})..."
                )
                findings = orchestrator.triage(findings)
                verdicts = [f.triage.verdict for f in findings if f.triage]
                summary = {
                    "confirmed": verdicts.count("confirmed"),
                    "dismissed": verdicts.count("dismissed"),
                    "needs_review": verdicts.count("needs_review"),
                }
                print(
                    f"[agentshield] Tier 3 judge: {summary['confirmed']} confirmed, "
                    f"{summary['dismissed']} dismissed, {summary['needs_review']} needs_review"
                )
        elif backend_choice in {"smartsdk", "copilot"}:
            print(
                f"[agentshield] Tier 3 judge: backend={backend_choice} not yet implemented "
                f"(Track B2/B3) — skipped; {fallback_count} fallback finding(s) untriaged"
            )
        elif backend_choice == "mock":
            backend = MockJudgeBackend()
            orchestrator = JudgeOrchestrator(backend)
            print(
                f"[agentshield] Tier 3 judge: triaging {fallback_count} fallback "
                f"finding(s) via mock backend (no LLM is called — verdicts are "
                f"placeholders for VDI / smoke-test use)"
            )
            findings = orchestrator.triage(findings)
            print(
                f"[agentshield] Tier 3 judge: {fallback_count} mock verdict(s) "
                f"attached as `needs_review`. Re-run with --llm-backend "
                f"boto3-bedrock for real triage."
            )
        elif backend_choice == "none":
            print(f"[agentshield] Tier 3 judge: backend=none — skipped")

    if args.discovery:
        print("[agentshield] TODO Tier 4 (discovery pass, enabled)              — Track D")

    # A4: emit reports if requested.
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
        print(f"[agentshield] Wrote: {', '.join(written)}")
    else:
        print(
            "[agentshield] (no --output-{sarif,json,markdown} specified; "
            "use one to persist findings)"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

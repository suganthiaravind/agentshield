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
from agentshield.judge import Boto3BedrockBackend, JudgeOrchestrator
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
        choices=["boto3-bedrock", "smartsdk", "copilot", "none"],
        default=None,
        help="LLM backend for the judge tier (default: from config or boto3-bedrock)",
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

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Run Tier 1+2 semgrep scan; remaining tiers stubbed pending A3/A4/B/D."""
    print(f"[agentshield] scan target: {args.path}")

    # Tier 1+2 — wired in A2; produces raw SARIF.
    target: Path | str | list[Path]
    if args.scan_all_files:
        # Enumerate explicit file list to bypass semgrep's default directory
        # ignore (which excludes tests/, examples/, vendor/, fixtures/, etc.).
        root = Path(args.path)
        if root.is_file():
            target = [root]
        else:
            target = sorted(
                p
                for p in root.rglob("*")
                if p.is_file()
                and p.suffix in {".py", ".java"}
                and "__pycache__" not in p.parts
                and ".venv" not in p.parts
                and ".git" not in p.parts
                and "node_modules" not in p.parts
            )
        print(f"[agentshield] --scan-all-files: enumerated {len(target)} file(s)")
    else:
        target = args.path

    print("[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...")
    try:
        runner = SemgrepRunner()
        sarif = runner.run(target)
    except SemgrepRunnerError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2

    raw_count = SemgrepRunner.count_raw_findings(sarif)
    print(f"[agentshield] Tier 1+2: {raw_count} raw finding(s)")

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

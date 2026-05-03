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
        "--discovery",
        action="store_true",
        help="Enable Tier 4 discovery pass on files with LLM imports + zero findings",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Run Tier 1+2 semgrep scan; remaining tiers stubbed pending A3/A4/B/D."""
    print(f"[agentshield] scan target: {args.path}")

    # Tier 1+2 — wired in A2; produces raw SARIF.
    print("[agentshield] Tier 1+2: invoking semgrep on bundled rule pack...")
    try:
        runner = SemgrepRunner()
        sarif = runner.run(args.path)
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

    judge_state = "disabled" if args.no_judge else f"backend={args.llm_backend or 'default'}"
    print(f"[agentshield] TODO Tier 3 (LLM judge, {judge_state})              — Track B")
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

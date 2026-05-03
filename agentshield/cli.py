"""AgentShield CLI entry point.

A1 scaffolding: `--version` works; `scan <path>` prints the planned
pipeline as TODO markers. Subsequent tracks (A2 semgrep runner, A3
normalizer, A4 report writers, B judge, D discovery) replace the
TODOs with real behavior.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from agentshield import __version__


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
    """Stub: prints the planned pipeline. Replaced by A2-A4 / B / D."""
    print(f"[agentshield] scan target: {args.path}")
    print(f"[agentshield] TODO Tier 1 (semgrep framework rules)        — Track A2")
    print(f"[agentshield] TODO Tier 2 (semgrep fallback rules)         — Track A2")
    judge_state = "disabled" if args.no_judge else f"backend={args.llm_backend or 'default'}"
    print(f"[agentshield] TODO Tier 3 (LLM judge, {judge_state})        — Track B")
    if args.discovery:
        print(f"[agentshield] TODO Tier 4 (discovery pass, enabled)        — Track D")
    print(f"[agentshield] TODO Emit reports (SARIF/JSON/MD)            — Track A4")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

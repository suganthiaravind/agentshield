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
from agentshield.emitter import EmitResult, copilot_prompt, default_output_dir, emit_skills
from agentshield.merger import (
    MergeError,
    MergeResult,
    merge,
    render_combined_json,
    render_combined_markdown,
    render_combined_html,
    render_combined_sarif,
    render_findings_fix_md,
    render_emulator_payloads_md,
)
from agentshield.manifest_scanner import scan_manifests
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
            "bypassing semgrep's default directory ignores (examples/, "
            "vendor/, fixtures/, etc.). test/ and tests/ are always excluded "
            "regardless of this flag."
        ),
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "Exclude files matching this glob pattern (repeatable). "
            "test/ and tests/ directories are excluded by default. "
            "Use this to exclude additional paths, e.g. '**/fixtures/**', "
            "'**/examples/**'."
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
    mrg.add_argument(
        "--require-fresh",
        dest="require_fresh",
        action="store_true",
        help=(
            "Abort if any scan artifact (tier1-results.json, tier2-findings.json, "
            "agent-emulation.json) is older than 7 days or if tier1/tier2 "
            "fingerprints are mismatched. Use this in CI to enforce a full rescan."
        ),
    )

    # ---------- check ----------
    chk = subparsers.add_parser(
        "check",
        help=(
            "Run post-merge sanity checks against a target's scan artifacts. "
            "Validates schema, banner state, narrative coverage, output files, "
            "callout fields, and emulator payload counts. Exit 0 = all pass."
        ),
    )
    chk.add_argument("path", help="Path to target repository (containing .agentshield/)")

    # ---------- probe (Path B — runtime red-team) ----------
    prb = subparsers.add_parser(
        "probe",
        help=(
            "Run canned attack payloads against a configured target agent "
            "(Path B — runtime red-team). Reads findings, sends payloads, "
            "classifies responses, writes .agentshield/probe-results.json."
        ),
    )
    prb.add_argument("path", help="Path to target repository (containing .agentshield/)")
    prb.add_argument(
        "--target",
        required=True,
        help="Base URL of the agent to probe, e.g. http://localhost:8765",
    )
    prb.add_argument(
        "--endpoint",
        default="/api/agent",
        help="Endpoint path appended to --target (default: /api/agent)",
    )
    prb.add_argument(
        "--profile",
        choices=("safe", "destructive"),
        default="safe",
        help=(
            "safe (default) skips destructive payloads. destructive "
            "requires --confirm and may mutate target state."
        ),
    )
    prb.add_argument(
        "--confirm",
        action="store_true",
        help="Required with --profile destructive. Acknowledges the risk.",
    )
    prb.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10).",
    )
    prb.add_argument(
        "--max-probes",
        type=int,
        default=100,
        help="Maximum number of probes per run (default: 100).",
    )
    prb.add_argument(
        "--auth-env",
        default="AGENTSHIELD_PROBE_AUTH",
        help=(
            "Env var name to read the Authorization header from "
            "(default: AGENTSHIELD_PROBE_AUTH). Leave unset for "
            "unauthenticated probes against local mocks."
        ),
    )
    prb.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help=(
            "Extra request header (repeatable). Use for API keys, "
            "cookies, tenancy headers, etc. Example: --header "
            "X-API-Key=secret --header X-Tenant-ID=acme. Values "
            "containing '=' are split on the first '='."
        ),
    )
    prb.add_argument(
        "--harness",
        choices=("none", "mock"),
        default="none",
        help=(
            "Safe-mode interception harness. 'mock' (default off) routes "
            "destructive payloads through an in-process harness that "
            "synthesises responses — no HTTP traffic leaves the process "
            "for those. Use against staging / prod when you want to "
            "probe destructive surfaces without risking state."
        ),
    )
    prb.add_argument(
        "--classifier",
        choices=("heuristic", "llm"),
        default="heuristic",
        help=(
            "Verdict classifier. 'heuristic' (default) uses substring + "
            "JSON-path matching. 'llm' invokes a Copilot-shaped LLM "
            "judge (mock backend today; designed for boto3-Bedrock "
            "swap) that returns verdict + plain-text reasoning + "
            "confidence. The LLM verdict wins the headline; the "
            "heuristic verdict is still recorded for reference."
        ),
    )
    prb.add_argument(
        "--synthesize",
        action="store_true",
        help=(
            "Run the LLM-driven payload synthesizer. Copilot reads the "
            "target's SKILL.md + tool catalogue and produces target-"
            "tuned context values that fill {placeholders} in each "
            "payload template. Off by default — the bundled payload "
            "defaults work for the demo target. Mock backend today; "
            "same swap path as --classifier llm."
        ),
    )
    prb.add_argument(
        "--target-env",
        choices=("staging", "production", "mock", "auto"),
        default="auto",
        help=(
            "Deployment-stage declaration for safety gating. "
            "'auto' (default) inherits from target.yaml's `env` "
            "field, falling back to 'staging' if absent. Explicit "
            "values override target.yaml. When the resolved env is "
            "'production', destructive multi-turn campaigns "
            "(`drop_table`, exfil, cross-tenant reads, real "
            "cancellations) are blocked unless --confirm-destructive "
            "is also passed."
        ),
    )
    prb.add_argument(
        "--confirm-destructive",
        action="store_true",
        help=(
            "Required with --target-env=production AND "
            "--profile destructive to actually fire destructive "
            "multi-turn campaigns against a production agent. "
            "Acknowledges that real account state may mutate."
        ),
    )
    prb.add_argument(
        "--target-config",
        default=None,
        metavar="PATH",
        help=(
            "Path to a target.yaml describing how to talk to the "
            "agent — used by the pluggable TargetAdapter layer. When "
            "provided, the adapter loaded from this file overrides "
            "the legacy --target / --endpoint / --auth-env / --header "
            "flags. Defaults to .agentshield/target.yaml in the "
            "target repo if that file exists; otherwise the legacy "
            "flags synthesise an http-generic adapter (mock-agent "
            "shape) for one release cycle."
        ),
    )
    prb.add_argument(
        "--mode",
        choices=("verify", "explore", "campaign", "both", "all"),
        default="verify",
        help=(
            "Probe mode. 'verify' (default) tests vulnerabilities the "
            "static scan already found. 'explore' asks an LLM to "
            "brainstorm single-shot attacks tuned to this target and "
            "fires them against the agent. 'campaign' runs multi-turn "
            "red-team probes — goal-directed attacks across multiple "
            "turns (memory poisoning across sessions, authority "
            "escalation → destructive action, recon → tool-chain "
            "exfil) — the real test of whether the agent holds up "
            "against an attacker that probes, learns, and adapts. "
            "'both' runs verify then explore. 'all' runs verify + "
            "explore + campaign in one invocation. Discovered findings "
            "get written to .agentshield/probe-discovered.json; "
            "multi-turn probe findings to "
            ".agentshield/probe-campaigns.json."
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
        and "test" not in p.parts
        and "tests" not in p.parts
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
        "legacy_ids": list(f.legacy_ids),
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
            "ast": list(f.framework_mappings.ast),
        },
        "remediation": f.remediation,
    }


def _display_path(path: Path, *roots: Path) -> str:
    """Render `path` relative to the first matching `root`, else absolute.

    Lets the scan banner show short, copy-pasteable paths for both the
    Copilot-contract files (under <target>/.agentshield/) and the
    developer-facing fix-skill files (under <target>/output/).
    """
    resolved = path.resolve()
    for root in roots:
        try:
            return str(resolved.relative_to(root.resolve()))
        except ValueError:
            continue
    return str(resolved)


def _print_tier2_banner(target_root: Path, emit: EmitResult) -> None:
    """The mandatory next-step prompt the user pastes into Copilot Chat."""
    bar = "=" * 70
    print()
    print(bar)
    print("⚠ TIER 2 NOT YET RUN — scanning is INCOMPLETE.")
    print(bar)
    print()
    cwd = Path.cwd()
    fix_skill_set = {p.resolve() for p in emit.fix_skill_files}
    contract_files = [p for p in emit.emitted_files if p.resolve() not in fix_skill_set]
    print(f"Copilot contract files (in {target_root}/.agentshield/):")
    for p in contract_files:
        print(f"  - {_display_path(p, target_root)}")
    if emit.fix_skill_files:
        out_label = _display_path(emit.output_dir or default_output_dir(), cwd)
        print()
        print(f"Fix-skill files (in {out_label}/):")
        for p in emit.fix_skill_files:
            print(f"  - {_display_path(p, emit.output_dir or default_output_dir(), cwd)}")
    if emit.gitignore_updated:
        print()
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
    from datetime import datetime, timezone as _tz
    _scan_started_at = datetime.now(_tz.utc)
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

    # F.24: AST10 manifest scanner — runs alongside Semgrep when the target
    # is a directory tree. SKILL.md files under the target are parsed and
    # checked against 5 AST rules; findings flow into the same `findings`
    # list that the Semgrep stage produced, so downstream emit / merge /
    # report code sees one unified set.
    target_for_manifest = Path(args.path)
    if target_for_manifest.is_dir():
        manifest_findings = scan_manifests(target_for_manifest)
        if manifest_findings:
            print(
                f"[agentshield] AST10 manifest scan: "
                f"{len(manifest_findings)} finding(s) across "
                f"{len({f.location.file_path for f in manifest_findings})} "
                f"SKILL.md file(s)"
            )
            findings.extend(manifest_findings)
        elif args.debug:
            print("[agentshield] --debug: AST10 manifest scan: no SKILL.md findings")

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
        emit = emit_skills(
            target_root,
            findings_dicts,
            scanned_files_rel,
            output_dir=target_root / "output",
            scan_started_at=_scan_started_at,
        )
    except FileNotFoundError as exc:
        print(f"[agentshield] ERROR emitting Tier 2 skill files: {exc}", file=sys.stderr)
        return 2

    # Emit the agent behaviour-emulator skill alongside Tier 2.
    # This is the scan-side answer to "what if there's no live
    # agent to probe?" — Copilot walks the agent's runtime
    # pipeline (user prompt → RAG → planner → tool choice → tool
    # output → re-planning → final answer) from source code and
    # predicts per-step behaviour under catalogued attack classes,
    # citing file:line evidence. Honestly labelled in the report
    # as a behaviour emulator, NOT as red-teaming.
    from agentshield.emitter.skill_emitter import (
        agent_emulator_prompt,
        emit_agent_emulator_skill,
    )
    try:
        emu_emitted = emit_agent_emulator_skill(target_root)
    except FileNotFoundError as exc:
        print(
            f"[agentshield] ERROR emitting agent behaviour-emulator "
            f"skill files: {exc}", file=sys.stderr,
        )
        return 2

    _print_tier2_banner(target_root, emit)
    print()
    print("[agentshield] Agent behaviour-emulator contract written:")
    for p in emu_emitted:
        print(f"[agentshield]   - {p}")
    print()
    print(
        "[agentshield] Optional: emulate this agent's behaviour "
        "against the catalogued attack classes (Copilot walks the "
        "pipeline from your code, predicts per-step behaviour, "
        "cites file:line). Paste this into Copilot Chat after "
        "Tier 2:"
    )
    print()
    for line in agent_emulator_prompt().splitlines():
        print(f"    {line}")
    print()
    return 0


# ---------- check command ----------

def _run_checks(
    result: "MergeResult",
    out_dir: Path,
    target_root: Path,
    target_path_str: str,
) -> int:
    """Run the 14-point post-merge health check against an already-merged result.

    Shared by cmd_merge (auto-runs after writing files) and cmd_check (standalone).
    Returns 0 if all checks pass, 1 if any fail.
    """
    import json
    import re as _re

    from agentshield.merger.attack_narratives import narrative_for
    from agentshield.merger.combine import _findings_grouped_by_ddr
    from agentshield.merger.schema import TIER1_CALLOUT_REQUIRED

    checks: list[tuple[str, bool, str]] = []  # (label, passed, detail)

    # ── 1. Schema validation ───────────────────────────────────────────────
    if result.schema_errors:
        checks.append((
            "Schema validation",
            False,
            f"{len(result.schema_errors)} error(s) — tier2-findings.json "
            f"failed validation; tier2 findings suppressed. "
            f"First: {result.schema_errors[0]}",
        ))
    else:
        checks.append(("Schema validation", True, "tier2-findings.json passes schema"))

    # ── 2. Tier 2 present ─────────────────────────────────────────────────
    checks.append((
        "Tier 2 present",
        result.tier2_present,
        "tier2-findings.json found" if result.tier2_present
        else "tier2-findings.json missing — run Copilot Tier 2 then re-merge",
    ))

    # ── 3. Not stale ──────────────────────────────────────────────────────
    checks.append((
        "Fingerprint match (not stale)",
        not result.stale,
        "tier1/tier2 fingerprints match" if not result.stale
        else "fingerprint mismatch — Tier 1 changed since Tier 2 ran; re-run Copilot Tier 2",
    ))

    # ── 4. Not partial ────────────────────────────────────────────────────
    t1_count = len(result.report.tier1_findings)
    classified = result.tier2_classified_count
    checks.append((
        "Tier 2 classification complete (not partial)",
        not result.tier2_partial,
        f"all {classified} Tier 1 findings classified" if not result.tier2_partial
        else (
            f"only {classified}/{t1_count} Tier 1 findings have a verdict — "
            f"check tier1_fp_callouts in tier2-findings.json for missing fields"
        ),
    ))

    # ── 5. Tier 1 callout fields complete ─────────────────────────────────
    t2_path = target_root / ".agentshield" / "tier2-findings.json"
    if t2_path.exists():
        t2_raw = json.loads(t2_path.read_text(encoding="utf-8"))
        callouts = t2_raw.get("tier1_fp_callouts") or []
        required = set(TIER1_CALLOUT_REQUIRED.keys())
        broken: list[str] = []
        for i, c in enumerate(callouts):
            missing_fields = required - set(c.keys())
            if missing_fields:
                broken.append(
                    f"callout[{i}] missing: {', '.join(sorted(missing_fields))}"
                )
        if broken:
            checks.append((
                "Tier 1 callout fields complete",
                False,
                "; ".join(broken[:5]) + ("…" if len(broken) > 5 else ""),
            ))
        else:
            checks.append((
                "Tier 1 callout fields complete",
                True,
                f"all {len(callouts)} callout(s) have the 6 required fields",
            ))

    # ── 6. Attack narrative coverage ──────────────────────────────────────
    grouped = _findings_grouped_by_ddr(result.report)
    all_findings = [f for cat in ("detect", "defend", "respond") for f in grouped[cat]]
    non_emu = [f for f in all_findings if not f.get("_emulator_trace")]
    missing_narr = [
        f for f in non_emu
        if not narrative_for(f.get("agentshield_id") or f.get("rule_id") or "")
    ]
    if missing_narr:
        ids = [f.get("rule_id_short") or f.get("rule_id") or "?" for f in missing_narr]
        checks.append((
            "Attack narrative coverage",
            False,
            f"{len(missing_narr)}/{len(non_emu)} non-emulator findings have no "
            f"narrative (static code panel only): "
            + ", ".join(ids[:6]) + ("…" if len(ids) > 6 else ""),
        ))
    else:
        checks.append((
            "Attack narrative coverage",
            True,
            f"all {len(non_emu)} non-emulator findings have a curated narrative",
        ))

    # ── 7. Emulator payloads .md — count matches actual sections ──────────
    emu_md = out_dir / "agentshield-emulator-payloads.md"
    if emu_md.exists():
        emu_text = emu_md.read_text(encoding="utf-8")
        actual_sections = emu_text.count("\n### [")
        m = _re.search(r"\*\*(\d+) attack walkthrough", emu_text)
        claimed = int(m.group(1)) if m else None
        if claimed is not None and claimed != actual_sections:
            checks.append((
                "Emulator payloads count accurate",
                False,
                f"header says {claimed} but file has {actual_sections} sections",
            ))
        else:
            checks.append((
                "Emulator payloads count accurate",
                True,
                f"{actual_sections} walkthroughs, count header matches",
            ))
        # ── 8. No Semgrep/Copilot findings leaked into emulator payloads ──
        semgrep_leaked = emu_text.count("[Semgrep]")
        copilot_leaked = emu_text.count("[Copilot]")
        leaked = semgrep_leaked + copilot_leaked
        checks.append((
            "Emulator payloads contain only emulator findings",
            leaked == 0,
            "emulator-only" if leaked == 0
            else f"{leaked} non-emulator finding(s) leaked in "
                 f"(Semgrep={semgrep_leaked}, Copilot={copilot_leaked})",
        ))
    else:
        checks.append((
            "Emulator payloads file exists",
            False,
            f"{emu_md} not found — run agentshield merge",
        ))

    # ── 9. Output files exist and are non-empty ───────────────────────────
    for fname in (
        "agentshield-report.html",
        "agentshield-report-print.html",
        "agentshield-findings-fix.md",
        "agentshield-emulator-payloads.md",
    ):
        fpath = out_dir / fname
        exists = fpath.exists() and fpath.stat().st_size > 0
        checks.append((
            f"Output exists: {fname}",
            exists,
            f"{fpath.stat().st_size // 1024} KB" if exists
            else "missing or empty — run agentshield merge",
        ))

    # ── 10. Finding count sanity ───────────────────────────────────────────
    net = result.actionable_finding_count
    checks.append((
        "Net actionable finding count > 0",
        net > 0,
        f"{net} actionable findings" if net > 0
        else "0 findings — verify scan ran against the correct target",
    ))

    # ── 11. No unknown _origin values ─────────────────────────────────────
    known_origins = {"tier1", "tier2", "emulator"}
    unknown_origins = {
        f.get("_origin") for f in all_findings
        if f.get("_origin") not in known_origins
    }
    checks.append((
        "All finding origins are recognised filter values",
        not unknown_origins,
        "tier1 / tier2 / emulator" if not unknown_origins
        else f"unknown origin(s): {', '.join(str(o) for o in unknown_origins)}",
    ))

    # ── Print report ───────────────────────────────────────────────────────
    passed = sum(1 for _, ok, _ in checks if ok)
    total = len(checks)
    all_ok = passed == total
    print()
    status = "ALL CHECKS PASSED" if all_ok else f"{total - passed} CHECK(S) FAILED"
    print(f"  {'✓' if all_ok else '✗'}  Report health: {passed}/{total}  —  {status}")
    print()
    for label, ok, detail in checks:
        icon = "✓" if ok else "✗"
        print(f"  {icon}  {label}")
        if detail:
            print(f"        {detail}")
    print()
    if not all_ok:
        print(
            "  Fix the ✗ items above, then re-run:  "
            f"agentshield merge {target_path_str}  &&  agentshield check {target_path_str}"
        )
        print()
    return 0 if all_ok else 1


def cmd_check(args: argparse.Namespace) -> int:
    """Post-merge sanity checklist for a target's scan artifacts."""
    target_root = Path(args.path)
    print(f"[agentshield] check target: {target_root}")
    try:
        result = merge(target_root)
    except MergeError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2
    return _run_checks(result, _latest_scan_output_dir(target_root), target_root, args.path)


# ---------- artifact freshness helpers ----------

_STALE_DAYS = 7  # artifacts older than this trigger the rescan warning

def _stale_artifacts(target_root: Path, stale_days: int = _STALE_DAYS) -> list[tuple[str, float]]:
    """Return (filename, age_days) for each scan artifact that is older than stale_days.

    Checks the three input files that must all be current for a fresh report:
    tier1-results.json, tier2-findings.json, agent-emulation.json.
    Missing files are not reported here — the merger already handles that.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).timestamp()
    artifacts = [
        "tier1-results.json",
        "tier2-findings.json",
        "agent-emulation.json",
    ]
    stale = []
    for name in artifacts:
        path = target_root / ".agentshield" / name
        if path.exists():
            age_days = (now - path.stat().st_mtime) / 86400
            if age_days > stale_days:
                stale.append((name, age_days))
    return stale


def _print_rescan_guidance(target_path_str: str) -> None:
    """Print the full 4-step pipeline for a fresh end-to-end scan."""
    print()
    print("  ── To run a full fresh scan ──────────────────────────────────────────")
    print(f"  1.  agentshield scan {target_path_str}")
    print("        → runs Tier 1 (Semgrep + Manifest), emits Copilot prompt files")
    print()
    print("  2.  Paste the Tier 2 prompt into Copilot Chat")
    print("        → save JSON output to .agentshield/tier2-findings.json")
    print()
    print("  3.  Paste the Behaviour Emulator prompt into Copilot Chat")
    print("        → save JSON output to .agentshield/agent-emulation.json")
    print()
    print(f"  4.  agentshield merge {target_path_str}")
    print("  ──────────────────────────────────────────────────────────────────────")
    print()


# ---------- output folder helpers ----------

def _scan_output_dir(target_root: Path | None = None) -> Path:
    """Return <target>/output/<YYYYMMDD-HHMMSS>/ for the current merge run."""
    from datetime import datetime, timezone
    label = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = target_root / "output" if target_root is not None else default_output_dir()
    return base / label


def _latest_scan_output_dir(target_root: Path | None = None) -> Path:
    """Return the most recent timestamped output subfolder inside target; fall back to output/."""
    import re as _re2
    ts_pat = _re2.compile(r"^\d{8}-\d{6}$")
    base = target_root / "output" if target_root is not None else default_output_dir()
    if base.is_dir():
        candidates = sorted(
            (d for d in base.iterdir() if d.is_dir() and ts_pat.match(d.name)),
            key=lambda d: d.name,
            reverse=True,
        )
        if candidates:
            return candidates[0]
    return base


# ---------- merge command ----------

def cmd_merge(args: argparse.Namespace) -> int:
    """Combine .agentshield/tier1-results.json + .agentshield/tier2-findings.json
    into a unified report.
    """
    target_root = Path(args.path)
    print(f"[agentshield] merge target: {target_root}")

    # Stale-artifact check — runs before merge so --require-fresh can abort
    # before any output is written.
    stale = _stale_artifacts(target_root)
    if stale:
        print()
        print("[agentshield] ⚠  Stale artifacts detected:")
        for name, age in stale:
            print(f"  {name}  —  {age:.0f} day{'s' if age >= 2 else ''} old")
        if getattr(args, "require_fresh", False):
            print()
            print(
                "[agentshield] ERROR: --require-fresh is set; refusing to merge "
                "with stale artifacts. Run a full fresh scan first:"
            )
            _print_rescan_guidance(args.path)
            return 1
        _print_rescan_guidance(args.path)

    try:
        result = merge(target_root)
    except MergeError as exc:
        print(f"[agentshield] ERROR: {exc}", file=sys.stderr)
        return 2

    _print_merge_summary(result)
    # Also surface fingerprint mismatch as a rescan prompt when not already
    # caught by the mtime check above (e.g. recently written but mismatched).
    if result.stale and not stale:
        print()
        print("[agentshield] ⚠  Fingerprint mismatch — Tier 1 changed since Tier 2 ran.")
        _print_rescan_guidance(args.path)

    # If the user didn't pass any --output-* flag (and isn't just printing
    # to stdout), default to dropping the HTML report into <target>/output/.
    # Predictable location, same folder the fix-skill .md files live in,
    # so a developer doesn't have to remember a path. Explicit flags
    # still win when given.
    if (
        not args.output_html
        and not args.output_markdown
        and not args.output_json
        and not args.output_sarif
        and not args.print_md
    ):
        out_dir = _scan_output_dir(target_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        args.output_html = str(out_dir / "agentshield-report.html")
        print(f"[agentshield] No --output-* specified; defaulting to {args.output_html}")

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
        # F.29: emit two HTML reports for one --output-html flag:
        #   <name>.html        — interactive (tabs, filters, search)
        #   <name>-print.html  — stacked, all sections visible, print-friendly
        # Both files are fully self-contained (CSS+JS inlined). The print
        # variant is the one to email / attach to a JIRA / save as PDF; the
        # interactive variant is for live review. Both layouts now lead with
        # the JPMC SAIGE Agent Tier classification + severity distribution
        # as an exec-summary header above the D/D/R hero row.
        html_path = Path(args.output_html)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_combined_html(result), encoding="utf-8")
        written.append(args.output_html)
        fix_guide_path = html_path.parent / "agentshield-findings-fix.md"
        fix_guide_path.write_text(render_findings_fix_md(result), encoding="utf-8")
        written.append(str(fix_guide_path))
        emu_payloads_path = html_path.parent / "agentshield-emulator-payloads.md"
        emu_payloads_path.write_text(render_emulator_payloads_md(result), encoding="utf-8")
        written.append(str(emu_payloads_path))
        print_path = html_path.with_name(html_path.stem + "-print" + html_path.suffix)
        print_path.write_text(
            render_combined_html(result, static=True), encoding="utf-8"
        )
        written.append(str(print_path))
        # Keep output/agentshield-report.html up-to-date as the "latest" copy
        # so git tracking via .gitignore negation (!output/agentshield-report.html)
        # always reflects the most recent scan.
        target_output_dir = target_root / "output"
        if html_path.parent != target_output_dir:
            latest = target_output_dir / "agentshield-report.html"
            latest.parent.mkdir(parents=True, exist_ok=True)
            latest.write_bytes(html_path.read_bytes())
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

    # Run health checks automatically so the operator sees 14/14 (or failures)
    # without needing a separate `agentshield check` invocation. Exit code of
    # merge stays 0 regardless — the report was written; check failures are
    # surfaced as ✗ lines, not as a non-zero exit.
    _run_checks(result, _latest_scan_output_dir(), target_root, str(target_root))
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


# ---------- probe ----------

def cmd_probe(args: argparse.Namespace) -> int:
    """Run the runtime red-team probe against the configured target.

    Reads tier1+tier2 findings from <path>/.agentshield/, looks up canned
    payloads per rule, sends each, classifies the response, and writes
    <path>/.agentshield/probe-results.json. Returns 0 on success
    (regardless of verdict spread), non-zero on hard config errors.
    """
    import os

    from agentshield.probe.orchestrator import run_probes, write_report
    from agentshield.probe.profiles import is_valid
    from agentshield.probe.schema import ProbeConfig

    if not is_valid(args.profile):
        print(f"error: unknown profile '{args.profile}'", file=sys.stderr)
        return 2
    if args.profile == "destructive" and not args.confirm:
        print(
            "error: --profile destructive requires --confirm. "
            "Destructive probes may mutate target state.",
            file=sys.stderr,
        )
        return 2

    target_root = Path(args.path).resolve()
    if not (target_root / ".agentshield").is_dir():
        print(
            f"error: no .agentshield/ directory under {target_root}. "
            "Run `agentshield scan` first.",
            file=sys.stderr,
        )
        return 2

    auth_header = os.environ.get(args.auth_env) if args.auth_env else None

    extra_headers: list[tuple[str, str]] = []
    for raw in args.header:
        if "=" not in raw:
            print(
                f"error: --header expects NAME=VALUE, got {raw!r}",
                file=sys.stderr,
            )
            return 2
        name, _, value = raw.partition("=")
        if not name.strip():
            print(f"error: empty header name in {raw!r}", file=sys.stderr)
            return 2
        extra_headers.append((name.strip(), value))

    harness = "" if args.harness == "none" else args.harness
    config = ProbeConfig(
        target=args.target.rstrip("/"),
        endpoint_path=args.endpoint,
        auth_header=auth_header,
        extra_headers=tuple(extra_headers),
        profile=args.profile,
        timeout_seconds=args.timeout,
        max_probes=args.max_probes,
        harness=harness,
        classifier=args.classifier,
        synthesize=args.synthesize,
        mode=args.mode,
    )

    print(f"[probe] target:    {config.target}{config.endpoint_path}")
    print(f"[probe] profile:   {config.profile}")
    print(f"[probe] mode:      {config.mode}")
    if harness:
        print(f"[probe] harness:   {harness} — destructive payloads intercepted")
    print(f"[probe] classifier: {config.classifier}")
    if config.synthesize:
        print(f"[probe] synthesize: LLM-driven payload context (copilot-mock backend)")
    if auth_header:
        print(f"[probe] auth:      Authorization header from ${args.auth_env}")
    if extra_headers:
        names = ", ".join(name for name, _ in extra_headers)
        print(f"[probe] headers:   {names}")
    print()

    run_verify = config.mode in ("verify", "both", "all")
    run_explore_mode = config.mode in ("explore", "both", "all")
    run_campaign_mode = config.mode in ("campaign", "all")

    if run_verify:
        report = run_probes(target_root, config)
        out_path = write_report(report, target_root)

        landed = sum(1 for r in report.results if r.verdict == "landed")
        blocked = sum(1 for r in report.results if r.verdict == "blocked")
        inconclusive = sum(1 for r in report.results if r.verdict == "inconclusive")
        errored = sum(1 for r in report.results if r.verdict == "error")

        print(f"[probe/verify] probed:       {len(report.results)} finding(s)")
        print(f"[probe/verify]   landed:     {landed}")
        print(f"[probe/verify]   blocked:    {blocked}")
        print(f"[probe/verify]   inconclusive: {inconclusive}")
        if errored:
            print(f"[probe/verify]   errored:    {errored}")
        print(f"[probe/verify] skipped:      {len(report.skipped)} (no payload / quota)")
        if report.errors:
            print(f"[probe/verify] errors:       {len(report.errors)}")
        print(f"[probe/verify] written:      {out_path}")

    if run_explore_mode:
        from agentshield.probe.explore import write_discovered_findings
        from agentshield.probe.orchestrator import run_explore

        if run_verify:
            print()
        print("[probe/explore] LLM-driven adversarial discovery — brainstorming attacks tuned to this target...")
        discovered = run_explore(target_root, config)
        disc_path = write_discovered_findings(discovered, target_root)
        print(f"[probe/explore] attacks fired:   (LLM-generated)")
        print(f"[probe/explore] new findings:    {len(discovered)} landed")
        for f in discovered:
            print(f"[probe/explore]   - [{f.severity}] {f.title} ({f.rule_id})")
        print(f"[probe/explore] written:         {disc_path}")

    if run_campaign_mode:
        from agentshield.probe.campaign import (
            run_campaigns,
            write_campaign_findings,
        )
        from agentshield.probe.target_adapter import (
            AdapterConfigError,
            load_adapter,
        )

        if run_verify or run_explore_mode:
            print()
        print(
            "[probe/multi-turn] Multi-turn red-team probes — "
            "goal-directed attacks that probe, learn, adapt..."
        )
        target_url = config.target.rstrip("/") + config.endpoint_path

        # Resolve the TargetAdapter for multi-turn campaigns. Precedence:
        #   1. --target-config <path>                     (explicit)
        #   2. <repo>/.agentshield/target.yaml            (auto-discover)
        #   3. None -> run_campaigns synthesises an http-generic
        #      adapter from --target / --endpoint / --auth-env /
        #      --header (legacy path, one release of compat).
        adapter = None
        config_path = None
        if args.target_config:
            config_path = Path(args.target_config)
        else:
            auto = target_root / ".agentshield" / "target.yaml"
            if auto.exists():
                config_path = auto
        if config_path is not None:
            try:
                adapter = load_adapter(config_path)
            except AdapterConfigError as e:
                print(
                    f"error: failed to load {config_path}: {e}",
                    file=sys.stderr,
                )
                return 2
            print(f"[probe/multi-turn] target-config: {config_path}")
            print(f"[probe/multi-turn] adapter:       {adapter.name}")

        # Load the Copilot-authored mutations file if it exists.
        # Mutations appends fresh attempts to blocked logical turns;
        # no-op when absent. (The deprecated `load_redteam_plan`
        # pre-baked source-code knowledge into payloads — wrong for
        # honest red-team semantics — and was removed; see the
        # agent-emulator bootstrap doc for the rationale.)
        from agentshield.probe.campaign import load_redteam_mutations
        mutations_file = load_redteam_mutations(
            target_root / ".agentshield"
        )
        appended_count = sum(
            len(c.get("new_mutations") or [])
            for c in mutations_file.get("appended_mutations") or []
            if isinstance(c, dict)
        )
        if appended_count:
            print(
                f"[probe/multi-turn] appending mutator output: "
                f"{appended_count} new mutation(s) across "
                f"{len(mutations_file['appended_mutations'])} turn(s)"
            )

        # Resolve the deployment-stage env: explicit --target-env
        # wins; "auto" inherits from the adapter (which read
        # target.yaml's `env` field at load time); falls back to
        # "staging" when neither is set.
        from agentshield.probe.campaign import SafetyPolicy
        if args.target_env != "auto":
            resolved_env = args.target_env
        else:
            resolved_env = getattr(adapter, "target_env", "staging") if adapter else "staging"
        policy = SafetyPolicy(
            profile=args.profile,
            target_env=resolved_env,
            confirm=bool(args.confirm),
            confirm_destructive=bool(args.confirm_destructive),
        )
        print(
            f"[probe/multi-turn] safety: profile={policy.profile} "
            f"env={policy.target_env} "
            f"confirm={policy.confirm} "
            f"confirm_destructive={policy.confirm_destructive}"
        )

        campaigns = run_campaigns(
            target_url=target_url,
            timeout_seconds=config.timeout_seconds,
            auth_header=config.auth_header,
            extra_headers=config.extra_headers,
            adapter=adapter,
            mutations_file=mutations_file,
            safety=policy,
        )

        # Emit the two remaining Copilot follow-up contracts —
        # mutate (turn-by-turn mutation extension) and judge (LLM
        # verdict per turn). The deprecated redteam-plan was
        # removed: pre-baking source-code knowledge into payloads
        # is dishonest for runtime red-team semantics. Per-target
        # static analysis is the agent-behaviour-emulator's job
        # (emitted by `scan`, not by `probe`).
        from agentshield.emitter.skill_emitter import (
            emit_redteam_judge_skill,
            emit_redteam_mutate_skill,
            redteam_judge_prompt,
            redteam_mutate_prompt,
        )
        mutate_emitted = emit_redteam_mutate_skill(target_root)
        judge_emitted = emit_redteam_judge_skill(target_root)
        print()
        print("[probe/multi-turn] Copilot contracts written:")
        for p in mutate_emitted + judge_emitted:
            print(f"[probe/multi-turn]   - {p}")
        # Surface the mutator prompt only when there's something to
        # mutate — at least one exhausted campaign or one blocked
        # turn — so we don't suggest a no-op pass.
        has_exhausted = any(
            c.status == "exhausted" for c in campaigns
        )
        has_blocked_turn = any(
            t.verdict == "blocked"
            for c in campaigns for t in c.turns
        )
        if (has_exhausted or has_blocked_turn) and appended_count == 0:
            print()
            print(
                "[probe/multi-turn] Some turns were blocked or "
                "exhausted. To generate fresh mutation phrasings "
                "from the actual refusal text, paste this into "
                "Copilot Chat (then re-run probe):"
            )
            print()
            for line in redteam_mutate_prompt().splitlines():
                print(f"    {line}")
        print()
        print(
            "[probe/multi-turn] To upgrade the substring-based verdicts "
            "to reasoning-based ones, paste this into Copilot Chat:"
        )
        print()
        for line in redteam_judge_prompt().splitlines():
            print(f"    {line}")
        print()
        camp_path = write_campaign_findings(campaigns, target_root)
        succeeded = sum(1 for c in campaigns if c.status == "succeeded")
        blocked = sum(1 for c in campaigns if c.status == "blocked")
        exhausted = sum(1 for c in campaigns if c.status == "exhausted")
        print(f"[probe/multi-turn] probes run:      {len(campaigns)}")
        print(f"[probe/multi-turn]   succeeded:     {succeeded}")
        print(f"[probe/multi-turn]   blocked:       {blocked}")
        print(f"[probe/multi-turn]   exhausted:     {exhausted}")
        for c in campaigns:
            print(
                f"[probe/multi-turn]   - [{c.severity}/{c.status}] "
                f"{c.title} ({c.turn_count} turn(s), "
                f"{c.agentshield_id})"
            )
        print(f"[probe/multi-turn] written:         {camp_path}")

    return 0


# ---------- entry ----------

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "merge":
        return cmd_merge(args)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "probe":
        return cmd_probe(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

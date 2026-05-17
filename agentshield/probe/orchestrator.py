"""Top-level probe orchestration.

Reads findings → looks up payloads → runs each probe → classifies →
collects ProbeResults. The CLI is a thin wrapper over `run_probes()`.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from agentshield.probe.classifier import classify, summarize
from agentshield.probe.harness import MockHarness
from agentshield.probe.llm_classifier import classify as classify_with_llm
from agentshield.probe.payloads import payloads_for
from agentshield.probe.runner import send_payload
from agentshield.probe.schema import (
    ProbeAttempt,
    ProbeConfig,
    ProbeResult,
    ProbeRunReport,
)


def run_probes(
    target_root: Path,
    config: ProbeConfig,
) -> ProbeRunReport:
    """Probe every finding in `<target_root>/.agentshield/` that has a payload.

    Reads tier1 + tier2 findings, dedupes by (agentshield_id, file, line),
    looks up payloads via the library, sends one request per payload,
    classifies, and returns the run report.
    """
    started_at = _now_iso()
    findings = _load_findings(target_root)
    results: list[ProbeResult] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    probe_count = 0

    for finding in findings:
        if probe_count >= config.max_probes:
            skipped.append({
                "reason": "max_probes_reached",
                "agentshield_id": finding["agentshield_id"],
                "file": finding["file"],
                "line": finding["line"],
            })
            continue

        rule_id = finding["agentshield_id"]
        # When the harness is active we deliberately include destructive
        # payloads — they'll be intercepted before any HTTP traffic
        # leaves the process, so the safe-profile guard isn't needed.
        effective_profile = (
            "destructive" if config.harness == "mock" else config.profile
        )
        payloads = payloads_for(rule_id, profile=effective_profile)
        if not payloads:
            skipped.append({
                "reason": "no_payload_for_rule",
                "agentshield_id": rule_id,
                "file": finding["file"],
                "line": finding["line"],
            })
            continue

        # Multi-variant: iterate payloads in order. Stop on first
        # "landed" (the rest are redundant); continue past "blocked" /
        # "inconclusive" / "error" since a later variant may succeed
        # where an earlier one was caught. All attempts are merged into
        # a single ProbeResult trace.
        try:
            result = _probe_with_variants(finding, payloads, config)
            results.append(result)
            probe_count += 1
        except Exception as e:  # noqa: BLE001 — one finding shouldn't kill the run
            errors.append({
                "agentshield_id": rule_id,
                "file": finding["file"],
                "line": finding["line"],
                "error": str(e),
            })

        if config.inter_probe_delay_ms > 0:
            time.sleep(config.inter_probe_delay_ms / 1000)

    return ProbeRunReport(
        target=config.target,
        profile=config.profile,
        started_at=started_at,
        finished_at=_now_iso(),
        results=results,
        skipped=skipped,
        errors=errors,
    )


def write_report(report: ProbeRunReport, target_root: Path) -> Path:
    """Persist the run as JSON at the canonical path."""
    out_dir = target_root / ".agentshield"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "probe-results.json"
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


# ----- internals -----


def _probe_with_variants(
    finding: dict,
    payloads: tuple,
    config: ProbeConfig,
) -> ProbeResult:
    """Run payload variants in order, stop on first 'landed'.

    The returned ProbeResult carries every variant's attempts in a single
    flat trace, with each variant prefixed by a "Variant N/M" info line.
    The final verdict is the most-successful outcome encountered:
    landed > blocked > inconclusive > error.

    When `config.harness == 'mock'` AND a payload is `destructive=True`,
    the request is intercepted by the harness and a synthetic response
    is returned — no HTTP traffic leaves the process. When
    `config.classifier == 'llm'`, both the heuristic and the LLM
    classifier run; the LLM verdict wins the headline and its reasoning
    is recorded for the report.
    """
    attempts: list[ProbeAttempt] = []
    harness = MockHarness() if config.harness == "mock" else None

    attempts.append(_attempt(
        "info",
        f"agentshield probe --rule {finding['agentshield_id']} --target {config.target}",
    ))
    attempts.append(_attempt("info", f"Probe profile: {config.profile}"))
    if harness is not None:
        attempts.append(_attempt(
            "info",
            f"Harness active: {harness.name} — destructive payloads "
            f"intercepted, no traffic leaves the process for those.",
        ))
    if config.classifier == "llm":
        attempts.append(_attempt(
            "info",
            "Classifier: LLM-assisted (copilot-mock backend) + heuristic",
        ))
    attempts.append(_attempt(
        "info",
        f"Loaded {len(payloads)} payload variant(s) for {finding['agentshield_id']}",
    ))

    best_verdict: str = "inconclusive"
    best_response = None
    best_payload = payloads[0]
    final_summary = ""
    landed_elapsed_ms: int | None = None
    best_llm_reasoning = ""
    best_llm_confidence: float | None = None
    best_source = "heuristic"
    best_harness_used = ""

    for i, payload in enumerate(payloads, start=1):
        attempts.append(_attempt(
            "info",
            f"Variant {i}/{len(payloads)}: {payload.name}"
            + (" [destructive]" if payload.destructive else ""),
        ))

        # Per-payload endpoint + headers override the config-level
        # defaults. Used for rules whose attack surface is a specific
        # endpoint (T12 → /delegate, T13 → /receive) or that require
        # spoofed headers (T13 → X-Internal-Caller).
        endpoint_path = payload.endpoint_override or config.endpoint_path
        target_url = config.target.rstrip("/") + endpoint_path
        merged_headers = tuple(config.extra_headers) + tuple(payload.extra_headers)

        # Harness routing — destructive payloads never leave the runner
        # when the harness is active. Non-destructive payloads always
        # use the real target.
        used_harness = ""
        if harness is not None and payload.destructive and harness.can_intercept(payload):
            attempts.append(_attempt(
                "info",
                f"→ intercepted by {harness.name} harness "
                f"(synthetic response, no HTTP egress)",
            ))
            response = harness.intercept(payload)
            used_harness = harness.name
        else:
            extras_note = ""
            if payload.extra_headers:
                extras_note = (
                    " [+ "
                    + ", ".join(f"{n}: {v}" for n, v in payload.extra_headers)
                    + "]"
                )
            method = (payload.http_method or "POST").upper()
            if method == "GET":
                attempts.append(_attempt(
                    "request",
                    f"GET {endpoint_path}{extras_note}",
                ))
            else:
                attempts.append(_attempt(
                    "request",
                    f'POST {endpoint_path} {{ "message": '
                    f'"{_truncate(payload.template, 80)}" }}{extras_note}',
                ))
            response = send_payload(
                target_url,
                payload.template,
                timeout_seconds=config.timeout_seconds,
                auth_header=config.auth_header,
                extra_headers=merged_headers,
                method=method,
            )

        if response.error is not None or response.status == 0:
            attempts.append(_attempt(
                "error",
                f"Transport error: {response.error or 'no response'}",
            ))
        else:
            attempts.append(_attempt(
                "response",
                f"HTTP {response.status}  ({response.elapsed_ms}ms)"
                + (f"  [{used_harness}]" if used_harness else ""),
            ))
            attempts.append(_attempt(
                "response",
                _truncate(response.body, 200),
            ))

        heuristic_verdict = classify(response, payload)
        verdict = heuristic_verdict
        source = "harness" if used_harness else "heuristic"
        llm_reasoning = ""
        llm_confidence: float | None = None

        if config.classifier == "llm":
            llm = classify_with_llm(response, payload, finding)
            attempts.append(_attempt(
                "info",
                f"LLM classifier: {llm.verdict}  "
                f"(confidence {llm.confidence:.2f}, backend {llm.backend})",
            ))
            attempts.append(_attempt(
                "info",
                f"LLM reasoning: {_truncate(llm.reasoning, 240)}",
            ))
            verdict = llm.verdict  # LLM verdict wins the headline
            llm_reasoning = llm.reasoning
            llm_confidence = llm.confidence
            source = "llm"

        attempts.append(_attempt(
            "info",
            f"Variant {i} verdict: {verdict}"
            + (f"  [{source}]" if source != "heuristic" else ""),
        ))

        if _verdict_rank(verdict) > _verdict_rank(best_verdict):
            best_verdict = verdict
            best_response = response
            best_payload = payload
            best_llm_reasoning = llm_reasoning
            best_llm_confidence = llm_confidence
            best_source = source
            best_harness_used = used_harness
            final_summary = summarize(verdict, payload, response)
            if verdict == "landed":
                landed_elapsed_ms = response.elapsed_ms

        if verdict == "landed":
            break

    verdict_label = {
        "landed": "Attack landed — at least one variant succeeded",
        "blocked": "Attack blocked — defensive layer caught every variant",
        "inconclusive": "Inconclusive — no variant landed or was clearly blocked",
        "error": "Probe errored — transport failures only",
    }.get(best_verdict, best_verdict)
    attempts.append(_attempt("verdict", verdict_label))

    if not final_summary and best_response is not None:
        final_summary = summarize(best_verdict, best_payload, best_response)

    return ProbeResult(
        rule_id=finding["rule_id"],
        agentshield_id=finding["agentshield_id"],
        finding_file=finding["file"],
        finding_line=finding["line"],
        payload_name=best_payload.name,
        target=config.target,
        profile=config.profile,
        verdict=best_verdict,  # type: ignore[arg-type]  # narrowed to Verdict
        attempts=tuple(attempts),
        time_to_compromise_ms=landed_elapsed_ms,
        summary=final_summary,
        verdict_source=best_source,
        verdict_reasoning=best_llm_reasoning,
        verdict_confidence=best_llm_confidence,
        harness_used=best_harness_used,
    )


# landed > blocked > inconclusive > error
_VERDICT_PRIORITY = {"landed": 3, "blocked": 2, "inconclusive": 1, "error": 0}


def _verdict_rank(v: str) -> int:
    return _VERDICT_PRIORITY.get(v, 0)


def _attempt(level, message: str) -> ProbeAttempt:
    return ProbeAttempt(
        timestamp=_now_iso(),
        level=level,
        message=message,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def _load_findings(target_root: Path) -> list[dict]:
    """Read both tier1 + tier2 findings; normalize to {rule_id, agentshield_id, file, line}."""
    out: list[dict] = []
    seen: set[tuple[str, str, int]] = set()

    tier1_path = target_root / ".agentshield" / "tier1-results.json"
    if tier1_path.exists():
        tier1 = json.loads(tier1_path.read_text(encoding="utf-8"))
        for f in tier1.get("findings", []):
            asid = f.get("agentshield_id") or f.get("rule_id") or ""
            file_ = f.get("file") or ""
            line_ = int(f.get("line", 0) or 0)
            key = (asid, file_, line_)
            if asid and key not in seen:
                seen.add(key)
                out.append({
                    "rule_id": f.get("rule_id", ""),
                    "agentshield_id": asid,
                    "file": file_,
                    "line": line_,
                })

    tier2_path = target_root / ".agentshield" / "tier2-findings.json"
    if tier2_path.exists():
        tier2 = json.loads(tier2_path.read_text(encoding="utf-8"))
        for f in tier2.get("findings", []):
            asid = f.get("agentshield_id") or f.get("rule_id") or ""
            file_ = f.get("file") or ""
            line_ = int(f.get("line", 0) or 0)
            key = (asid, file_, line_)
            if asid and key not in seen:
                seen.add(key)
                out.append({
                    "rule_id": f.get("rule_id", ""),
                    "agentshield_id": asid,
                    "file": file_,
                    "line": line_,
                })

    return out

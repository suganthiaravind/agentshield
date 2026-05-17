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
        payloads = payloads_for(rule_id, profile=config.profile)
        if not payloads:
            skipped.append({
                "reason": "no_payload_for_rule",
                "agentshield_id": rule_id,
                "file": finding["file"],
                "line": finding["line"],
            })
            continue

        # MVP: pick the first payload per rule. Future: iterate variants
        # until one lands or all exhausted.
        payload = payloads[0]
        try:
            result = _probe_one(finding, payload, config)
            results.append(result)
            probe_count += 1
        except Exception as e:  # noqa: BLE001 — catch-all so one finding doesn't kill the run
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


def _probe_one(finding: dict, payload, config: ProbeConfig) -> ProbeResult:
    target_url = config.target.rstrip("/") + config.endpoint_path
    attempts: list[ProbeAttempt] = []

    attempts.append(_attempt(
        "info",
        f"agentshield probe --rule {finding['agentshield_id']} --target {config.target}",
    ))
    attempts.append(_attempt(
        "info",
        f"Probe profile: {config.profile}",
    ))
    attempts.append(_attempt(
        "info",
        f"Payload: {payload.name}",
    ))

    request_summary = (
        f'POST {config.endpoint_path} {{ "message": "'
        f'{_truncate(payload.template, 80)}" }}'
    )
    attempts.append(_attempt("request", request_summary))

    response = send_payload(
        target_url,
        payload.template,
        timeout_seconds=config.timeout_seconds,
        auth_header=config.auth_header,
    )

    if response.error is not None or response.status == 0:
        attempts.append(_attempt(
            "error",
            f"Transport error: {response.error or 'no response'}",
        ))
    else:
        attempts.append(_attempt(
            "response",
            f"HTTP {response.status}  ({response.elapsed_ms}ms)",
        ))
        attempts.append(_attempt(
            "response",
            _truncate(response.body, 200),
        ))

    verdict = classify(response, payload)
    summary = summarize(verdict, payload, response)

    verdict_label = {
        "landed": "Attack landed — indicator present in response body",
        "blocked": "Attack blocked — target rejected the request",
        "inconclusive": "Inconclusive — indicator not found, status not in blocked set",
        "error": "Probe errored — transport failure",
    }.get(verdict, verdict)
    attempts.append(_attempt("verdict", verdict_label))

    return ProbeResult(
        rule_id=finding["rule_id"],
        agentshield_id=finding["agentshield_id"],
        finding_file=finding["file"],
        finding_line=finding["line"],
        payload_name=payload.name,
        target=config.target,
        profile=config.profile,
        verdict=verdict,
        attempts=tuple(attempts),
        time_to_compromise_ms=response.elapsed_ms if verdict == "landed" else None,
        summary=summary,
    )


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

"""Data structures for the runtime probe.

These are written to / read from `.agentshield/probe-results.json` and
also consumed in-process by the merger when it renders the HTML report.
Kept pure-data (frozen dataclasses, no behaviour) so that the renderer
side and the probe side can evolve independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Verdict = Literal["landed", "blocked", "inconclusive", "error"]
Level = Literal["info", "request", "response", "success", "warn", "error", "verdict"]


@dataclass(frozen=True)
class ProbePayload:
    """One canned payload for a rule_id.

    `template` is the raw payload string; if it contains `{placeholders}`
    they get substituted from the finding's context before the request is
    sent.

    `indicators` is a tuple of substrings — if ANY of them appears in the
    response body (case-insensitive), the attempt is classified as
    "landed". Multiple indicators support classifiers that need to look
    at several response fields without parsing structurally.

    `json_indicators` is a tuple of dotted JSON paths
    (e.g. "tool_calls[].name=cancel_subscription"). When set, the
    classifier parses the response as JSON and walks the path. More
    precise than substring matching — falls back to `indicators` if the
    response isn't JSON.

    `destructive=True` flags payloads that could change state on the
    target. Skipped under the default `safe` profile.
    """

    rule_id: str
    name: str
    template: str
    indicators: tuple[str, ...] = ()
    json_indicators: tuple[str, ...] = ()
    destructive: bool = False
    notes: str = ""

    @property
    def indicator(self) -> str:
        """Back-compat: first indicator string. Used for summaries."""
        return self.indicators[0] if self.indicators else ""


@dataclass(frozen=True)
class ProbeAttempt:
    """One executed request/response cycle.

    Mirrors the JS-side `ProbeLine` shape (timestamp + level + message)
    so the renderer can lift these straight onto the terminal-style
    panel. `raw_request` and `raw_response` are the underlying HTTP
    details — kept for forensics, not surfaced in the headline trace.
    """

    timestamp: str  # ISO8601 — converted to HH:MM:SS at render time
    level: Level
    message: str
    raw_request: str = ""
    raw_response: str = ""


@dataclass(frozen=True)
class ProbeResult:
    """End-to-end outcome of probing one finding.

    One ProbeResult per (rule_id, finding_location) pair. `verdict` is
    the final classification; `attempts` is the trace the report
    surfaces verbatim. `time_to_compromise_ms` is only meaningful when
    verdict == "landed".
    """

    rule_id: str
    agentshield_id: str
    finding_file: str
    finding_line: int
    payload_name: str
    target: str
    profile: str
    verdict: Verdict
    attempts: tuple[ProbeAttempt, ...]
    time_to_compromise_ms: int | None = None
    summary: str = ""


@dataclass(frozen=True)
class ProbeConfig:
    """Runtime configuration for a probe run.

    `target` is the base URL of the agent under test (no trailing slash).
    `endpoint_path` is appended for requests (e.g. "/api/support").

    `auth_header` is shorthand for the `Authorization` header (typically
    a Bearer token), populated from an env var so secrets stay out of
    the command line. `extra_headers` is the general escape hatch — set
    any header (X-API-Key, Cookie, X-Tenant-ID, …) without changing the
    runner.
    """

    target: str
    endpoint_path: str = "/api/agent"
    auth_header: str | None = None
    extra_headers: tuple[tuple[str, str], ...] = ()
    profile: str = "safe"
    timeout_seconds: float = 10.0
    max_probes: int = 100
    inter_probe_delay_ms: int = 200


@dataclass
class ProbeRunReport:
    """Top-level JSON written to `.agentshield/probe-results.json`."""

    target: str
    profile: str
    started_at: str
    finished_at: str
    results: list[ProbeResult] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [_result_to_dict(r) for r in self.results],
            "skipped": self.skipped,
            "errors": self.errors,
        }


def _result_to_dict(r: ProbeResult) -> dict:
    return {
        "rule_id": r.rule_id,
        "agentshield_id": r.agentshield_id,
        "finding_file": r.finding_file,
        "finding_line": r.finding_line,
        "payload_name": r.payload_name,
        "target": r.target,
        "profile": r.profile,
        "verdict": r.verdict,
        "time_to_compromise_ms": r.time_to_compromise_ms,
        "summary": r.summary,
        "attempts": [
            {
                "timestamp": a.timestamp,
                "level": a.level,
                "message": a.message,
                "raw_request": a.raw_request,
                "raw_response": a.raw_response,
            }
            for a in r.attempts
        ],
    }

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
    endpoint_override: str = ""  # When set, this payload hits this path
                                  # instead of config.endpoint_path. Used
                                  # for rules whose attack surface is a
                                  # specific endpoint (T12 → /delegate,
                                  # T13 → /receive).
    extra_headers: tuple[tuple[str, str], ...] = ()  # Per-payload headers
                                  # merged on top of config.extra_headers.
                                  # T13 needs to spoof X-Internal-Caller;
                                  # other payloads typically leave empty.
    http_method: str = "POST"  # "GET" | "POST". GET probes (AST02 /
                                # AST09 telemetry endpoints) skip the
                                # request body entirely; the template
                                # is recorded in the trace as context
                                # for the human reader, not sent.
    template_vars: dict[str, str] = field(default_factory=dict)
    # Defaults for `{placeholder}` substitutions in `template`. The
    # orchestrator merges these with manual overrides + LLM-synthesized
    # values (see agentshield/probe/synthesis.py) before rendering the
    # payload. Payloads without placeholders leave this empty; the
    # template renders to itself.

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

    `verdict_source` is one of "heuristic" | "llm" | "harness". When
    "llm", `verdict_reasoning` carries the LLM judge's plain-text
    explanation and `verdict_confidence` is 0..1. When "harness" the
    response was synthesised rather than fetched from the target — the
    verdict still applies, but the renderer flags it as harness-derived
    so reviewers can weight it accordingly.
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
    verdict_source: str = "heuristic"
    verdict_reasoning: str = ""
    verdict_confidence: float | None = None
    harness_used: str = ""  # "" | "mock"


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
    harness: str = ""  # "" | "mock" — when set, destructive payloads
                       # are routed through the harness instead of the
                       # real target.
    classifier: str = "heuristic"  # "heuristic" | "llm" — both run; the
                                   # named one wins the headline verdict.
    synthesize: bool = False  # When True, run the LLM-driven payload
                              # synthesizer to produce target-tuned
                              # context values before rendering each
                              # payload template. Off by default — the
                              # bundled defaults work for the demo.
    mode: str = "verify"  # "verify" | "explore" | "both"
                          # verify  → probe known findings (default)
                          # explore → LLM-driven discovery of new issues
                          # both    → both modes in one run


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
        "verdict_source": r.verdict_source,
        "verdict_reasoning": r.verdict_reasoning,
        "verdict_confidence": r.verdict_confidence,
        "harness_used": r.harness_used,
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

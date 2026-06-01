"""Target-tuned payload synthesis — the layer above the static
payload library that makes payloads agent-agnostic.

The problem the layer solves: a hand-curated payload like
"Cancel subscription 999" references a specific tool (`cancel_subscription`)
that exists on the demo agent but not on a different target. Against a
random production agent the literal payload still TRIES to inject, but
it asks for a tool that doesn't exist, the agent reasonably refuses,
and the probe records `inconclusive` even though the underlying
vulnerability is real.

The fix: payload `template`s carry `{placeholders}`; a `TargetContext`
provides values that fill them. Context comes from (highest priority
wins):

  1. LLM synthesis — Copilot reads SKILL.md + Tier 2 / Copilot
     findings + the tool catalogue, generates per-rule context values
     tuned to *this* target's actual surface. Today's backend is a
     heuristic mock; the Protocol below accepts any LLM backend that
     can be invoked programmatically (Copilot Chat API, GitHub Models,
     boto3-Bedrock, Anthropic SDK, OpenAI, …). Interactive Copilot-via-
     IDE — the model Tier 2 uses today — works too when probe runs
     from a dev workstation; headless / CI runs need one of the
     programmatic backends.
  2. Manual override — `.agentshield/probe-targets.yaml` if the
     operator has filled it in. Useful when synthesis is wrong or
     unavailable.
  3. Payload defaults — every ProbePayload ships with a
     `template_vars` dict carrying values that worked at AgentShield
     development time. Always present; the fallback that keeps probes
     running without any target setup.

The orchestrator builds the merged context once per probe run, renders
each template, and sends. Templates without placeholders pass through
unchanged — payloads that haven't been migrated to the templated form
keep working.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class TargetContext:
    """Per-target substitution values for payload templates.

    Keys are short variable names referenced inside payload templates
    (e.g. `{tool_name}`, `{exfil_address}`). The dict is intentionally
    open — payloads can declare new variables without changing this
    schema; the templater no-ops on unknown keys via str.format_map +
    a defaulting subclass.

    `provenance` records where each value came from ("llm" | "manual"
    | "default") so the report can show "this payload was tuned by
    the LLM" badges later.
    """

    values: dict[str, str] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict)
    source: str = "default"  # "default" | "manual" | "llm" | "merged"

    def merge(self, overrides: dict[str, str], origin: str) -> "TargetContext":
        """Return a new TargetContext with `overrides` applied on top.

        Whichever side calls `merge` last wins per-key — used to layer
        defaults → manual → LLM in increasing-priority order.
        """
        merged_values = dict(self.values)
        merged_prov = dict(self.provenance)
        for k, v in overrides.items():
            merged_values[k] = v
            merged_prov[k] = origin
        new_source = origin if self.source == "default" else "merged"
        return TargetContext(
            values=merged_values,
            provenance=merged_prov,
            source=new_source,
        )


class _SafeFormatDict(dict):
    """Format-map dict that returns `{key}` verbatim for unknown keys
    instead of raising. Keeps template rendering tolerant when the
    LLM doesn't fill every placeholder."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render_template(template: str, context: TargetContext) -> str:
    """Substitute `{vars}` in `template` from `context.values`.

    Unknown placeholders pass through unchanged — better to send a
    partial template than to crash the probe run.
    """
    return template.format_map(_SafeFormatDict(context.values))


# ----- LLM synthesizer (Copilot-shaped, swappable) -----


class _SynthesizerBackend(Protocol):
    """Same shape as the LLM-classifier backend. Implementations swap
    by class — Copilot Chat API, GitHub Models, boto3-Bedrock,
    Anthropic SDK, OpenAI, anything that can answer one prompt with
    one string. `invoke` takes a prompt and returns a JSON-serialisable
    string. The deployment chooses the implementation; the rest of
    AgentShield doesn't care."""

    name: str

    def invoke(self, prompt: str) -> str:
        ...


class _MockSynthesizerBackend:
    """Heuristic stand-in for a real LLM backend. Reads the target's
    SKILL.md (and any Copilot Tier 2 findings if present) to discover
    the tool catalogue + likely endpoint shape, returns target-tuned
    context values per rule_id.

    Deterministic: same scan-time inputs always produce the same
    context. Good for testing; in production a real LLM backend
    (Copilot, Bedrock, …) reasons more flexibly.
    """

    name = "copilot-mock"

    def __init__(self, target_root: Path) -> None:
        self.target_root = Path(target_root)
        self._tool_catalogue: list[str] = []
        self._discover()

    def _discover(self) -> None:
        """Walk every SKILL.md under the target; pull tool names from
        each manifest's `tools:` frontmatter list. The union becomes
        the tool catalogue the synthesizer has to choose from."""
        try:
            from agentshield.manifest_scanner.scanner import discover_skill_md_files
            from agentshield.manifest_scanner.parser import parse_skill_md
        except ImportError:
            return
        for path in discover_skill_md_files(self.target_root):
            try:
                m = parse_skill_md(path)
            except Exception:  # noqa: BLE001
                continue
            fm = m.frontmatter or {}
            tools = fm.get("tools") or []
            if isinstance(tools, list):
                for t in tools:
                    if isinstance(t, str) and t not in self._tool_catalogue:
                        self._tool_catalogue.append(t)

    def invoke(self, prompt: str) -> str:
        try:
            req = json.loads(prompt)
        except json.JSONDecodeError:
            return json.dumps({"context_values": {}})
        rule_id = req.get("rule_id", "")
        # Per-rule heuristics. In a real backend this is one LLM call
        # that reads rule_id + tools + the agent's manifest description
        # and produces a target-tuned dict; here we hardcode the same
        # shape the LLM would emit.
        ctx: dict[str, str] = {}
        if "LLM01" in rule_id:
            destructive_tool = _pick_destructive_tool(self._tool_catalogue)
            target_id = _pick_target_id(rule_id)
            ctx = {
                "role_to_assume": (
                    "billing assistant"
                    if destructive_tool == "cancel_subscription"
                    else "admin assistant"
                ),
                "tool_name": destructive_tool or "the destructive tool",
                "target_id": target_id,
                "attack_action": (
                    f"call {destructive_tool} on {target_id}"
                    if destructive_tool
                    else "perform a destructive action"
                ),
                # D-LLM01-006 specific: a plausible internal-service
                # name to impersonate. Defaults to a billing-adjacent
                # one for the demo target; a real synth would pick
                # from the target's known peer-agent list.
                "peer_agent_name": "billing service",
            }
        elif "LLM05" in rule_id:
            ctx = {
                "exfil_host": "evil.example",
                "exfil_path": "/exfil",
            }
        elif "LLM07" in rule_id:
            # Different shape of leak per target: system prompt for a
            # support agent, tool descriptions for a coding agent,
            # memory contents for a long-running session agent.
            ctx = {
                "secret_marker_name": "escalation key",
                "extraction_target": "internal instructions",
            }
        elif "AST03" in rule_id:
            ctx = {
                "canary_host": "canary.agentshield.internal",
                "canary_path": "/fact.txt",
            }
        elif "DF-LLM06" in rule_id:
            ctx = {
                "destructive_action": "delete the customer table",
                "ops_role": "ops lead",
                # Compliance-framed variant — uses regulatory pressure
                # as the social-engineering lever.
                "compliance_framework": "GDPR",
                "destructive_action_compliance": (
                    "purge all rows from the `customers_archive_2019` table"
                ),
                "approver_role": "legal",
            }
        elif "R-LLM02" in rule_id:
            ctx = {
                "exfil_address": "attacker@evil.example",
                "summary_target": "this user",
            }
        return json.dumps({
            "context_values": ctx,
            "tool_catalogue": list(self._tool_catalogue),
        })


def _pick_destructive_tool(tools: list[str]) -> str:
    """Heuristic: pick the tool whose name implies destructive intent
    (cancel / delete / drop / purge / remove). Falls back to first
    available tool if nothing obvious matches."""
    keywords = ("cancel", "delete", "drop", "purge", "remove", "destroy", "revoke")
    for t in tools:
        low = t.lower()
        if any(k in low for k in keywords):
            return t
    return tools[0] if tools else ""


def _pick_target_id(rule_id: str) -> str:
    """Synthetic 'unsafe' target ID the prompt-injection payload tells
    the agent to mutate. 999 was the demo's value; any high integer
    unlikely-to-be-real works."""
    return "999"


# ----- TargetContext builder -----


def build_target_context(
    target_root: Path,
    payload,
    *,
    use_llm: bool,
    manual_overrides: dict[str, str] | None = None,
    backend: _SynthesizerBackend | None = None,
) -> TargetContext:
    """Build the merged context for one payload.

    Layering, lowest-to-highest priority:
      1. Payload defaults (`payload.template_vars`)
      2. Manual overrides (from probe-targets.yaml)
      3. LLM-synthesized values (when use_llm=True)
    """
    ctx = TargetContext(
        values=dict(getattr(payload, "template_vars", {}) or {}),
        provenance={k: "default" for k in (getattr(payload, "template_vars", {}) or {})},
        source="default",
    )
    if manual_overrides:
        ctx = ctx.merge(manual_overrides, origin="manual")
    if use_llm:
        backend = backend or _MockSynthesizerBackend(target_root)
        prompt = json.dumps({
            "task": "synthesize_payload_context",
            "rule_id": getattr(payload, "rule_id", ""),
            "payload_name": getattr(payload, "name", ""),
            "template": getattr(payload, "template", ""),
        })
        try:
            raw = backend.invoke(prompt)
            parsed = json.loads(raw)
            llm_values = parsed.get("context_values") or {}
            if isinstance(llm_values, dict):
                # Filter to string→string for safety.
                llm_values = {
                    str(k): str(v) for k, v in llm_values.items()
                    if isinstance(v, (str, int, float))
                }
                ctx = ctx.merge(llm_values, origin="llm")
        except (json.JSONDecodeError, ValueError):
            pass  # LLM unavailable / malformed — defaults stand.
    return ctx


def load_manual_overrides(target_root: Path) -> dict[str, dict[str, str]]:
    """Read `.agentshield/probe-targets.yaml` if present.

    Shape: `{rule_id: {var: value}}`. Returns an empty dict if the
    file doesn't exist or fails to parse — the operator can opt in
    by creating it, and a malformed file is treated as "no overrides"
    rather than a hard error.
    """
    path = target_root / ".agentshield" / "probe-targets.yaml"
    if not path.exists():
        return {}
    try:
        import yaml
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, Exception):  # noqa: BLE001
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for rule_id, overrides in raw.items():
        if isinstance(rule_id, str) and isinstance(overrides, dict):
            out[rule_id] = {
                str(k): str(v) for k, v in overrides.items()
                if isinstance(v, (str, int, float))
            }
    return out

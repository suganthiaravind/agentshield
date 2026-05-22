"""Pluggable target adapters — how AgentShield talks to a real agent.

------------------------------------------------------------------
Why this exists
------------------------------------------------------------------
Before this module, the probe layer was hard-coded to POST
`{message, session_id}` to a configured URL and read the response
body as a JSON string. That shape happens to match
`testbed/mock-agent/server.py` but not much else. To run AgentShield
against a real customer agent — a Bedrock-Agents invocation, an
OpenAI Assistants thread, a LangChain Serve route, a custom HTTP
bridge — we need a pluggable transport.

The split:
  * The PROBE LAYER decides *what* to send (campaign turn plans,
    payload library, mutation chains).
  * The TARGET ADAPTER decides *how* to send it: URL shape, auth,
    request/response JSON layout, session-id plumbing.

That keeps the campaign engine vendor-neutral. Adding a new agent
runtime is a 50-line adapter, not a fork of the probe layer.

------------------------------------------------------------------
Scanner-side vs scanned-side
------------------------------------------------------------------
This module is the SCANNED-SIDE bridge — the thing AgentShield uses
to talk to the target agent. AgentShield's own LLM stack (judge,
adversary planner, mutation generator) runs inside Copilot via the
existing skills pattern, unrelated to whatever adapter sits here.

------------------------------------------------------------------
target.yaml — the config the customer writes
------------------------------------------------------------------
Lives at `<repo>/.agentshield/target.yaml`. One file per scanned
agent. The CLI loads it via `load_adapter()` below. Example shapes:

  # ----- 1. The bundled mock agent (default) -----
  target:
    type: http-generic
    url: http://localhost:8765/api/agent
    method: POST
    auth:
      kind: none
    request:
      content_type: application/json
      body:
        message: "{{message}}"
        session_id: "{{session_id}}"
    response:
      reply_text_path: $.reply
      tool_calls_path: $.tool_calls

  # ----- 2. AWS Bedrock Agents (skeleton — needs boto3) -----
  target:
    type: bedrock-agents
    agent_id: ABCD1234EF
    agent_alias_id: TSTALIASID
    region: us-east-1

  # ----- 3. LangChain / LangServe -----
  target:
    type: http-generic
    url: https://staging.example.com/agent/invoke
    method: POST
    auth:
      kind: bearer
      env: STAGING_BEARER
    request:
      content_type: application/json
      body:
        input:
          messages:
            - role: user
              content: "{{message}}"
        config:
          configurable:
            session_id: "{{session_id}}"
    response:
      reply_text_path: $.output.content
      tool_calls_path: $.output.tool_calls

The `http-generic` adapter handles 80% of cases declaratively
(dot-path response accessors + Jinja-style `{{message}}` /
`{{session_id}}` substitution anywhere in the request body).
Specialised adapters exist for runtimes whose API isn't
RESTful-POST-and-read-JSON.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


# ----- Errors -----


class AdapterConfigError(Exception):
    """Raised at load time when target.yaml is malformed or
    references a missing env var. Surfaced to the user as a clear
    CLI error rather than a mid-campaign crash."""


# ----- Request / Response shapes -----


@dataclass(frozen=True)
class TargetRequest:
    """One outbound turn from AgentShield to the target agent."""

    message: str
    session_id: str
    timeout_seconds: float = 10.0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetResponse:
    """Normalised reply from the target agent.

    Every adapter MUST populate `reply_text` (the natural-language
    string a user would see in chat) and `raw_body` (the full,
    unmodified response — preserved for the heuristic substring
    classifier and forensic display). `tool_calls` is optional but
    strongly preferred — when the adapter can extract it, the LLM
    judge can reason about tool-layer attacks that don't surface in
    chat output.

    `error` is set only for transport failures (timeout, connection
    refused, auth rejected). A successful HTTP call with a refusal
    reply is `error=None` + the refusal text in `reply_text`.
    """

    reply_text: str
    raw_body: str
    tool_calls: tuple[dict, ...] = ()
    elapsed_ms: int = 0
    http_status: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the transport succeeded. Says nothing about
        whether the *attack* succeeded — that's the classifier's call."""
        return self.error is None


@dataclass(frozen=True)
class AgentMetadata:
    """Optional self-description the adapter can pull from the
    target on startup. Used by the `redteam-plan` Copilot skill to
    adapt campaign turn-text to the specific agent's vocabulary."""

    system_prompt: str = ""
    tool_names: tuple[str, ...] = ()
    tool_descriptions: dict[str, str] = field(default_factory=dict)
    agent_kind: str = ""


# ----- The Protocol every adapter implements -----


@runtime_checkable
class TargetAdapter(Protocol):
    """Sync because the campaign loop is sync today. If we move to
    async later, this becomes `AsyncTargetAdapter` with `async def
    send_turn`. Adapters MUST be stateless across `send_turn` calls
    *except* for the session bookkeeping that the target API
    requires (e.g. an OpenAI adapter caching `thread_id` per
    `session_id`)."""

    name: str

    def send_turn(self, request: TargetRequest) -> TargetResponse:
        """Fire one turn at the target and return the normalised
        reply. MUST NOT raise on transport errors — return a
        TargetResponse with `error` set instead."""
        ...

    def discover_metadata(self) -> AgentMetadata:
        """Best-effort self-description. Returning an empty
        AgentMetadata is fine — the planner degrades."""
        ...


# ----- Helpers used by HttpGenericAdapter -----


def _render_placeholders(value: Any, vars: dict[str, str]) -> Any:
    """Recursively walk a dict/list structure, substituting
    `{{name}}` placeholders in string leaves with the matching
    value from `vars`. Non-string scalars pass through. Lists and
    dicts are deep-copied so the input template stays intact."""
    if isinstance(value, str):
        out = value
        for name, replacement in vars.items():
            out = out.replace("{{" + name + "}}", str(replacement))
        return out
    if isinstance(value, dict):
        return {k: _render_placeholders(v, vars) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_placeholders(v, vars) for v in value]
    return value


def _extract_path(data: Any, path: str) -> Any:
    """Extract a value from nested dict/list at a `$.foo.bar[0].baz`
    path. Returns None if any segment is missing — callers treat
    None as 'reply_text not extractable; fall back to raw_body'.

    Intentionally narrow vs full JSONPath: dots descend into dict
    keys, `[N]` indexes into lists. No wildcards, filters, or
    slices. Covers every agent shape we've seen and stays at
    ~25 lines instead of pulling in jsonpath-ng."""
    if not path:
        return None
    # Tolerate both `$.foo.bar` and `foo.bar` for ergonomics.
    if path.startswith("$."):
        path = path[2:]
    elif path.startswith("$"):
        path = path[1:]
    if not path:
        return data
    cursor: Any = data
    # Split on `.` but keep `[N]` attached to the preceding segment,
    # so `foo[0].bar` -> ["foo[0]", "bar"].
    for raw in path.split("."):
        if not raw:
            continue
        # Pull off any trailing `[N]` indexers (chain like `foo[0][1]`).
        key = raw
        indexers: list[int] = []
        while key.endswith("]") and "[" in key:
            lb = key.rfind("[")
            try:
                indexers.append(int(key[lb + 1:-1]))
            except ValueError:
                return None
            key = key[:lb]
        indexers.reverse()
        if key:
            if not isinstance(cursor, dict) or key not in cursor:
                return None
            cursor = cursor[key]
        for idx in indexers:
            if not isinstance(cursor, list) or idx < 0 or idx >= len(cursor):
                return None
            cursor = cursor[idx]
    return cursor


def _resolve_env(value: Any) -> str:
    """Resolve a config value that may be either a literal string
    or an `{env: VARNAME}` reference. Raises AdapterConfigError
    if the env var is unset — fail-fast at load time so a missing
    secret doesn't blow up mid-campaign."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "env" in value:
        var = value["env"]
        resolved = os.environ.get(var)
        if resolved is None:
            raise AdapterConfigError(
                f"target.yaml references env var ${var} but it is "
                f"not set in the current environment"
            )
        return resolved
    raise AdapterConfigError(
        f"Expected string or {{env: VARNAME}} reference, got: {value!r}"
    )


# ----- Reference adapter #1: http-generic -----


@dataclass(frozen=True)
class HttpGenericAdapter:
    """Declarative HTTP adapter — what the bundled mock agent uses,
    and what most LangChain-style POST-and-read-JSON agents use.
    All shape lives in `target.yaml`; no per-target code."""

    name: str = "http-generic"
    url: str = ""
    method: str = "POST"
    content_type: str = "application/json"
    # Deployment-stage declaration carried over from target.yaml so
    # the campaign-engine's SafetyPolicy can default to "production"
    # when the customer has committed `env: production` to source
    # control. Values: "staging" (default), "production", "mock".
    target_env: str = "staging"
    # Auth: kind in {"none", "bearer", "header", "basic"}; auth_value
    # already resolved from env at load time.
    auth_kind: str = "none"
    auth_value: str = ""
    auth_header_name: str = ""             # for kind="header"
    # Extra static headers (e.g. tenant tags). Keys/values resolved.
    extra_headers: tuple[tuple[str, str], ...] = ()
    # Body template — Python-side dict that becomes JSON. Strings
    # may contain `{{message}}` / `{{session_id}}` placeholders.
    body_template: dict[str, Any] = field(default_factory=dict)
    # Response accessors. None of these are required; if the path
    # doesn't resolve, we fall back to the raw body for reply_text
    # and an empty tuple for tool_calls.
    reply_text_path: str = "$.reply"
    tool_calls_path: str = "$.tool_calls"

    def send_turn(self, request: TargetRequest) -> TargetResponse:
        rendered = _render_placeholders(self.body_template, {
            "message": request.message,
            "session_id": request.session_id,
        })
        body_bytes = json.dumps(rendered).encode("utf-8")
        headers: dict[str, str] = {
            "User-Agent": "agentshield-probe/0.1",
            "Content-Type": self.content_type,
        }
        if self.auth_kind == "bearer":
            headers["Authorization"] = f"Bearer {self.auth_value}"
        elif self.auth_kind == "basic":
            # auth_value is the literal "user:pass" string; base64
            # at send time so it's never logged in clear-text from a
            # config object dump.
            import base64
            token = base64.b64encode(self.auth_value.encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        elif self.auth_kind == "header":
            if not self.auth_header_name:
                return TargetResponse(
                    reply_text="", raw_body="",
                    error="auth.kind=header requires auth.name",
                )
            headers[self.auth_header_name] = self.auth_value
        # auth_kind == "none" -> nothing to add
        for name, value in self.extra_headers:
            headers[name] = value

        req = urllib.request.Request(
            self.url, data=body_bytes, headers=headers, method=self.method,
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=request.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return self._normalise(raw, elapsed_ms, resp.status, None)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            # HTTPError carries a status — keep it as a non-error
            # response so the classifier can still verdict on the
            # body (some agents return 4xx with a meaningful refusal
            # message). The transport DID work.
            return self._normalise(raw, elapsed_ms, e.code, None)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return TargetResponse(
                reply_text="",
                raw_body="",
                elapsed_ms=elapsed_ms,
                error=str(e),
            )

    def _normalise(
        self,
        raw: str,
        elapsed_ms: int,
        http_status: int,
        error: str | None,
    ) -> TargetResponse:
        """Try to JSON-decode the response and extract reply_text +
        tool_calls via the configured paths. If JSON decode fails,
        treat the entire body as reply_text — covers agents that
        return plain text rather than structured JSON."""
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return TargetResponse(
                reply_text=raw,
                raw_body=raw,
                elapsed_ms=elapsed_ms,
                http_status=http_status,
                error=error,
            )
        reply = _extract_path(parsed, self.reply_text_path)
        tools_raw = _extract_path(parsed, self.tool_calls_path)
        tool_calls: tuple[dict, ...] = ()
        if isinstance(tools_raw, list):
            tool_calls = tuple(t for t in tools_raw if isinstance(t, dict))
        return TargetResponse(
            reply_text=str(reply) if reply is not None else raw,
            raw_body=raw,
            tool_calls=tool_calls,
            elapsed_ms=elapsed_ms,
            http_status=http_status,
            error=error,
        )

    def discover_metadata(self) -> AgentMetadata:
        # Generic HTTP has no introspection convention. Customers who
        # need per-target adaptation expose `/.well-known/agent.json`
        # or similar — wire that in here when the convention firms up.
        return AgentMetadata(agent_kind=self.name)


# ----- Reference adapter #2: bedrock-agents (still a skeleton) -----


@dataclass(frozen=True)
class BedrockAgentsAdapter:
    """AWS Bedrock Agents — invokeAgent over the bedrock-agent-runtime
    SDK. Skeleton only; implementation lands when we add `boto3` as
    an optional extra. Why this needs its own adapter (vs
    http-generic): streaming response (`completion` is an event
    stream), sessionId is a top-level SDK param not a body field,
    auth is SigV4 (boto3 handles it, not a static header)."""

    name: str = "bedrock-agents"
    agent_id: str = ""
    agent_alias_id: str = ""
    region: str = "us-east-1"
    aws_profile: str | None = None
    target_env: str = "staging"

    def send_turn(self, request: TargetRequest) -> TargetResponse:
        raise NotImplementedError(
            "BedrockAgentsAdapter — pending boto3 optional dep. See "
            "the implementation sketch in this module's history."
        )

    def discover_metadata(self) -> AgentMetadata:
        raise NotImplementedError(
            "BedrockAgentsAdapter.discover_metadata — pending boto3."
        )


# ----- Loader -----


_VALID_ENVS = ("staging", "production", "mock")


def _resolve_target_env(target: dict) -> str:
    """Pull the deployment-stage declaration off the target block.
    Defaults to 'staging' (permissive) so customers opt INTO 'production'
    explicitly. Raises if the value is unrecognised — typo'd env values
    must not silently degrade to staging."""
    env = target.get("env", "staging")
    if env not in _VALID_ENVS:
        raise AdapterConfigError(
            f"target.env must be one of {_VALID_ENVS}, got {env!r}"
        )
    return env


def _build_http_generic(target: dict) -> HttpGenericAdapter:
    """Validate + build an HttpGenericAdapter from a parsed target
    block. Raises AdapterConfigError on missing required fields."""
    url = target.get("url")
    if not url:
        raise AdapterConfigError("http-generic: target.url is required")
    method = target.get("method", "POST")
    request_block = target.get("request") or {}
    response_block = target.get("response") or {}
    auth_block = target.get("auth") or {"kind": "none"}

    auth_kind = auth_block.get("kind", "none")
    auth_value = ""
    auth_header_name = ""
    if auth_kind == "bearer":
        auth_value = _resolve_env({"env": auth_block["env"]})
    elif auth_kind == "basic":
        auth_value = _resolve_env({"env": auth_block["env"]})
    elif auth_kind == "header":
        auth_header_name = auth_block.get("name") or ""
        if not auth_header_name:
            raise AdapterConfigError(
                "http-generic: auth.kind=header requires auth.name"
            )
        auth_value = _resolve_env({"env": auth_block["env"]})
    elif auth_kind == "none":
        pass
    else:
        raise AdapterConfigError(
            f"http-generic: unsupported auth.kind={auth_kind!r}; "
            f"expected one of: none, bearer, basic, header"
        )

    extra_headers_block = request_block.get("headers") or {}
    extra_headers = tuple(
        (str(k), _resolve_env(v) if isinstance(v, dict) else str(v))
        for k, v in extra_headers_block.items()
    )

    return HttpGenericAdapter(
        url=url,
        method=method,
        content_type=request_block.get("content_type", "application/json"),
        auth_kind=auth_kind,
        auth_value=auth_value,
        auth_header_name=auth_header_name,
        extra_headers=extra_headers,
        body_template=request_block.get("body") or {},
        reply_text_path=response_block.get("reply_text_path", "$.reply"),
        tool_calls_path=response_block.get("tool_calls_path", "$.tool_calls"),
        target_env=_resolve_target_env(target),
    )


def _build_bedrock_agents(target: dict) -> BedrockAgentsAdapter:
    for required in ("agent_id", "agent_alias_id"):
        if not target.get(required):
            raise AdapterConfigError(
                f"bedrock-agents: target.{required} is required"
            )
    return BedrockAgentsAdapter(
        agent_id=target["agent_id"],
        agent_alias_id=target["agent_alias_id"],
        region=target.get("region", "us-east-1"),
        aws_profile=target.get("auth", {}).get("profile"),
        target_env=_resolve_target_env(target),
    )


_BUILDERS: dict[str, Any] = {
    "http-generic": _build_http_generic,
    "bedrock-agents": _build_bedrock_agents,
}


def load_adapter(config_path: Path) -> TargetAdapter:
    """Read `.agentshield/target.yaml` and return the configured
    adapter. Resolves env-var references at load time so the
    adapter object itself never touches os.environ later. Fails
    fast on:
      * file missing / unreadable
      * unparseable YAML
      * unknown target.type
      * missing required field
      * unresolvable env var
    """
    if not config_path.exists():
        raise AdapterConfigError(f"target config not found: {config_path}")
    import yaml
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise AdapterConfigError(f"target.yaml is not valid YAML: {e}") from e
    if not isinstance(raw, dict) or "target" not in raw:
        raise AdapterConfigError(
            "target.yaml must contain a top-level `target:` block"
        )
    target = raw["target"]
    if not isinstance(target, dict):
        raise AdapterConfigError("target.yaml: `target` must be a mapping")
    kind = target.get("type")
    if not kind:
        raise AdapterConfigError("target.yaml: target.type is required")
    builder = _BUILDERS.get(kind)
    if builder is None:
        raise AdapterConfigError(
            f"target.yaml: unknown target.type={kind!r}. Known: "
            f"{sorted(_BUILDERS)}"
        )
    return builder(target)


__all__ = [
    "AdapterConfigError",
    "AgentMetadata",
    "BedrockAgentsAdapter",
    "HttpGenericAdapter",
    "TargetAdapter",
    "TargetRequest",
    "TargetResponse",
    "load_adapter",
]

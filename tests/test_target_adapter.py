"""Tests for the pluggable target-adapter layer.

Covers:
  * helper functions (placeholder rendering, path extraction, env
    resolution) at unit-test granularity
  * the YAML loader's happy and error paths
  * HttpGenericAdapter end-to-end against an in-process stdlib
    HTTPServer so we exercise the real urllib codepath without
    needing the testbed mock to be running
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agentshield.probe.target_adapter import (
    AdapterConfigError,
    AgentMetadata,
    BedrockAgentsAdapter,
    HttpGenericAdapter,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
    load_adapter,
)
from agentshield.probe.target_adapter import (
    _extract_path,
    _render_placeholders,
    _resolve_env,
)


# ---------- helper-function unit tests ----------


def test_render_placeholders_substitutes_in_strings() -> None:
    out = _render_placeholders(
        "Hello {{name}}, your id is {{session_id}}",
        {"name": "Alice", "session_id": "s1"},
    )
    assert out == "Hello Alice, your id is s1"


def test_render_placeholders_walks_dicts_and_lists() -> None:
    template = {
        "input": {
            "messages": [{"role": "user", "content": "{{message}}"}],
            "config": {"configurable": {"session_id": "{{session_id}}"}},
        },
        "model": "claude",
    }
    out = _render_placeholders(template, {"message": "hi", "session_id": "abc"})
    assert out["input"]["messages"][0]["content"] == "hi"
    assert out["input"]["config"]["configurable"]["session_id"] == "abc"
    # Non-string scalars pass through untouched.
    assert out["model"] == "claude"


def test_render_placeholders_leaves_unknown_placeholders_intact() -> None:
    out = _render_placeholders("{{message}} and {{unknown}}", {"message": "hi"})
    assert out == "hi and {{unknown}}"


def test_render_placeholders_does_not_mutate_template() -> None:
    template = {"k": "{{v}}"}
    _render_placeholders(template, {"v": "rendered"})
    assert template == {"k": "{{v}}"}


def test_extract_path_basic_dot_descent() -> None:
    data = {"reply": "ok", "tool_calls": [{"name": "search"}]}
    assert _extract_path(data, "$.reply") == "ok"
    assert _extract_path(data, "reply") == "ok"        # `$` is optional


def test_extract_path_indexes_into_lists() -> None:
    data = {"output": {"messages": [{"role": "user"}, {"role": "assistant"}]}}
    assert _extract_path(data, "$.output.messages[1].role") == "assistant"


def test_extract_path_returns_none_on_missing_segment() -> None:
    data = {"a": {"b": 1}}
    assert _extract_path(data, "$.a.c") is None
    assert _extract_path(data, "$.x.y") is None
    assert _extract_path(data, "$.a.b[0]") is None     # b is not a list


def test_extract_path_empty_path_returns_root() -> None:
    data = {"k": "v"}
    assert _extract_path(data, "$") == data
    assert _extract_path(data, "") is None             # empty string is no-op


def test_resolve_env_passes_through_literal_strings() -> None:
    assert _resolve_env("literal") == "literal"


def test_resolve_env_reads_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSHIELD_TEST_TOKEN", "s3cret")
    assert _resolve_env({"env": "AGENTSHIELD_TEST_TOKEN"}) == "s3cret"


def test_resolve_env_raises_when_var_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENTSHIELD_TEST_TOKEN", raising=False)
    with pytest.raises(AdapterConfigError, match="AGENTSHIELD_TEST_TOKEN"):
        _resolve_env({"env": "AGENTSHIELD_TEST_TOKEN"})


# ---------- adapter Protocol conformance ----------


def test_reference_adapters_satisfy_protocol() -> None:
    """Static + runtime check that both shipped adapters satisfy
    the TargetAdapter Protocol. Catches accidental signature drift."""
    assert isinstance(HttpGenericAdapter(url="http://x"), TargetAdapter)
    assert isinstance(
        BedrockAgentsAdapter(agent_id="A", agent_alias_id="B"),
        TargetAdapter,
    )


def test_http_generic_discover_metadata_returns_kind() -> None:
    md = HttpGenericAdapter(url="http://x").discover_metadata()
    assert isinstance(md, AgentMetadata)
    assert md.agent_kind == "http-generic"
    # Generic HTTP has no introspection — fields are empty.
    assert md.tool_names == ()
    assert md.system_prompt == ""


# ---------- in-process HTTP server fixture for end-to-end tests ----------


class _RecordingHandler(BaseHTTPRequestHandler):
    """In-process handler that records the last request and replies
    with a canned JSON body. The reply shape mirrors the bundled
    mock-agent enough that the default reply_text_path / tool_calls_path
    resolve cleanly."""

    recorded: list[dict] = []
    reply_payload: dict = {
        "reply": "default ok",
        "tool_calls": [{"name": "noop"}],
    }
    reply_status: int = 200

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"_raw": body}
        type(self).recorded.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": parsed,
        })
        payload = json.dumps(type(self).reply_payload).encode("utf-8")
        self.send_response(type(self).reply_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return  # silence stderr noise during tests


@pytest.fixture()
def http_server():
    """Spin a recording HTTPServer on a random port, yield its URL,
    tear it down after the test."""
    _RecordingHandler.recorded = []
    _RecordingHandler.reply_payload = {
        "reply": "default ok",
        "tool_calls": [{"name": "noop"}],
    }
    _RecordingHandler.reply_status = 200
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Tiny wait so the bind is observable; serve_forever runs
    # immediately but the OS may need a tick on busy machines.
    time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# ---------- HttpGenericAdapter end-to-end ----------


def test_http_generic_round_trip_renders_body_and_extracts_reply(
    http_server: str,
) -> None:
    adapter = HttpGenericAdapter(
        url=f"{http_server}/api/agent",
        body_template={"message": "{{message}}", "session_id": "{{session_id}}"},
    )
    resp = adapter.send_turn(TargetRequest(message="hello", session_id="s1"))
    assert resp.ok
    assert resp.reply_text == "default ok"
    assert resp.tool_calls == ({"name": "noop"},)
    # The server saw the rendered body with placeholders substituted.
    rec = _RecordingHandler.recorded[-1]
    assert rec["body"] == {"message": "hello", "session_id": "s1"}


def test_http_generic_extracts_nested_reply_text_path(
    http_server: str,
) -> None:
    _RecordingHandler.reply_payload = {
        "output": {"content": "nested reply"},
        "trace": [{"name": "lookup"}],
    }
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"input": "{{message}}"},
        reply_text_path="$.output.content",
        tool_calls_path="$.trace",
    )
    resp = adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    assert resp.reply_text == "nested reply"
    assert resp.tool_calls == ({"name": "lookup"},)


def test_http_generic_falls_back_to_raw_when_path_misses(
    http_server: str,
) -> None:
    _RecordingHandler.reply_payload = {"unexpected_key": "value"}
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"m": "{{message}}"},
    )
    resp = adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    # reply_text_path doesn't resolve -> reply_text is the raw body.
    assert "unexpected_key" in resp.reply_text
    assert resp.tool_calls == ()


def test_http_generic_handles_plain_text_response(
    http_server: str,
) -> None:
    """Some agents return plain text instead of JSON. Adapter must
    treat the whole body as reply_text and not crash."""
    # Replace the handler to return non-JSON. Content-Length must be
    # set explicitly — without it the client sees a connection reset.
    class _PlainHandler(_RecordingHandler):
        def do_POST(self) -> None:  # noqa: N802
            payload = b"just plain text"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    # Swap on the running server.
    server = HTTPServer(("127.0.0.1", 0), _PlainHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.02)
    try:
        adapter = HttpGenericAdapter(
            url=f"http://127.0.0.1:{port}/x",
            body_template={"m": "{{message}}"},
        )
        resp = adapter.send_turn(TargetRequest(message="hi", session_id="s"))
        assert resp.ok
        assert resp.reply_text == "just plain text"
        assert resp.raw_body == "just plain text"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_generic_returns_error_response_on_connection_refused() -> None:
    """Pick a port nothing is listening on; expect a TargetResponse
    with `error` set rather than an exception."""
    adapter = HttpGenericAdapter(
        url="http://127.0.0.1:1/",          # port 1: nothing should bind here
        body_template={"m": "{{message}}"},
    )
    resp = adapter.send_turn(
        TargetRequest(message="hi", session_id="s", timeout_seconds=2.0),
    )
    assert not resp.ok
    assert resp.error is not None
    assert resp.reply_text == ""


def test_http_generic_preserves_4xx_body_as_response(
    http_server: str,
) -> None:
    """4xx is a successful transport with a meaningful refusal body
    in many agent stacks. Adapter should expose the body, not crash."""
    _RecordingHandler.reply_status = 403
    _RecordingHandler.reply_payload = {"reply": "guardrail blocked"}
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"m": "{{message}}"},
    )
    resp = adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    assert resp.ok                              # transport-level success
    assert resp.http_status == 403
    assert resp.reply_text == "guardrail blocked"


def _header_ci(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup — urllib title-cases custom
    header names (`X-API-Key` -> `X-Api-Key`) so direct dict.get
    fails. HTTP headers are case-insensitive on the wire, so a
    case-insensitive assert is the correct contract."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def test_http_generic_sends_bearer_auth_header(
    http_server: str,
) -> None:
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"m": "{{message}}"},
        auth_kind="bearer",
        auth_value="tok-abc",
    )
    adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    rec = _RecordingHandler.recorded[-1]
    assert _header_ci(rec["headers"], "Authorization") == "Bearer tok-abc"


def test_http_generic_sends_custom_header_auth(
    http_server: str,
) -> None:
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"m": "{{message}}"},
        auth_kind="header",
        auth_header_name="X-API-Key",
        auth_value="k123",
    )
    adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    rec = _RecordingHandler.recorded[-1]
    assert _header_ci(rec["headers"], "X-API-Key") == "k123"


def test_http_generic_sends_extra_headers(
    http_server: str,
) -> None:
    adapter = HttpGenericAdapter(
        url=f"{http_server}/x",
        body_template={"m": "{{message}}"},
        extra_headers=(("X-Tenant", "acme"), ("X-Trace", "abc123")),
    )
    adapter.send_turn(TargetRequest(message="hi", session_id="s"))
    rec = _RecordingHandler.recorded[-1]
    assert _header_ci(rec["headers"], "X-Tenant") == "acme"
    assert _header_ci(rec["headers"], "X-Trace") == "abc123"


# ---------- load_adapter ----------


def test_load_adapter_builds_http_generic_from_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TEST_BEARER", "from-env")
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://localhost:1234/agent\n"
        "  auth:\n"
        "    kind: bearer\n"
        "    env: AGENTSHIELD_TEST_BEARER\n"
        "  request:\n"
        "    content_type: application/json\n"
        "    body:\n"
        "      message: \"{{message}}\"\n"
        "      session_id: \"{{session_id}}\"\n"
        "  response:\n"
        "    reply_text_path: $.output.content\n"
        "    tool_calls_path: $.output.tool_calls\n"
    )
    adapter = load_adapter(cfg)
    assert isinstance(adapter, HttpGenericAdapter)
    assert adapter.url == "http://localhost:1234/agent"
    assert adapter.auth_kind == "bearer"
    assert adapter.auth_value == "from-env"
    assert adapter.reply_text_path == "$.output.content"
    assert adapter.body_template["session_id"] == "{{session_id}}"


def test_load_adapter_builds_bedrock_agents(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: bedrock-agents\n"
        "  agent_id: ABCD1234\n"
        "  agent_alias_id: TSTALIASID\n"
        "  region: us-west-2\n"
    )
    adapter = load_adapter(cfg)
    assert isinstance(adapter, BedrockAgentsAdapter)
    assert adapter.agent_id == "ABCD1234"
    assert adapter.region == "us-west-2"


def test_load_adapter_missing_file_raises() -> None:
    with pytest.raises(AdapterConfigError, match="not found"):
        load_adapter(Path("/nonexistent/target.yaml"))


def test_load_adapter_unknown_type_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text("target:\n  type: invented-runtime\n")
    with pytest.raises(AdapterConfigError, match="unknown target.type"):
        load_adapter(cfg)


def test_load_adapter_missing_url_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text("target:\n  type: http-generic\n")
    with pytest.raises(AdapterConfigError, match="target.url is required"):
        load_adapter(cfg)


def test_load_adapter_missing_env_var_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENTSHIELD_NOT_SET", raising=False)
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://x\n"
        "  auth:\n"
        "    kind: bearer\n"
        "    env: AGENTSHIELD_NOT_SET\n"
    )
    with pytest.raises(AdapterConfigError, match="AGENTSHIELD_NOT_SET"):
        load_adapter(cfg)


def test_load_adapter_unsupported_auth_kind(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://x\n"
        "  auth:\n"
        "    kind: kerberos\n"
    )
    with pytest.raises(AdapterConfigError, match="unsupported auth.kind"):
        load_adapter(cfg)


def test_load_adapter_resolves_extra_header_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTSHIELD_TEST_TENANT", "acme-prod")
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://x\n"
        "  request:\n"
        "    headers:\n"
        "      X-Tenant:\n"
        "        env: AGENTSHIELD_TEST_TENANT\n"
        "      X-Static: literal-value\n"
    )
    adapter = load_adapter(cfg)
    headers = dict(adapter.extra_headers)
    assert headers["X-Tenant"] == "acme-prod"
    assert headers["X-Static"] == "literal-value"

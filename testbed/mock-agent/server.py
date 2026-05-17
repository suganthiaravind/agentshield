"""Mock vulnerable agent — local target for AgentShield probe development.

A minimal HTTP server (stdlib only — no FastAPI dep) that mimics the
customer-support-agent vulnerability pattern. POST a JSON body with a
`message` field; the "agent" runs a fake LLM that obeys any instruction
in the message and returns a `tool_calls` list reflecting what it would
do.

By design, it's vulnerable to direct prompt injection: any message
containing "cancel subscription <id>" produces a tool_call for
cancel_subscription, regardless of who's asking.

Run:
    python testbed/mock-agent/server.py

Then probe:
    agentshield probe testbed/demo-agent --target http://localhost:8765

This server intentionally has NO real backend — tool_calls are described
in the response but never actually executed. It exists purely so the
probe runner has something honest to send packets at during development.
"""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8765


class MockAgentHandler(BaseHTTPRequestHandler):
    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}

    def _respond(self, status: int, body: dict) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        if self.path != "/api/agent" and self.path != "/api/support":
            self._respond(404, {"error": "unknown path", "path": self.path})
            return

        body = self._read_body()
        message = body.get("message", "")
        if not isinstance(message, str):
            self._respond(400, {"error": "message must be a string"})
            return

        tool_calls = _fake_llm_planner(message)
        reply = _fake_llm_reply(message, tool_calls)
        self._respond(200, {"reply": reply, "tool_calls": tool_calls})

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Quieten the default per-request stderr noise so probe output
        # stays clean. Comment out for debugging.
        sys.stderr.write(
            f"[mock-agent] {self.command} {self.path}\n"
        )


def _fake_llm_planner(message: str) -> list[dict]:
    """Decide which tool calls the 'agent' would emit for this message.

    Vulnerable by design: any instruction that mentions cancelling a
    subscription wins, regardless of authority or system prompt. This
    mirrors the agentshield-demo/customer-support-agent pattern.
    """
    calls: list[dict] = []
    cancel_match = re.search(
        r"cancel\s+(?:the\s+)?subscription\s+(\d+|all)",
        message,
        re.IGNORECASE,
    )
    if cancel_match:
        sub_id = cancel_match.group(1)
        try:
            arg_value: object = int(sub_id)
        except ValueError:
            arg_value = sub_id
        calls.append({
            "name": "cancel_subscription",
            "args": {"subscription_id": arg_value},
        })
    return calls


def _fake_llm_reply(message: str, tool_calls: list[dict]) -> str:
    if tool_calls:
        names = ", ".join(c["name"] for c in tool_calls)
        return (
            f"I'll help with that. Calling {names} now."
        )
    return "I'm a support assistant — how can I help?"


def main() -> int:
    server = HTTPServer(("127.0.0.1", PORT), MockAgentHandler)
    print(f"[mock-agent] listening on http://127.0.0.1:{PORT}/api/agent")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-agent] shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())

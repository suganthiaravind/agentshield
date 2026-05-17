"""HTTP probe runner — stdlib only, no `requests` dep.

Sends one payload to the target endpoint and captures (status, headers,
body, elapsed_ms). The caller (classifier) decides whether the captured
response indicates the attack landed.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class RawResponse:
    """What the runner captures from a single request."""

    status: int
    body: str
    headers: dict[str, str]
    elapsed_ms: int
    error: str | None = None


def send_payload(
    target_url: str,
    payload_text: str,
    *,
    timeout_seconds: float = 10.0,
    auth_header: str | None = None,
    extra_headers: tuple[tuple[str, str], ...] = (),
    message_field: str = "message",
    method: str = "POST",
) -> RawResponse:
    """Send `payload_text` as a JSON POST (or GET) to `target_url`.

    For POST, the payload is wrapped as `{"<message_field>": payload_text}`.
    For GET, the payload text is recorded for the trace but no body is
    sent — used by AST02 / AST09 telemetry probes that query the
    target's `/api/agentshield/loaded-skills` and `/recent-logs`
    endpoints.

    `extra_headers` is a tuple of (name, value) pairs added to the
    request — caller's escape hatch for API keys, cookies, tenancy
    headers, etc. `auth_header` is the convenience override for the
    Authorization header specifically.

    Network / transport failures (timeout, refused, DNS) are caught and
    returned as `RawResponse(status=0, error=...)` rather than raised,
    so the orchestrator can record the failure and move on.
    """
    headers = {
        "User-Agent": "agentshield-probe/0.1",
    }
    request_body: bytes | None = None
    if method.upper() == "POST":
        request_body = json.dumps({message_field: payload_text}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    for name, value in extra_headers:
        headers[name] = value
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(
        target_url,
        data=request_body,
        headers=headers,
        method=method.upper(),
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return RawResponse(
                status=resp.status,
                body=body,
                headers=dict(resp.headers),
                elapsed_ms=elapsed_ms,
            )
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return RawResponse(
            status=e.code,
            body=body,
            headers=dict(e.headers or {}),
            elapsed_ms=elapsed_ms,
        )
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return RawResponse(
            status=0,
            body="",
            headers={},
            elapsed_ms=elapsed_ms,
            error=str(e),
        )

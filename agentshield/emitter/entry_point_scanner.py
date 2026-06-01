"""Deterministic entry-point discovery from Python source.

Walks the target repo with Python's ast module to find real handlers:
  - AWS Lambda handlers  (def lambda_handler / any fn taking event+context)
  - Flask / FastAPI HTTP routes  (@app.route, @router.post, etc.)
  - Queue / event consumers  (SQS, SNS, Kafka — detected by decorator name)
  - Orchestrator / sub-agent receivers  (common naming patterns)

Output is written to .agentshield/entry-points.json so the emulator
prompt can reference a code-derived handler set instead of LLM-invented
labels, giving stable "entries scanned" counts across runs.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

# Directories to skip during the walk
_SKIP_DIRS: frozenset[str] = frozenset({
    ".venv", "venv", ".env", "__pycache__", ".agentshield",
    "node_modules", "tests", "test", "testing", ".tox",
    "dist", "build", ".git", ".mypy_cache", ".ruff_cache",
    "site-packages", "htmlcov",
})

# FastAPI / Flask HTTP method attribute names
_HTTP_METHODS: frozenset[str] = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options",
})

# Decorator attribute names that suggest queue / event consumers
_CONSUMER_ATTRS: frozenset[str] = frozenset({
    "on_event", "consumer", "handler",
    "subscribe", "listener", "on_message",
})


def _slugify(text: str) -> str:
    """Turn arbitrary text into a stable lowercase slug."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "handler"


def _path_slug(route: str) -> str:
    """Extract the last meaningful segment of a URL path as a slug."""
    segments = [s for s in route.strip("/").split("/")
                if s and not s.startswith("{")]
    return _slugify(segments[-1]) if segments else "root"


def _decorator_name(dec: ast.expr) -> str:
    """Return a best-effort string for a decorator node."""
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    return ""


def _extract_first_str_arg(call: ast.Call) -> str:
    """Return the first string-literal positional argument of a Call node."""
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return ""


def _scan_python_file(path: Path, repo_root: Path) -> list[dict]:
    """Return entry-point dicts found in one Python file."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    rel = str(path.relative_to(repo_root))
    results: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        func_name: str = node.name
        decorators: list[ast.expr] = node.decorator_list
        handler_ref = f"{rel}:{func_name}"

        # ── 1. AWS Lambda handler ──────────────────────────────────────────
        # Canonical name OR any function whose first two params are
        # `event` and `context` in a file whose stem contains 'handler'.
        is_lambda = func_name == "lambda_handler"
        if not is_lambda and "handler" in Path(rel).stem.lower():
            params = [a.arg for a in node.args.args[:2]]
            if params == ["event", "context"] or params == ["evt", "ctx"]:
                is_lambda = True

        if is_lambda:
            stem = Path(rel).stem
            ep_id = _slugify(f"{stem}_{func_name}") if stem not in ("handler", "lambda") else "lambda_handler"
            results.append({
                "id": ep_id,
                "route": f"Lambda: {rel}",
                "handler": handler_ref,
                "handler_type": "lambda",
                "description": f"AWS Lambda handler in {rel}",
            })
            continue

        # ── 2. HTTP route handlers ─────────────────────────────────────────
        for dec in decorators:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not isinstance(func, ast.Attribute):
                continue

            attr = func.attr.lower()

            # @something.route('/path', methods=['POST', ...])
            if attr == "route":
                url = _extract_first_str_arg(dec)
                method = "HTTP"
                for kw in dec.keywords:
                    if kw.arg == "methods":
                        if isinstance(kw.value, (ast.List, ast.Tuple)):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    method = elt.value.upper()
                                    break
                slug = _path_slug(url) if url else _slugify(func_name)
                results.append({
                    "id": slug,
                    "route": f"{method} {url}" if url else f"{method} (route)",
                    "handler": handler_ref,
                    "handler_type": "http_route",
                    "description": f"{method} {url} in {rel}" if url else f"HTTP route in {rel}",
                })
                break

            # @router.post('/path') / @app.get('/path') / etc.
            if attr in _HTTP_METHODS:
                url = _extract_first_str_arg(dec)
                method = attr.upper()
                slug = _path_slug(url) if url else _slugify(func_name)
                results.append({
                    "id": slug,
                    "route": f"{method} {url}" if url else f"{method} (route)",
                    "handler": handler_ref,
                    "handler_type": "http_route",
                    "description": f"{method} {url} in {rel}" if url else f"HTTP route in {rel}",
                })
                break

            # @something.consumer / @something.subscribe / etc.
            if attr in _CONSUMER_ATTRS:
                slug = _slugify(func_name)
                results.append({
                    "id": slug,
                    "route": f"event: {func_name}",
                    "handler": handler_ref,
                    "handler_type": "event_consumer",
                    "description": f"Event consumer in {rel}",
                })
                break

    return results


def scan_entry_points(target_root: Path) -> list[dict]:
    """Walk all Python files in target_root and return discovered entry points.

    IDs are deduplicated: if two handlers resolve to the same slug the
    second gets a numeric suffix (_2, _3, …).
    """
    target_root = Path(target_root).resolve()
    raw: list[dict] = []

    for py_file in sorted(target_root.rglob("*.py")):
        rel_parts = py_file.relative_to(target_root).parts
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        raw.extend(_scan_python_file(py_file, target_root))

    # Deduplicate IDs while preserving discovery order
    seen: dict[str, int] = {}
    out: list[dict] = []
    for ep in raw:
        base = ep["id"]
        if base not in seen:
            seen[base] = 1
            out.append(ep)
        else:
            seen[base] += 1
            ep = dict(ep)
            ep["id"] = f"{base}_{seen[base]}"
            out.append(ep)

    return out


def write_entry_points(target_root: Path) -> tuple[Path, list[dict]]:
    """Scan target_root and write .agentshield/entry-points.json.

    Returns (output_path, entry_points_list).
    """
    target_root = Path(target_root).resolve()
    entry_points = scan_entry_points(target_root)

    payload = {
        "generated_by": "agentshield-entry-point-scanner",
        "target": str(target_root),
        "entry_points": entry_points,
    }
    out = target_root / ".agentshield" / "entry-points.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return out, entry_points

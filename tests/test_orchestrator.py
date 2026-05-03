"""Unit tests for the judge orchestrator (Track B4).

Uses synthetic Findings + a fake JudgeBackend so tests are hermetic
and independent of the rule corpus / semgrep / Bedrock.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentshield.judge import JudgeBackend, JudgeBackendError, JudgeOrchestrator
from agentshield.judge.source_window import (
    extract_imports,
    read_code_window,
    read_matched_line,
)
from agentshield.judge.types import JudgeRequest
from agentshield.normalize.schema import (
    CodeLocation,
    Finding,
    FrameworkMappings,
    TriageVerdict,
)


def _finding(tier: str, file_path: str = "/tmp/x.py", line: int = 5) -> Finding:
    return Finding(
        rule_id=f"agentshield.detect.fake-{tier}",
        rule_id_short=f"fake-{tier}",
        agentshield_id=f"AS-D-001-{tier.upper()}",
        category="detect",
        tier=tier,  # type: ignore[arg-type]
        severity="medium",
        confidence="low",
        location=CodeLocation(file_path=file_path, start_line=line),
        message="m",
        language="python",
        framework_mappings=FrameworkMappings(),
    )


def _fake_backend(verdict: str = "confirmed") -> Any:
    backend = MagicMock(spec=JudgeBackend)
    backend.name = "fake"
    backend.model_id = "fake-model"
    backend.judge.return_value = TriageVerdict(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.9,
        reasoning="r",
        backend="fake",
        model_id="fake-model",
    )
    return backend


# --- Filtering: only fallback findings get triaged ----------------------


def test_only_fallback_findings_are_triaged() -> None:
    backend = _fake_backend()
    orch = JudgeOrchestrator(backend)
    findings = [
        _finding("framework"),
        _finding("fallback"),
        _finding("framework"),
        _finding("fallback"),
    ]
    out = orch.triage(findings)
    # Both fallback findings should now have triage attached; framework ones not.
    assert [f.tier for f in out] == ["framework", "fallback", "framework", "fallback"]
    assert out[0].triage is None
    assert out[1].triage is not None
    assert out[2].triage is None
    assert out[3].triage is not None


def test_backend_called_once_per_fallback_finding() -> None:
    backend = _fake_backend()
    orch = JudgeOrchestrator(backend)
    orch.triage([_finding("framework"), _finding("fallback"), _finding("fallback")])
    assert backend.judge.call_count == 2


def test_count_fallback_helper() -> None:
    findings = [
        _finding("framework"),
        _finding("fallback"),
        _finding("fallback"),
        _finding("framework"),
    ]
    assert JudgeOrchestrator.count_fallback(findings) == 2


# --- Verdict attachment uses model_copy (immutability) -------------------


def test_triage_returns_new_finding_does_not_mutate_input() -> None:
    backend = _fake_backend()
    orch = JudgeOrchestrator(backend)
    original = _finding("fallback")
    out = orch.triage([original])
    assert original.triage is None  # input untouched
    assert out[0].triage is not None  # output has verdict
    assert out[0].triage.verdict == "confirmed"


# --- Error handling: backend errors → needs_review ----------------------


def test_backend_error_yields_needs_review_verdict() -> None:
    backend = MagicMock(spec=JudgeBackend)
    backend.name = "fake"
    backend.model_id = "fake-model"
    backend.judge.side_effect = JudgeBackendError("Bedrock throttling")
    orch = JudgeOrchestrator(backend)
    out = orch.triage([_finding("fallback")])
    assert out[0].triage is not None
    assert out[0].triage.verdict == "needs_review"
    assert out[0].triage.confidence == 0.0
    assert "Bedrock throttling" in out[0].triage.reasoning


def test_one_finding_error_does_not_block_others() -> None:
    backend = MagicMock(spec=JudgeBackend)
    backend.name = "fake"
    backend.model_id = "fake-model"
    good = TriageVerdict(
        verdict="confirmed", confidence=0.9, reasoning="r", backend="fake", model_id="fake-model"
    )
    backend.judge.side_effect = [JudgeBackendError("transient"), good]
    orch = JudgeOrchestrator(backend)
    out = orch.triage([_finding("fallback"), _finding("fallback")])
    assert out[0].triage.verdict == "needs_review"
    assert out[1].triage.verdict == "confirmed"


# --- JudgeRequest construction ------------------------------------------


def test_request_includes_code_window_and_imports(tmp_path: Path) -> None:
    src = tmp_path / "vuln.py"
    src.write_text(
        "import openai\n"
        "from flask import Flask, request\n"
        "client = openai.OpenAI()\n"
        "def f():\n"
        "    return client.invoke(request.args.get('q'))\n"
    )
    backend = _fake_backend()
    orch = JudgeOrchestrator(backend, context_lines=10)
    f = _finding("fallback", file_path=str(src), line=5)
    orch.triage([f])

    request_arg: JudgeRequest = backend.judge.call_args.args[0]
    assert request_arg.line == 5
    assert "openai" in request_arg.imports_in_file
    assert "flask" in request_arg.imports_in_file
    assert "client.invoke" in request_arg.code_window
    assert "client.invoke" in request_arg.matched_code


# --- Source-window helpers ---------------------------------------------


def test_read_code_window_marks_center_line(tmp_path: Path) -> None:
    src = tmp_path / "f.py"
    src.write_text("a\nb\nc\nd\ne\n")
    window = read_code_window(src, center_line=3, context_lines=1)
    assert ">" in window  # marker present
    lines = window.splitlines()
    # 3 lines: 2, 3, 4
    assert len(lines) == 3
    assert lines[1].lstrip().startswith("> 3")


def test_read_code_window_empty_on_missing_file() -> None:
    assert read_code_window("/nonexistent/path.py", 1) == ""


def test_read_matched_line_returns_exact_line(tmp_path: Path) -> None:
    src = tmp_path / "f.py"
    src.write_text("first\nsecond\nthird\n")
    assert read_matched_line(src, 2) == "second"
    assert read_matched_line(src, 999) == ""


def test_extract_imports_python(tmp_path: Path) -> None:
    src = tmp_path / "x.py"
    src.write_text(
        "import openai\n"
        "import boto3.session\n"
        "from anthropic import Anthropic\n"
        "from langchain.llms import OpenAI\n"
        "import openai  # duplicate\n"
    )
    imports = extract_imports(src, "python")
    assert imports == ["openai", "boto3.session", "anthropic", "langchain.llms"]


def test_extract_imports_java(tmp_path: Path) -> None:
    src = tmp_path / "x.java"
    src.write_text(
        "package com.example;\n"
        "import org.springframework.ai.chat.client.ChatClient;\n"
        "import static java.util.Arrays.asList;\n"
        "import com.openai.api.Client;\n"
    )
    imports = extract_imports(src, "java")
    assert "org.springframework.ai.chat.client.ChatClient" in imports
    assert "java.util.Arrays.asList" in imports
    assert "com.openai.api.Client" in imports


def test_extract_imports_unsupported_language_returns_empty(tmp_path: Path) -> None:
    src = tmp_path / "x.go"
    src.write_text('import "fmt"\n')
    assert extract_imports(src, "go") == []

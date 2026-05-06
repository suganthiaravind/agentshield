"""Tests for the Phase E.3 --exclude glob filter on _enumerate_candidate_files.

The third VDI judge run on a Spring AI codebase showed 17 of 31 findings
(55%) were FPs from `src/test/` files when --scan-all-files was used.
The --exclude flag lets users drop test directories explicitly when
semgrep's built-in .semgrepignore is bypassed.
"""

from pathlib import Path

import pytest

from agentshield.cli import _enumerate_candidate_files, _matches_any_pattern


@pytest.fixture()
def java_tree(tmp_path: Path) -> Path:
    """Lay out a typical Maven/Gradle project with src/main + src/test."""
    (tmp_path / "src/main/java/com/example").mkdir(parents=True)
    (tmp_path / "src/test/java/com/example").mkdir(parents=True)
    (tmp_path / "src/main/java/com/example/Service.java").write_text("class Service {}")
    (tmp_path / "src/test/java/com/example/ServiceTest.java").write_text("class ServiceTest {}")
    return tmp_path


@pytest.fixture()
def python_tree(tmp_path: Path) -> Path:
    (tmp_path / "src/agent").mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/agent/main.py").write_text("x = 1")
    (tmp_path / "tests/test_main.py").write_text("y = 2")
    return tmp_path


def test_no_exclude_includes_everything(java_tree: Path) -> None:
    files = _enumerate_candidate_files(java_tree)
    rels = sorted(p.relative_to(java_tree).as_posix() for p in files)
    assert rels == [
        "src/main/java/com/example/Service.java",
        "src/test/java/com/example/ServiceTest.java",
    ]


def test_exclude_drops_src_test(java_tree: Path) -> None:
    files = _enumerate_candidate_files(java_tree, exclude=["**/src/test/**"])
    rels = sorted(p.relative_to(java_tree).as_posix() for p in files)
    assert rels == ["src/main/java/com/example/Service.java"]


def test_exclude_drops_python_tests(python_tree: Path) -> None:
    files = _enumerate_candidate_files(python_tree, exclude=["**/tests/**"])
    rels = sorted(p.relative_to(python_tree).as_posix() for p in files)
    assert rels == ["src/agent/main.py"]


def test_exclude_multiple_patterns(java_tree: Path, tmp_path: Path) -> None:
    # Add a Python tests dir alongside the Java tree to cover both conventions.
    (java_tree / "tests").mkdir()
    (java_tree / "tests/conftest.py").write_text("")
    files = _enumerate_candidate_files(
        java_tree, exclude=["**/src/test/**", "**/tests/**"]
    )
    rels = sorted(p.relative_to(java_tree).as_posix() for p in files)
    assert rels == ["src/main/java/com/example/Service.java"]


def test_exclude_no_match_keeps_everything(java_tree: Path) -> None:
    files = _enumerate_candidate_files(java_tree, exclude=["**/never/matches/**"])
    assert len(files) == 2


def test_exclude_on_single_file_match(tmp_path: Path) -> None:
    f = tmp_path / "test_x.py"
    f.write_text("z = 0")
    assert _enumerate_candidate_files(f) == [f]
    assert _enumerate_candidate_files(f, exclude=["test_*.py"]) == []


def test_matches_any_pattern_basic(tmp_path: Path) -> None:
    p = tmp_path / "src/test/java/Foo.java"
    p.parent.mkdir(parents=True)
    p.touch()
    assert _matches_any_pattern(p, tmp_path, ["**/src/test/**"])
    assert not _matches_any_pattern(p, tmp_path, ["**/src/main/**"])

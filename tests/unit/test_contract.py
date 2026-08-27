"""Tests for loopkeeper contract path and parsing — ported from Relay contract logic."""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

import pytest

from loopkeeper.contract import contract_relative_path, load_contract_or_empty, parse_contract
from loopkeeper.types import TrustedReader


def test_contract_relative_path_slash_replacement():
    path = contract_relative_path("feat/loop-arbiter")
    assert str(path) == "docs/contracts/feat-loop-arbiter-564bdc00f842.md"
    # slash replaced
    assert "/" not in str(path).split("docs/contracts/")[1].split("-")[0] or "-" in str(path)


def test_contract_relative_path_collision_resistant_hash():
    a = contract_relative_path("feature/a-b")
    b = contract_relative_path("feature-a/b")
    assert a != b
    assert str(a).startswith("docs/contracts/feature-a-b-")
    assert str(b).startswith("docs/contracts/feature-a-b-")
    # Different hashes
    assert a.name != b.name
    # Deterministic
    assert contract_relative_path("feat/loop-arbiter") == contract_relative_path("feat/loop-arbiter")
    # No branch resolves onto README
    assert contract_relative_path("README") != PurePosixPath("docs/contracts/README.md")


def test_contract_relative_path_empty_branch_rejected():
    with pytest.raises((ValueError, TypeError)):
        contract_relative_path("")
    with pytest.raises((ValueError, TypeError)):
        contract_relative_path(None)  # type: ignore


def test_contract_relative_path_control_characters_rejected():
    with pytest.raises(ValueError):
        contract_relative_path("feat\x00bad")
    with pytest.raises(ValueError):
        contract_relative_path("feat\nbad")
    with pytest.raises(ValueError):
        contract_relative_path("feat\rbad")


def test_contract_relative_path_hash_is_sha12():
    branch = "feat/loop-arbiter"
    expected_hash = hashlib.sha256(branch.encode("utf-8")).hexdigest()[:12]
    path = contract_relative_path(branch)
    assert path.name == f"feat-loop-arbiter-{expected_hash}.md"


def test_parse_contract_valid_exact_header():
    text = "# Contract: feat/x\n\n## Goal\nExample.\n"
    contract = parse_contract(text, "feat/x")
    assert contract.branch == "feat/x"
    assert not contract.is_empty
    assert contract.text == text


def test_parse_contract_valid_with_leading_blank_lines():
    text = "\n   \n# Contract: feat/x\nBody\n"
    contract = parse_contract(text, "feat/x")
    assert contract.branch == "feat/x"
    assert not contract.is_empty


def test_parse_contract_mismatched_header_raises():
    text = "# Contract: some/other-branch\n\nBody\n"
    with pytest.raises(ValueError):
        parse_contract(text, "feat/x")


def test_parse_contract_plural_contracts_rejected():
    text = "# Contracts\n\nBody\n"
    with pytest.raises(ValueError):
        parse_contract(text, "feat/x")


def test_parse_contract_empty_text_rejected():
    with pytest.raises(ValueError):
        parse_contract("", "feat/x")
    with pytest.raises(ValueError):
        parse_contract("   \n\n  \n", "feat/x")


def test_parse_contract_rejects_missing_colon():
    text = "# Contract feat/x\n"
    with pytest.raises(ValueError):
        parse_contract(text, "feat/x")


class InMemoryReader:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def read_text(self, path: str, max_bytes: int) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        text = self.files[path]
        if len(text.encode("utf-8")) > max_bytes:
            raise ValueError("too large")
        return text


def test_load_contract_or_empty_missing_returns_empty():
    reader = InMemoryReader({})
    contract = load_contract_or_empty(reader, "feat/missing")
    assert contract.is_empty
    assert contract.branch == "feat/missing"
    assert contract.text == ""


def test_load_contract_or_empty_mismatched_header_returns_empty():
    branch = "feat/x"
    path = str(contract_relative_path(branch))
    reader = InMemoryReader({path: "# Contract: other/branch\nBody"})
    contract = load_contract_or_empty(reader, branch)
    assert contract.is_empty


def test_load_contract_or_empty_valid_returns_contract():
    branch = "feat/x"
    path = str(contract_relative_path(branch))
    body = "# Contract: feat/x\n\n## Goal\nExample.\n"
    reader = InMemoryReader({path: body})
    contract = load_contract_or_empty(reader, branch)
    assert not contract.is_empty
    assert contract.text == body
    assert contract.branch == branch


def test_load_contract_or_empty_uses_reader_bound_to_verified_default_branch():
    # Reader must not open arbitrary paths — ensure loader uses derived path
    branch = "feat/x"
    correct_path = str(contract_relative_path(branch))
    wrong_path = "docs/contracts/wrong.md"
    reader = InMemoryReader({wrong_path: "# Contract: feat/x\n"})
    contract = load_contract_or_empty(reader, branch)
    assert contract.is_empty  # wrong path not used

    # Also ensure loader does not invoke git or filesystem itself
    import inspect
    import loopkeeper.contract as mod
    src = inspect.getsource(mod.load_contract_or_empty)
    assert "subprocess" not in src
    assert "open(" not in src
    assert "git" not in src.lower()


def test_parse_contract_does_not_invoke_git_or_filesystem():
    import inspect
    import loopkeeper.contract as mod
    src = inspect.getsource(mod.parse_contract)
    assert "subprocess" not in src
    assert "open(" not in src

def test_contract_relative_path_pure_no_io():
    import inspect
    import loopkeeper.contract as mod
    src = inspect.getsource(mod.contract_relative_path)
    assert "subprocess" not in src
    assert "open(" not in src
    assert "os." not in src

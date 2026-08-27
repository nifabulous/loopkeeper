from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from loopkeeper.adapters.github.arbiter_io import CollectionUnavailable, _collect_with_api, _collect_with_gh


class FailingDiffApi:
    def get_pr(self, repo: str, pr: int) -> dict:
        return {"headRefOid": "a" * 40, "state": "OPEN"}

    def get_pr_diff_files(self, repo: str, pr: int) -> list[str]:
        raise RuntimeError("GitHub API unavailable")

    def list_comments(self, repo: str, pr: int, per_page: int, page: int) -> list[dict]:
        return []


def test_changed_file_read_failure_is_unavailable_not_empty_evidence():
    with pytest.raises(CollectionUnavailable, match="changed files"):
        _collect_with_api("example/project", 7, "b" * 40, "github-actions[bot]", FailingDiffApi())


def test_gh_changed_file_read_failure_is_unavailable_not_empty_evidence(monkeypatch):
    def fake_run(args, **kwargs):
        if args[:3] == ["git", "rev-parse", "HEAD"]:
            return SimpleNamespace(stdout="a" * 40)
        if args[:3] == ["gh", "pr", "view"] and args[-1] == "state,headRefOid,headRefName":
            return SimpleNamespace(stdout=json.dumps({"headRefOid": "b" * 40, "state": "OPEN"}))
        if args[:3] == ["gh", "pr", "view"] and args[-1] == "files":
            raise RuntimeError("GitHub API unavailable")
        if args[:2] == ["gh", "api"]:
            return SimpleNamespace(stdout="[]")
        raise AssertionError(f"unexpected command: {args}")

    monkeypatch.setattr("loopkeeper.adapters.github.arbiter_io.subprocess.run", fake_run)
    with pytest.raises(CollectionUnavailable, match="changed files"):
        _collect_with_gh("example/project", 7, "a" * 40, "github-actions[bot]")


def test_arbiter_writer_requires_explicit_operator_argument(monkeypatch):
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    monkeypatch.setattr("loopkeeper.adapters.github.arbiter_io.subprocess.run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("API must not be called")))
    with pytest.raises(PermissionError, match="operator argument"):
        from loopkeeper.adapters.github.arbiter_io import post_arbiter_comment

        post_arbiter_comment("example/project", 7, object(), False)

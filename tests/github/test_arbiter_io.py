from __future__ import annotations

import json
import io
import os
import re
from types import SimpleNamespace

import pytest

from loopkeeper.adapters.github.arbiter_io import (
    CollectionUnavailable,
    _collect_with_api,
    _collect_with_gh,
    _read_arbiter_comments,
    post_arbiter_comment,
)


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


class _ArbiterCommentGH:
    def __init__(self, head: str):
        self.head = head
        self.comments: list[dict] = []
        self.calls: list[list[str]] = []

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ["gh", "pr", "view"]:
            return SimpleNamespace(stdout=json.dumps({"headRefOid": self.head, "state": "OPEN"}))
        if args[:2] == ["gh", "api"] and "--method" not in args:
            payload = json.dumps(self.comments)
            if output := kwargs.get("stdout"):
                output.write(payload.encode("utf-8"))
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(stdout=payload)
        if args[:3] == ["gh", "pr", "comment"]:
            body = kwargs["input"].decode("utf-8")
            self.comments.append({
                "id": len(self.comments) + 1,
                "user": {"login": "github-actions[bot]"},
                "body": body,
            })
            return SimpleNamespace(stdout="{}")
        if args[:3] == ["gh", "api", "--method"]:
            raise AssertionError("append-only arbiter writer must not PATCH a prior comment")
        raise AssertionError(f"unexpected command: {args}")

    def popen(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["gh", "api"] and "--method" not in args:
            return _FakeProcess(json.dumps(self.comments).encode("utf-8"))
        raise AssertionError(f"unexpected command: {args}")


class _FakeProcess:
    def __init__(self, payload: bytes):
        self.stdout = io.BytesIO(payload)
        self.returncode = None

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _MalformedArbiterCommentsGH(_ArbiterCommentGH):
    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ["gh", "pr", "view"]:
            return SimpleNamespace(stdout=json.dumps({"headRefOid": self.head, "state": "OPEN"}))
        if args[:2] == ["gh", "api"] and "--method" not in args:
            payload = json.dumps({"not": "a list"})
            if output := kwargs.get("stdout"):
                output.write(payload.encode("utf-8"))
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(stdout=payload)
        return super().run(args, **kwargs)

    def popen(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["gh", "api"] and "--method" not in args:
            return _FakeProcess(json.dumps({"not": "a list"}).encode("utf-8"))
        return super().popen(args, **kwargs)


class _PaginatedArbiterCommentGH(_ArbiterCommentGH):
    def run(self, args, **kwargs):
        if args[:2] == ["gh", "api"] and "--method" not in args:
            self.calls.append(args)
            page_match = re.search(r"[?&]page=(\d+)", args[2])
            page = int(page_match.group(1)) if page_match else 1
            start = (page - 1) * 100
            payload = json.dumps(self.comments[start : start + 100])
            if output := kwargs.get("stdout"):
                output.write(payload.encode("utf-8"))
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(stdout=payload)
        return super().run(args, **kwargs)

    def popen(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["gh", "api"] and "--method" not in args:
            page_match = re.search(r"[?&]page=(\d+)", args[2])
            page = int(page_match.group(1)) if page_match else 1
            start = (page - 1) * 100
            payload = json.dumps(self.comments[start : start + 100]).encode("utf-8")
            return _FakeProcess(payload)
        return super().popen(args, **kwargs)


def _patch_arbiter_gh(monkeypatch, fake):
    monkeypatch.setattr("loopkeeper.adapters.github.arbiter_io.subprocess.run", fake.run)
    monkeypatch.setattr("loopkeeper.adapters.github.arbiter_io.subprocess.Popen", fake.popen)


def _arbiter_decision(round_count: int):
    return SimpleNamespace(
        recommendation="CONTINUE",
        loop_action="CONTINUE",
        cited_rule="CONTINUE",
        needs_human=False,
        round_count=round_count,
        proposed_gaps=[],
        detail="",
    )


def test_arbiter_comment_appends_changed_decision_for_same_head(monkeypatch):
    head = "a" * 40
    fake = _ArbiterCommentGH(head)
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    post_arbiter_comment("example/project", 7, _arbiter_decision(1), True)
    post_arbiter_comment("example/project", 7, _arbiter_decision(2), True)

    assert len(fake.comments) == 2
    assert not any("--method" in call for call in fake.calls)
    assert fake.comments[0]["body"] != fake.comments[1]["body"]


def test_arbiter_comment_suppresses_exact_decision_retry(monkeypatch):
    head = "b" * 40
    fake = _ArbiterCommentGH(head)
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    decision = _arbiter_decision(1)
    post_arbiter_comment("example/project", 7, decision, True)
    post_arbiter_comment("example/project", 7, decision, True)

    assert len(fake.comments) == 1
    assert not any("--method" in call for call in fake.calls)


def test_arbiter_comment_suppresses_retry_when_marker_is_on_second_page(monkeypatch):
    head = "e" * 40
    fake = _PaginatedArbiterCommentGH(head)
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    decision = _arbiter_decision(1)
    post_arbiter_comment("example/project", 7, decision, True)
    exact_comment = fake.comments[0]
    fake.comments[:0] = [
        {"id": index + 2, "user": {"login": "someone-else"}, "body": "filler"}
        for index in range(100)
    ]

    post_arbiter_comment("example/project", 7, decision, True)

    marker = exact_comment["body"].splitlines()[0]
    assert sum(marker in comment["body"] for comment in fake.comments) == 1
    assert any("page=2" in call[2] for call in fake.calls if call[:2] == ["gh", "api"])


def test_arbiter_comment_fails_closed_when_comment_page_cap_is_reached(monkeypatch):
    fake = _PaginatedArbiterCommentGH("f" * 40)
    fake.comments = [
        {"id": index + 1, "user": {"login": "someone-else"}, "body": "filler"}
        for index in range(1000)
    ]
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    with pytest.raises(RuntimeError, match="page cap"):
        post_arbiter_comment("example/project", 7, _arbiter_decision(1), True)

    assert len(fake.comments) == 1000


def test_arbiter_comment_rejects_oversized_page_before_json_parse(tmp_path, monkeypatch):
    fake_gh = tmp_path / "gh"
    completed = tmp_path / "completed"
    fake_gh.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "for _ in range(1024):\n"
        "    sys.stdout.write('x' * 1024)\n"
        "    sys.stdout.flush()\n"
        "pathlib.Path(os.environ['LOOPKEEPER_TEST_COMPLETED']).write_text('completed')\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("LOOPKEEPER_CHECK_MAX_RAW_BYTES", "64")
    monkeypatch.setenv("LOOPKEEPER_TEST_COMPLETED", str(completed))
    real_loads = json.loads

    def reject_oversized_parse(raw):
        if isinstance(raw, str) and len(raw.encode("utf-8")) > 64:
            raise AssertionError("oversized response reached JSON parsing")
        return real_loads(raw)

    monkeypatch.setattr("loopkeeper.adapters.github.arbiter_io.json.loads", reject_oversized_parse)

    with pytest.raises(RuntimeError, match="byte cap"):
        _read_arbiter_comments("example/project", 7)

    assert not completed.exists()


def test_arbiter_comment_does_not_reuse_legacy_marker(monkeypatch):
    head = "c" * 40
    fake = _ArbiterCommentGH(head)
    fake.comments.append({
        "id": 99,
        "user": {"login": "github-actions[bot]"},
        "body": f"<!-- loopkeeper-arbiter:7:{head} -->\nlegacy disposition",
    })
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    post_arbiter_comment("example/project", 7, _arbiter_decision(1), True)

    assert len(fake.comments) == 2
    assert "legacy disposition" in fake.comments[0]["body"]
    assert not any("--method" in call for call in fake.calls)


def test_arbiter_comment_fails_closed_on_malformed_comment_read(monkeypatch):
    fake = _MalformedArbiterCommentsGH("d" * 40)
    monkeypatch.setenv("LOOPKEEPER_OPERATOR", "1")
    _patch_arbiter_gh(monkeypatch, fake)

    with pytest.raises(RuntimeError, match="could not list comments for arbiter"):
        post_arbiter_comment("example/project", 7, _arbiter_decision(1), True)

    assert not any(call[:3] == ["gh", "pr", "comment"] for call in fake.calls)

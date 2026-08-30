"""Fail-closed subprocess contracts for the issue-triage writer."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRITER = ROOT / "adapters" / "github" / "post_triage_comment.sh"
ISSUE_NUMBER = "42"
REPO = "example-org/consumer"
BOT = "github-actions[bot]"
MAX_RAW_BYTES = 4096


def _fingerprint(title: str = "Stub issue", body: str = "Stub body") -> str:
    canonical = json.dumps({"title": title, "body": body}, separators=(",", ":")) + "\n"
    return hashlib.sha256(canonical.encode()).hexdigest()


def _write_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -uo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    *,
    operator: str | None = "1",
    artifact: bool = True,
    title: str = "Stub issue",
    body: str = "Stub body",
    state: str = "OPEN",
    metadata_padding: int = 0,
    comments_available: bool = True,
    existing_marker: bool = False,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    assert WRITER.is_file(), "the triage writer adapter must exist"
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    log = tmp_path / "invocations.log"
    log.touch()
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    fingerprint = _fingerprint()
    marker = f"<!-- loopkeeper-issue-triage:{ISSUE_NUMBER}:{fingerprint} -->"
    if artifact:
        (artifact_dir / "triage.md").write_text("Stub triage.\n", encoding="utf-8")
        (artifact_dir / "comment.md").write_text(f"{marker}\n\nStub triage.\n", encoding="utf-8")
        (artifact_dir / "triage-metadata.json").write_text(
            json.dumps({"issue_number": int(ISSUE_NUMBER), "fingerprint": fingerprint}),
            encoding="utf-8",
        )

    issue = json.dumps(
        {"title": title, "body": body + ("x" * metadata_padding), "state": state}
    )
    comments = (
        json.dumps([{"user": {"login": BOT}, "body": marker}])
        if existing_marker
        else "[]"
    )
    gh_stub = f'''\nprintf '%s\\n' "gh $*" >>"$LOOPKEEPER_TEST_LOG"
case "$*" in
  "issue view"*) printf '%s\\n' {json.dumps(issue)} ;;
  "api repos/"*"/issues/"*"/comments"*)
    [[ "$LOOPKEEPER_TEST_COMMENTS_AVAILABLE" == "1" ]] || exit 1
    if [[ "$*" == *"page=1" ]]; then
      printf '%s\\n' {json.dumps(comments)}
    else
      printf '[]\\n'
    fi
    ;;
  "issue comment"*) printf 'created\\n' ;;
  *) exit 1 ;;
esac
'''
    _write_stub(stubs / "gh", gh_stub)

    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{stubs}{os.pathsep}{env['PATH']}",
            "LOOPKEEPER_TEST_LOG": str(log),
            "LOOPKEEPER_TEST_COMMENTS_AVAILABLE": "1" if comments_available else "0",
            "GH_TOKEN": "stub-token",
            "GH_REPO": REPO,
            "LOOPKEEPER_TRIAGE_ARTIFACT_DIR": str(artifact_dir),
            "LOOPKEEPER_CHECK_MAX_RAW_BYTES": str(MAX_RAW_BYTES),
            "LOOPKEEPER_BOT_LOGIN": BOT,
        }
    )
    if operator is None:
        env.pop("LOOPKEEPER_OPERATOR", None)
    else:
        env["LOOPKEEPER_OPERATOR"] = operator
    result = subprocess.run(
        [str(WRITER), ISSUE_NUMBER],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def _writes(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("gh issue comment")]


def test_writer_refuses_missing_operator_flag(tmp_path):
    result, calls = _run(tmp_path, operator=None)
    assert result.returncode != 0
    assert _writes(calls) == []


def test_writer_refuses_missing_artifact(tmp_path):
    result, calls = _run(tmp_path, artifact=False)
    assert result.returncode != 0
    assert _writes(calls) == []


def test_writer_refuses_changed_issue_fingerprint(tmp_path):
    result, calls = _run(tmp_path, title="Changed issue")
    assert result.returncode == 0
    assert _writes(calls) == []


def test_writer_refuses_closed_issue(tmp_path):
    result, calls = _run(tmp_path, state="CLOSED")
    assert result.returncode == 0
    assert _writes(calls) == []


def test_writer_refuses_oversized_metadata(tmp_path):
    result, calls = _run(tmp_path, metadata_padding=MAX_RAW_BYTES + 1)
    assert result.returncode != 0
    assert _writes(calls) == []


def test_writer_refuses_unavailable_comment_history(tmp_path):
    result, calls = _run(tmp_path, comments_available=False)
    assert result.returncode != 0
    assert _writes(calls) == []


def test_writer_suppresses_existing_authenticated_marker(tmp_path):
    result, calls = _run(tmp_path, existing_marker=True)
    assert result.returncode == 0
    assert _writes(calls) == []


def test_writer_posts_exactly_once_after_all_rechecks(tmp_path):
    result, calls = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert len(_writes(calls)) == 1

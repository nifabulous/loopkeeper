"""Source and behavior contract for the GitHub PR-review adapter.

The review writer runs in the job that holds ``pull-requests: write``. These
tests assert that no consumer-controlled value can reach the Python it
executes: every embedded block is a quoted heredoc, shell values arrive
through ``sys.argv``, and the consumer checkout is never placed on
``sys.path`` where it could shadow the trusted ``loopkeeper`` package.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from loopkeeper.adapters.github.comment_state import (
    CommentState,
    decide_comment_action,
)

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / "adapters" / "github" / "review_pr.sh"

HEAD_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
BOT = "github-actions[bot]"

_HEREDOC_START = re.compile(r"<<(?P<quote>'?)(?P<tag>PY)(?P=quote)")


@dataclass(frozen=True)
class Heredoc:
    """One embedded Python block extracted from the adapter source."""

    line_number: int
    header: str
    body: str
    quoted: bool

    @property
    def has_arguments(self) -> bool:
        """True when the header passes positional arguments to the block."""
        before = self.header.split("<<", 1)[0]
        return bool(re.search(r"python3\s+-\s+\S", before))


def _heredocs() -> list[Heredoc]:
    lines = REVIEW.read_text(encoding="utf-8").splitlines()
    found: list[Heredoc] = []
    index = 0
    while index < len(lines):
        match = _HEREDOC_START.search(lines[index])
        if not match:
            index += 1
            continue
        header = lines[index]
        quoted = match.group("quote") == "'"
        body: list[str] = []
        cursor = index + 1
        while cursor < len(lines) and lines[cursor].strip() != "PY":
            body.append(lines[cursor])
            cursor += 1
        found.append(
            Heredoc(
                line_number=index + 1,
                header=header,
                body="\n".join(body),
                quoted=quoted,
            )
        )
        index = cursor + 1
    return found


def test_embedded_python_blocks_are_discoverable():
    """Guard the parser itself so the other source tests cannot vacuously pass."""
    blocks = _heredocs()
    assert len(blocks) >= 7, f"expected the adapter's Python blocks, found {len(blocks)}"


def test_review_script_has_no_consumer_sys_path_insertion():
    """The reviewed repository must never precede trusted code on sys.path."""
    source = REVIEW.read_text(encoding="utf-8")
    assert "sys.path.insert(0" not in source
    assert "sys.path.insert" not in source


def test_every_embedded_python_heredoc_is_quoted():
    """An unquoted heredoc interpolates shell values into Python source."""
    unquoted = [block.line_number for block in _heredocs() if not block.quoted]
    assert unquoted == [], f"unquoted Python heredocs at lines {unquoted}"


def test_review_metadata_values_are_passed_as_arguments():
    """Blocks that need shell values must receive them through sys.argv."""
    for block in _heredocs():
        if block.has_arguments:
            assert "sys.argv" in block.body, (
                f"block at line {block.line_number} takes arguments but never reads sys.argv"
            )


def test_no_embedded_python_block_interpolates_a_shell_variable():
    """No Python block may contain a shell expansion, quoted or otherwise."""
    offenders: list[tuple[int, str]] = []
    for block in _heredocs():
        for raw in block.body.splitlines():
            if re.search(r'"\$\{?[A-Za-z_]', raw):
                offenders.append((block.line_number, raw.strip()))
    assert offenders == [], f"shell interpolation inside Python: {offenders}"


def test_workflow_run_ci_replaces_fallback_for_same_head():
    """Exact-head CI evidence replaces a fallback comment in place."""
    existing = [
        CommentState(
            comment_id=101,
            head_sha=HEAD_SHA,
            evidence_state="fallback",
            author_login=BOT,
            body="prior fallback review",
            created_at="2026-01-01T00:00:00Z",
        )
    ]

    action = decide_comment_action(existing, "ci", HEAD_SHA)

    assert action.kind == "REPLACE_FALLBACK"
    assert action.canonical_id == 101
    assert action.superseded_ids == ()


def test_ci_replay_keeps_one_current_head_comment():
    """Replaying CI evidence for the same head creates no second comment."""
    existing = [
        CommentState(
            comment_id=101,
            head_sha=HEAD_SHA,
            evidence_state="ci",
            author_login=BOT,
            body="already replaced with CI evidence",
            created_at="2026-01-01T00:00:00Z",
        )
    ]

    action = decide_comment_action(existing, "ci", HEAD_SHA)

    assert action.kind == "SUPPRESS_DUPLICATE"
    assert action.kind != "CREATE"
    assert action.canonical_id == 101

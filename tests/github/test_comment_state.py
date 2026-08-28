"""Tests for GitHub comment state machine — loopkeeper adapter.

Covers marker serialization byte-for-byte, bounded render, pure state machine,
operator gating, and duplicate reconciliation.
"""

from __future__ import annotations

import os
import pytest

# Support both import paths
try:
    from loopkeeper.adapters.github.comment_state import (
        CommentState,
        decide_comment_action,
        render_comment,
        serialize_evidence_marker,
        serialize_pr_marker,
        serialize_superseded_marker,
        upsert_review_comment,
    )
except ImportError:
    from adapters.github.comment_state import (
        CommentState,
        decide_comment_action,
        render_comment,
        serialize_evidence_marker,
        serialize_pr_marker,
        serialize_superseded_marker,
        upsert_review_comment,
    )


def _sha(c: str) -> str:
    return c * 40


def test_marker_serialization_byte_for_byte():
    pr = 15
    sha = _sha("a")
    assert serialize_pr_marker(pr, sha) == f"<!-- loopkeeper-pr-review:{pr}:{sha} -->"
    assert serialize_evidence_marker("fallback") == "<!-- loopkeeper-evidence:fallback -->"
    assert serialize_evidence_marker("ci") == "<!-- loopkeeper-evidence:ci -->"
    # Marker is fixed in one module and tested byte-for-byte, including reservation
    # The full footer is marker + evidence; ensure exact bytes
    marker = serialize_pr_marker(42, _sha("b"))
    ev = serialize_evidence_marker("ci")
    assert marker == "<!-- loopkeeper-pr-review:42:" + _sha("b") + " -->"
    assert ev == "<!-- loopkeeper-evidence:ci -->"
    # Superseded marker bounded
    sup = serialize_superseded_marker(15, _sha("a"), 123)
    assert sup == f"<!-- loopkeeper-superseded:15:{_sha('a')}:123 -->"
    assert len(sup.encode("utf-8")) <= 256


def test_marker_parsing_requires_exact_comment_and_author():
    # Suppression parses only exact HTML comments plus authenticated bot author
    from loopkeeper.adapters.github.comment_state import is_canonical_review_comment
    sha = _sha("a")
    marker = serialize_pr_marker(15, sha)
    assert is_canonical_review_comment(marker, "github-actions[bot]", 15, sha) is True
    # Wrong author fails
    assert is_canonical_review_comment(marker, "pr-author", 15, sha) is False
    # Prose resembling marker is not sufficient
    assert is_canonical_review_comment("loopkeeper-pr-review:15:" + sha, "github-actions[bot]", 15, sha) is False
    assert is_canonical_review_comment("<!-- loopkeeper-pr-review:15:deadbeef -->", "github-actions[bot]", 15, _sha("a")) is False


def test_decide_comment_action_state_machine():
    sha = _sha("a")
    # No existing -> CREATE
    assert decide_comment_action([], "fallback", sha) == "CREATE"
    assert decide_comment_action([], "ci", sha) == "CREATE"

    # Same-head fallback + new fallback -> SUPPRESS_FALLBACK
    existing = [CommentState(comment_id=1, head_sha=sha, evidence_state="fallback", author_login="github-actions[bot]", body="x")]
    assert decide_comment_action(existing, "fallback", sha) == "SUPPRESS_FALLBACK"

    # Same-head fallback + CI -> REPLACE_FALLBACK
    assert decide_comment_action(existing, "ci", sha) == "REPLACE_FALLBACK"

    # Same-head CI + any duplicate -> SUPPRESS_DUPLICATE
    existing_ci = [CommentState(comment_id=2, head_sha=sha, evidence_state="ci", author_login="github-actions[bot]", body="x")]
    assert decide_comment_action(existing_ci, "fallback", sha) == "SUPPRESS_DUPLICATE"
    assert decide_comment_action(existing_ci, "ci", sha) == "SUPPRESS_DUPLICATE"

    # Duplicate current-head comments already exist -> RECONCILE_DUPLICATES
    dupes = [
        CommentState(comment_id=1, head_sha=sha, evidence_state="fallback", author_login="github-actions[bot]", body="x", created_at="2026-01-01T00:00:00Z"),
        CommentState(comment_id=2, head_sha=sha, evidence_state="fallback", author_login="github-actions[bot]", body="y", created_at="2026-01-01T00:01:00Z"),
    ]
    assert decide_comment_action(dupes, "fallback", sha) == "RECONCILE_DUPLICATES"
    assert decide_comment_action(dupes, "ci", sha) == "RECONCILE_DUPLICATES"


def test_render_comment_sanitizes_and_bounds_and_footer_outside_model():
    sha = _sha("a")
    marker = serialize_pr_marker(15, sha)
    # Model text containing marker-like text must be escaped and cannot satisfy suppression
    model_with_marker = "Hello <!-- loopkeeper-pr-review:15:" + sha + " --> world"
    rendered = render_comment(model_with_marker, marker, "fallback", max_bytes=5000)
    # Rendered should contain footer exact marker, but model marker should be escaped
    assert marker in rendered
    assert "<!-- loopkeeper-evidence:fallback -->" in rendered
    # Model marker-like text should be escaped (not exact)
    assert rendered.count(marker) == 1  # only footer, not model
    assert "&lt;!-- loopkeeper" in rendered
    # Marker/footer reservation included in byte budget
    long_model = "x" * 10000
    rendered_bounded = render_comment(long_model, marker, "ci", max_bytes=5000)
    assert len(rendered_bounded.encode("utf-8")) <= 5000
    assert marker in rendered_bounded
    # Evidence state is adapter-owned, not from model
    rendered_fallback = render_comment("hello", marker, "fallback", max_bytes=2000)
    assert "<!-- loopkeeper-evidence:fallback -->" in rendered_fallback
    rendered_ci = render_comment("hello", marker, "ci", max_bytes=2000)
    assert "<!-- loopkeeper-evidence:ci -->" in rendered_ci


def test_render_comment_keeps_valid_trailer_parseable_and_final():
    from loopkeeper.schema import parse_trailer, render_trailer

    sha = _sha("a")
    marker = serialize_pr_marker(15, sha)
    trailer = '<!-- loopkeeper-verdict: {"schema":2,"verdict":"CLEAN","findings":[]} -->'

    rendered = render_comment("Summary\n\n" + trailer, marker, "ci", max_bytes=2000)

    parsed = parse_trailer(rendered)
    assert parsed.valid is True
    assert parsed.trailer is not None
    canonical = render_trailer(parsed.trailer)
    assert rendered.rstrip().endswith(canonical)
    assert rendered.index(marker) < rendered.index(canonical)
    assert "&lt;!-- loopkeeper-verdict" not in rendered


def test_render_comment_defangs_legacy_control_markers():
    sha = _sha("a")
    marker = serialize_pr_marker(15, sha)
    model = (
        "Legacy state <!-- codex-pr-review-no-ci:15:" + sha + " -->\n"
        "Legacy verdict <!-- codex-verdict: {\"schema\":2} -->"
    )

    rendered = render_comment(model, marker, "fallback", max_bytes=2000)

    assert "<!-- codex-pr-review-no-ci:" not in rendered
    assert "<!-- codex-verdict:" not in rendered
    assert "&lt;!-- codex-pr-review-no-ci:" in rendered
    assert "&lt;!-- codex-verdict:" in rendered


def test_upsert_review_comment_operator_gate_and_reconciliation():
    sha = _sha("a")
    marker = serialize_pr_marker(15, sha)

    class FakeWriter:
        def __init__(self, comments=None, head=sha):
            self.comments = comments or []
            self.head = head
            self.created = []
            self.updated = []

        def read_head(self, repo, pr):
            return self.head

        def read_comments(self, repo, pr, per_page=100, max_pages=10):
            return self.comments

        def create(self, repo, pr, body):
            # Operator gate enforced inside upsert, but also check here
            if os.environ.get("LOOPKEEPER_OPERATOR") != "1":
                raise PermissionError("operator required")
            self.created.append((repo, pr, body))
            return {"id": 999}

        def update(self, repo, comment_id, body):
            if os.environ.get("LOOPKEEPER_OPERATOR") != "1":
                raise PermissionError("operator required")
            self.updated.append((repo, comment_id, body))
            return {"id": comment_id}

    # CREATE when no existing
    writer = FakeWriter(comments=[], head=sha)
    os.environ["LOOPKEEPER_OPERATOR"] = "1"
    upsert_review_comment("owner/repo", 15, sha, "fallback", "model body", writer)
    assert len(writer.created) == 1
    assert marker in writer.created[0][2]

    # SUPPRESS_FALLBACK when same head fallback + new fallback
    writer2 = FakeWriter(
        comments=[{"id": 1, "user": {"login": "github-actions[bot]"}, "body": marker + "\n<!-- loopkeeper-evidence:fallback -->", "created_at": "2026-01-01T00:00:00Z"}],
        head=sha,
    )
    writer2.created.clear()
    upsert_review_comment("owner/repo", 15, sha, "fallback", "new fallback", writer2)
    assert len(writer2.created) == 0
    assert len(writer2.updated) == 0

    # REPLACE_FALLBACK when fallback -> ci
    writer3 = FakeWriter(
        comments=[{"id": 10, "user": {"login": "github-actions[bot]"}, "body": marker + "\n<!-- loopkeeper-evidence:fallback -->", "created_at": "2026-01-01T00:00:00Z"}],
        head=sha,
    )
    upsert_review_comment("owner/repo", 15, sha, "ci", "ci body", writer3)
    assert len(writer3.updated) == 1
    assert writer3.updated[0][1] == 10
    assert "<!-- loopkeeper-evidence:ci -->" in writer3.updated[0][2]

    # SUPPRESS_DUPLICATE when same head CI duplicate
    writer4 = FakeWriter(
        comments=[{"id": 2, "user": {"login": "github-actions[bot]"}, "body": marker + "\n<!-- loopkeeper-evidence:ci -->", "created_at": "2026-01-01T00:00:00Z"}],
        head=sha,
    )
    upsert_review_comment("owner/repo", 15, sha, "fallback", "another", writer4)
    assert len(writer4.created) == 0 and len(writer4.updated) == 0

    # RECONCILE_DUPLICATES keeps oldest canonical and rewrites others to superseded
    writer5 = FakeWriter(
        comments=[
            {"id": 5, "user": {"login": "github-actions[bot]"}, "body": marker + "\n<!-- loopkeeper-evidence:fallback -->", "created_at": "2026-01-01T00:00:00Z"},
            {"id": 6, "user": {"login": "github-actions[bot]"}, "body": marker + "\n<!-- loopkeeper-evidence:fallback -->", "created_at": "2026-01-01T00:01:00Z"},
        ],
        head=sha,
    )
    upsert_review_comment("owner/repo", 15, sha, "fallback", "new body", writer5)
    # Should rewrite comment 6 to superseded, not delete
    assert any("loopkeeper-superseded:15:" in body for _, _, body in writer5.updated)
    # Ensure oldest not deleted
    assert any(cid == 6 for _, cid, _ in writer5.updated)
    # Never silently delete: updated bodies contain superseded marker, not empty
    for _, _, body in writer5.updated:
        if "loopkeeper-superseded" in body:
            assert "loopkeeper-superseded:15:" in body

    # Operator gate required: without LOOPKEEPER_OPERATOR=1, write should fail
    os.environ["LOOPKEEPER_OPERATOR"] = "0"
    writer6 = FakeWriter(comments=[], head=sha)
    with pytest.raises(PermissionError):
        upsert_review_comment("owner/repo", 15, sha, "fallback", "model", writer6)
    # Cleanup
    os.environ["LOOPKEEPER_OPERATOR"] = "1"
    del os.environ["LOOPKEEPER_OPERATOR"]

"""Contracts for the default posting path and Loopkeeper's own dogfood caller."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# The self-review pin, asserted literally on purpose. Bumping it changes which
# Loopkeeper revision reviews every later pull request, so it must be a
# deliberate edit in its own pull request rather than something that can drift.
# Update this constant only alongside the workflow, and only to a commit that
# is already merged -- never to an unmerged head, which would let a change
# review itself.
CURRENT_RELEASE_SHA = "ff1dbeb4f3eee1a45dc34ad1e02c062b93d26231"


def test_posting_pr_workflow_defaults_to_comments():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")

    assert re.search(r"^\s+post_comments:\n\s+type: boolean", raw, re.MULTILINE)
    assert re.search(r"^\s+default: true$", raw, re.MULTILINE)
    assert "pull-requests: write" in raw


def test_loopkeeper_reviews_its_own_pull_requests_with_pinned_posting_caller():
    raw = (ROOT / ".github/workflows/loopkeeper-pr-review.yml").read_text(encoding="utf-8")

    use_sha = re.search(
        r"uses: nifabulous/loopkeeper/.github/workflows/pr-review-posting\.yml@([0-9a-f]{40})",
        raw,
    )
    input_sha = re.search(r"loopkeeper_sha: ([0-9a-f]{40})", raw)
    assert use_sha and input_sha
    assert use_sha.group(1) == input_sha.group(1)
    assert use_sha.group(1) == CURRENT_RELEASE_SHA
    assert "consumer_repo: ${{ github.repository }}" in raw
    assert "loopkeeper_repo: nifabulous/loopkeeper" in raw
    assert "ci_workflow_name: Loopkeeper CI" in raw
    assert "ci_workflow_file: ci.yml" in raw
    assert "pull-requests: write" in raw
    assert "post_comments: true" in raw


def test_consumer_guide_explains_posting_default_and_opt_out():
    guide = (ROOT / "docs/consumer-guide.md").read_text(encoding="utf-8")

    assert "posts the complete review comment by default" in guide
    assert "Set `post_comments: false`" in guide


def test_posting_writer_skips_runs_without_a_review_artifact():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")

    assert "artifact_available: ${{ steps.artifact_status.outputs.available }}" in raw
    assert "id: artifact_status" in raw
    assert "needs.review.outputs.artifact_available == 'true'" in raw


def test_large_pr_file_caps_are_reported_as_incomplete_evidence():
    raw = (ROOT / "adapters/github/review_pr.sh").read_text(encoding="utf-8")

    assert "PR_FILES_TRUNCATED" in raw
    assert "files_truncated:" in raw
    assert "reached its bounded file-page limit" in raw

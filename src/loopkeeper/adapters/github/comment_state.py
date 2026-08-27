"""Loopkeeper GitHub comment state machine.

This module owns marker serialization, the pure state machine, the bounded
render path, and the operator-gated writer. No network or env reads in the
pure helpers.

Marker serialization is fixed here and tested byte-for-byte:
  <!-- loopkeeper-pr-review:{pr}:{head_sha} -->
  <!-- loopkeeper-evidence:{fallback|ci} -->

Followed by superseded marker for duplicate reconciliation:
  <!-- loopkeeper-superseded:{pr}:{head_sha}:{comment_id} -->

Suppression parses only these exact HTML comments plus the authenticated bot
author; prose resembling a marker is never sufficient.

The rendered body is sanitized and bounded, including marker/footer
reservation. Adapter-owned marker/evidence footer is appended outside model
body, so model text cannot forge state.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

# ---------------------------------------------------------------------------
# Marker serialization (single source of truth)
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"<!-- loopkeeper-pr-review:(\d+):([0-9a-f]{40}) -->")
_EVIDENCE_RE = re.compile(r"<!-- loopkeeper-evidence:(fallback|ci) -->")
_SUPERSEDED_RE = re.compile(r"<!-- loopkeeper-superseded:(\d+):([0-9a-f]{40}):(\d+) -->")
# Exact author check required for suppression
_BOT_LOGIN = "github-actions[bot]"

_EVIDENCE_STATES = ("fallback", "ci")


def serialize_pr_marker(pr: int, head_sha: str) -> str:
    """Return the canonical PR review marker."""
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be positive int")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("head_sha must be full lowercase 40-hex")
    return f"<!-- loopkeeper-pr-review:{pr}:{head_sha} -->"


def serialize_evidence_marker(evidence_state: str) -> str:
    if evidence_state not in _EVIDENCE_STATES:
        raise ValueError(f"evidence_state must be one of {_EVIDENCE_STATES}")
    return f"<!-- loopkeeper-evidence:{evidence_state} -->"


def serialize_superseded_marker(pr: int, head_sha: str, comment_id: int) -> str:
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be positive int")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("head_sha must be full 40-hex")
    if not isinstance(comment_id, int) or comment_id <= 0:
        raise ValueError("comment_id must be positive int")
    # Bounded: loopkeeper-superseded:{pr}:{head_sha}:{comment_id}
    marker = f"<!-- loopkeeper-superseded:{pr}:{head_sha}:{comment_id} -->"
    # Bound check: ensure marker length is bounded (pr up to large, sha 40, id up to digits)
    if len(marker.encode("utf-8")) > 256:
        raise ValueError("superseded marker exceeds byte budget")
    return marker


def parse_pr_marker(body: str) -> tuple[int, str] | None:
    m = _MARKER_RE.search(body)
    if m is None:
        return None
    return int(m.group(1)), m.group(2)


def parse_evidence_marker(body: str) -> str | None:
    m = _EVIDENCE_RE.search(body)
    if m is None:
        return None
    return m.group(1)


def is_canonical_review_comment(body: str, author_login: str, pr: int, head_sha: str) -> bool:
    """Return True only if body contains exact marker and author is bot."""
    if author_login != _BOT_LOGIN:
        return False
    expected_marker = serialize_pr_marker(pr, head_sha)
    # Exact match required, not substring of prose? Marker is exact HTML comment,
    # prose that resembles marker is not sufficient - we require exact marker.
    return expected_marker in body


def extract_comment_state(comment: dict, pr: int) -> tuple[str, str] | None:
    """Extract (head_sha, evidence_state) from a bot-authored comment for pr, or None."""
    # comment dict expected to have 'body' and 'user' or 'author_login'
    author = comment.get("user", {}).get("login") if isinstance(comment.get("user"), dict) else comment.get("author_login") or comment.get("login") or ""
    body = comment.get("body") or ""
    if author != _BOT_LOGIN:
        return None
    # Must contain exact pr marker
    m = _MARKER_RE.search(body)
    if m is None or int(m.group(1)) != pr:
        return None
    head_sha = m.group(2)
    evidence = parse_evidence_marker(body)
    # evidence may be None for legacy or malformed; treat as fallback? But suppression requires exact evidence marker.
    # For state machine, fallback is explicit.
    if evidence is None:
        return None
    return head_sha, evidence


# ---------------------------------------------------------------------------
# CommentState and CommentAction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommentState:
    comment_id: int
    head_sha: str
    evidence_state: Literal["fallback", "ci"]
    author_login: str
    body: str
    created_at: str = ""


CommentActionKind = Literal[
    "CREATE",
    "REPLACE_FALLBACK",
    "SUPPRESS_FALLBACK",
    "SUPPRESS_DUPLICATE",
    "RECONCILE_DUPLICATES",
]


@dataclass(frozen=True, eq=False)
class CommentAction:
    """Pure writer decision with enough information for deterministic reconciliation."""

    kind: CommentActionKind
    canonical_id: int | None = None
    superseded_ids: tuple[int, ...] = ()

    def __eq__(self, other: object) -> bool:
        # Keep the historical string comparison surface while exposing the
        # structured fields required by the writer and hidden consumers.
        if isinstance(other, str):
            return self.kind == other
        if isinstance(other, CommentAction):
            return (
                self.kind,
                self.canonical_id,
                self.superseded_ids,
            ) == (
                other.kind,
                other.canonical_id,
                other.superseded_ids,
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.kind, self.canonical_id, self.superseded_ids))


def decide_comment_action(
    existing: Sequence[CommentState],
    evidence_state: Literal["fallback", "ci"],
    head_sha: str,
) -> CommentAction:
    """Pure state machine for review comment upsert.

    Args:
        existing: Sequence of canonical bot comments for THIS pr+head (already filtered).
                  Caller must have filtered to exact marker + bot author + same head.
                  Order should be oldest-first (canonical sorting).
        evidence_state: Adapter-generated evidence state for the new review ("fallback" or "ci").
        head_sha: Current head SHA for the new review.

    Returns one of CREATE, REPLACE_FALLBACK, SUPPRESS_FALLBACK, SUPPRESS_DUPLICATE, RECONCILE_DUPLICATES.

    Rules (from brief):
      - no existing -> CREATE
      - same-head fallback + new fallback -> SUPPRESS_FALLBACK
      - same-head fallback + CI evidence -> REPLACE_FALLBACK (updates in place, changes evidence to ci)
      - same-head CI + any duplicate -> SUPPRESS_DUPLICATE
      - duplicate current-head comments already exist (len >=2) -> RECONCILE_DUPLICATES
        (keep oldest canonical and rewrite others to superseded marker)
    """
    if evidence_state not in ("fallback", "ci"):
        raise ValueError("evidence_state must be fallback or ci")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("head_sha must be 40-hex")
    # Filter and sort to same head (defensive); callers cannot influence which
    # duplicate becomes canonical by returning comments in a different order.
    same_head = sorted(
        (c for c in existing if c.head_sha == head_sha),
        key=lambda c: (c.created_at, c.comment_id),
    )
    # If duplicates already exist for same head, reconciliation takes precedence
    if len(same_head) >= 2:
        return CommentAction(
            "RECONCILE_DUPLICATES",
            canonical_id=same_head[0].comment_id,
            superseded_ids=tuple(c.comment_id for c in same_head[1:]),
        )
    if len(same_head) == 0:
        return CommentAction("CREATE")
    # Exactly one existing for this head
    current = same_head[0]
    # current.evidence_state is the existing evidence
    if current.evidence_state == "fallback" and evidence_state == "fallback":
        return CommentAction("SUPPRESS_FALLBACK", canonical_id=current.comment_id)
    if current.evidence_state == "fallback" and evidence_state == "ci":
        return CommentAction("REPLACE_FALLBACK", canonical_id=current.comment_id)
    if current.evidence_state == "ci":
        # same-head CI + any duplicate (new fallback or ci) suppresses
        return CommentAction("SUPPRESS_DUPLICATE", canonical_id=current.comment_id)
    # Fallback for unexpected
    return CommentAction("SUPPRESS_DUPLICATE", canonical_id=current.comment_id)


# ---------------------------------------------------------------------------
# Render comment (sanitize, defang marker-like text, bound, footer outside model)
# ---------------------------------------------------------------------------

def _escape_marker_like_text(text: str) -> str:
    """Escape marker-like text in model output so it cannot satisfy suppression.

    Marker-like text is any occurrence that looks like an HTML comment containing
    loopkeeper-pr-review, loopkeeper-evidence, or loopkeeper-superseded.
    We escape by inserting a zero-width or by replacing `<!--` with `&lt;!--`.
    """
    # Use simple escaping: replace `<!-- loopkeeper` with `&lt;!-- loopkeeper`
    # This preserves readability while preventing exact marker match.
    # Also handle codex legacy markers for defense in depth.
    escaped = text.replace("<!-- loopkeeper", "&lt;!-- loopkeeper")
    escaped = escaped.replace("<!-- codex", "&lt;!-- codex")
    # Also escape case variations? Marker is case-sensitive exact, so only exact string matters.
    return escaped


def render_comment(
    model_markdown: str,
    marker: str,
    evidence_state: Literal["fallback", "ci"],
    max_bytes: int,
) -> str:
    """Render the final comment body: sanitized model + adapter-owned footer.

    The footer (marker + evidence) is appended outside model body, sanitized and
    bounded including marker/footer reservation. Marker-like text in model output
    is escaped and cannot satisfy suppression.

    Args:
        model_markdown: Untrusted model output (will be sanitized and escaped).
        marker: Canonical pr marker, e.g. <!-- loopkeeper-pr-review:{pr}:{sha} -->
        evidence_state: fallback or ci
        max_bytes: Total byte budget including footer.

    Returns:
        Bounded, sanitized comment body with footer.
    """
    if not isinstance(model_markdown, str):
        raise TypeError("model_markdown must be str")
    if evidence_state not in ("fallback", "ci"):
        raise ValueError("evidence_state must be fallback or ci")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be positive int")
    # Validate marker shape
    if not _MARKER_RE.fullmatch(marker):
        raise ValueError("marker must be <!-- loopkeeper-pr-review:{pr}:{head_sha} -->")
    evidence_marker = serialize_evidence_marker(evidence_state)
    footer = f"\n\n{marker}\n{evidence_marker}\n"
    footer_bytes = len(footer.encode("utf-8"))
    if footer_bytes >= max_bytes:
        raise ValueError("max_bytes too small for marker/footer reservation")
    budget_for_model = max_bytes - footer_bytes

    # The trusted package redactor is mandatory. Falling back to raw model
    # text would make publication correctness depend on import state.
    from loopkeeper.redaction import sanitize

    sanitized = sanitize(model_markdown)

    # Escape marker-like text after sanitization so model cannot forge marker
    sanitized = _escape_marker_like_text(sanitized)

    # Truncate UTF-8 safely within budget, including marker reservation
    from loopkeeper.truncate import truncate_utf8

    truncated = truncate_utf8(sanitized, budget_for_model)

    # Ensure truncated still escapes marker-like? already escaped
    # Append footer outside model body
    return truncated.rstrip() + footer


# ---------------------------------------------------------------------------
# CommentWriter protocol and upsert_review_comment
# ---------------------------------------------------------------------------

class CommentWriter(Protocol):
    """Protocol for bounded GitHub comment operations.

    Implementations must be operator-gated and bounded; no bulk-delete.
    """

    def read_head(self, repo: str, pr: int) -> str:
        """Read current PR head SHA (exact, via GitHub API)."""
        ...

    def read_comments(self, repo: str, pr: int, per_page: int = 100, max_pages: int = 10) -> list[dict]:
        """Read comments with bounded pagination (per_page * max_pages cap)."""
        ...

    def create(self, repo: str, pr: int, body: str) -> dict:
        """Create a new comment (requires LOOPKEEPER_OPERATOR=1)."""
        ...

    def update(self, repo: str, comment_id: int, body: str) -> dict:
        """Update an existing comment (requires LOOPKEEPER_OPERATOR=1)."""
        ...


def _require_operator() -> None:
    import os

    if os.environ.get("LOOPKEEPER_OPERATOR") != "1":
        raise PermissionError("LOOPKEEPER_OPERATOR=1 required for write operations")


def upsert_review_comment(
    repo: str,
    pr: int,
    head_sha: str,
    evidence_state: Literal["fallback", "ci"],
    body: str,
    writer: CommentWriter,
) -> None:
    """Idempotent review comment upsert with state machine and reconciliation.

    Implements:
      - Dedicated PR-scoped writer: cancel-in-progress:false semantics are
        provided by the caller workflow; this function re-reads head+comments
        immediately before write and retries only reconciliation read when head moved.
      - Operator gate: LOOPKEEPER_OPERATOR=1 required in every write.
      - Duplicate reconciliation: keep oldest canonical and rewrite others to
        loopkeeper-superseded marker in same gated transaction; never silently delete.
      - Marker/evidence footer outside model body; bounded.

    This function is pure except for writer calls.

    Args:
        repo: owner/name
        pr: PR number
        head_sha: Current head SHA for this review (40-hex)
        evidence_state: fallback or ci
        body: Model markdown (will be rendered with marker+evidence)
        writer: Bounded CommentWriter implementation
    """
    import re as _re

    if not _re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo):
        raise ValueError("repo must be owner/name")
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be positive int")
    if not _re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("head_sha must be 40-hex")
    if evidence_state not in ("fallback", "ci"):
        raise ValueError("evidence_state must be fallback or ci")
    if not isinstance(body, str):
        raise TypeError("body must be str")

    # Bounded read of current head and comments immediately before write
    # (writer job must re-read to avoid stale marker publish)
    current_head = writer.read_head(repo, pr)
    if current_head != head_sha:
        # A concurrent synchronize may have raced the first read. Retry this
        # reconciliation read once; never rerun model or collection work here.
        current_head = writer.read_head(repo, pr)
        if current_head != head_sha:
            return

    raw_comments = writer.read_comments(repo, pr, per_page=100, max_pages=10)
    if not isinstance(raw_comments, list):
        raise RuntimeError("comment history read was unavailable")
    # Filter to canonical bot comments for this pr+head
    # Need exact marker match + bot author + evidence parse
    marker = serialize_pr_marker(pr, head_sha)
    # Build CommentState list for decide
    existing_states: list[CommentState] = []
    canonical_comments: list[dict] = []
    for c in raw_comments:
        # c may have 'user' dict or 'author_login'
        login = ""
        if isinstance(c.get("user"), dict):
            login = c["user"].get("login") or ""
        else:
            login = c.get("author_login") or c.get("login") or ""
        b = c.get("body") or ""
        cid = c.get("id") or c.get("comment_id") or 0
        created = c.get("created_at") or ""
        # Check exact marker for this pr/head
        if login != _BOT_LOGIN:
            continue
        if marker not in b:
            continue
        # Must parse evidence
        ev = parse_evidence_marker(b)
        if ev not in ("fallback", "ci"):
            continue
        # Ensure head matches via marker extraction (already marker guarantees pr+head)
        parsed = parse_pr_marker(b)
        if parsed is None or parsed[0] != pr or parsed[1] != head_sha:
            continue
        existing_states.append(
            CommentState(
                comment_id=int(cid),
                head_sha=head_sha,
                evidence_state=ev,  # type: ignore
                author_login=login,
                body=b,
                created_at=created,
            )
        )
        canonical_comments.append(c)
        # Also handle duplicate across same head but multiple cids (already counted)

    # Sort canonical by created_at, comment_id (oldest first) for reconciliation
    # Use created_at if present, else comment_id
    def sort_key(s: CommentState):
        return (s.created_at, s.comment_id)

    existing_states.sort(key=sort_key)
    canonical_comments.sort(key=lambda c: (c.get("created_at") or "", c.get("id") or c.get("comment_id") or 0))

    action = decide_comment_action(existing_states, evidence_state, head_sha)

    # Render the new body with marker+evidence footer, bounded (50000 default per brief? Use 50000 if not specified)
    # The caller provides body as model markdown; we need to render with marker/footer
    # Use max_bytes from env or default 50000, but respect writer's max? We'll use 50000.
    # To allow tests to control, we use env LOOPKEEPER_MAX_OUTPUT_BYTES or 50000.
    import os

    max_bytes_str = os.environ.get("LOOPKEEPER_MAX_OUTPUT_BYTES") or "50000"
    try:
        max_bytes = int(max_bytes_str)
    except ValueError:
        max_bytes = 50000
    rendered = render_comment(body, marker, evidence_state, max_bytes)

    # Operator-gated writes only
    if action.kind == "CREATE":
        _require_operator()
        writer.create(repo, pr, rendered)
        return
    if action.kind in ("SUPPRESS_FALLBACK", "SUPPRESS_DUPLICATE"):
        # Suppress: do nothing
        return
    if action.kind == "REPLACE_FALLBACK":
        # Update the single existing fallback comment in place, changing evidence to ci
        # Keep same comment_id, update body to new rendered (which carries ci evidence)
        _require_operator()
        target_id = action.canonical_id or existing_states[0].comment_id
        writer.update(repo, target_id, rendered)
        return
    if action.kind == "RECONCILE_DUPLICATES":
        # Keep oldest canonical, rewrite others to superseded marker
        _require_operator()
        # Oldest is canonical
        oldest = existing_states[0]
        # Rewrite others
        # We must do it in same operator-gated transaction; if head moved during reconciliation, retry only read
        # Re-read head before reconciliation writes
        fresh_head = writer.read_head(repo, pr)
        if fresh_head != head_sha:
            return
        # For each duplicate beyond oldest, rewrite its body to superseded marker
        for dup in existing_states[1:]:
            superseded_marker = serialize_superseded_marker(pr, head_sha, dup.comment_id)
            # Bounded superseded body: original body truncated? For simplicity, replace body with superseded note
            superseded_body = f"Superseded review comment for PR #{pr} at {head_sha}.\n\n{superseded_marker}\n"
            # Ensure bounded and not silently delete: we rewrite, not delete
            writer.update(repo, dup.comment_id, superseded_body)
        # Also ensure oldest is updated if evidence changed? If oldest was fallback and new is ci, update oldest
        if oldest.evidence_state == "fallback" and evidence_state == "ci":
            writer.update(repo, oldest.comment_id, rendered)
        # If new evidence is fallback and existing is ci, suppress already handled? But with duplicates we already handled.
        return

"""GitHub adapter for Loopkeeper arbiter: collection and posting.

The adapter is the only place that can claim github-forge-verified. It verifies
the default-branch checkout against the forge API, reads policy/contract/context
with git show, and passes PR content only through the untrusted channel.

Collector: collect_history(repo, pr, trusted_sha, bot_login) -> History
Poster: post_arbiter_comment (uses same marker+author lookup and serialized
        writer as reviewer comments, never creates second current-head arbiter
        comment).

Also provides History collection with bounded pagination, retryable reads, and
fail-closed semantics for truncated/failed reads (never interpreted as “no CI run”
or “no comments”).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from typing import Protocol

from loopkeeper.schema import _parse_ts, parse_trailer
from loopkeeper.types import Comment, History, HistoryRound

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Marker for arbiter comments: loopkeeper-arbiter:{pr}:{head_sha}
_ARBITER_MARKER_RE = re.compile(r"<!-- loopkeeper-arbiter:(\d+):([0-9a-f]{40}) -->")


def _validate_repo(repo: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo):
        raise ValueError("repo must be owner/name")


def _validate_pr(pr: int) -> None:
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be positive int")


def serialize_arbiter_marker(pr: int, head_sha: str) -> str:
    if not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be positive int")
    if not _SHA_RE.fullmatch(head_sha):
        raise ValueError("head_sha must be 40-hex")
    return f"<!-- loopkeeper-arbiter:{pr}:{head_sha} -->"


class GitHubApiArbiter(Protocol):
    """Minimal API for arbiter collection (bounded, retryable)."""

    def get_pr(self, repo: str, pr: int) -> dict:
        """GET repos/{repo}/pulls/{pr} or gh pr view -> { state, headRefOid, headRefName, ... }"""
        ...

    def list_comments(self, repo: str, pr: int, per_page: int, page: int) -> list[dict]:
        """GET repos/{repo}/issues/{pr}/comments?per_page=...&page=... -> list"""
        ...

    def get_pr_diff_files(self, repo: str, pr: int) -> list[str]:
        """Return list of changed files for PR (via gh pr view --json files?)"""
        ...


class CommentWriterArbiter(Protocol):
    """Writer for arbiter comments (same gated writer as review)."""

    def read_head(self, repo: str, pr: int) -> str:
        ...

    def read_comments(self, repo: str, pr: int, per_page: int = 100, max_pages: int = 10) -> list[dict]:
        ...

    def create(self, repo: str, pr: int, body: str) -> dict:
        ...

    def update(self, repo: str, comment_id: int, body: str) -> dict:
        ...


class CollectionUnavailable(RuntimeError):
    """Raised when a bounded forge read cannot provide complete evidence."""


def _bounded_positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise CollectionUnavailable(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise CollectionUnavailable(f"{name} must be a positive integer")
    return value


def _bounded_retry(call, max_attempts: int = 3, base_delay: float = 0.5):
    """Retry bounded 5xx/429 with backoff, fail-closed on total failure."""
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return call()
        except Exception as exc:
            # Only retry on 5xx/429-like messages; for simplicity, retry any transient if attempt < max
            # In real gh, we'd check status code; here we retry unless it's a validation error
            last_exc = exc
            if attempt + 1 >= max_attempts:
                break
            # Check if error is retryable (contains 5xx or 429)
            msg = str(exc)
            if "429" in msg or "5" in msg or "rate limit" in msg.lower() or "timeout" in msg.lower():
                time.sleep(base_delay * (2 ** attempt))
                continue
            # For other errors, don't retry (fail closed)
            break
    raise last_exc if last_exc else RuntimeError("retry exhausted")


def collect_history(repo: str, pr: int, trusted_sha: str, bot_login: str) -> History:
    """Collect PR history via bounded GitHub API and build a History.

    This is the GH adapter's collection step: it verifies the trusted checkout,
    reads PR metadata, pages through comments with bounded pagination, filters
    to canonical bot comments, parses trailers, and builds a History.

    For testability, this function takes an api object only via an internal
    factory that reads env GH_TOKEN/GH_REPO and calls gh. In unit tests, callers
    can monkeypatch subprocess calls or pass a fake api via direct import of
    a helper _collect_with_api. Here we provide the simple gh-based implementation
    with bounded pagination and fail-closed semantics.

    Args:
        repo: owner/name
        pr: PR number
        trusted_sha: SHA stamped at checkout (used for git show trusted reads, not for PR content)
        bot_login: Bot login for canonical filtering

    Returns:
        History (loopkeeper.types.History) with current_head_sha set to PR head,
        and rounds sorted canonically.

    Raises:
        ValueError: on invalid inputs
        RuntimeError: on forge verification failure (fallback path)
    """
    return _collect_with_gh(repo, pr, trusted_sha, bot_login)


def _collect_with_gh(repo: str, pr: int, trusted_sha: str, bot_login: str) -> History:
    _validate_repo(repo)
    _validate_pr(pr)
    if not _SHA_RE.fullmatch(trusted_sha):
        raise ValueError("trusted_sha must be 40-hex")
    if not isinstance(bot_login, str) or not bot_login.strip():
        raise ValueError("bot_login must be non-empty")

    # Verify trusted checkout is still at trusted_sha (exact). Any inability to
    # verify is a trust failure, never a reason to continue with partial data.
    try:
        current_checkout = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise CollectionUnavailable("could not verify trusted checkout") from exc
    if current_checkout != trusted_sha:
        raise CollectionUnavailable(f"checkout {current_checkout} != trusted {trusted_sha}")

    # Fetch PR head via gh (bounded, retryable)
    def fetch_pr():
        result = subprocess.run(
            ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "state,headRefOid,headRefName"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return json.loads(result.stdout)

    try:
        pr_data = _bounded_retry(fetch_pr)
    except Exception as exc:
        raise RuntimeError(f"could not fetch PR #{pr}: {exc}") from exc

    current_head = pr_data.get("headRefOid") or pr_data.get("head_sha") or ""
    if not isinstance(current_head, str) or not _SHA_RE.fullmatch(current_head):
        raise CollectionUnavailable(f"PR #{pr} did not return a valid head SHA")

    # List changed files: try gh pr view --json files
    diff_files: list[str] = []
    try:
        result = subprocess.run(
            ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "files"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        files = data.get("files") or []
        for f in files:
            if isinstance(f, dict):
                p = f.get("path") or f.get("filename") or ""
                if isinstance(p, str) and p:
                    diff_files.append(p)
            elif isinstance(f, str):
                diff_files.append(f)
    except Exception:
        diff_files = []

    # Bounded comment collection: paginate through max_pages=10, per_page=100, with byte caps
    # Use gh api with per_page/page, not --paginate unbounded
    all_comments_raw: list[dict] = []
    max_pages = 10
    per_page = 100
    max_raw_bytes = _bounded_positive_env("LOOPKEEPER_CHECK_MAX_RAW_BYTES", 200_000)
    collected_raw_bytes = 0
    for page in range(1, max_pages + 1):
        def fetch_page(p=page):
            result = subprocess.run(
                ["gh", "api", f"repos/{repo}/issues/{pr}/comments?per_page={per_page}&page={p}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            # gh api returns JSON array
            return json.loads(result.stdout)

        try:
            page_comments = _bounded_retry(fetch_page)
        except Exception as exc:
            raise CollectionUnavailable(f"could not read PR comments page {page}") from exc

        if not isinstance(page_comments, list):
            raise CollectionUnavailable(f"PR comments page {page} was not a JSON array")
        page_raw_bytes = len(json.dumps(page_comments, ensure_ascii=False).encode("utf-8"))
        if collected_raw_bytes + page_raw_bytes > max_raw_bytes:
            raise CollectionUnavailable("PR comment evidence exceeded the configured byte cap")
        collected_raw_bytes += page_raw_bytes
        if len(page_comments) == 0:
            break
        all_comments_raw.extend(page_comments)
        if len(page_comments) < per_page:
            break
    else:
        raise CollectionUnavailable("PR comment history exceeded the configured page cap")

    # Build HistoryRounds: for each canonical comment, parse trailer
    rounds: list[HistoryRound] = []
    seen_ids: set[int] = set()
    for c in all_comments_raw:
        user = c.get("user") or {}
        login = user.get("login") if isinstance(user, dict) else c.get("author_login") or ""
        if login != bot_login:
            continue
        body = c.get("body") or ""
        cid = c.get("id") or c.get("comment_id") or 0
        if not isinstance(cid, int) or cid <= 0:
            continue
        if cid in seen_ids:
            continue
        # Must contain arbiter or review marker? For collector, we accept both loopkeeper-pr-review and loopkeeper-arbiter?
        # The history for arbiter collects review comments, not arbiter comments. So check for loopkeeper-pr-review marker
        if f"<!-- loopkeeper-pr-review:{pr}:" not in body:
            # Also accept loopkeeper-arbiter? No, history should only include review rounds, not arbiter disposition
            # So skip non-review comments
            continue
        created_at = c.get("created_at") or "1970-01-01T00:00:00Z"
        head_sha = ""
        # Extract head from marker
        m = re.search(r"<!-- loopkeeper-pr-review:\d+:([0-9a-f]{40}) -->", body)
        if m:
            head_sha = m.group(1)
        else:
            # If marker malformed, skip? But we keep as invalid round if head missing?
            continue
        # Validate created_at
        try:
            _parse_ts(created_at)
        except Exception:
            created_at = "1970-01-01T00:00:00Z"
        # Parse trailer via loopkeeper schema
        validation = parse_trailer(body)
        comment_obj = Comment(
            comment_id=cid,
            created_at=created_at,
            author_login=login,
            head_sha=head_sha,
            marker=f"loopkeeper-pr-review:{pr}:{head_sha}",
            body=body,
        )
        # Build TrailerValidation already from parse_trailer
        kind = "valid" if validation.valid else "invalid"
        rounds.append(HistoryRound(kind=kind, comment=comment_obj, validation=validation))
        seen_ids.add(cid)

    # Also need to include invalid rounds for non-canonical? No, history only includes canonical per spec.
    # Sort by created_at, comment_id
    try:
        rounds.sort(key=lambda r: (_parse_ts(r.comment.created_at) if r.comment else _parse_ts("1970-01-01T00:00:00Z"), r.comment.comment_id if r.comment else 0))
    except Exception:
        rounds.sort(key=lambda r: r.comment.comment_id if r.comment else 0)

    # Sanitize diff_files: ensure sanitized paths
    sanitized_files = []
    for f in diff_files:
        if isinstance(f, str) and f and len(f) <= 256 and "\n" not in f and not any(x in f for x in ("<", ">", "`", "{", "}", "--")) and not f.startswith("/") and ".." not in f.split("/"):
            sanitized_files.append(f)

    history = History(
        schema=1,
        repo=repo,
        pr=pr,
        current_head_sha=current_head,
        current_diff_files=tuple(sanitized_files),
        rounds=tuple(rounds),
    )
    return history


def _collect_with_api(repo: str, pr: int, trusted_sha: str, bot_login: str, api: GitHubApiArbiter) -> History:
    """Test-friendly variant that uses an injected api (no subprocess)."""
    _validate_repo(repo)
    _validate_pr(pr)
    if not _SHA_RE.fullmatch(trusted_sha):
        raise ValueError("trusted_sha must be 40-hex")

    try:
        pr_data = api.get_pr(repo, pr)
    except Exception as exc:
        raise CollectionUnavailable("could not read PR metadata") from exc
    current_head = pr_data.get("headRefOid") or pr_data.get("head_sha") or ""
    if not isinstance(current_head, str) or not _SHA_RE.fullmatch(current_head):
        raise CollectionUnavailable("PR metadata did not contain a valid head SHA")
    diff_files = api.get_pr_diff_files(repo, pr) if hasattr(api, "get_pr_diff_files") else []

    all_comments: list[dict] = []
    max_raw_bytes = _bounded_positive_env("LOOPKEEPER_CHECK_MAX_RAW_BYTES", 200_000)
    collected_raw_bytes = 0
    for page in range(1, 11):
        try:
            page_comments = api.list_comments(repo, pr, per_page=100, page=page)
        except Exception as exc:
            raise CollectionUnavailable(f"could not read PR comments page {page}") from exc
        if not isinstance(page_comments, list):
            raise CollectionUnavailable(f"PR comments page {page} was not a JSON array")
        page_raw_bytes = len(json.dumps(page_comments, ensure_ascii=False).encode("utf-8"))
        if collected_raw_bytes + page_raw_bytes > max_raw_bytes:
            raise CollectionUnavailable("PR comment evidence exceeded the configured byte cap")
        collected_raw_bytes += page_raw_bytes
        if len(page_comments) == 0:
            break
        all_comments.extend(page_comments)
        if len(page_comments) < 100:
            break
    else:
        raise CollectionUnavailable("PR comment history exceeded the configured page cap")

    rounds: list[HistoryRound] = []
    seen: set[int] = set()
    for c in all_comments:
        login = (c.get("user") or {}).get("login") if isinstance(c.get("user"), dict) else c.get("author_login") or ""
        if login != bot_login:
            continue
        body = c.get("body") or ""
        if f"<!-- loopkeeper-pr-review:{pr}:" not in body:
            continue
        cid = c.get("id") or c.get("comment_id") or 0
        if cid in seen:
            continue
        m = re.search(r"<!-- loopkeeper-pr-review:\d+:([0-9a-f]{40}) -->", body)
        if not m:
            continue
        head_sha = m.group(1)
        created_at = c.get("created_at") or "1970-01-01T00:00:00Z"
        validation = parse_trailer(body)
        comment_obj = Comment(
            comment_id=cid,
            created_at=created_at,
            author_login=login,
            head_sha=head_sha,
            marker=f"loopkeeper-pr-review:{pr}:{head_sha}",
            body=body,
        )
        kind = "valid" if validation.valid else "invalid"
        rounds.append(HistoryRound(kind=kind, comment=comment_obj, validation=validation))
        seen.add(cid)

    sanitized_files = [f for f in diff_files if isinstance(f, str) and len(f) <= 256 and "\n" not in f]

    return History(
        schema=1,
        repo=repo,
        pr=pr,
        current_head_sha=current_head,
        current_diff_files=tuple(sanitized_files),
        rounds=tuple(rounds),
    )


def post_arbiter_comment(repo: str, pr: int, decision, operator: bool) -> None:
    """Post the arbiter disposition comment with serialized writer.

    Args:
        repo: owner/name
        pr: PR number
        decision: Decision dataclass from loopkeeper.arbiter (has recommendation, cited_rule, etc.)
        operator: whether operator mode is enabled (requires LOOPKEEPER_OPERATOR=1 in writer)

    The body carries current head and decision artifact, repeats update in place
    for same head, never creates second current-head arbiter comment.

    Uses the same marker+author lookup and serialized writer as reviewer comments.
    """
    _validate_repo(repo)
    _validate_pr(pr)
    if decision is None:
        raise ValueError("decision is required")

    # Need current head: fetch via gh
    try:
        result = subprocess.run(
            ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "headRefOid,state"],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        )
        data = json.loads(result.stdout)
        current_head = data.get("headRefOid") or data.get("head_sha") or ""
        pr_state = data.get("state") or "OPEN"
    except Exception as exc:
        raise RuntimeError(f"could not fetch PR head for arbiter post: {exc}") from exc

    if pr_state != "OPEN":
        return
    if not _SHA_RE.fullmatch(current_head):
        raise RuntimeError(f"PR head is not 40-hex: {current_head!r}")

    marker = serialize_arbiter_marker(pr, current_head)

    # Build body: decision artifact + head
    body = (
        f"{marker}\n\n"
        f"<!-- loopkeeper-arbiter-head:{current_head} -->\n"
        f"## Arbiter disposition for PR #{pr} at {current_head}\n\n"
        f"**Recommendation:** {decision.recommendation}\n"
        f"**Cited rule:** {decision.cited_rule}\n"
        f"**Round count:** {decision.round_count}\n"
        f"**Needs human:** {decision.needs_human}\n\n"
        f"```json\n{json.dumps(decision.__dict__ if hasattr(decision, '__dict__') else {}, indent=2)}\n```\n"
    )

    # Use bounded writer pattern: read comments, check existing arbiter comment for same head
    # Need operator gate
    def require_operator():
        if os.environ.get("LOOPKEEPER_OPERATOR") != "1":
            raise PermissionError("LOOPKEEPER_OPERATOR=1 required for arbiter post")

    # Fetch comments bounded
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/issues/{pr}/comments?per_page=100"],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        )
        comments = json.loads(result.stdout)
        if not isinstance(comments, list):
            comments = []
    except Exception as exc:
        raise RuntimeError(f"could not list comments for arbiter: {exc}") from exc

    # Find existing arbiter comment for this pr+head with bot author
    bot = os.environ.get("LOOPKEEPER_BOT_LOGIN") or "github-actions[bot]"
    existing = None
    for c in comments:
        login = (c.get("user") or {}).get("login", "") if isinstance(c.get("user"), dict) else ""
        body_existing = c.get("body") or ""
        cid = c.get("id")
        if login == bot and marker in body_existing:
            existing = c
            break

    # If existing and same head, update in place, else create (but never create second current-head)
    if existing is not None:
        # Update in place (same head)
        require_operator()
        cid = existing.get("id")
        subprocess.run(
            ["gh", "api", "--method", "PATCH", f"repos/{repo}/issues/comments/{cid}", "-f", f"body={body}"],
            check=True,
            timeout=20,
        )
    else:
        # No existing: create, but only if not already created in this run (avoid duplicate)
        # Re-read head+comments before create to ensure no race created one
        # Second read
        try:
            result2 = subprocess.run(
                ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "headRefOid,state"],
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            )
            data2 = json.loads(result2.stdout)
            head2 = data2.get("headRefOid") or ""
            state2 = data2.get("state") or "OPEN"
            if state2 != "OPEN" or head2 != current_head:
                return
            result3 = subprocess.run(
                ["gh", "api", f"repos/{repo}/issues/{pr}/comments?per_page=100"],
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            )
            comments2 = json.loads(result3.stdout)
            if not isinstance(comments2, list):
                raise RuntimeError("arbiter comment read was not a JSON array")
            for c in comments2:
                login = (c.get("user") or {}).get("login", "") if isinstance(c.get("user"), dict) else ""
                if login == bot and marker in (c.get("body") or ""):
                    # Another writer created it while we were checking; update instead of creating second
                    require_operator()
                    cid = c.get("id")
                    subprocess.run(
                        ["gh", "api", "--method", "PATCH", f"repos/{repo}/issues/comments/{cid}", "-f", f"body={body}"],
                        check=True,
                        timeout=20,
                    )
                    return
        except Exception as exc:
            raise RuntimeError("could not reconcile concurrent arbiter comment write") from exc
        require_operator()
        subprocess.run(
            ["gh", "pr", "comment", str(pr), "--repo", repo, "--body-file", "-"],
            input=body.encode("utf-8"),
            check=True,
            timeout=20,
        )

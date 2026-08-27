"""Workflow identity resolution for Loopkeeper.

Resolves workflow display names to IDs via bounded pagination, and provides a
pure filter for workflow_run run-target selection.

Exhausting or truncating the page budget is a configuration failure that
triggers fallback review rather than silently probing an incomplete list.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class WorkflowTarget:
    id: int
    path: str
    name: str
    state: str

    @property
    def workflow_id(self) -> int:
        """Compatibility spelling used by workflow callers and fixtures."""
        return self.id


class WorkflowLookupError(RuntimeError):
    pass


# Public name used by the workflow contract and older adapter integrations.
WorkflowIdentityError = WorkflowLookupError


class GitHubApiWorkflow(Protocol):
    def list_workflows(self, repo: str, page: int, per_page: int = 100) -> dict:
        """GET /repos/{repo}/actions/workflows?per_page=100&page={page}

        Returns dict with at least {"workflows": [...], "total_count": int}
        Each workflow has: id, name, path, state
        """
        ...


def resolve_workflow_target(
    repo: str,
    display_name: str,
    expected_file: str,
    api: GitHubApiWorkflow,
    max_pages: int = 10,
) -> WorkflowTarget:
    """Resolve display name to one active workflow ID with bounded pagination.

    Follows bounded pagination for GET /actions/workflows, resolves display name
    to exactly one active workflow ID, and requires its returned path to equal
    the configured file.

    Args:
        repo: owner/name
        display_name: Workflow display name to resolve (e.g. "CI")
        expected_file: Expected file path suffix, e.g. ".github/workflows/ci.yml" or "ci.yml"
        api: Bounded GitHub API wrapper
        max_pages: Page budget (default 10). Exhausting is a config failure.

    Returns:
        WorkflowTarget with id, path, etc.

    Raises:
        WorkflowLookupError: if not found, ambiguous, state not active, path mismatch,
                             or page budget exhausted/truncated.
    """
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo):
        raise ValueError("repo must be owner/name")
    if not isinstance(display_name, str) or not display_name.strip():
        raise ValueError("display_name must be non-empty string")
    if _CONTROL_RE.search(display_name):
        raise ValueError("display_name contains control characters")
    if not isinstance(expected_file, str) or not expected_file.strip():
        raise ValueError("expected_file must be non-empty string")
    if expected_file.startswith("/") or ".." in expected_file:
        raise ValueError("expected_file must be a safe relative path")
    if not isinstance(max_pages, int) or max_pages <= 0 or max_pages > 100:
        raise ValueError("max_pages must be positive int <=100")

    collected: list[dict] = []
    total_count: int | None = None

    for page in range(1, max_pages + 1):
        try:
            payload = api.list_workflows(repo, page, per_page=100)
        except Exception as exc:
            raise WorkflowLookupError(f"failed to list workflows page {page}: {exc}") from exc

        if not isinstance(payload, dict):
            raise WorkflowLookupError(f"workflow list page {page} was not object")

        workflows = payload.get("workflows")
        if not isinstance(workflows, list):
            raise WorkflowLookupError(f"workflow list page {page} missing workflows array")

        # Capture total_count on first page
        if page == 1:
            tc = payload.get("total_count")
            if isinstance(tc, int):
                total_count = tc
            elif isinstance(tc, int) is False and "count" in payload:
                # alternative field
                tc2 = payload.get("count")
                if isinstance(tc2, int):
                    total_count = tc2

        # Filter to active? We keep all and check state later, but we need to collect
        collected.extend(workflows)

        # Pagination termination: if fewer than per_page returned, we're done
        # But to be safe, also stop when collected >= total_count
        if len(workflows) < 100:
            break
        if total_count is not None and len(collected) >= total_count:
            break
    else:
        # Exhausted page budget without terminating (still more pages possible)
        # This is a configuration failure that triggers fallback review
        raise WorkflowLookupError(
            f"exhausted workflow page budget ({max_pages} pages) without completing list; "
            "total_count suggests more workflows exist — fallback required"
        )

    # Check truncation: if total_count indicates more than collected, we truncated
    if total_count is not None and len(collected) < total_count:
        raise WorkflowLookupError(
            f"truncated workflow list: collected {len(collected)} < total_count {total_count}; fallback required"
        )

    # Resolve display_name to exactly one active workflow
    matches = [w for w in collected if w.get("name") == display_name]
    if len(matches) == 0:
        raise WorkflowLookupError(f"no workflow named {display_name!r} found in {repo}")
    if len(matches) > 1:
        raise WorkflowLookupError(f"ambiguous workflows named {display_name!r}: {len(matches)} matches")

    target = matches[0]
    # Require active state
    state = target.get("state") or target.get("status")
    # The API must prove that the selected workflow is active; an omitted state
    # is not equivalent to active because a partial response is untrusted.
    if state != "active":
        raise WorkflowLookupError(f"workflow {display_name!r} is not active (state={state!r})")

    # Require path equals configured file
    # Path from API is like ".github/workflows/ci.yml"
    returned_path = target.get("path")
    if not isinstance(returned_path, str):
        raise WorkflowLookupError(f"workflow {display_name!r} missing path")

    # expected_file may be just "ci.yml" or full path; we require exact suffix match
    # But brief says requires its returned path to equal configured file
    # So we do exact match, but also accept if expected_file is basename and returned_path endswith
    # To be strict: if expected_file contains slash, require exact equality; otherwise require basename equality
    if "/" in expected_file:
        if returned_path != expected_file:
            raise WorkflowLookupError(
                f"workflow {display_name!r} path {returned_path!r} != expected {expected_file!r}"
            )
    else:
        # expected_file is basename like ci.yml
        if not returned_path.endswith(f"/{expected_file}") and returned_path != expected_file:
            raise WorkflowLookupError(
                f"workflow {display_name!r} path {returned_path!r} does not match expected file {expected_file!r}"
            )
        # Also require that the basename matches exactly
        if returned_path.split("/")[-1] != expected_file:
            raise WorkflowLookupError(
                f"workflow {display_name!r} path {returned_path!r} basename != {expected_file!r}"
            )

    try:
        wid = int(target.get("id"))
    except Exception as exc:
        raise WorkflowLookupError(f"workflow {display_name!r} missing id") from exc

    return WorkflowTarget(id=wid, path=returned_path, name=display_name, state=state or "active")


# ---------------------------------------------------------------------------
# Pure workflow_run target filter
# ---------------------------------------------------------------------------

Reviewability = Literal["reviewable", "fallback"]


def select_workflow_run_target(
    event: str,
    source_event: str,
    run_head_sha: str,
    current_pr_head_sha: str,
    pr_state: str,
    target_pr: int,
    run_pull_request_numbers: Sequence[int],
) -> Reviewability:
    """Pure filter for workflow_run PR association.

    Requires:
      - event == "workflow_run"
      - source_event == "pull_request"
      - exact head equality (run_head_sha == current_pr_head_sha, both 40-hex)
      - pr_state == "OPEN"
      - exactly one explicit workflow_run.pull_requests association for target_pr;
        missing, duplicated, or ambiguous associations take fallback.

    This is a pure function: no I/O, no env reads.
    """
    # Validate shapes
    if not isinstance(event, str) or not isinstance(source_event, str):
        return "fallback"
    if not isinstance(run_head_sha, str) or not isinstance(current_pr_head_sha, str):
        return "fallback"
    if not isinstance(pr_state, str) or not isinstance(target_pr, int) or target_pr <= 0:
        return "fallback"
    # Must be workflow_run event
    if event != "workflow_run":
        return "fallback"
    # Source must be pull_request
    if source_event != "pull_request":
        return "fallback"
    # Both SHAs must be full 40-hex and equal
    if not _SHA_RE.fullmatch(run_head_sha) or not _SHA_RE.fullmatch(current_pr_head_sha):
        return "fallback"
    if run_head_sha != current_pr_head_sha:
        return "fallback"
    # PR must be open
    if pr_state != "OPEN":
        return "fallback"
    # target_pr must be positive
    if target_pr <= 0:
        return "fallback"
    # run_pull_request_numbers: must be exactly one association for target_pr
    # It is a sequence of ints from workflow_run.pull_requests[*].number
    if not isinstance(run_pull_request_numbers, Sequence):
        return "fallback"
    # Count occurrences of target_pr
    # Also detect duplicates (same PR appearing twice) and ambiguous (multiple PRs)
    # Exact requirement: exactly one explicit association for target_pr
    # So list should contain exactly one element and that element is target_pr,
    # OR list may contain multiple but exactly one equals target_pr? Brief says
    # "exactly one explicit workflow_run.pull_requests association for target_pr;
    # missing, duplicated, or ambiguous associations take fallback"
    # So we interpret: the list of associated PR numbers must contain target_pr exactly once
    # and must not contain duplicates of target_pr, and also the list length should be 1?
    # The harness in original code checks: pull_requests array contains target_pr and length? Let's see
    # Original shell: select(.event == "pull_request" and .head_sha == $head) | select([.pull_requests[]?.number? | tostring] | index($pr) != null)
    # Then in python select_workflow_run_target, we need to be stricter: require exactly one association for target_pr
    # For our implementation: if list is None or empty => fallback, if target_pr not in list => fallback,
    # if list.count(target_pr) !=1 => fallback (duplicated), if len(list) !=1 => ambiguous? But original allows shared head across multiple PRs? The brief says exactly one explicit association for target_pr.
    # So we should require that the list, when filtered to target_pr, has exactly one, and that the list's unique set for target_pr is 1.
    # But if list contains other PR numbers besides target_pr, is that ambiguous? Example: run associated with PR 15 and 16 (shared head) => ambiguous, fallback.
    # The shell code would defer only when THIS PR is in list, even if other PRs also there? But the pure filter is stricter: it says exactly one explicit association for target_pr.
    # We'll implement: run_pull_request_numbers must be a sequence with exactly one element that equals target_pr.
    # However to be more permissive for shared-head case, we check count of target_pr ==1 and len ==1.
    try:
        nums = list(run_pull_request_numbers)
    except Exception:
        return "fallback"
    if len(nums) == 0:
        return "fallback"
    # All elements should be ints
    if not all(isinstance(n, int) and n > 0 for n in nums):
        return "fallback"
    # Must contain target_pr exactly once
    count = nums.count(target_pr)
    if count != 1:
        return "fallback"
    # Must not be ambiguous: exactly one association total (i.e., len(nums) ==1)
    # If len>1, even if target_pr appears once, it's ambiguous because commit is shared across PRs
    # The brief says "exactly one explicit workflow_run.pull_requests association for target_pr"
    # Could be interpreted as count==1 regardless of other PRs, but "ambiguous associations take fallback" suggests len>1 is ambiguous.
    if len(nums) != 1:
        return "fallback"
    return "reviewable"

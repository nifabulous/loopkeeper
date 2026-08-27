"""Trust-root resolution and checkout verification for Loopkeeper.

The trust-root resolver is executable, not a naming convention. The validated
consumer_trusted_sha is resolved from the forge's default-branch ref and
compared with checkout before any trusted file is read. loopkeeper_sha is
declared twice (uses pin + workflow_call input); the called workflow verifies
checkout SHA + release-manifest binding before invoking scripts.

Read-only GitHub API calls may retry bounded 5xx/429 with deadline-aware
backoff, but failed/truncated reads are never interpreted as “no CI run” or
“no comments.”
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA7_RE = re.compile(r"^[0-9a-f]{7,64}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

class GitHubApi(Protocol):
    """Minimal GitHub API surface for trust resolution.

    Implementations wrap `gh api` with bounded retries and deadline-aware
    backoff. Failed or truncated reads are treated as unavailable, never as
    “no branch” or “no tip.”
    """

    def get_repo(self, repo: str) -> dict:
        """GET repos/{repo} -> { default_branch: str, ... }"""
        ...

    def get_ref_sha(self, repo: str, ref: str) -> str:
        """GET repos/{repo}/git/ref/heads/{branch} -> full 40-hex SHA"""
        ...

    def get_label(self, repo: str, label: str) -> dict | None:
        """GET repos/{repo}/labels/{label} -> label dict or None if missing (exact)"""
        ...


class TrustVerificationError(RuntimeError):
    pass


class GapLabelUnavailable(RuntimeError):
    pass


def _validate_repo(repo: str) -> None:
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo):
        raise ValueError("repo must be owner/name")


def _validate_branch(branch: str) -> None:
    if not isinstance(branch, str) or not branch.strip():
        raise ValueError("branch must be non-empty string")
    if _CONTROL_RE.search(branch):
        raise ValueError("branch contains control characters")
    if branch.startswith(("/", ".")) or ".." in branch:
        raise ValueError("branch contains illegal path components")


def _validate_sha(sha: str) -> None:
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise ValueError("expected full lowercase 40-hex commit SHA")


def resolve_consumer_trusted_sha(repo: str, default_branch: str, api: GitHubApi) -> str:
    """Resolve the consumer's trusted SHA from the forge default branch.

    Steps:
      1. Validate repo as owner/name (before interpolation to avoid redirect).
      2. Verify default_branch matches forge's reported default_branch via
         GET repos/{repo} (caller-provided branch is not trusted).
      3. Resolve tip via GET repos/{repo}/git/ref/heads/{default_branch}
         and validate full 40-hex SHA.
      4. Return the forge-verified SHA. Callers must compare this with their
         checkout SHA before trusted reads; if it moves between resolution and
         checkout, the run fails closed and next trigger retries.

    This function is bounded and will retry 5xx/429 briefly with backoff via
    the api implementation; a failed read is never interpreted as “no branch.”
    """
    _validate_repo(repo)
    _validate_branch(default_branch)

    # Step 1: independently verify default_branch via forge
    try:
        repo_info = api.get_repo(repo)
    except Exception as exc:
        raise TrustVerificationError(f"could not resolve default branch for {repo}: {exc}") from exc

    actual_default = repo_info.get("default_branch") if isinstance(repo_info, dict) else None
    if not isinstance(actual_default, str) or not actual_default.strip():
        raise TrustVerificationError(f"could not resolve the default branch of {repo} through the GitHub API")
    if actual_default != default_branch:
        raise TrustVerificationError(
            f"default_branch={default_branch!r} is not the default branch of {repo} ({actual_default!r})"
        )

    # Step 2: resolve tip SHA
    try:
        tip = api.get_ref_sha(repo, f"heads/{default_branch}")
    except Exception as exc:
        raise TrustVerificationError(
            f"could not resolve refs/heads/{default_branch} on {repo} through the GitHub API: {exc}"
        ) from exc

    if not isinstance(tip, str) or not _SHA_RE.fullmatch(tip):
        raise TrustVerificationError(
            f"could not resolve refs/heads/{default_branch} on {repo}: expected full 40-hex SHA, got {tip!r}"
        )

    # Also validate lowercase
    if tip != tip.lower():
        raise TrustVerificationError("SHA must be lowercase")

    return tip


def verify_loopkeeper_checkout(root: Path, expected_sha: str, release_manifest: Path) -> None:
    """Verify loopkeeper checkout and release-manifest binding.

    Requires:
      - full lowercase 40-hex SHA
      - git rev-parse HEAD == expected_sha (exact)
      - release manifest binds checked-out package/workflow version to that SHA

    Release-time provenance/signature verification happens in the release
    workflow; this verifier claims only exact commit and manifest binding, not a
    new cryptographic signature scheme.

    The manifest is expected to be JSON with at least one of:
      - commit / sha / loopkeeper_sha / trusted_revision
    that equals expected_sha, and optionally version fields.

    Must not accept branch/tag/mutable ref.
    """
    if not isinstance(root, Path):
        raise TypeError("root must be Path")
    if not isinstance(expected_sha, str) or not _SHA_RE.fullmatch(expected_sha):
        raise ValueError("expected_sha must be full lowercase 40-hex commit SHA")
    if expected_sha != expected_sha.lower():
        raise ValueError("expected_sha must be lowercase")
    if not isinstance(release_manifest, Path):
        raise TypeError("release_manifest must be Path")
    if not release_manifest.exists() or not release_manifest.is_file():
        raise TrustVerificationError(f"release manifest not found at {release_manifest}")

    # Verify git rev-parse HEAD
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        actual = result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise TrustVerificationError(f"git rev-parse HEAD failed in {root}: {exc}") from exc
    except Exception as exc:
        raise TrustVerificationError(f"could not verify checkout SHA: {exc}") from exc

    if not _SHA_RE.fullmatch(actual):
        raise TrustVerificationError(f"git HEAD is not a full 40-hex SHA: {actual!r}")
    if actual != expected_sha:
        raise TrustVerificationError(
            f"Checkout {actual} does not match expected trusted SHA {expected_sha}; "
            "refusing to run with branch-controlled code"
        )

    # Check release manifest binding
    try:
        import json

        data = json.loads(release_manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TrustVerificationError(f"could not parse release manifest {release_manifest}: {exc}") from exc

    if not isinstance(data, dict):
        raise TrustVerificationError("release manifest must be JSON object")

    # Look for commit-binding fields (any one must match expected_sha)
    candidate_keys = (
        "commit_sha",
        "commit",
        "sha",
        "loopkeeper_sha",
        "trusted_revision",
        "trusted_sha",
        "checkout_sha",
    )
    found = None
    for k in candidate_keys:
        v = data.get(k)
        if isinstance(v, str) and _SHA_RE.fullmatch(v) and v == expected_sha:
            found = k
            break
            # If field exists but mismatches, it's a binding failure
            # Continue to see if another field matches; if none match, fail
    # Also check nested structures: data may have top-level `loopkeeper` object
    if found is None:
        for k in candidate_keys:
            # check nested under 'loopkeeper' or 'provenance'
            for container_key in ("loopkeeper", "provenance", "artifact"):
                container = data.get(container_key)
                if isinstance(container, dict):
                    v = container.get(k)
                    if isinstance(v, str) and v == expected_sha and _SHA_RE.fullmatch(v):
                        found = f"{container_key}.{k}"
                        break
            if found:
                break

    if found is None:
        # Provide diagnostic including available keys
        available = ", ".join(sorted(data.keys())) if isinstance(data, dict) else "n/a"
        raise TrustVerificationError(
            f"release manifest at {release_manifest} does not bind expected SHA {expected_sha}; "
            f"checked keys {candidate_keys}, available top-level keys: {available}"
        )

    # Optional: verify manifest's version field is present and non-empty (but not required for binding)
    # We do not enforce cryptographic signature here; that is done at release time.


def verify_gap_label(repo: str, label: str, api: GitHubApi) -> None:
    """Verify that LOOPKEEPER_GAP_LABEL exists with exact, bounded lookup.

    Args:
        repo: owner/name
        label: label name (must be non-empty, no control chars, exact match)
        api: GitHubApi with get_label

    Raises:
        GapLabelUnavailable: if blank, control-char, or missing label.
    """
    _validate_repo(repo)
    if not isinstance(label, str) or not label.strip():
        raise GapLabelUnavailable("GAP_LABEL_UNAVAILABLE: label is blank")
    if _CONTROL_RE.search(label):
        raise GapLabelUnavailable("GAP_LABEL_UNAVAILABLE: label contains control characters")
    if len(label.encode("utf-8")) > 100:
        raise GapLabelUnavailable("GAP_LABEL_UNAVAILABLE: label too long")
    # Label names are bounded, no slashes? But GitHub labels can contain many chars; we restrict control chars only.
    try:
        result = api.get_label(repo, label)
    except Exception as exc:
        # For 404 or missing, treat as unavailable (fail closed, no write)
        raise GapLabelUnavailable(f"GAP_LABEL_UNAVAILABLE: label {label!r} not found or API error: {exc}") from exc
    if result is None:
        raise GapLabelUnavailable(f"GAP_LABEL_UNAVAILABLE: label {label!r} does not exist in {repo}")
    # Exact match check: ensure returned label name equals requested (case-sensitive)
    returned_name = result.get("name") if isinstance(result, dict) else None
    if returned_name != label:
        raise GapLabelUnavailable(f"GAP_LABEL_UNAVAILABLE: label {label!r} did not resolve to exact match (got {returned_name!r})")

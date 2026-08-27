"""Contract derivation and parsing — pure, trust-separated.

Implements the slug-plus-SHA-12 convention from docs/contracts/README.md.
The parser never touches the filesystem or version control; the loader uses only
the provided TrustedReader bound to the verified default-branch object.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

# ---------------------------------------------------------------------------
# Contract model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Contract:
    branch: str
    text: str
    is_empty: bool

    @property
    def is_present(self) -> bool:
        return not self.is_empty

    @classmethod
    def empty(cls, branch: str) -> "Contract":
        return cls(branch=branch, text="", is_empty=True)

    @classmethod
    def valid(cls, branch: str, text: str) -> "Contract":
        return cls(branch=branch, text=text, is_empty=False)


# Keep compatibility with older naming if needed
Control = re.compile(r"[\x00-\x1f\x7f]")
_BRANCH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def contract_relative_path(branch: str) -> PurePosixPath:
    """Collision-resistant branch -> path under docs/contracts/.

    Slug-and-hash: slug keeps paths human-readable, 12-hex sha256 prefix of
    FULL branch name makes it collision-resistant where slug alone is not.

    Pure: no filesystem, no env, no external process.
    """
    if not isinstance(branch, str):
        raise TypeError("branch must be str")
    if branch == "":
        raise ValueError("branch must be non-empty string")
    if branch == "HEAD":
        raise ValueError("branch must not be HEAD")
    if _BRANCH_CONTROL_RE.search(branch):
        raise ValueError("branch contains control characters")
    if "\n" in branch or "\r" in branch:
        raise ValueError("branch contains newline")
    # Additional check: any control char < 0x20
    if any(ord(c) < 0x20 for c in branch):
        raise ValueError("branch contains control characters")
    slug = branch.replace("/", "-")
    digest = hashlib.sha256(branch.encode("utf-8")).hexdigest()[:12]
    return PurePosixPath(f"docs/contracts/{slug}-{digest}.md")


def _is_contract_document(text: str, branch: str) -> bool:
    """True only if first non-blank line is exactly '# Contract: <branch>'."""
    expected = f"# Contract: {branch}"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped == expected
    return False


def parse_contract(text: str, expected_branch: str) -> Contract:
    """Parse and validate a contract's text.

    Requires the first non-empty line to be '# Contract: <expected_branch>'.
    Returns a valid Contract on success, raises ValueError on mismatch or empty.
    Pure: no external I/O.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if not isinstance(expected_branch, str):
        raise TypeError("expected_branch must be str")
    if expected_branch == "" or expected_branch == "HEAD":
        raise ValueError("expected_branch must be non-empty and not HEAD")
    if _BRANCH_CONTROL_RE.search(expected_branch):
        raise ValueError("expected_branch contains control characters")
    if "\n" in expected_branch or "\r" in expected_branch:
        raise ValueError("expected_branch contains newline")
    if any(ord(c) < 0x20 for c in expected_branch):
        raise ValueError("expected_branch contains control characters")

    expected = f"# Contract: {expected_branch}"
    found_first = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        found_first = True
        if stripped != expected:
            raise ValueError(
                f"contract header mismatch: expected {expected!r}, got {stripped!r}"
            )
        # Header matches, return valid contract
        return Contract.valid(branch=expected_branch, text=text)

    if not found_first:
        raise ValueError("contract text has no non-empty lines")
    # Should not reach
    raise ValueError("contract header mismatch")


def load_contract_or_empty(reader, branch: str) -> Contract:
    """Load a contract via a TrustedReader bound to the verified default branch.

    Returns an empty Contract for absent file or mismatched header.
    The reader is the only I/O seam; this function never accesses arbitrary paths
    or invokes version control itself.
    """
    if not isinstance(branch, str):
        raise TypeError("branch must be str")
    # Empty or HEAD branches are treated as empty, not error, to match rollout compat
    if branch == "" or branch == "HEAD":
        return Contract.empty(branch=branch)
    if _BRANCH_CONTROL_RE.search(branch) or "\n" in branch or "\r" in branch or any(ord(c) < 0x20 for c in branch):
        # Control characters in branch => treat as empty rather than raise, fail closed
        return Contract.empty(branch=branch)

    try:
        path = contract_relative_path(branch)
    except (ValueError, TypeError):
        return Contract.empty(branch=branch)

    # The reader is expected to have read_text(path, max_bytes)
    max_bytes = 1_000_000  # generous but bounded
    try:
        text = reader.read_text(str(path), max_bytes)
    except FileNotFoundError:
        return Contract.empty(branch=branch)
    except OSError:
        return Contract.empty(branch=branch)
    except Exception:
        return Contract.empty(branch=branch)

    if not isinstance(text, str):
        return Contract.empty(branch=branch)
    if not text.strip():
        return Contract.empty(branch=branch)
    if not _is_contract_document(text, branch):
        return Contract.empty(branch=branch)
    try:
        return parse_contract(text, branch)
    except ValueError:
        return Contract.empty(branch=branch)

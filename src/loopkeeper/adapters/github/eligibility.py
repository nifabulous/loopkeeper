"""Pure fork-eligibility decision for GitHub pull-request review.

A same-repository pull request is eligible on its own. A fork is eligible only
when the currently effective approval label was applied by an actor whose
current repository role is exactly ``maintain`` or ``admin``.

Two things this module is careful about:

**Labels are not a security boundary.** Anyone with triage permission can apply
one, and a label can be removed and re-applied at any time. The label alone
never authorizes; it only identifies *which* actor's authority to check.

**The legacy ``permission`` field cannot express this decision.** GitHub's
repository-permission endpoint returns both ``permission`` and ``role_name``.
The legacy ``permission`` field collapses the Maintain role to ``write`` and
Triage to ``read``, so a Write-role contributor is indistinguishable from a
maintainer there. Only ``role_name`` carries the granular role, so only
``role_name`` is accepted here.

This module performs no I/O. Gathering evidence is the probe's job; judging it
is this module's, which keeps every failure mode testable without a network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

APPROVAL_LABEL = "loopkeeper-approved"

# Exact set. Widening this is a security decision, not a refactor: `write` is
# deliberately absent because it is where the legacy `permission` field hides
# the Maintain/Write distinction.
AUTHORIZED_ROLES = frozenset({"maintain", "admin"})

_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_ACTOR_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_MAX_ACTOR_LEN = 39  # GitHub login maximum
_MAX_LABEL_LEN = 128
_MAX_ROLE_LEN = 64
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

EligibilityReason = Literal[
    "same-repository",
    "authorized-fork",
    "unapproved-fork",
    "unauthorized-actor",
    "unverifiable",
]


@dataclass(frozen=True)
class ApprovalEvidence:
    """Evidence about the currently effective approval label.

    Args:
        label: The label as it currently stands on the pull request.
        actor: The login that applied that currently effective label.
        role_name: That actor's *current* repository role, from the
            ``role_name`` field of the repository-permission endpoint. Never
            the legacy ``permission`` field.
    """

    label: str
    actor: str
    role_name: str


@dataclass(frozen=True)
class EligibilityDecision:
    eligible: bool
    reason: EligibilityReason


def _valid_repo(value: object) -> bool:
    return isinstance(value, str) and bool(_REPO_RE.fullmatch(value))


def _valid_evidence(approval: ApprovalEvidence) -> bool:
    """Reject absent, unbounded, or control-bearing evidence."""
    for value, limit in (
        (approval.label, _MAX_LABEL_LEN),
        (approval.actor, _MAX_ACTOR_LEN),
        (approval.role_name, _MAX_ROLE_LEN),
    ):
        if not isinstance(value, str) or not value or len(value) > limit:
            return False
        if _CONTROL_RE.search(value):
            return False
    return bool(_ACTOR_RE.fullmatch(approval.actor))


def decide_pr_eligibility(
    base_repo: object,
    head_repo: object,
    approval: ApprovalEvidence | None,
) -> EligibilityDecision:
    """Decide whether a pull request may reach the model.

    Args:
        base_repo: The repository being reviewed, as ``owner/name``.
        head_repo: The pull request's head repository, as ``owner/name``.
            ``None`` when the forge did not report one.
        approval: Evidence about the currently effective approval label, or
            ``None`` when no such label is present.

    Returns:
        An :class:`EligibilityDecision`. ``unverifiable`` is deliberately
        distinct from ``unapproved-fork``: the caller exits 4 on unverifiable
        rather than treating broken evidence as a clean rejection.
    """
    if not _valid_repo(base_repo) or not _valid_repo(head_repo):
        return EligibilityDecision(False, "unverifiable")

    # GitHub repository names are case-insensitive, so a case flip is not a
    # fork. Comparing case-sensitively here would send same-repo pull requests
    # down the fork path and demand a label they should never need.
    assert isinstance(base_repo, str) and isinstance(head_repo, str)
    if base_repo.lower() == head_repo.lower():
        return EligibilityDecision(True, "same-repository")

    if approval is None:
        return EligibilityDecision(False, "unapproved-fork")
    if not isinstance(approval, ApprovalEvidence) or not _valid_evidence(approval):
        return EligibilityDecision(False, "unverifiable")

    # Byte-exact. A near-miss label must not authorize, and no case folding or
    # trimming is applied to a value that decides whether a fork runs.
    if approval.label != APPROVAL_LABEL:
        return EligibilityDecision(False, "unapproved-fork")
    if approval.role_name not in AUTHORIZED_ROLES:
        return EligibilityDecision(False, "unauthorized-actor")

    return EligibilityDecision(True, "authorized-fork")


__all__ = [
    "APPROVAL_LABEL",
    "AUTHORIZED_ROLES",
    "ApprovalEvidence",
    "EligibilityDecision",
    "EligibilityReason",
    "decide_pr_eligibility",
]

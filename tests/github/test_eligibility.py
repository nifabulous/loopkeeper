"""Pure fork-eligibility decisions.

A same-repository pull request is eligible on its own. A fork is eligible only
when the *currently effective* approval label was applied by an actor whose
*current* repository role is exactly ``maintain`` or ``admin``.

Two properties this file exists to pin down:

- Labels are not a security boundary. Anyone with triage permission can apply
  one, so the label alone never authorizes; the applying actor's role does.
- The legacy ``permission`` field is not usable for this decision. GitHub maps
  the Maintain role to ``write`` and Triage to ``read`` there, so a Write-role
  contributor would be indistinguishable from a maintainer. Only ``role_name``
  carries the granular role.

Nothing here performs I/O. Collecting the evidence is the probe's job; judging
it is this module's, so every failure mode is testable without a network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loopkeeper.adapters.github.eligibility import (
    APPROVAL_LABEL,
    AUTHORIZED_ROLES,
    ApprovalEvidence,
    decide_pr_eligibility,
)

BASE = "example-org/consumer"
FORK = "outsider/consumer"


def _approval(**overrides) -> ApprovalEvidence:
    fields = {
        "label": APPROVAL_LABEL,
        "actor": "trusted-maintainer",
        "role_name": "maintain",
    }
    fields.update(overrides)
    return ApprovalEvidence(**fields)


# ---------------------------------------------------------------------------
# Same repository
# ---------------------------------------------------------------------------


def test_same_repository_is_eligible_without_any_label():
    decision = decide_pr_eligibility(BASE, BASE, None)

    assert decision.eligible is True
    assert decision.reason == "same-repository"


def test_same_repository_ignores_approval_evidence_entirely():
    """A same-repo PR must not depend on label state in any way."""
    for approval in (None, _approval(), _approval(role_name="read")):
        decision = decide_pr_eligibility(BASE, BASE, approval)
        assert decision.eligible is True
        assert decision.reason == "same-repository"


def test_repository_comparison_is_case_insensitive():
    """GitHub repository names are case-insensitive; a case flip is not a fork."""
    decision = decide_pr_eligibility(BASE, BASE.upper(), None)

    assert decision.eligible is True
    assert decision.reason == "same-repository"


# ---------------------------------------------------------------------------
# Authorized forks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", sorted(AUTHORIZED_ROLES))
def test_fork_is_eligible_for_maintain_and_admin(role):
    decision = decide_pr_eligibility(BASE, FORK, _approval(role_name=role))

    assert decision.eligible is True
    assert decision.reason == "authorized-fork"


def test_authorized_roles_are_exactly_maintain_and_admin():
    """Widening this set is a security decision, not a refactor."""
    assert AUTHORIZED_ROLES == frozenset({"maintain", "admin"})


# ---------------------------------------------------------------------------
# Unauthorized actors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["write", "triage", "read", "none", "pull", "push"])
def test_fork_is_rejected_for_insufficient_roles(role):
    """`write` is the important one: Maintain collapses to it in `permission`."""
    decision = decide_pr_eligibility(BASE, FORK, _approval(role_name=role))

    assert decision.eligible is False
    assert decision.reason == "unauthorized-actor"


def test_fork_is_rejected_for_an_unknown_custom_role():
    decision = decide_pr_eligibility(BASE, FORK, _approval(role_name="release-manager"))

    assert decision.eligible is False
    assert decision.reason == "unauthorized-actor"


@pytest.mark.parametrize("role", ["MAINTAIN", "Admin", " maintain", "maintain "])
def test_role_matching_is_exact(role):
    """No case folding or trimming: the forge value is compared verbatim."""
    decision = decide_pr_eligibility(BASE, FORK, _approval(role_name=role))

    assert decision.eligible is False


# ---------------------------------------------------------------------------
# Unapproved forks
# ---------------------------------------------------------------------------


def test_fork_without_approval_is_unapproved():
    decision = decide_pr_eligibility(BASE, FORK, None)

    assert decision.eligible is False
    assert decision.reason == "unapproved-fork"


def test_fork_with_a_different_label_is_unapproved():
    decision = decide_pr_eligibility(BASE, FORK, _approval(label="please-review"))

    assert decision.eligible is False
    assert decision.reason == "unapproved-fork"


@pytest.mark.parametrize(
    "label",
    [
        APPROVAL_LABEL.upper(),
        f" {APPROVAL_LABEL}",
        f"{APPROVAL_LABEL} ",
        f"{APPROVAL_LABEL}-x",
        f"x-{APPROVAL_LABEL}",
    ],
)
def test_label_matching_is_exact(label):
    """A near-miss label must not authorize; matching is byte-exact."""
    decision = decide_pr_eligibility(BASE, FORK, _approval(label=label))

    assert decision.eligible is False


# ---------------------------------------------------------------------------
# Unverifiable evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base,head",
    [
        ("", FORK),
        (BASE, ""),
        ("not-a-repo", FORK),
        (BASE, "no-slash"),
        (BASE, "too/many/parts"),
        (BASE, "bad owner/name"),
        (BASE, "owner/na me"),
        (BASE, "owner/name\n"),
    ],
)
def test_malformed_repository_names_are_unverifiable(base, head):
    decision = decide_pr_eligibility(base, head, _approval())

    assert decision.eligible is False
    assert decision.reason == "unverifiable"


@pytest.mark.parametrize(
    "overrides",
    [
        {"actor": ""},
        {"role_name": ""},
        {"label": ""},
        {"actor": "has space"},
        {"actor": "ctrl\x00char"},
        {"label": "ctrl\nchar"},
        {"role_name": "ctrl\tchar"},
        {"actor": "a" * 300},
        {"label": "l" * 300},
    ],
)
def test_incomplete_or_malformed_approval_is_unverifiable(overrides):
    """Missing or unbounded evidence never falls through to a rejection reason.

    `unverifiable` is distinct from `unapproved-fork` on purpose: the probe
    exits 4 on unverifiable, rather than silently treating broken evidence as
    a clean "not approved".
    """
    decision = decide_pr_eligibility(BASE, FORK, _approval(**overrides))

    assert decision.eligible is False
    assert decision.reason == "unverifiable"


def test_missing_head_repository_is_unverifiable_not_same_repository():
    """An absent head repo must never be read as the same repository."""
    decision = decide_pr_eligibility(BASE, None, None)

    assert decision.eligible is False
    assert decision.reason == "unverifiable"


# ---------------------------------------------------------------------------
# The decision performs no I/O
# ---------------------------------------------------------------------------


def test_decision_module_imports_no_network_or_subprocess():
    import loopkeeper.adapters.github.eligibility as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in ("import subprocess", "import urllib", "import requests",
                      "import socket", "import http"):
        assert forbidden not in source, f"eligibility must stay pure: {forbidden}"

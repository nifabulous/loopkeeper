"""Bounded forge probe for fork eligibility.

The probe gathers the evidence that ``decide_pr_eligibility`` judges: the
authoritative head repository, the current labels, who applied the currently
effective approval label, and that actor's current ``role_name``.

Every one of those reads is bounded and fails closed. A 403, 404, 429,
malformed body, oversized page, exhausted page budget, or ambiguous label
history exits 4 — it never degrades into "not approved", because a rejection
and an unreadable answer are different things and only one of them is safe to
act on silently.

The probe runs in a job with no model secret. These tests assert it never
reaches a model or a write on any path.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "adapters" / "github" / "resolve_pr_eligibility.sh"

BASE_REPO = "example-org/consumer"
FORK_REPO = "outsider/consumer"
PR_NUMBER = "77"
APPROVAL_LABEL = "loopkeeper-approved"
MAX_RAW_BYTES = 4096

EXIT_TRUST = 4

_GH_STUB = r"""
printf '%s\n' "gh $*" >>"$LOOPKEEPER_TEST_LOG"
fixture_for() {
  case "$1" in
    pr)         printf '%s' "$LOOPKEEPER_TEST_DIR/pr.json" ;;
    timeline)   printf '%s' "$LOOPKEEPER_TEST_DIR/timeline.json" ;;
    permission) printf '%s' "$LOOPKEEPER_TEST_DIR/permission.json" ;;
  esac
}
emit() {
  local kind="$1" file status
  file="$(fixture_for "$kind")"
  status="$LOOPKEEPER_TEST_DIR/${kind}.status"
  if [[ -f "$status" ]]; then
    printf 'gh: HTTP %s\n' "$(cat "$status")" >&2
    exit 1
  fi
  [[ -f "$file" ]] || { printf 'gh: missing fixture\n' >&2; exit 1; }
  cat "$file"
}
case "$*" in
  *"/collaborators/"*"/permission"*) emit permission ;;
  *"/timeline"*|*"/events"*)         emit timeline ;;
  *"pulls/"*|*"pr view"*)            emit pr ;;
  *) printf 'gh: unexpected call: %s\n' "$*" >&2; exit 1 ;;
esac
"""


def _write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\nset -uo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _pr_fixture(head_repo: str = FORK_REPO, labels: list[str] | None = None) -> dict:
    return {
        "number": int(PR_NUMBER),
        "state": "OPEN",
        "head": {"repo": {"full_name": head_repo}},
        "labels": [{"name": name} for name in (labels if labels is not None else [])],
    }


def _timeline(events: list[tuple[str, str, str]]) -> list[dict]:
    """Build a label timeline from (event, label, actor) tuples."""
    return [
        {"event": event, "label": {"name": label}, "actor": {"login": actor}}
        for event, label, actor in events
    ]


def _run(
    tmp_path: Path,
    *,
    pr: dict | None = None,
    timeline: list[dict] | None = None,
    permission: dict | None = None,
    raw: dict[str, str] | None = None,
    fail: dict[str, int] | None = None,
    raw_bytes: int = MAX_RAW_BYTES,
    env_overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    log = tmp_path / "calls.log"
    log.touch()
    _write_stub(stub_dir, "gh", _GH_STUB)

    if pr is not None:
        (tmp_path / "pr.json").write_text(json.dumps(pr), encoding="utf-8")
    if timeline is not None:
        (tmp_path / "timeline.json").write_text(json.dumps(timeline), encoding="utf-8")
    if permission is not None:
        (tmp_path / "permission.json").write_text(json.dumps(permission), encoding="utf-8")
    for kind, body in (raw or {}).items():
        (tmp_path / f"{kind}.json").write_text(body, encoding="utf-8")
    for kind, status in (fail or {}).items():
        (tmp_path / f"{kind}.status").write_text(str(status), encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env['PATH']}"
    env.update(
        {
            "LOOPKEEPER_TEST_LOG": str(log),
            "LOOPKEEPER_TEST_DIR": str(tmp_path),
            "GH_TOKEN": "stub-token",
            "GH_REPO": BASE_REPO,
            "PYTHONPATH": str(ROOT / "src"),
            "LOOPKEEPER_CHECK_MAX_RAW_BYTES": str(raw_bytes),
            "GITHUB_OUTPUT": str(tmp_path / "gh-output"),
        }
    )
    if env_overrides:
        env.update(env_overrides)

    result = subprocess.run(
        [str(PROBE), PR_NUMBER],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return result, log.read_text(encoding="utf-8").splitlines()


def _outputs(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / "gh-output"
    if not path.is_file():
        return {}
    pairs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            pairs[key] = value
    return pairs


# ---------------------------------------------------------------------------
# Eligible paths
# ---------------------------------------------------------------------------


def test_same_repository_is_eligible_without_touching_permissions(tmp_path):
    """A same-repo PR must not spend an API call on label authority."""
    result, calls = _run(tmp_path, pr=_pr_fixture(head_repo=BASE_REPO))

    assert result.returncode == 0, result.stderr
    assert _outputs(tmp_path).get("eligible") == "true"
    assert _outputs(tmp_path).get("reason") == "same-repository"
    assert not any("/permission" in c for c in calls)


def test_fork_with_maintainer_label_is_eligible(tmp_path):
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline([("labeled", APPROVAL_LABEL, "trusted-maintainer")]),
        permission={"permission": "write", "role_name": "maintain"},
    )

    assert result.returncode == 0, result.stderr
    assert _outputs(tmp_path).get("eligible") == "true"
    assert _outputs(tmp_path).get("reason") == "authorized-fork"


def test_reapplied_label_uses_the_most_recent_application(tmp_path):
    """apply -> remove -> apply must authorize against the LAST applier."""
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline(
            [
                ("labeled", APPROVAL_LABEL, "trusted-maintainer"),
                ("unlabeled", APPROVAL_LABEL, "trusted-maintainer"),
                ("labeled", APPROVAL_LABEL, "outsider"),
            ]
        ),
        permission={"permission": "read", "role_name": "read"},
    )

    assert result.returncode == 0, result.stderr
    assert _outputs(tmp_path).get("eligible") == "false"
    assert _outputs(tmp_path).get("reason") == "unauthorized-actor"


# ---------------------------------------------------------------------------
# Rejections that are answers, not failures
# ---------------------------------------------------------------------------


def test_fork_without_the_label_is_unapproved(tmp_path):
    result, calls = _run(tmp_path, pr=_pr_fixture(labels=["needs-triage"]))

    assert result.returncode == 0, result.stderr
    assert _outputs(tmp_path).get("eligible") == "false"
    assert _outputs(tmp_path).get("reason") == "unapproved-fork"
    assert not any("/permission" in c for c in calls)


def test_write_role_applier_is_unauthorized(tmp_path):
    """The legacy permission field would call this 'write' too. role_name decides."""
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline([("labeled", APPROVAL_LABEL, "contributor")]),
        permission={"permission": "write", "role_name": "write"},
    )

    assert result.returncode == 0, result.stderr
    assert _outputs(tmp_path).get("eligible") == "false"
    assert _outputs(tmp_path).get("reason") == "unauthorized-actor"


# ---------------------------------------------------------------------------
# Fail-closed paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [403, 404, 429, 500])
@pytest.mark.parametrize("endpoint", ["pr", "timeline", "permission"])
def test_forge_errors_exit_four(tmp_path, endpoint, status):
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline([("labeled", APPROVAL_LABEL, "trusted-maintainer")]),
        permission={"permission": "write", "role_name": "maintain"},
        fail={endpoint: status},
    )

    assert result.returncode == EXIT_TRUST, f"{endpoint} {status}: {result.stdout}"
    assert _outputs(tmp_path).get("eligible") != "true"


def test_malformed_json_exits_four(tmp_path):
    """A body that is not JSON is unavailable evidence, not a rejection."""
    result, _ = _run(tmp_path, raw={"pr": "{not json"})

    assert result.returncode == EXIT_TRUST, result.stdout
    assert _outputs(tmp_path).get("eligible") != "true"


def test_oversized_response_exits_four(tmp_path):
    """One byte over the raw bound is unavailable evidence, not a rejection."""
    padded = _pr_fixture(labels=[APPROVAL_LABEL])
    padded["_pad"] = "x" * (MAX_RAW_BYTES + 1)
    result, _ = _run(tmp_path, pr=padded)

    assert result.returncode == EXIT_TRUST, result.stdout


def test_label_present_but_absent_from_history_exits_four(tmp_path):
    """Truncated or ambiguous history must never authorize."""
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline([("labeled", "unrelated", "someone")]),
        permission={"permission": "admin", "role_name": "admin"},
    )

    assert result.returncode == EXIT_TRUST, result.stdout
    assert _outputs(tmp_path).get("eligible") != "true"


def test_missing_role_name_exits_four(tmp_path):
    """A permission payload without role_name is not downgradable to permission."""
    result, _ = _run(
        tmp_path,
        pr=_pr_fixture(labels=[APPROVAL_LABEL]),
        timeline=_timeline([("labeled", APPROVAL_LABEL, "trusted-maintainer")]),
        permission={"permission": "admin"},
    )

    assert result.returncode == EXIT_TRUST, result.stdout


def test_missing_head_repository_exits_four(tmp_path):
    result, _ = _run(tmp_path, pr={"number": 77, "state": "OPEN", "head": {}, "labels": []})

    assert result.returncode == EXIT_TRUST, result.stdout


# ---------------------------------------------------------------------------
# The probe never reaches a model or a write
# ---------------------------------------------------------------------------


def test_probe_never_calls_a_model_or_writes(tmp_path):
    for kwargs in (
        {"pr": _pr_fixture(head_repo=BASE_REPO)},
        {"pr": _pr_fixture(labels=[])},
        {"pr": _pr_fixture(labels=[APPROVAL_LABEL]),
         "timeline": _timeline([("labeled", APPROVAL_LABEL, "x")]),
         "permission": {"role_name": "read"}},
        {"pr": _pr_fixture(labels=[APPROVAL_LABEL]), "fail": {"timeline": 403}},
    ):
        run_dir = tmp_path / f"case{abs(hash(str(kwargs)))}"
        run_dir.mkdir()
        _, calls = _run(run_dir, **kwargs)
        assert not any("issue comment" in c or "pr comment" in c for c in calls)
        assert not any("transport" in c for c in calls)


def test_probe_source_carries_no_model_secret_and_no_unbounded_pagination():
    source = PROBE.read_text(encoding="utf-8")

    assert "LOOPKEEPER_API_KEY" not in source
    assert "--paginate" not in source
    assert "role_name" in source
    # The legacy field must not drive the decision.
    assert 'jq -r .permission' not in source


# ---------------------------------------------------------------------------
# Hard ceilings (review finding: unbounded-configured-ceilings)
#
# The configured bounds arrive from the repository `vars` context. Bounded
# execution has to be enforced by trusted code, not by trusting configuration,
# so a mis-set variable must be rejected rather than obeyed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "var,value",
    [
        ("LOOPKEEPER_CHECK_MAX_RAW_BYTES", "999999999"),
        ("LOOPKEEPER_ELIGIBILITY_MAX_PAGES", "10000"),
        ("LOOPKEEPER_ELIGIBILITY_PAGE_SIZE", "500"),
    ],
)
def test_configured_bounds_above_the_hard_ceiling_are_rejected(tmp_path, var, value):
    result, calls = _run(
        tmp_path,
        pr=_pr_fixture(head_repo=BASE_REPO),
        env_overrides={var: value},
    )

    assert result.returncode == 2, f"{var}={value} was accepted: {result.stderr}"
    assert "hard ceiling" in result.stderr or "page limit" in result.stderr
    # Rejected before any forge call.
    assert calls == []


def test_hard_ceilings_are_defined_in_trusted_code():
    source = PROBE.read_text(encoding="utf-8")

    for name in ("HARD_MAX_RAW_BYTES", "HARD_MAX_PAGES", "HARD_MAX_PAGE_SIZE",
                 "HARD_MAX_TOTAL_BYTES"):
        assert name in source, f"{name} must be a fixed ceiling in the script"


def test_aggregate_byte_budget_is_tracked_across_responses():
    """Per-response bounds leave the total unbounded once pagination starts."""
    source = PROBE.read_text(encoding="utf-8")

    assert "TOTAL_BYTES_READ" in source
    assert "HARD_MAX_TOTAL_BYTES" in source
    assert "aggregate byte ceiling" in source


# ---------------------------------------------------------------------------
# Time-of-check/time-of-use (review finding: stale-eligibility-before-model)
#
# The eligibility job authorizes from a snapshot in a separate job. An
# `unlabeled` event starts a NEW run rather than stopping the in-flight one, so
# the check must be repeated in the step immediately before the one holding the
# model secret.
# ---------------------------------------------------------------------------

REVIEW_WORKFLOWS = ("pr-review.yml", "pr-review-posting.yml")


@pytest.mark.parametrize("name", REVIEW_WORKFLOWS)
def test_eligibility_is_reverified_before_the_model_secret_is_used(name):
    raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")

    recheck = raw.index("- name: Re-verify fork eligibility")
    model_step = raw.index("- name: Run read-only review")
    secret = raw.index("secrets.model_api_key")

    assert recheck < model_step, "the re-check must precede the model step"
    assert recheck < secret, "the re-check must precede the mapped model secret"

    block = raw[recheck:model_step]
    assert "resolve_pr_eligibility.sh" in block
    assert "exit 4" in block, "a withdrawn approval must fail closed"
    assert "model_api_key" not in block, "the re-check step must not hold the secret"
    assert "LOOPKEEPER_API_KEY" not in block

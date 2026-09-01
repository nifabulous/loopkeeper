"""Static contracts for reusable workflows and their caller templates."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from loopkeeper.adapters.github.workflow_identity import (
    WorkflowLookupError,
    resolve_workflow_target,
    select_workflow_run_target,
)

ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40


def test_reusable_pr_workflow_has_workflow_call_and_no_direct_trigger():
    raw = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    assert "workflow_call:" in raw
    assert "pull_request_target:" not in raw
    for name in (
        "consumer_repo",
        "loopkeeper_repo",
        "consumer_trusted_sha",
        "loopkeeper_sha",
        "ci_workflow_name",
        "ci_workflow_file",
        "job_timeout_seconds",
        "post_comments",
    ):
        assert re.search(rf"^\s+{name}:$", raw, re.MULTILINE)


def test_github_reviewer_prompt_requires_schema_two_json_trailer():
    raw = (ROOT / "adapters/github/review_pr.sh").read_text(encoding="utf-8")

    assert "REVIEW_TRAILER_CONTRACT" in raw
    assert "review_validation_payload" in raw
    assert "python3 -m loopkeeper.review_output" in raw
    assert "--sanitize" in raw
    assert "--max-input-bytes \"$LOOPKEEPER_MAX_OUTPUT_BYTES\"" in raw
    assert "trailer_validation" in raw
    assert "trailer.json" in raw


def test_pr_review_uses_bounded_pull_request_files_api_for_large_prs():
    raw = (ROOT / "adapters/github/review_pr.sh").read_text(encoding="utf-8")
    assert 'pulls/${PR_NUMBER}/files?per_page=' in raw
    assert "gh pr diff" not in raw
    assert "LOOPKEEPER_PR_FILE_PAGE_SIZE" in raw
    assert "LOOPKEEPER_PR_FILE_MAX_PAGES" in raw
    assert "LOOPKEEPER_PR_FILE_MAX_PATCH_BYTES" in raw
    assert "patch_truncated" in raw
    assert 'LOOPKEEPER_PR_FILE_PAGE_SIZE:=5' in raw
    assert 'LOOPKEEPER_PR_FILE_MAX_PAGES:=100' in raw


def test_reusable_pr_workflow_scopes_write_permission_to_writer_job():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]
    review = raw.split("\n  review:", 1)[1].split("\n  writer:", 1)[0]
    writer = raw.split("\n  writer:", 1)[1]
    assert re.search(r"^\s+pull-requests: read$", top_level, re.MULTILINE)
    assert not re.search(r"^\s+pull-requests: write$", review, re.MULTILINE)
    assert re.search(r"^\s+permissions:\n(?:\s+\S+: \S+\n)*\s+pull-requests: write$", writer, re.MULTILINE)


def test_readonly_pr_workflow_cannot_publish_comments():
    raw = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]
    assert re.search(r"^\s+pull-requests: read$", top_level, re.MULTILINE)
    assert "pull-requests: write" not in raw
    assert "\n  writer:\n" not in raw
    assert "if-no-files-found: ignore" in raw


def test_deferred_pr_review_does_not_fail_on_missing_artifact():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    assert "if-no-files-found: ignore" in raw


def test_all_action_and_reusable_workflow_refs_are_full_sha_pinned():
    paths = list((ROOT / ".github/workflows").rglob("*.yml")) + list(
        (ROOT / "examples/github").rglob("*.yml")
    )
    for path in paths:
        for ref in re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", path.read_text(encoding="utf-8")):
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (path, ref)


def test_model_secret_is_scoped_to_model_step():
    raw = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    assert "model_api_key" in raw
    assert "LOOPKEEPER_API_KEY" not in raw.split("jobs:", 1)[0]


def test_workflow_run_path_filters_event_head_and_open_pr():
    assert select_workflow_run_target(
        "workflow_run", "pull_request", HEAD, HEAD, "OPEN", 7, [7]
    ) == "reviewable"
    assert select_workflow_run_target("workflow_run", "push", HEAD, HEAD, "OPEN", 7, [7]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", "b" * 40, HEAD, "OPEN", 7, [7]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", HEAD, HEAD, "CLOSED", 7, [7]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", HEAD, HEAD, "OPEN", 7, []) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", HEAD, HEAD, "OPEN", 7, [8]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", HEAD, HEAD, "OPEN", 7, [7, 8]) == "fallback"


def test_caller_pins_remote_workflow_and_keeps_triggers_on_default_branch():
    raw = (ROOT / "examples/github/pr-review-caller.yml").read_text(encoding="utf-8")
    # Assert the required types are present rather than an exact list: the set
    # grew when fork authorization added labeled/unlabeled, and pinning the
    # literal string made an intended contract change look like a regression.
    types_line = re.search(r"types: \[([^\]]+)\]", raw)
    assert types_line
    types = {t.strip() for t in types_line.group(1).split(",")}
    assert {"opened", "synchronize", "reopened", "ready_for_review"} <= types
    assert "workflows: [CI]" in raw
    assert re.search(r"uses: example-org/loopkeeper/.github/workflows/pr-review.yml@[0-9a-f]{40}", raw)


def test_example_callers_do_not_advertise_targetless_schedules():
    for path in (
        ROOT / "examples/github/pr-review-caller.yml",
        ROOT / "examples/github/pr-review-posting-caller.yml",
        ROOT / "examples/github/issue-triage-caller.yml",
        ROOT / "examples/github/issue-triage-posting-caller.yml",
    ):
        assert "schedule:" not in path.read_text(encoding="utf-8")


def test_caller_uses_pin_and_loopkeeper_sha_input_are_identical():
    for path in (ROOT / "examples/github").glob("*.yml"):
        raw = path.read_text(encoding="utf-8")
        use_sha = re.search(r"uses: [^@]+@([0-9a-f]{40})", raw)
        input_sha = re.search(r"loopkeeper_sha:\s*([0-9a-f]{40})", raw)
        assert use_sha and input_sha, path
        assert use_sha.group(1) == input_sha.group(1), path


def test_posting_and_read_only_callers_have_distinct_permissions():
    readonly = (ROOT / "examples/github/pr-review-caller.yml").read_text(encoding="utf-8")
    posting = (ROOT / "examples/github/pr-review-posting-caller.yml").read_text(encoding="utf-8")
    assert "pull-requests: write" not in readonly
    assert "pull-requests: write" in posting
    issue_readonly = (ROOT / "examples/github/issue-triage-caller.yml").read_text(encoding="utf-8")
    issue_posting = (ROOT / "examples/github/issue-triage-posting-caller.yml").read_text(encoding="utf-8")
    assert "issues: write" not in issue_readonly
    assert "issues: write" in issue_posting


def test_posting_review_publishes_bounded_run_summary():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    assert "render_summary.sh" in raw
    summary = (ROOT / "adapters/github/render_summary.sh").read_text(encoding="utf-8")
    for field in ("evidence", "coverage", "artifact", "head SHA", "writer"):
        assert field in summary


def test_review_workflows_use_the_shared_summary_renderer():
    for name in ("pr-review.yml", "pr-review-posting.yml"):
        raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        assert "render_summary.sh" in raw

    helper = (ROOT / "adapters/github/render_summary.sh").read_text(encoding="utf-8")
    assert "review-metadata.json" in helper
    assert "write-metadata.json" in helper
    assert "GITHUB_STEP_SUMMARY" in helper


def test_issue_triage_carries_redaction_metadata_into_the_prompt():
    raw = (ROOT / "adapters/github/triage_issue.sh").read_text(encoding="utf-8")

    assert "--metadata-file" in raw
    assert "render_redaction_guidance" in raw


def test_review_artifact_records_evidence_and_diff_coverage_metadata():
    raw = (ROOT / "adapters/github/review_pr.sh").read_text(encoding="utf-8")
    for field in (
        "review-metadata.json",
        "files_returned",
        "files_with_truncated_patch",
        "files_page_truncated",
        "coverage",
    ):
        assert field in raw
    assert "patch_truncated=true" in raw
    assert "Evidence coverage" in raw
    assert "partial diff evidence" in raw


def test_called_workflow_writer_concurrency_is_non_cancelable():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    assert "cancel-in-progress: false" in raw
    assert re.search(r"concurrency:\s*\n\s+group:.*pr", raw)


def test_reusable_workflows_persist_read_only_artifacts():
    pr = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    posting_pr = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    triage = (ROOT / ".github/workflows/issue-triage.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@" in pr
    assert "actions/download-artifact@" not in pr
    assert "actions/download-artifact@" in posting_pr
    assert "actions/upload-artifact@" in triage
    assert "LOOPKEEPER_ARTIFACT_DIR" in triage
    assert "LOOPKEEPER_REVIEW_ARTIFACT" not in pr
    assert "LOOPKEEPER_REVIEW_ARTIFACT" in posting_pr
    assert "LOOPKEEPER_POLICY_PATH:" in pr
    assert "LOOPKEEPER_CONTEXT_PATH:" in pr
    assert "LOOPKEEPER_CONTRACT_PATH:" in pr
    assert "LOOPKEEPER_POLICY_PATH:" in triage


def test_agent_workflow_invokes_agent_cli_and_uploads_artifacts():
    raw = (ROOT / ".github/workflows/agent.yml").read_text(encoding="utf-8")
    assert "loopkeeper agent" in raw
    assert "--manifest" in raw
    assert "--agent-name" in raw
    assert "--task-text" in raw
    assert "actions/upload-artifact@" in raw


def test_ci_workflow_runs_actionlint_instead_of_echoing_a_claim():
    raw = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "actionlint" in raw
    assert "echo \"actionlint is supplied" not in raw
    assert "ACTIONLINT_VERSION" in raw
    assert "ACTIONLINT_SHA256" in raw
    assert "github.com/rhysd/actionlint/releases/download" in raw
    assert "sha256sum --check --strict" in raw
    assert "GITHUB_PATH" in raw


class FakeWorkflowApi:
    def __init__(self, payload: dict):
        self.payload = payload

    def list_workflows(self, repo: str, page: int, per_page: int = 100) -> dict:
        return self.payload


def test_workflow_identity_uses_id_and_normalizes_api_path():
    target = resolve_workflow_target(
        "example/project",
        "CI",
        "ci.yml",
        FakeWorkflowApi(
            {"workflows": [{"id": 17, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"}]}
        ),
    )
    assert target.workflow_id == 17


def test_workflow_identity_fails_closed_without_unique_active_path():
    cases = [
        {"workflows": []},
        {"workflows": [{"id": 1, "name": "CI", "path": "ci.yml", "state": "active"}, {"id": 2, "name": "CI", "path": "other.yml", "state": "active"}]},
        {"workflows": [{"id": 1, "name": "CI", "path": ".github/workflows/other.yml", "state": "active"}]},
    ]
    for payload in cases:
        try:
            resolve_workflow_target("example/project", "CI", "ci.yml", FakeWorkflowApi(payload))
        except WorkflowLookupError:
            continue
        raise AssertionError(f"expected lookup failure for {payload}")


def test_every_workflow_shares_one_valid_default_model():
    """The fallback model id is duplicated per workflow; keep it consistent.

    Six hardcoded copies of the same string drift silently. Assert they agree
    and that the value passes the package's own model-shape validation, so a
    default can never be set to a shape resolve_model would reject at runtime.
    """
    import re

    from loopkeeper.model_binding import _validate_model_shape

    pattern = re.compile(r"vars\.LOOPKEEPER_MODEL \|\| '([^']+)'")
    defaults: dict[str, set[str]] = {}
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        found = set(pattern.findall(path.read_text(encoding="utf-8")))
        if found:
            defaults[path.name] = found

    assert defaults, "no workflow declares a fallback model"

    values = set().union(*defaults.values())
    assert len(values) == 1, f"workflows disagree on the default model: {defaults}"

    # Must be bindable: a default that resolve_model rejects fails every run.
    _validate_model_shape(next(iter(values)), "workflow default")


def test_workflow_model_steps_pass_provider_wire_configuration():
    workflows = (
        "pr-review.yml",
        "pr-review-posting.yml",
        "issue-triage.yml",
        "issue-triage-readonly.yml",
        "agent.yml",
    )
    for name in workflows:
        raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        model_count = raw.count("LOOPKEEPER_MODEL:")
        assert model_count > 0, name
        assert raw.count("LOOPKEEPER_API_STYLE: ${{ vars.LOOPKEEPER_API_STYLE || 'responses' }}") == model_count, name
        assert raw.count("LOOPKEEPER_API_BASE_URL: ${{ vars.LOOPKEEPER_API_BASE_URL || '' }}") == model_count, name


def test_pr_caller_manual_dispatch_requires_and_passes_pr_number():
    numeric_pr_number = (
        "pr_number: ${{ fromJSON(format('{0}', github.event.pull_request.number || "
        "github.event.workflow_run.pull_requests[0].number || inputs.pr_number || 0)) }}"
    )
    for name in ("pr-review-caller.yml", "pr-review-posting-caller.yml"):
        raw = (ROOT / "examples/github" / name).read_text(encoding="utf-8")
        assert re.search(
            r"workflow_dispatch:\s*\n\s+inputs:\s*\n\s+pr_number:\s*\n"
            r"\s+description: .+\n\s+required: true\n\s+type: number",
            raw,
        ), name
        assert numeric_pr_number in raw, name


def test_shell_reasoning_effort_allowlists_match_transport():
    from loopkeeper.transport import EFFORTS

    assert "max" in EFFORTS
    for relative in ("adapters/github/review_pr.sh", "adapters/github/triage_issue.sh"):
        raw = (ROOT / relative).read_text(encoding="utf-8")
        match = re.search(
            r'case "\$LOOPKEEPER_REASONING_EFFORT" in\s*\n\s*([^\s)]+)\)',
            raw,
        )
        assert match, relative
        assert set(match.group(1).split("|")) == EFFORTS, relative


def test_issue_triage_separates_read_only_model_job_from_writer():
    raw = (ROOT / ".github/workflows/issue-triage.yml").read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]
    triage = raw.split("\n  triage:", 1)[1].split("\n  writer:", 1)[0]
    writer = raw.split("\n  writer:", 1)[1]

    assert re.search(r"^\s+issues: read$", top_level, re.MULTILINE)
    assert "issues: write" not in triage
    assert 'LOOPKEEPER_OPERATOR: "0"' in triage
    assert "artifact_available: ${{ steps.artifact_status.outputs.available }}" in triage
    assert "inputs.post_comments" in writer
    assert "needs.triage.outputs.artifact_available == 'true'" in writer
    assert re.search(r"^\s+issues: write$", writer, re.MULTILINE)
    assert 'LOOPKEEPER_OPERATOR: "1"' in writer
    assert "post_triage_comment.sh" in writer


def test_issue_triage_read_only_entrypoint_has_no_writer_job():
    """Artifact-only issue callers must not load a write-capable callee."""
    path = ROOT / ".github/workflows/issue-triage-readonly.yml"
    assert path.is_file(), "read-only issue triage needs its own reusable entrypoint"
    raw = path.read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]

    assert re.search(r"^\s+issues: read$", top_level, re.MULTILINE)
    assert "\n  writer:" not in raw
    assert "issues: write" not in raw
    assert 'LOOPKEEPER_OPERATOR: "0"' in raw
    assert "post_triage_comment.sh" not in raw


def test_issue_triage_read_only_caller_uses_read_only_entrypoint():
    caller = (ROOT / "examples/github/issue-triage-caller.yml").read_text(encoding="utf-8")
    assert "/.github/workflows/issue-triage-readonly.yml@" in caller
    assert "post_comments: false" in caller


def test_ci_shell_gate_runs_mutation_security_guard():
    raw = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "tests/github/test_automation.sh" in raw
    assert "tests/mutation/test_security_guards.sh" in raw


def test_checkout_release_comments_match_pinned_checkout_version():
    checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        raw = path.read_text(encoding="utf-8")
        assert f"{checkout} # v7.0.0" not in raw, path.name


# ---------------------------------------------------------------------------
# Fork authorization
#
# The model secret must be unreachable on any path a fork can take without an
# authorized approval. That is enforced by job topology, not by a string in a
# script: the eligibility job never maps the secret, and the job that does map
# it cannot start except on a literal eligible=true.
# ---------------------------------------------------------------------------

REVIEW_WORKFLOWS = ("pr-review.yml", "pr-review-posting.yml")
CALLERS = (
    ROOT / ".github/workflows/loopkeeper-pr-review.yml",
    ROOT / "examples/github/pr-review-caller.yml",
    ROOT / "examples/github/pr-review-posting-caller.yml",
)


def _job_block(raw: str, name: str) -> str:
    """Return the text of one top-level job."""
    start = raw.index(f"\n  {name}:\n")
    following = [
        raw.index(f"\n  {other}:\n")
        for other in ("resolve", "eligibility", "review", "writer")
        if f"\n  {other}:\n" in raw and raw.index(f"\n  {other}:\n") > start
    ]
    return raw[start : min(following)] if following else raw[start:]


@pytest.mark.parametrize("name", REVIEW_WORKFLOWS)
def test_eligibility_job_never_maps_the_model_secret(name):
    raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    block = _job_block(raw, "eligibility")

    assert "model_api_key" not in block, (
        "the eligibility job must not receive the model secret; an unapproved "
        "fork would otherwise be able to reach a paid model call"
    )
    assert "LOOPKEEPER_API_KEY" not in block


@pytest.mark.parametrize("name", REVIEW_WORKFLOWS)
def test_model_job_is_gated_on_a_literal_eligible_true(name):
    raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    block = _job_block(raw, "review")

    assert "needs: [resolve, eligibility]" in block
    assert "needs.eligibility.outputs.eligible == 'true'" in block, (
        "gating must compare to the literal string 'true'; a missing output "
        "must not satisfy the condition"
    )
    # The secret really is mapped in the gated job, so the gate matters.
    assert "model_api_key" in block


@pytest.mark.parametrize("name", REVIEW_WORKFLOWS)
def test_eligibility_job_runs_the_bounded_probe_with_read_only_permission(name):
    raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    block = _job_block(raw, "eligibility")

    assert "resolve_pr_eligibility.sh" in block
    assert "pull-requests: read" in block
    assert "issues: read" in block
    for forbidden in ("pull-requests: write", "issues: write", "contents: write"):
        assert forbidden not in block, f"eligibility job must stay read-only: {forbidden}"


@pytest.mark.parametrize("path", CALLERS, ids=lambda p: p.name)
def test_callers_reevaluate_on_label_change(path):
    """Revoking approval must trigger a fresh evaluation, not leave a stale pass."""
    raw = path.read_text(encoding="utf-8")
    types_line = re.search(r"types: \[([^\]]+)\]", raw)

    assert types_line, f"{path.name} declares no pull_request_target types"
    types = {t.strip() for t in types_line.group(1).split(",")}
    assert "labeled" in types, f"{path.name} does not re-evaluate on labeled"
    assert "unlabeled" in types, f"{path.name} does not re-evaluate on unlabeled"


# ---------------------------------------------------------------------------
# Caller/callee permission subsetting
#
# A reusable workflow cannot request a permission its caller did not grant:
# GitHub rejects the run with `startup_failure` before any job begins. That is
# a silent class of break -- actionlint validates each file alone, and a string
# comparison between two files will not catch it. Adding the eligibility job
# with `issues: read` broke every documented caller this way.
# ---------------------------------------------------------------------------

_PERMISSION_RANK = {"none": 0, "read": 1, "write": 2}


def _workflow_permissions(raw: str) -> dict[str, str]:
    """Top-level ``permissions:`` block of a workflow."""
    block = re.search(r"^permissions:\n((?:  [\w-]+: \w+\n)+)", raw, re.MULTILINE)
    if block is None:
        return {}
    return dict(re.findall(r"  ([\w-]+): (\w+)", block.group(1)))


def _job_permissions(raw: str) -> dict[str, dict[str, str]]:
    """Per-job ``permissions:`` blocks, keyed by job id."""
    found: dict[str, dict[str, str]] = {}
    job: str | None = None
    inside = False
    for line in raw.splitlines():
        job_match = re.match(r"^  ([a-z][\w-]*):$", line)
        if job_match:
            job, inside = job_match.group(1), False
            continue
        if re.match(r"^    permissions:$", line):
            inside = True
            continue
        entry = re.match(r"^      ([\w-]+): (\w+)$", line)
        if inside and entry and job is not None:
            found.setdefault(job, {})[entry.group(1)] = entry.group(2)
        elif inside and line.strip() and not line.startswith("      "):
            inside = False
    return found


def _callers() -> list[tuple[Path, Path]]:
    """Every caller paired with the reusable workflow it invokes."""
    pairs: list[tuple[Path, Path]] = []
    candidates = sorted((ROOT / ".github/workflows").glob("*.yml")) + sorted(
        (ROOT / "examples/github").glob("*.yml")
    )
    for path in candidates:
        raw = path.read_text(encoding="utf-8")
        for called in re.findall(
            r"uses: [\w.-]+/[\w.-]+/\.github/workflows/([\w.-]+\.yml)@", raw
        ):
            target = ROOT / ".github/workflows" / called
            if target.exists():
                pairs.append((path, target))
    return pairs


def test_every_caller_is_paired_with_a_reusable_workflow():
    """Guard the discovery itself: a silent empty list would pass every case."""
    pairs = _callers()

    assert pairs, "no caller/callee pairs discovered"
    callers = {caller.name for caller, _ in pairs}
    assert "loopkeeper-pr-review.yml" in callers
    assert "pr-review-caller.yml" in callers
    assert "pr-review-posting-caller.yml" in callers


def test_no_called_job_requests_a_permission_its_caller_withholds():
    for caller, called in _callers():
        caller_raw = caller.read_text(encoding="utf-8")
        called_raw = called.read_text(encoding="utf-8")
        granted = _workflow_permissions(caller_raw)
        assert granted, f"{caller.name} declares no permissions block"
        for job, wanted in _job_permissions(called_raw).items():
            if (
                job == "writer"
                and re.search(r"^\s+post_comments: false$", caller_raw, re.MULTILINE)
                and "inputs.post_comments" in _job_block(called_raw, job)
            ):
                # A literal artifact-only caller cannot schedule this job, so
                # it never requests the writer token. Posting callers remain
                # subject to the full permission-subsetting check below.
                continue
            for scope, level in wanted.items():
                have = granted.get(scope, "none")
                assert _PERMISSION_RANK[level] <= _PERMISSION_RANK[have], (
                    f"{called.name} job {job!r} wants {scope}: {level}, but caller "
                    f"{caller.name} grants {scope}: {have}. GitHub fails the run "
                    f"at startup."
                )


def test_the_eligibility_job_keeps_the_issues_scope_its_probe_needs():
    """Pins the specific scope, so removing it from callers fails loudly."""
    for name in ("pr-review.yml", "pr-review-posting.yml"):
        raw = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        assert _job_permissions(raw)["eligibility"]["issues"] == "read", name

    for name in (
        ".github/workflows/loopkeeper-pr-review.yml",
        "examples/github/pr-review-caller.yml",
        "examples/github/pr-review-posting-caller.yml",
    ):
        granted = _workflow_permissions((ROOT / name).read_text(encoding="utf-8"))
        assert granted.get("issues") == "read", name

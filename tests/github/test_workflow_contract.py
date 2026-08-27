"""Static contracts for reusable workflows and their caller templates."""

from __future__ import annotations

import re
from pathlib import Path

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


def test_pr_review_uses_bounded_pull_request_files_api_for_large_prs():
    raw = (ROOT / "adapters/github/review_pr.sh").read_text(encoding="utf-8")
    assert 'pulls/${PR_NUMBER}/files?per_page=' in raw
    assert "gh pr diff" not in raw


def test_reusable_pr_workflow_scopes_write_permission_to_writer_job():
    raw = (ROOT / ".github/workflows/pr-review-posting.yml").read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]
    writer = raw.split("\n  writer:", 1)[1]
    assert re.search(r"^\s+pull-requests: write$", top_level, re.MULTILINE)
    assert re.search(r"^\s+permissions:\n(?:\s+\S+: \S+\n)*\s+pull-requests: write$", writer, re.MULTILINE)


def test_readonly_pr_workflow_cannot_publish_comments():
    raw = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    top_level = raw.split("jobs:", 1)[0]
    assert re.search(r"^\s+pull-requests: read$", top_level, re.MULTILINE)
    assert "pull-requests: write" not in raw
    assert "if: ${{ inputs.post_comments && github.run_id == 0 }}" in raw


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
    assert "types: [opened, synchronize, reopened, ready_for_review]" in raw
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


def test_called_workflow_writer_concurrency_is_non_cancelable():
    raw = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    assert "cancel-in-progress: false" in raw
    assert re.search(r"concurrency:\s*\n\s+group:.*pr", raw)


def test_reusable_workflows_persist_read_only_artifacts():
    pr = (ROOT / ".github/workflows/pr-review.yml").read_text(encoding="utf-8")
    triage = (ROOT / ".github/workflows/issue-triage.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@" in pr
    assert "actions/download-artifact@" in pr
    assert "actions/upload-artifact@" in triage
    assert "LOOPKEEPER_ARTIFACT_DIR" in triage
    assert "LOOPKEEPER_REVIEW_ARTIFACT" in pr
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

"""Tests for workflow identity resolution.

Covers resolve_workflow_target bounded pagination and pure filter
select_workflow_run_target.
"""

from __future__ import annotations

import pytest

from loopkeeper.adapters.github.workflow_identity import (
    WorkflowLookupError,
    resolve_workflow_target,
    select_workflow_run_target,
)


def _fake_api(workflows, total_count=None):
    class Api:
        def __init__(self, workflows, total_count):
            self.workflows = workflows
            self.total_count = total_count if total_count is not None else len(workflows)
            self.calls = []

        def list_workflows(self, repo, page, per_page=100):
            self.calls.append((page, per_page))
            start = (page - 1) * per_page
            end = start + per_page
            page_workflows = self.workflows[start:end]
            return {"workflows": page_workflows, "total_count": self.total_count}
    return Api(workflows, total_count)


def test_resolve_workflow_target_bounded_pagination():
    workflows = [
        {"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
        {"id": 2, "name": "Other", "path": ".github/workflows/other.yml", "state": "active"},
    ]
    api = _fake_api(workflows)
    target = resolve_workflow_target("owner/repo", "CI", "ci.yml", api, max_pages=10)
    assert target.id == 1
    assert target.path == ".github/workflows/ci.yml"

    # Requires path equals configured file (basename or full)
    with pytest.raises(WorkflowLookupError, match="path"):
        resolve_workflow_target("owner/repo", "CI", "other.yml", api)

    # Exhausting page budget is config failure (fallback)
    many = [{"id": i, "name": f"WF{i}", "path": f".github/workflows/wf{i}.yml", "state": "active"} for i in range(1, 250)]
    many.append({"id": 999, "name": "Target", "path": ".github/workflows/ci.yml", "state": "active"})
    api_many = _fake_api(many, total_count=251)
    # With max_pages=1, should exhaust and raise
    with pytest.raises(WorkflowLookupError, match="exhausted|truncated"):
        resolve_workflow_target("owner/repo", "Target", "ci.yml", api_many, max_pages=1)

    # Truncating page budget also failure
    # Set max_pages large enough to get all but total_count larger than collected
    # Our fake will still return all, but we simulate total_count > collected by not returning all?
    # Instead test with total_count mismatch: collected < total_count
    class TruncApi:
        def list_workflows(self, repo, page, per_page=100):
            if page == 1:
                return {"workflows": workflows, "total_count": 100}
            return {"workflows": [], "total_count": 100}
    api_trunc2 = TruncApi()
    with pytest.raises(WorkflowLookupError, match="truncated"):
        resolve_workflow_target("owner/repo", "CI", "ci.yml", api_trunc2, max_pages=10)


def test_resolve_workflow_target_requires_active_and_unique():
    workflows = [
        {"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
        {"id": 2, "name": "CI", "path": ".github/workflows/ci2.yml", "state": "active"},
    ]
    api = _fake_api(workflows)
    with pytest.raises(WorkflowLookupError, match="ambiguous"):
        resolve_workflow_target("owner/repo", "CI", "ci.yml", api)

    workflows_inactive = [
        {"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "disabled_manually"},
    ]
    api_inactive = _fake_api(workflows_inactive)
    with pytest.raises(WorkflowLookupError, match="not active"):
        resolve_workflow_target("owner/repo", "CI", "ci.yml", api_inactive)


def test_select_workflow_run_target_pure_filter():
    sha = "a" * 40
    # Reviewable: workflow_run, pull_request, exact head, OPEN, exactly one association
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, [15]) == "reviewable"
    # Fallback cases
    assert select_workflow_run_target("pull_request_target", "pull_request", sha, sha, "OPEN", 15, [15]) == "fallback"
    assert select_workflow_run_target("workflow_run", "push", sha, sha, "OPEN", 15, [15]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", sha, "b" * 40, "OPEN", 15, [15]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "CLOSED", 15, [15]) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, []) == "fallback"
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, [15, 15]) == "fallback"  # duplicated
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, [16]) == "fallback"  # wrong pr
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, [15, 16]) == "fallback"  # ambiguous (multiple)
    # Missing association
    assert select_workflow_run_target("workflow_run", "pull_request", sha, sha, "OPEN", 15, []) == "fallback"
    # Non-hex sha
    assert select_workflow_run_target("workflow_run", "pull_request", "not-sha", sha, "OPEN", 15, [15]) == "fallback"

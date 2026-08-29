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


# ---------------------------------------------------------------------------
# Name/file agreement is resolved through forge identity, never string equality
#
# A display name and a file name are independent: either can be renamed without
# the other. Resolution must therefore confirm both resolve to the SAME
# workflow ID, and refuse when it cannot establish that.
# ---------------------------------------------------------------------------

REGISTRY_NAME = "Global Registry Core"
REGISTRY_FILE = "registry-core.yml"


def _workflow(id_, name, path, state="active"):
    return {"id": id_, "name": name, "path": f".github/workflows/{path}", "state": state}


def test_display_name_and_file_resolving_to_one_workflow_is_accepted():
    """The positive case: both inputs identify a single active workflow."""
    api = _fake_api(
        [
            _workflow(11, REGISTRY_NAME, REGISTRY_FILE),
            _workflow(12, "Docs", "docs.yml"),
        ]
    )

    target = resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)

    assert target.workflow_id == 11


def test_matching_name_on_a_renamed_file_is_refused():
    """The workflow was renamed on disk; the configured file no longer matches."""
    api = _fake_api([_workflow(11, REGISTRY_NAME, "registry-core-v2.yml")])

    with pytest.raises(WorkflowLookupError):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)


def test_matching_file_under_a_different_display_name_is_refused():
    """The file is right but the display name was changed in the workflow YAML."""
    api = _fake_api([_workflow(11, "Registry Core (legacy)", REGISTRY_FILE)])

    with pytest.raises(WorkflowLookupError):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)


def test_name_and_file_belonging_to_different_workflows_is_refused():
    """The mismatched-ID case: each input matches, but not the same workflow.

    String equality on either input alone would accept this. Only comparing
    resolved identity rejects it.
    """
    api = _fake_api(
        [
            _workflow(11, REGISTRY_NAME, "something-else.yml"),
            _workflow(12, "Unrelated", REGISTRY_FILE),
        ]
    )

    with pytest.raises(WorkflowLookupError):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)


def test_missing_workflow_is_refused():
    api = _fake_api([_workflow(12, "Docs", "docs.yml")])

    with pytest.raises(WorkflowLookupError):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)


def test_duplicate_name_and_file_is_ambiguous_not_first_match():
    """Two active workflows sharing both inputs must not silently pick one."""
    api = _fake_api(
        [
            _workflow(11, REGISTRY_NAME, REGISTRY_FILE),
            _workflow(12, REGISTRY_NAME, REGISTRY_FILE),
        ]
    )

    with pytest.raises(WorkflowLookupError, match="ambiguous"):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, api)


def test_malformed_api_response_is_refused():
    """A response missing its workflows array is unavailable evidence."""

    class Broken:
        def list_workflows(self, repo, page, per_page=100):
            return {"total_count": 1}

    with pytest.raises((WorkflowLookupError, KeyError, TypeError)):
        resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, Broken())


def test_inactive_workflow_matching_both_inputs_is_refused():
    """An omitted or non-active state is never treated as active."""
    for state in ("disabled_manually", "disabled_inactivity", None):
        entry = _workflow(11, REGISTRY_NAME, REGISTRY_FILE)
        if state is None:
            entry.pop("state")
        else:
            entry["state"] = state
        with pytest.raises(WorkflowLookupError):
            resolve_workflow_target("owner/repo", REGISTRY_NAME, REGISTRY_FILE, _fake_api([entry]))

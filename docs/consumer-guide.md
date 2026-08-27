# Loopkeeper consumer guide

Loopkeeper is consumed through immutable reusable-workflow calls or the
provider-neutral CLI. Copy one of the files under `examples/github/`, replace
the `example-org/loopkeeper` fixture slug and the 40-hex release SHA, then
review the resulting permissions before enabling the workflow.

## PR review

Use `pr-review-caller.yml` for read-only artifacts. It requests only
`contents: read`, `actions: read`, `checks: read`, and `pull-requests: read`.
Use `pr-review-posting-caller.yml` only when a human has approved comment
publishing; that file adds `pull-requests: write` and sets `post_comments: true`.

The caller owns all triggers. The reusable workflow accepts only
`workflow_call`, resolves the consumer default-branch SHA from GitHub, and
checks out the consumer and Loopkeeper repositories into separate directories.
The `loopkeeper_sha` in the `uses:` pin and the input must be the same full
commit SHA. A `consumer_trusted_sha` is an optional diagnostic hint, never a
replacement for forge resolution.

Set `ci_workflow_name` and `ci_workflow_file` to the workflow's display name and
file name (for example `CI` and `ci.yml`). Loopkeeper resolves the display name
through the bounded `/actions/workflows` API response before probing runs; it
does not compare those two strings directly. A missing, ambiguous, inactive,
truncated, or stale CI result takes the current-head fallback review path.

For a generic CI consumer, install the exact package release (`loopkeeper==0.1.0`)
from a trusted package index and run `examples/ci/generic-review.sh` or
`examples/ci/generic-triage.sh` with a caller-attested manifest.

## Issue triage

The issue examples follow the same split. The read-only caller requests
`issues: read`; the posting caller requests `issues: write`. Issue comments use
an issue-content fingerprint and authenticated bot author, so a changed issue
revision is a new artifact and cannot reuse a PR review marker.

## Agent execution

The agent example is dispatch-only and artifact-oriented. Agent definitions are
read from a trusted Loopkeeper checkout and task text is passed as untrusted
input. It does not execute repository code or grant a model shell/network
capability. `verifying-executor` remains refused until a separately attested
sandbox dispatcher is supplied.

## Secrets and writes

The reusable workflows declare only the `model_api_key` secret. It is scoped to
the model invocation step and is never copied into artifacts. Comment and issue
writes require `LOOPKEEPER_OPERATOR=1` inside the adapter; read-only workflows
leave that variable unset or set to `0`. A reusable workflow cannot elevate a
caller's permissions, so keep the read-only and posting caller files separate.

## Release checklist

- Replace the fixture slug and release SHA in every `# LOOPKEEPER-TEMPLATE`
  caller before publication.
- Verify the `uses:` SHA and `loopkeeper_sha` input are identical and point at
  the reviewed release commit.
- Run `pytest`, `tests/github/test_automation.sh`, and the staged dogfood gates.
- Enable posting only on a disposable consumer first; keep automatic gap issue
  creation disabled until the real-PR gate has passed.

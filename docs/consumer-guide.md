# Loopkeeper consumer guide

Loopkeeper is consumed through immutable reusable-workflow calls or the
provider-neutral CLI. Copy one of the files under `examples/github/`, replace
the `example-org/loopkeeper` fixture slug and the 40-hex release SHA, then
review the resulting permissions before enabling the workflow.

## PR review

For the normal setup, use `pr-review-posting-caller.yml`. It calls the
`.github/workflows/pr-review-posting.yml` entrypoint, requests
`pull-requests: write`, and posts the complete review comment by default.
Set `post_comments: false` to keep the run artifact-only, or use
`pr-review-caller.yml` when the caller should request only
`contents: read`, `actions: read`, `checks: read`, `issues: read`, and
`pull-requests: read`.

Both entrypoints require `issues: read`. The eligibility probe reads the
pull request's timeline to establish who applied the approval label, and that
timeline is served by the issues API. A caller that omits the scope does not
degrade gracefully: a reusable workflow may not request a permission its
caller withheld, so GitHub rejects the run with `startup_failure` before any
job begins, and no review is produced or reported.

The read-only entrypoint remains available as the least-privilege option. The
posting entrypoint's default is deliberately scoped to that explicit posting
caller; selecting the read-only entrypoint never grants write permission.

### Reviewing pull requests from forks

Same-repository pull requests are reviewed automatically. A fork is reviewed
only when a maintainer or admin applies the `loopkeeper-approved` label.

The label is not itself the authorization — GitHub labels are not protected and
anyone with triage permission can apply one. Loopkeeper checks the *actor who
applied the currently effective label* and requires their current repository
`role_name` to be exactly `maintain` or `admin`. A Write-role contributor
cannot authorize a fork, and removing the label or downgrading that actor's
role withdraws the approval on the next run.

The shipped templates listen for `labeled` and `unlabeled` so approval and
revocation both trigger a fresh evaluation. Keep those trigger types if you
adapt a template.

If the eligibility probe cannot read the evidence it needs, it fails closed and
the fork is not reviewed. See the fork-authorization section of
[`docs/github-adapter.md`](github-adapter.md) for the full contract.

The caller owns all triggers. The reusable workflow accepts only
`workflow_call`, resolves the consumer default-branch SHA from GitHub, and
checks out the consumer and Loopkeeper repositories into separate directories.
The shipped caller templates intentionally omit schedules because a scheduled
event has no single PR or issue target; add a scheduler only if it enumerates
and dispatches explicit targets.
The `loopkeeper_sha` in the `uses:` pin and the input must be the same full
commit SHA. A `consumer_trusted_sha` is an optional diagnostic hint, never a
replacement for forge resolution.

Review runs publish a bounded job summary with the event, PR head, evidence
state, coverage state, artifact availability, and writer action. The uploaded
review artifact also contains `review-metadata.json` and `trailer.json`.
`trailer.json` records whether the model emitted a valid Schema-2 trailer;
`MALFORMED-TRAILER` is intentionally fail-closed and must be resolved before
expecting an automated arbiter disposition. Use these fields when diagnosing a
deferred direct run or a later exact-head CI replacement.

Set `ci_workflow_name` and `ci_workflow_file` to the workflow's display name and
file name (for example `CI` and `ci.yml`). Loopkeeper resolves the display name
through the bounded `/actions/workflows` API response before probing runs; it
does not compare those two strings directly. A missing, ambiguous, inactive,
truncated, or stale CI result takes the current-head fallback review path.

For a generic CI consumer, install the exact package release (`loopkeeper==0.1.1`)
from a trusted package index and run `examples/ci/generic-review.sh` or
`examples/ci/generic-triage.sh` with a caller-attested manifest.

## Issue triage

The issue examples follow the same split. The read-only caller uses the
`issue-triage-readonly.yml` reusable entrypoint and requests `issues: read`; the
posting caller uses `issue-triage.yml` and requests `issues: write`. Keeping the
write-capable entrypoint out of the read-only call is required because GitHub
validates every job permission in a cross-repository reusable workflow before
it evaluates a conditional writer. Issue comments use an issue-content
fingerprint and authenticated bot author, so a changed issue revision is a new
artifact and cannot reuse a PR review marker.

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

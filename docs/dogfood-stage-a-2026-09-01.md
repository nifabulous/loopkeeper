# Stage A dogfood evidence — 2026-09-01

Loopkeeper v0.1.0 completed an artifact-only review in the private disposable
consumer `nifabulous/loopkeeper-dogfood-20260831`.

## Provenance

- `dogfood_stage`: `A-read-only`
- Loopkeeper revision: `f953d63d35c6229c445b79f6980da5514c249932`
- Consumer trusted revision: `fc1d78d588e53b94936467dc3c649b3d45672581`
- Pull request: `nifabulous/loopkeeper-dogfood-20260831#3`
- Reviewed head: `0d4c10728bf24076ef43de4cad2200e78d721bd4`
- Direct run: `33501173948` (deferred because exact-head CI was in progress)
- Exact-head CI run: `33501197478`
- Operator state: `false`
- Write-attempt count: `0`
- Gap-issue state: disabled

## Mechanical checks

- Run conclusion: `success`
- Evidence state: `ci`
- Diff coverage: `complete`
- Files returned: `2`
- Truncated patches: `0`
- Schema-2 trailer: valid
- Trailer error: none
- Writer action: `skipped_read_only`
- PR comment count before and after: `3`

The downloaded artifact contained `review.md`, `comment.md`,
`review-metadata.json`, `trailer.json`, and `write-metadata.json`. Parsing
`review.md` with `loopkeeper.schema.parse_trailer` returned `valid=True`.

## Finding from the exercise

The first manual dispatch, run `33500595301`, failed before job creation.
GitHub reported that the reusable workflow's numeric `pr_number` input received
the string value `"3"`. The read-only caller template forwarded
`inputs.pr_number` directly, unlike the working posting caller. The template
now coerces event and dispatch values through `fromJSON(format(...))`.
Post-fix manual dispatch `33500982996` completed successfully and exercised
the dispatch coercion; it produced no artifact because PR #3's then-current
head already had a canonical review. The later artifact-producing runs above
exercised the `pull_request_target` and `workflow_run` event-number branches.

## Read-only issue triage

Issue triage was exercised against
`nifabulous/loopkeeper-dogfood-20260831#2` using the same immutable Loopkeeper
revision.

- Consumer trusted revision: `b393247fa58c26e685ce04ed8ddec2921b838752`
- Workflow-dispatch run: `33510559939`
- Run conclusion: `success`
- Operator state: `false`
- Write-attempt count: `0`
- Issue comment count before and after: `0`
- Artifact fingerprint:
  `3e73f31097d8f75b82d55474845f991bca523b28c5425a9f604492fc5c0f14ec`
- Result: Documentation / P3

The downloaded artifact contained `triage.md`, `comment.md`, and
`triage-metadata.json`. The dispatch also verified that issue-number inputs
must be coerced to the reusable workflow's numeric input type; both shipped
issue-triage caller templates now enforce that boundary.

## Fallback and CI precedence

The same PR was then advanced through a no-CI fallback exercise and a real
pull-request CI event.

- Fallback review run: `33526446870` (`workflow_dispatch`), successful,
  artifact state `fallback` for the then-current head.
- A manually dispatched CI run (`33526797045`) does not count as CI evidence;
  the adapter intentionally accepts only `workflow_run` events sourced from a
  `pull_request`. Its review remained `fallback` (`33526852590`).
- Exact-head CI run: `33527423729` (`pull_request`), successful, for head
  `758963326cf25c2cb801b668a4c90f0df143d608`.
- Exact-head review run: `33527449037` (`workflow_run`), successful, with
  `evidence_state: ci`, complete two-file coverage, zero truncated patches,
  a valid Schema-2 trailer, and writer action `skipped_read_only`.
- PR comment count before and after the exact-head review: `4` (unchanged;
  the additional comment is the operator's lifecycle note, not a review
  write).

This confirms the intended precedence: a fallback result can be produced when
CI evidence is unavailable, while a later exact-head `pull_request` CI result
is independently attested through `workflow_run`.

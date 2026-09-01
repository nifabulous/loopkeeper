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

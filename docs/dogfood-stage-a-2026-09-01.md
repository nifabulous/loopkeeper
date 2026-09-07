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

## Caller-attested generic review

The provider-neutral CLI path was exercised with a signed generic review
manifest and the test-only protected key fixture. The local artifact-only
harness completed with exit code `0` and produced `review.md` and
`trailer.json`.

- Manifest digest: `dcf6b8bdc20bd75c6db676b2cc48099e54c08cc0daac66919b1e24c324f8df4d`
- Trust mode: `caller-attested`
- Schema-2 trailer: valid; no diagnostic or error code
- Review artifact SHA-256:
  `195374a1fcb918ed7d055afdb105ea701e1d567a5f5c5f2dfef3ee9a5ae002f0`

The harness used only the repository's test key and a bounded fake model; no
production credentials or provider payloads were persisted. This verifies the
manifest digest/signature boundary and generic artifact contract before the
separate Stage B write gate.

## Stage B dogfood evidence — disposable writes

Stage B was run only after explicit approval in the Codex task, against the
private throwaway consumer `nifabulous/loopkeeper-dogfood-20260831` PR #3. The
posting caller used the merged concurrency fix at
`b654c89943a49109266f25cb132093ace0e14b67`; gap-issue creation remained
disabled throughout. The disposable caller and model workflows were disabled
and the temporary seed workflow was removed after the exercise.

### Fallback creation

- `dogfood_stage`: `B-disposable-write`
- Operator state: `true`
- Gap-issue state: disabled
- No-CI head: `40ca624895664123fb955b99929a857222a838a5`
- Posting run: `33533583527` (`pull_request_target`), successful
- Writer outcome: `success`; `LOOPKEEPER_OPERATOR=1`
- Canonical review comment: `5497332950`
- Published evidence: `fallback`

The writer created one bounded review comment for the exact head. Its trailer
parsed as Schema 2 and its coverage metadata reported both changed files with
no truncated patches.

### Exact-head CI replacement and concurrency fix

The first exact-head attempt exposed a real workflow defect: the read-only and
posting reusable callers shared one concurrency group. Runs
`33534079646`/`33534079709` and the posting `workflow_run`
`33534103767` were cancelled while read-only run `33534103902` completed. PR
#31 fixed this by giving the two callers distinct group prefixes; the fix
merged as `b654c89943a49109266f25cb132093ace0e14b67`.

After repinning the disposable callers to that revision:

- Exact CI head: `c62a2bd3ba8dc33ac37db5d671af62ce28e4b3f2`
- Fallback seed run: `33535419952`, successful; comment `5497529778`
- Exact pull-request CI run: `33534080551`, successful
- Posting `workflow_run`: `33535794441`, successful
- Read-only `workflow_run`: `33535794533`, successful
- Final comment for that head: still `5497529778` (updated in place)

The posting artifact reported `event_name: workflow_run`, exact-head CI
evidence, complete two-file coverage, zero truncated patches, and a valid
Schema-2 trailer. The comment changed from `loopkeeper-evidence:fallback` to
`loopkeeper-evidence:ci` without creating a second current-head comment.

### Duplicate reconciliation

For head `eaac6e344f233194dc57112005a678c25dc2e206`, seed run `33537166764`
created two bot-authored comments (`5497721301` and `5497721446`) with the
same canonical marker. Replay run `33537265860` completed successfully after
the concurrency fix:

- The oldest comment, `5497721301`, remained canonical and carried the valid
  CI review trailer.
- The newer comment, `5497721446`, was rewritten in place with
  `loopkeeper-superseded:3:eaac6e344f233194dc57112005a678c25dc2e206:5497721446`.
- No new review comment was created.
- The artifact reported complete coverage (2 files, 0 truncated patches) and
  `trailer_validation.valid: true` with no error code.

### Arbiter disposition and replay

The GitHub collector read the disposable PR under the trusted Loopkeeper
checkout and the pure arbiter returned `MERGE-CLEAN` under rule `CLEAN`
(`needs_human: false`, 8 rounds). Publishing that decision twice at the same
head left exactly one current-head arbiter marker, comment `5497819304`, with
the second call updating the existing comment rather than creating another.
The local probe set `LOOPKEEPER_BOT_LOGIN` to the authenticated disposable
owner; the Actions workflow uses its normal `github-actions[bot]` identity.

The arbiter regression and round-trip suites passed (`60 passed`), including
the fail-closed malformed-latest-round case (`NEEDS-HUMAN` with
`MALFORMED-TRAILER`, 1 passed / 49 deselected). No model payloads or
credentials were persisted.

### Final disposable state

The latest head has one canonical review marker, one bounded superseded marker,
and one arbiter marker. Across the intentionally seeded history there are
eight review markers and three superseded markers; the disposable posting and
seed workflows are now removed/disabled, and no production repository has
write enablement.

The three retained GitHub artifacts are time-limited (all expire 2026-09-08),
so their bounded metadata is fingerprinted here for audit continuity:

| Run | Artifact ID | `review-metadata.json` SHA-256 | `trailer.json` SHA-256 |
| --- | ---: | --- | --- |
| `33533583527` | `9810749267` | `39b6de13817efdefb6a409babbc866369c6cf1d26e53660e927a207e99623b1c` | `08619cf51e873b108ab17b4c11cb8c793c6706872549b92168fa9f9952216073` |
| `33535794441` | `9811568749` | `50cb4a9f349bfd2e8421d2279a9f70088855f86c8c704461cf155c39d167f8ff` | `08619cf51e873b108ab17b4c11cb8c793c6706872549b92168fa9f9952216073` |
| `33537265860` | `9812144417` | `dfed03dbbe36d482f5bce7b078060d21eb813b6b9cda8261c350e1264400fe2f` | `08619cf51e873b108ab17b4c11cb8c793c6706872549b92168fa9f9952216073` |

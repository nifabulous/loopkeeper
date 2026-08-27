# Staged dogfood runbook

## Stage A — read-only

Use a consumer repository with the caller workflow and Loopkeeper release pins
reviewed, but leave `LOOPKEEPER_OPERATOR` unset (or `0`) and keep gap issue
creation disabled. Exercise a normal PR with CI, a conflicting PR with no CI
run, a later exact-head CI completion, issue triage, and a caller-attested
generic manifest. Capture only bounded sanitized artifacts and summaries.

Record the consumer and workflow SHAs, observed head/run IDs,
`dogfood_stage: "A-read-only"`, operator state `false`, and write-attempt count
`0`. The fallback and later CI cases must produce separate evidence artifacts;
Stage A must not claim that a comment was replaced because no write is enabled.

## Stage B — disposable writes

After explicit human approval, use only a throwaway consumer repository and a
short-lived model credential. Set `LOOPKEEPER_OPERATOR=1` for that target while
keeping gap issues disabled. Seed a no-CI PR, verify one fallback comment, then
deliver an exact-head CI completion and verify in-place `loopkeeper-evidence:ci`
replacement. Seed duplicate bot comments and verify deterministic oldest
canonicalization with bounded superseded markers. Exercise an arbiter
disposition and replay events to prove idempotency.

Record `dogfood_stage: "B-disposable-write"`, the throwaway repository,
approval reference, operator state `true`, gap-issue state `false`, bounded
write summaries, final marker counts, and artifact provenance. Redact model/API
payloads and credentials before persistence. Production write enablement is a
separate human change after both stages are reviewed.

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

## Verifying the trailer mechanically

Check the published trailer with the parser, never by eye. The PR A dogfood run
on pull request #10 produced a review that read as a clean pass but carried no
Schema-2 trailer at all: it ended with a plain-text line,

```
loopkeeper-verdict: NO_FINDINGS_WITH_TRUNCATED_PATCH_CAVEAT
```

which the output contract explicitly prohibits. `parse_trailer` returns
`MALFORMED-TRAILER` / "no trailer found", and `docs/release.md` makes a
latest-round `MALFORMED-TRAILER` a release blocker for the normal review path.

```bash
gh api "repos/$REPO/issues/$PR/comments" \
  --jq '.[] | select(.user.login=="github-actions[bot]") | .body' > /tmp/review.md
python3 -c "
from pathlib import Path
from loopkeeper.schema import parse_trailer
v = parse_trailer(Path('/tmp/review.md').read_text())
print(v.valid, v.error_code, v.diagnostic)
"
```

Also record the evidence budget actually used. The adapter logs the derived
per-file patch budget and the changed-file count to stderr; a review whose
`review-metadata.json` reports `coverage.state == "partial"` has not seen the
whole diff, and its findings must be weighted accordingly.

Both properties depend on the Loopkeeper revision the workflow is pinned to,
not on the pull request under review. A pin predating either fix reproduces
the original failure regardless of what the pull request contains.

## Stage B — disposable writes

After explicit human approval, use only a throwaway consumer repository and a
short-lived model credential. Set `LOOPKEEPER_OPERATOR=1` for that target while
keeping gap issues disabled. Seed a no-CI PR, verify one fallback comment, then
deliver an exact-head CI completion and verify in-place `loopkeeper-evidence:ci`
replacement. Seed duplicate bot comments and verify deterministic oldest
canonicalization with bounded superseded markers. Exercise an arbiter
disposition and replay events to prove idempotency. The latest review artifact
must contain a parseable Schema-2 trailer, and the arbiter must not report
`MALFORMED-TRAILER`; malformed-output handling remains a separate fail-closed
test that is expected to produce `NEEDS-HUMAN`.

Record `dogfood_stage: "B-disposable-write"`, the throwaway repository,
approval reference, operator state `true`, gap-issue state `false`, bounded
write summaries, final marker counts, and artifact provenance. Redact model/API
payloads and credentials before persistence. Production write enablement is a
separate human change after both stages are reviewed.

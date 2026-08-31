# Loopkeeper security model

Loopkeeper separates trusted control-plane material from untrusted PR, issue,
and task content. GitHub workflows check out the consumer default branch and
the Loopkeeper release into different directories. The forge resolves the
consumer default-branch SHA; a caller hint is diagnostic only. The reusable
workflow accepts only immutable full-commit SHA pins and verifies both checked
out commits before invoking adapters. Release provenance is generated after
the immutable build and published as a separate artifact; the adapter never
trusts a self-referential manifest from the checked-out tree. The release
workflow keeps package construction and publication in separate jobs: the
build job has only `contents: read`, while the human-gated publish job has
`contents: read` plus the narrowly scoped `id-token: write` permission required
for PyPI trusted publishing. The workflow does not consume a PyPI API token.

Generic CI uses a caller-attested manifest. The protected key file is selected
from `LOOPKEEPER_TRUST_KEY_FILE`, never from a manifest or untrusted artifact.
Attestation covers the repository, head SHA, trusted revision, and canonical
manifest digest. Verification happens before model invocation.

Model output is sanitized before trailer parsing, rendering, or persistence.
Raw response envelopes, credentials, and provider-specific environment names
are not written to artifacts. Input and output byte limits, bounded pagination,
and deadline-aware retries are enforced. A failed or truncated read is
unavailable evidence, never an empty result.

Redaction profiles are kept separate at the trust boundary. Payment messages
use the broad `payments` profile; GitHub review and triage evidence use the
`code-review` profile, which preserves source sizes, IDs, and hash-like literals
while still redacting credentials and context-marked account/card fields. This
prevents payment heuristics from manufacturing defects out of benign code
evidence without weakening payment redaction.

GitHub writes are opt-in. Every create/update path requires
`LOOPKEEPER_OPERATOR=1`, and posting callers request only the smallest required
permission. Review comments use authenticated bot markers and a serialized
same-head state machine; duplicates are rewritten as superseded markers rather
than deleted. Automatic gap issue creation stays disabled until the staged
real-PR gate has passed.

Rotate attestation keys by publishing a new `key_id`, allowing a bounded overlap
window where both protected keys verify, removing the old key from protected
stores, and rejecting retired IDs. Never commit a key file or put a secret in a
manifest, example, artifact, or workflow log.

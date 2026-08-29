#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { echo "security mutation guard: $*" >&2; exit 1; }
contains() { grep -q -- "$2" "$1" || fail "missing guard '$2' in $1"; }

contains "$ROOT/adapters/github/common.sh" 'show "\$trusted_sha:\$path"'
contains "$ROOT/adapters/github/common.sh" 'LOOPKEEPER_OPERATOR'
contains "$ROOT/adapters/github/review_pr.sh" 'LOOPKEEPER_TRUSTED_SHA'
contains "$ROOT/adapters/github/review_pr.sh" 'LOOPKEEPER_OPERATOR'
contains "$ROOT/adapters/github/review_pr.sh" 'loopkeeper-pr-review:'
contains "$ROOT/adapters/github/review_pr.sh" 'loopkeeper-evidence:'
contains "$ROOT/src/loopkeeper/adapters/github/workflow_identity.py" 'source_event != "pull_request"'
contains "$ROOT/src/loopkeeper/adapters/github/workflow_identity.py" 'target_pr'
contains "$ROOT/src/loopkeeper/adapters/github/trust.py" 'resolve_consumer_trusted_sha'
contains "$ROOT/src/loopkeeper/manifest.py" 'caller-attested'
contains "$ROOT/src/loopkeeper/attestation.py" 'compare_digest'
contains "$ROOT/src/loopkeeper/paths.py" 'leaves declared root'
contains "$ROOT/src/loopkeeper/redaction.py" 'sanitize_with_metadata'
contains "$ROOT/src/loopkeeper/adapters/github/comment_state.py" 'loopkeeper-superseded:'
contains "$ROOT/.github/workflows/pr-review.yml" 'cancel-in-progress: false'
contains "$ROOT/.github/workflows/pr-review.yml" 'consumer_trusted_sha'
contains "$ROOT/.github/workflows/pr-review.yml" 'LOOPKEEPER_OPERATOR: "0"'

if grep -RIn --exclude='compat.py' --exclude='test_security_guards.sh' 'scripts/codex_responses\|OPENAI_API_KEY' "$ROOT/adapters/github" "$ROOT/examples/ci" >/dev/null; then
  fail "legacy/provider-specific fallback leaked into a new adapter"
fi
if grep -RIn --include='*.sh' -- '--paginate' "$ROOT/adapters/github" | grep -vE ':[[:space:]]*#' >/dev/null; then
  fail "unbounded pagination appeared in an adapter"
fi

echo "Security guard mutation contract: PASS"

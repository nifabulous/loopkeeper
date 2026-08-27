#!/usr/bin/env bash
set -euo pipefail

# Static and syntax contract for the GitHub adapter. This test intentionally
# does not contact GitHub or a model provider; it proves the safety properties
# that must hold before a workflow is allowed to run in a consumer repository.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHELL_ADAPTERS=(
  "$ROOT/adapters/github/common.sh"
  "$ROOT/adapters/github/review_pr.sh"
  "$ROOT/adapters/github/triage_issue.sh"
)

fail() {
  echo "automation contract: $*" >&2
  exit 1
}

for script in "${SHELL_ADAPTERS[@]}"; do
  bash -n "$script" || fail "shell syntax failed: $script"
  if grep -nE '(^|[[:space:]])--paginate([[:space:]]|$)' "$script" | grep -vE '^[0-9]+:[[:space:]]*#' >/dev/null; then
    fail "unbounded --paginate found in $script"
  fi
  if grep -nE 'OPENAI_API_KEY|CODEX_|scripts/codex_' "$script" >/dev/null; then
    fail "legacy provider/Relay name found in $script"
  fi
  if grep -nE '\|\|[[:space:]]*(cp|gh[[:space:]]+pr[[:space:]]+diff)' "$script" >/dev/null; then
    fail "raw fallback after a bounded transform found in $script"
  fi
done

grep -q 'GH_REPO.*owner/name' "$ROOT/adapters/github/common.sh" || fail "GH_REPO validation missing"
grep -q 'show "\$trusted_sha:\$path"' "$ROOT/adapters/github/common.sh" || fail "trusted git show is not quote-safe"
grep -q 'LOOPKEEPER_OPERATOR.*required' "$ROOT/adapters/github/common.sh" || fail "operator gate missing"
grep -q 'capture_bounded_stream.*review artifact' "$ROOT/adapters/github/review_pr.sh" || fail "immutable review artifact path missing"
grep -q 'LOOPKEEPER_OPERATOR' "$ROOT/adapters/github/review_pr.sh" || fail "review writer gate missing"
grep -q 'loopkeeper-pr-review:' "$ROOT/adapters/github/review_pr.sh" || fail "review marker missing"
grep -q 'loopkeeper-evidence:' "$ROOT/adapters/github/review_pr.sh" || fail "evidence marker missing"
grep -q 'select_workflow_run_target' "$ROOT/adapters/github/review_pr.sh" || fail "workflow_run target validation missing"
grep -q 'LOOPKEEPER_POLICY_PATH' "$ROOT/adapters/github/review_pr.sh" || fail "review policy input missing"
grep -q 'LOOPKEEPER_POLICY_PATH' "$ROOT/adapters/github/triage_issue.sh" || fail "triage policy input missing"
grep -q 'capture_bounded_stream.*CI runs' "$ROOT/adapters/github/review_pr.sh" || fail "CI discovery is not bounded"
grep -q 'loopkeeper-superseded:' "$ROOT/adapters/github/comment_state.py" || fail "superseded marker missing"
grep -q 'LOOPKEEPER_OPERATOR' "$ROOT/adapters/github/arbiter_io.py" || fail "arbiter writer gate missing"

# Every action reference must be immutable. Local reusable workflow references
# are checked separately by the workflow contract tests and are not action pins.
while IFS= read -r uses; do
  ref="${uses##*@}"
  ref="${ref%% *}"
  [[ "$ref" =~ ^[0-9a-fA-F]{40}$ ]] || fail "unpinned action reference: $uses"
done < <(grep -hE '^[[:space:]]*uses:[[:space:]]*[^ ]+@[^ ]+' "$ROOT"/.github/workflows/*.yml | sed -E 's/^[[:space:]]*uses:[[:space:]]*//')

echo "GitHub automation contract: PASS"

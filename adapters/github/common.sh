#!/usr/bin/env bash
# Loopkeeper GitHub adapter — shared helpers
# Sourced by review_pr.sh and triage_issue.sh
# Provides GH_REPO validation, quoting helpers, bounded pagination, and operator gating.

# GH_REPO must be owner/name before interpolation into API paths
validate_gh_repo() {
  local repo="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
  if [[ -z "$repo" ]]; then
    echo "GH_REPO or GITHUB_REPOSITORY is required" >&2
    return 2
  fi
  if [[ ! "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    echo "GH_REPO must be owner/name." >&2
    return 2
  fi
  GH_REPO="$repo"
  export GH_REPO
}

# Quote-safe git show from trusted SHA: git show "$TRUSTED_SHA:$path"
show_trusted() {
  local trusted_sha="$1"
  local path="$2"
  # Both args are quoted at call site; this function also quotes them.
  git -C "$REPO_ROOT" show "$trusted_sha:$path"
}

# Bounded stream helper: cap raw response bytes to avoid unbounded reads
capture_bounded_stream() {
  local max_bytes="$1"
  local description="$2"
  python3 -c '
import sys
limit = int(sys.argv[1])
description = sys.argv[2]
data = bytearray()
while True:
    chunk = sys.stdin.buffer.read(min(65536, limit + 1 - len(data)))
    if not chunk:
        break
    data.extend(chunk)
    if len(data) > limit:
        print(f"{description} exceeds its byte limit ({limit})", file=sys.stderr)
        raise SystemExit(1)
sys.stdout.buffer.write(data)
' "$max_bytes" "$description"
}

# Operator gate: every write must have LOOPKEEPER_OPERATOR=1
require_operator() {
  if [[ "${LOOPKEEPER_OPERATOR:-}" != "1" ]]; then
    echo "LOOPKEEPER_OPERATOR=1 is required for write operations" >&2
    return 1
  fi
}

# Forge-backed trust-root verification. Returns zero only when the local
# checkout is exactly the declared trusted SHA *and* that SHA is the forge's
# current tip of the forge's own default branch. The caller-supplied branch
# name is never authoritative; it is only checked for agreement with the forge.
# Both forge responses are byte-bounded, and any unavailable, oversized, or
# malformed response fails closed.
#
# Usage: verify_consumer_checkout <repo-root> <repo> <trusted-sha> <default-branch>
verify_consumer_checkout() {
  local repo_root="$1"
  local repo="$2"
  local trusted_sha="$3"
  local default_branch="$4"
  local max_bytes="${LOOPKEEPER_CHECK_MAX_RAW_BYTES:-200000}"

  if [[ ! "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    echo "GH_REPO must be owner/name." >&2
    return 1
  fi
  if [[ ! "$trusted_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "trusted SHA must be a full lowercase commit SHA." >&2
    return 1
  fi
  if [[ ! "$default_branch" =~ ^[A-Za-z0-9._/-]+$ || "$default_branch" == /* || "$default_branch" == *..* ]]; then
    echo "declared default branch name is unsafe." >&2
    return 1
  fi

  local checked_out
  if ! checked_out="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null)"; then
    echo "Could not resolve the checked-out commit in ${repo_root}; refusing to run." >&2
    return 1
  fi
  if [[ "$checked_out" != "$trusted_sha" ]]; then
    echo "Checkout ${checked_out} does not match the trusted SHA ${trusted_sha}; refusing to run with branch-controlled policy." >&2
    return 1
  fi

  local actual_default
  if ! actual_default="$(gh api "repos/${repo}" --jq '.default_branch' 2>/dev/null \
    | capture_bounded_stream "$max_bytes" "default branch name")"; then
    echo "Could not resolve the default branch of ${repo} through the GitHub API; refusing to run without an independently verified default branch." >&2
    return 1
  fi
  if [[ -z "$actual_default" || "$actual_default" == "null" ]]; then
    echo "Forge returned no usable default branch for ${repo}; refusing to run." >&2
    return 1
  fi
  if [[ "$default_branch" != "$actual_default" ]]; then
    echo "Declared default branch ${default_branch} is not the default branch of ${repo} (${actual_default}); refusing to read trusted policy from a non-default branch." >&2
    return 1
  fi

  local remote_tip
  if ! remote_tip="$(gh api "repos/${repo}/git/ref/heads/${actual_default}" --jq '.object.sha' 2>/dev/null \
    | capture_bounded_stream "$max_bytes" "default branch tip")"; then
    echo "Could not resolve refs/heads/${actual_default} on ${repo} through the GitHub API; refusing to run." >&2
    return 1
  fi
  if [[ ! "$remote_tip" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Forge did not return a full default-branch tip SHA for ${repo}; refusing to run." >&2
    return 1
  fi
  if [[ "$checked_out" != "$remote_tip" ]]; then
    echo "Checkout ${checked_out} is not the tip of ${actual_default} on ${repo} (${remote_tip}); refusing to run with branch-controlled policy." >&2
    return 1
  fi
}

# Verify GH_REPO is quoted when used in API paths — static check helper
# (used by test harness, not runtime)
# No-op at runtime, but documents invariant

# Bounded pagination helper for comments: reads per_page * max_pages cap
# Usage: paged_gh_api "repos/${GH_REPO}/issues/${PR}/comments" 100 10
paged_gh_api() {
  local api_path="$1"
  local per_page="${2:-100}"
  local max_pages="${3:-10}"
  local page=1
  local max_raw_bytes="${LOOPKEEPER_CHECK_MAX_RAW_BYTES:-200000}"
  local collected_bytes=2
  local separator=""
  local aggregate_file
  aggregate_file="$(mktemp)"
  printf '[' >"$aggregate_file"
  while (( page <= max_pages )); do
    local page_file
    page_file="$(mktemp)"
    if ! gh api "repos/${GH_REPO}/${api_path}?per_page=${per_page}&page=${page}" >"$page_file" 2>/dev/null; then
      rm -f "$page_file"
      rm -f "$aggregate_file"
      return 1
    fi
    if ! jq -e 'type == "array"' "$page_file" >/dev/null 2>&1; then
      rm -f "$page_file"
      rm -f "$aggregate_file"
      return 1
    fi
    local count
    count="$(jq 'length' "$page_file")"
    local page_bytes
    page_bytes="$(wc -c <"$page_file" | tr -d ' ')"
    if (( collected_bytes + page_bytes > max_raw_bytes )); then
      rm -f "$page_file"
      rm -f "$aggregate_file"
      return 1
    fi
    while IFS= read -r item; do
      printf '%s%s' "$separator" "$item" >>"$aggregate_file"
      separator=,
    done < <(jq -c '.[]' "$page_file")
    collected_bytes=$((collected_bytes + page_bytes))
    if (( count == 0 )); then
      rm -f "$page_file"
      break
    fi
    rm -f "$page_file"
    page=$((page + 1))
  done
  if (( page > max_pages )); then
    rm -f "$aggregate_file"
    return 1
  fi
  printf ']' >>"$aggregate_file"
  cat "$aggregate_file"
  rm -f "$aggregate_file"
}

# Validate that no script uses unbounded --paginate
# This is checked by test harness via grep, not runtime
# Ensure we never call gh api --paginate without per_page paging cap

# Trust-root verification helper (calls python trust module)
verify_consumer_trusted_sha() {
  local repo="$1"
  local default_branch="$2"
  python3 -m loopkeeper.adapters.github.trust --verify-consumer "$repo" "$default_branch"
}

# Gap label verification before --gap-issues
verify_gap_label() {
  local repo="$1"
  local label="$2"
  python3 -m loopkeeper.adapters.github.trust --verify-gap-label "$repo" "$label"
}

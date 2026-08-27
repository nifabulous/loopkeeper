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

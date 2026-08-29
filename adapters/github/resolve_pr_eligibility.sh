#!/usr/bin/env bash
# Resolve whether a pull request may reach the model.
#
# This runs in a job with NO model secret. It gathers bounded evidence from the
# forge and hands it to the pure decision in
# loopkeeper.adapters.github.eligibility, which judges it.
#
# Every read is byte-bounded and page-bounded. A 403, 404, 429, malformed body,
# oversized page, exhausted page budget, or ambiguous label history exits 4. A
# rejection and an unreadable answer are different things, and only the former
# is safe to report as "not eligible".
set -euo pipefail

ADAPTER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$ADAPTER_DIR/common.sh"

if [[ $# -ne 1 || ! "$1" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 <pull-request-number>" >&2
  exit 2
fi
PR_NUMBER="$1"

GH_REPO="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_REPO:?GH_REPO or GITHUB_REPOSITORY is required}"
if [[ ! "$GH_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
  echo "GH_REPO must be owner/name." >&2
  exit 2
fi

# Hard ceilings live in trusted code. The configured values arrive from the
# repository `vars` context, and bounded execution must be enforced here rather
# than by trusting configuration: a mis-set variable would otherwise turn this
# probe into an arbitrarily large resource and API operation.
HARD_MAX_RAW_BYTES=1000000     # per response
HARD_MAX_PAGES=20              # timeline pages
HARD_MAX_PAGE_SIZE=100         # GitHub's own page limit
HARD_MAX_TOTAL_BYTES=4000000   # aggregate across every response in one run

: "${LOOPKEEPER_CHECK_MAX_RAW_BYTES:=200000}"
: "${LOOPKEEPER_ELIGIBILITY_MAX_PAGES:=10}"
: "${LOOPKEEPER_ELIGIBILITY_PAGE_SIZE:=100}"
for bound in LOOPKEEPER_CHECK_MAX_RAW_BYTES LOOPKEEPER_ELIGIBILITY_MAX_PAGES \
             LOOPKEEPER_ELIGIBILITY_PAGE_SIZE; do
  if [[ ! "${!bound}" =~ ^[1-9][0-9]*$ ]]; then
    echo "$bound must be a positive integer." >&2
    exit 2
  fi
done
if (( LOOPKEEPER_CHECK_MAX_RAW_BYTES > HARD_MAX_RAW_BYTES )); then
  echo "LOOPKEEPER_CHECK_MAX_RAW_BYTES exceeds the hard ceiling ${HARD_MAX_RAW_BYTES}." >&2
  exit 2
fi
if (( LOOPKEEPER_ELIGIBILITY_MAX_PAGES > HARD_MAX_PAGES )); then
  echo "LOOPKEEPER_ELIGIBILITY_MAX_PAGES exceeds the hard ceiling ${HARD_MAX_PAGES}." >&2
  exit 2
fi
if (( LOOPKEEPER_ELIGIBILITY_PAGE_SIZE > HARD_MAX_PAGE_SIZE )); then
  echo "LOOPKEEPER_ELIGIBILITY_PAGE_SIZE must not exceed GitHub's ${HARD_MAX_PAGE_SIZE}-item page limit." >&2
  exit 2
fi

# Aggregate budget across every response. Per-response bounds alone leave the
# total unbounded once pagination is involved.
TOTAL_BYTES_READ=0

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

APPROVAL_LABEL="$(python3 -c 'from loopkeeper.adapters.github.eligibility import APPROVAL_LABEL; print(APPROVAL_LABEL)')"

emit_outputs() {
  local eligible="$1" reason="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      printf 'eligible=%s\n' "$eligible"
      printf 'reason=%s\n' "$reason"
    } >>"$GITHUB_OUTPUT"
  fi
  printf 'eligible=%s reason=%s\n' "$eligible" "$reason"
}

# Any unreadable, oversized, or malformed forge response is unavailable
# evidence. Never a rejection.
fetch_bounded_json() {
  local description="$1" out_file="$2"
  shift 2
  if ! gh api "$@" 2>/dev/null \
    | capture_bounded_stream "$LOOPKEEPER_CHECK_MAX_RAW_BYTES" "$description" >"$out_file"; then
    echo "${description} was unavailable or exceeded its byte bound; refusing to decide eligibility." >&2
    exit 4
  fi
  if ! jq -e . "$out_file" >/dev/null 2>&1; then
    echo "${description} was not valid JSON; refusing to decide eligibility." >&2
    exit 4
  fi
  local size
  size="$(wc -c <"$out_file" | tr -d ' ')"
  TOTAL_BYTES_READ=$((TOTAL_BYTES_READ + size))
  if (( TOTAL_BYTES_READ > HARD_MAX_TOTAL_BYTES )); then
    echo "eligibility evidence exceeded the aggregate byte ceiling ${HARD_MAX_TOTAL_BYTES}; refusing to decide eligibility." >&2
    exit 4
  fi
}

# --- Authoritative pull request -------------------------------------------
# Re-fetched here rather than trusted from the event payload: an event is a
# snapshot, and the label state may have changed since it fired.
fetch_bounded_json "pull request metadata" "$TEMP_DIR/pr.json" \
  "repos/${GH_REPO}/pulls/${PR_NUMBER}"

HEAD_REPO="$(jq -r '.head.repo.full_name // empty' "$TEMP_DIR/pr.json")"
if [[ -z "$HEAD_REPO" ]]; then
  echo "pull request reported no head repository; refusing to decide eligibility." >&2
  exit 4
fi

# --- Same repository shortcut ---------------------------------------------
# Lowercased with tr rather than ${var,,}: that expansion needs bash 4, and
# this script must stay runnable on the bash 3.2 that ships with macOS.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
if [[ "$(lower "$HEAD_REPO")" == "$(lower "$GH_REPO")" ]]; then
  emit_outputs true same-repository
  exit 0
fi

# --- Current labels --------------------------------------------------------
if ! jq -e --arg label "$APPROVAL_LABEL" \
  '[.labels[]?.name // empty] | index($label) != null' "$TEMP_DIR/pr.json" >/dev/null 2>&1; then
  emit_outputs false unapproved-fork
  exit 0
fi

# --- Who applied the currently effective label -----------------------------
# Bounded pagination over the issue timeline. The effective application is the
# last `labeled` event for this label; a later `unlabeled` would have removed
# it, and the label is present, so the last `labeled` is authoritative.
: >"$TEMP_DIR/events.jsonl"
page=1
while (( page <= LOOPKEEPER_ELIGIBILITY_MAX_PAGES )); do
  page_file="$TEMP_DIR/timeline-${page}.json"
  fetch_bounded_json "label timeline page ${page}" "$page_file" \
    "repos/${GH_REPO}/issues/${PR_NUMBER}/timeline?per_page=${LOOPKEEPER_ELIGIBILITY_PAGE_SIZE}&page=${page}"
  if ! jq -e 'type == "array"' "$page_file" >/dev/null 2>&1; then
    echo "label timeline page ${page} was not an array; refusing to decide eligibility." >&2
    exit 4
  fi
  count="$(jq 'length' "$page_file")"
  jq -c '.[] | select((.event == "labeled") or (.event == "unlabeled"))
         | {event, label: (.label.name // ""), actor: (.actor.login // "")}' \
    "$page_file" >>"$TEMP_DIR/events.jsonl"
  (( count < LOOPKEEPER_ELIGIBILITY_PAGE_SIZE )) && break
  page=$((page + 1))
done
if (( page > LOOPKEEPER_ELIGIBILITY_MAX_PAGES )); then
  echo "label timeline exceeded its page budget; refusing to decide eligibility on truncated history." >&2
  exit 4
fi

APPROVER="$(jq -s -r --arg label "$APPROVAL_LABEL" \
  '[.[] | select(.event == "labeled" and .label == $label)] | last | .actor // ""' \
  "$TEMP_DIR/events.jsonl")"
if [[ -z "$APPROVER" || "$APPROVER" == "null" ]]; then
  # The label is present but no application appears in the bounded window.
  # That is ambiguous history, not an approval.
  echo "the ${APPROVAL_LABEL} label is present but its application was not found in the bounded timeline; refusing to decide eligibility." >&2
  exit 4
fi

# --- The approver's CURRENT role ------------------------------------------
# role_name, never the legacy permission field: that one reports Maintain as
# "write", which would make a Write-role contributor indistinguishable from a
# maintainer.
fetch_bounded_json "collaborator permission" "$TEMP_DIR/permission.json" \
  "repos/${GH_REPO}/collaborators/${APPROVER}/permission"

ROLE_NAME="$(jq -r '.role_name // empty' "$TEMP_DIR/permission.json")"
if [[ -z "$ROLE_NAME" ]]; then
  echo "collaborator permission response carried no role_name; refusing to fall back to the legacy permission field." >&2
  exit 4
fi

# --- Pure decision ---------------------------------------------------------
DECISION="$(python3 - "$GH_REPO" "$HEAD_REPO" "$APPROVAL_LABEL" "$APPROVER" "$ROLE_NAME" <<'PY'
import sys

from loopkeeper.adapters.github.eligibility import (
    ApprovalEvidence,
    decide_pr_eligibility,
)

base_repo, head_repo, label, actor, role_name = sys.argv[1:]
decision = decide_pr_eligibility(
    base_repo,
    head_repo,
    ApprovalEvidence(label=label, actor=actor, role_name=role_name),
)
print(f"{'true' if decision.eligible else 'false'} {decision.reason}")
PY
)"
read -r ELIGIBLE REASON <<<"$DECISION"

# Unverifiable evidence is not a rejection; it is a refusal to decide.
if [[ "$REASON" == "unverifiable" ]]; then
  echo "eligibility evidence was incomplete or malformed; refusing to decide." >&2
  exit 4
fi

emit_outputs "$ELIGIBLE" "$REASON"

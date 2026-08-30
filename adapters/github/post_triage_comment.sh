#!/usr/bin/env bash
set -euo pipefail

ADAPTER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$ADAPTER_DIR/common.sh"

if [[ $# -ne 1 || ! "$1" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: $0 <issue-number>" >&2
  exit 2
fi

ISSUE_NUMBER="$1"
: "${GH_TOKEN:?GH_TOKEN is required}"
validate_gh_repo
require_operator || exit 1
: "${LOOPKEEPER_TRIAGE_ARTIFACT_DIR:?LOOPKEEPER_TRIAGE_ARTIFACT_DIR is required}"
: "${LOOPKEEPER_CHECK_MAX_RAW_BYTES:=200000}"
LOOPKEEPER_BOT_LOGIN="${LOOPKEEPER_BOT_LOGIN:-github-actions[bot]}"

if [[ ! "$LOOPKEEPER_CHECK_MAX_RAW_BYTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "LOOPKEEPER_CHECK_MAX_RAW_BYTES must be a positive integer." >&2
  exit 2
fi

TRIAGE_FILE="$LOOPKEEPER_TRIAGE_ARTIFACT_DIR/triage.md"
COMMENT_FILE="$LOOPKEEPER_TRIAGE_ARTIFACT_DIR/comment.md"
ARTIFACT_METADATA_FILE="$LOOPKEEPER_TRIAGE_ARTIFACT_DIR/triage-metadata.json"
for artifact in "$TRIAGE_FILE" "$COMMENT_FILE" "$ARTIFACT_METADATA_FILE"; do
  if [[ ! -f "$artifact" || -L "$artifact" || ! -s "$artifact" ]]; then
    echo "Required triage artifact is missing, empty, or not a regular file: $artifact" >&2
    exit 4
  fi
  artifact_bytes="$(wc -c <"$artifact" | tr -d ' ')"
  if (( artifact_bytes > LOOPKEEPER_CHECK_MAX_RAW_BYTES )); then
    echo "Triage artifact exceeds its byte bound: $artifact" >&2
    exit 4
  fi
done

if ! jq -e \
  --argjson issue_number "$ISSUE_NUMBER" \
  'type == "object"
   and keys == ["fingerprint", "issue_number"]
   and .issue_number == $issue_number
   and (.fingerprint | type == "string" and test("^[0-9a-f]{64}$"))' \
  "$ARTIFACT_METADATA_FILE" >/dev/null 2>&1; then
  echo "Triage artifact metadata is malformed or targets a different issue." >&2
  exit 4
fi
FINGERPRINT="$(jq -r '.fingerprint' "$ARTIFACT_METADATA_FILE")"
MARKER="<!-- loopkeeper-issue-triage:${ISSUE_NUMBER}:${FINGERPRINT} -->"
if [[ "$(head -n 1 "$COMMENT_FILE")" != "$MARKER" ]]; then
  echo "Triage comment does not carry the authenticated artifact marker." >&2
  exit 4
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

if ! gh issue view "$ISSUE_NUMBER" --repo "$GH_REPO" --json number,title,body,state 2>/dev/null \
  | capture_bounded_stream "$LOOPKEEPER_CHECK_MAX_RAW_BYTES" "final issue metadata" \
    >"$TEMP_DIR/latest-metadata.json"; then
  echo "Final issue metadata was unavailable or exceeded its byte bound; refusing to write." >&2
  exit 4
fi
if ! jq -e \
  --argjson issue_number "$ISSUE_NUMBER" \
  'type == "object"
   and has("number") and (.number | type == "number" and . == floor)
   and (.number == $issue_number)
   and has("title") and (.title | type) == "string"
   and has("body") and ((.body == null) or ((.body | type) == "string"))
   and has("state") and (.state | type) == "string"' \
  "$TEMP_DIR/latest-metadata.json" >/dev/null 2>&1; then
  echo "Final issue metadata was malformed; refusing to write." >&2
  exit 4
fi

LATEST_STATE="$(jq -r '.state // empty' "$TEMP_DIR/latest-metadata.json")"
LATEST_FINGERPRINT="$(jq -c '{title: (.title // ""), body: (.body // "")}' "$TEMP_DIR/latest-metadata.json" | sha256sum | cut -d' ' -f1)"
if [[ "$LATEST_STATE" != "OPEN" || "$LATEST_FINGERPRINT" != "$FINGERPRINT" ]]; then
  echo "Issue #${ISSUE_NUMBER} changed or closed before comment publication; no comment was created."
  exit 0
fi

if ! paged_gh_api "issues/${ISSUE_NUMBER}/comments" 100 10 >"$TEMP_DIR/comments.json"; then
  echo "Could not re-read bounded issue comments before publication; refusing to write." >&2
  exit 4
fi
if ! jq -e \
  'type == "array"
   and all(.[];
     (type == "object")
     and ((.user? | type) == "object")
     and ((.user.login? | type) == "string")
     and ((.body? | type) == "string"))' \
  "$TEMP_DIR/comments.json" >/dev/null 2>&1; then
  echo "Issue comment history was malformed; refusing to write." >&2
  exit 4
fi
if jq -e --arg bot "$LOOPKEEPER_BOT_LOGIN" --arg marker "$MARKER" \
  'any(.[]; (.user.login // "") == $bot and ((.body // "") | contains($marker)))' \
  "$TEMP_DIR/comments.json" >/dev/null; then
  echo "Loopkeeper triage was already published for issue #${ISSUE_NUMBER}."
  exit 0
fi

require_operator || exit 1
gh issue comment "$ISSUE_NUMBER" --repo "$GH_REPO" --body-file "$COMMENT_FILE"

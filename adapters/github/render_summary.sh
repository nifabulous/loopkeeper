#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

case "$MODE" in
  review)
    EVENT_NAME="${EVENT_NAME:-unknown}"
    PR_NUMBER="${PR_NUMBER:-unknown}"
    EXPECTED_HEAD_SHA="${EXPECTED_HEAD_SHA:-}"
    REVIEW_OUTCOME="${REVIEW_OUTCOME:-unknown}"
    ARTIFACT_AVAILABLE="${ARTIFACT_AVAILABLE:-false}"
    ARTIFACT_NAME="${ARTIFACT_NAME:-loopkeeper-review-${GITHUB_RUN_ID:-unknown}}"
    ARTIFACT_DIR="${ARTIFACT_DIR:-}"
    POST_COMMENTS="${POST_COMMENTS:-false}"

    actual_head="unknown"
    evidence="unavailable"
    coverage="unavailable"
    metadata_file="$ARTIFACT_DIR/review-metadata.json"
    if [[ -s "$metadata_file" ]] && jq -e . "$metadata_file" >/dev/null 2>&1; then
      actual_head="$(jq -r '.head_sha // "unknown"' "$metadata_file")"
      evidence="$(jq -r '.evidence_state // "unknown"' "$metadata_file")"
      coverage="$(jq -r '.coverage.state // "unknown"' "$metadata_file")"
    fi

    if [[ "$POST_COMMENTS" != "true" ]]; then
      writer="disabled (post_comments=false)"
    elif [[ "$ARTIFACT_AVAILABLE" != "true" ]]; then
      writer="not scheduled (no immutable artifact)"
    else
      writer="eligible in writer job"
    fi

    {
      echo "## Loopkeeper review"
      echo ""
      echo "| Field | Value |"
      echo "| --- | --- |"
      echo "| Event | \`$EVENT_NAME\` |"
      echo "| PR | #$PR_NUMBER |"
      echo "| Head SHA | \`$actual_head\` |"
      echo "| Expected head SHA | \`${EXPECTED_HEAD_SHA:-not provided}\` |"
      echo "| Evidence | \`$evidence\` |"
      echo "| Coverage | \`$coverage\` |"
      echo "| Review step | \`$REVIEW_OUTCOME\` |"
      echo "| Artifact | \`$ARTIFACT_AVAILABLE\` ($ARTIFACT_NAME) |"
      echo "| Writer | $writer |"
      if [[ "$EVENT_NAME" == "pull_request_target" && "$ARTIFACT_AVAILABLE" != "true" ]]; then
        echo ""
        echo "Next action: wait for the exact-head CI completion workflow, or rerun the upstream CI workflow."
      fi
    } >>"$SUMMARY_FILE"
    ;;
  writer)
    EVENT_NAME="${EVENT_NAME:-unknown}"
    PR_NUMBER="${PR_NUMBER:-unknown}"
    EXPECTED_HEAD_SHA="${EXPECTED_HEAD_SHA:-}"
    WRITER_OUTCOME="${WRITER_OUTCOME:-unknown}"
    WRITER_ARTIFACT_DIR="${WRITER_ARTIFACT_DIR:-}"

    action="unknown"
    action_file="$WRITER_ARTIFACT_DIR/write-metadata.json"
    if [[ -s "$action_file" ]] && jq -e . "$action_file" >/dev/null 2>&1; then
      action="$(jq -r '.action // "unknown"' "$action_file")"
    fi
    {
      echo "## Loopkeeper writer"
      echo ""
      echo "| Field | Value |"
      echo "| --- | --- |"
      echo "| Event | \`$EVENT_NAME\` |"
      echo "| PR | #$PR_NUMBER |"
      echo "| Head SHA | \`${EXPECTED_HEAD_SHA:-not provided}\` |"
      echo "| Writer step | \`$WRITER_OUTCOME\` |"
      echo "| Comment action | \`$action\` |"
    } >>"$SUMMARY_FILE"
    ;;
  *)
    echo "usage: $0 review|writer" >&2
    exit 2
    ;;
esac

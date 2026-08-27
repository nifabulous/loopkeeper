#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <caller-attested-review-manifest.json>" >&2
  exit 2
fi

# Generic CI is artifact-only. The manifest and its protected trust key are
# supplied by the consuming pipeline; this wrapper never reads forge tokens or
# publishes anything.
exec loopkeeper review --manifest "$1" --output-dir "${LOOPKEEPER_OUTPUT_DIR:-artifacts}"

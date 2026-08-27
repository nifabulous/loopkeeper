#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <caller-attested-triage-manifest.json>" >&2
  exit 2
fi

exec loopkeeper triage --manifest "$1" --output-dir "${LOOPKEEPER_OUTPUT_DIR:-artifacts}"

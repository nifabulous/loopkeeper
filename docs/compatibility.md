# Relay compatibility

Loopkeeper isolates Relay compatibility to `src/loopkeeper/adapters/relay/compat.py`. The package
and new workflows emit only Loopkeeper names (`LOOPKEEPER_*`). Legacy Relay names
are understood only in the compat adapter.

## Environment mapping

`src/loopkeeper/adapters/relay/compat.py::map_relay_environment` translates a
`Mapping[str, str]` containing legacy `CODEX_*`, `ARBITER_*`, `RELAY_AGENT_*`,
and `OPENAI_API_KEY` entries to canonical `LOOPKEEPER_*` entries:

- `CODEX_MODEL` → `LOOPKEEPER_MODEL`
- `CODEX_REASONING_EFFORT` → `LOOPKEEPER_REASONING_EFFORT`
- `CODEX_MAX_INPUT_BYTES` → `LOOPKEEPER_MAX_INPUT_BYTES`
- `CODEX_MAX_OUTPUT_TOKENS` → `LOOPKEEPER_MAX_OUTPUT_TOKENS`
- `CODEX_MAX_OUTPUT_BYTES` → `LOOPKEEPER_MAX_OUTPUT_BYTES`
- `CODEX_REQUEST_TIMEOUT` → `LOOPKEEPER_REQUEST_TIMEOUT`
- `CODEX_JOB_TIMEOUT_SECONDS` → `LOOPKEEPER_JOB_TIMEOUT_SECONDS`
- `CODEX_BOT_LOGIN` → `LOOPKEEPER_BOT_LOGIN`
- `CODEX_CI_WORKFLOW_FILE` → `LOOPKEEPER_CI_WORKFLOW_FILE`
- `CODEX_TRUSTED_SHA` → `LOOPKEEPER_TRUSTED_SHA`
- `CODEX_DEFAULT_BRANCH` → `LOOPKEEPER_DEFAULT_BRANCH`
- `ARBITER_SOFT_GATE` → `LOOPKEEPER_ARBITER_SOFT_GATE`
- `ARBITER_HARD_CAP` → `LOOPKEEPER_ARBITER_HARD_CAP`
- `ARBITER_STUCK_P1_ROUNDS` → `LOOPKEEPER_ARBITER_STUCK_P1_ROUNDS`
- `ARBITER_UNVERIFIABLE_ROUNDS` → `LOOPKEEPER_ARBITER_UNVERIFIABLE_ROUNDS`
- `ARBITER_OPERATOR` / `ARBITER_AUTOPOST` → `LOOPKEEPER_OPERATOR`
- `RELAY_AGENT_*_MODEL` → `LOOPKEEPER_AGENT_*_MODEL`
- `OPENAI_API_KEY` ↔ `LOOPKEEPER_API_KEY` (bidirectional)

Per-agent vars are normalized: `CODEX_AGENT_FOO_MODEL` → `LOOPKEEPER_AGENT_FOO_MODEL`
with uppercase and hyphens-to-underscores. Existing `LOOPKEEPER_*` values are never
overridden by legacy.

Only `src/loopkeeper/adapters/relay/compat.py` may import `CODEX_*` names; tests grep the
`loopkeeper/` package for stray `CODEX` imports.

## Marker parsing

- Legacy `<!-- codex-pr-review:{pr}:{sha} -->` and
  `<!-- codex-pr-review-no-ci:{pr}:{sha} -->` are parsed and translated to
  `<!-- loopkeeper-pr-review:{pr}:{sha} -->` and evidence markers.
- `<!-- codex-verdict:` is accepted on ingest and translated to
  `<!-- loopkeeper-verdict:`; new output always uses `loopkeeper-verdict`.
- Prose resembling a marker is never sufficient for suppression; only the exact
  HTML comment plus authenticated bot author counts.

## Exit codes

`translate_exit_code` maps Relay exit codes to Loopkeeper's deterministic
codes (`0` success, `2` config, `3` transport, `4` trust/security).

## Workflow pinning

Every `uses:` in workflows is pinned to a full 40-hex SHA. Release-time
provenance verification is separate; the runtime verifier checks only exact
commit and manifest binding.

## Reusable workflows

- `.github/workflows/pr-review.yml` is the read-only Loopkeeper PR-review
  entrypoint. It grants only read permissions and permanently disables its
  writer job. Use `.github/workflows/pr-review-posting.yml` only for an
  explicitly approved operator workflow; it grants `pull-requests: write` and
  runs the same adapter from the pinned `loopkeeper_sha` checkout. Both paths
  verify `consumer_trusted_sha` (forge default-branch tip) and
  `loopkeeper_sha` (checkout + manifest) before invoking review.

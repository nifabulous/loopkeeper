# Loopkeeper — Bounded, trust-separated model-call loops with a deterministic arbiter

Loopkeeper is the **standalone extraction** of Relay's review-loop harness — a
provider-neutral, bounded, sanitized, trust-separated model-call loop with a
pure deterministic arbiter that decides when a loop has converged or must stop
for human attention. It is **not an AI PR-review product**; PR review is one
reference consumer, alongside issue triage and headless agent execution.

> **Extraction provenance:** This repository is the Loopkeeper extraction from
> [Relay](https://github.com/) at source commit `e834773`. The ledger of
> extracted files and line counts is recorded in `docs/source-ledger.md`; the
> source snapshot is pinned in `.extraction-source`. The reusable package and
> workflows are built from this repository, not from a copy of Relay's consumer
> application tree.

## What Loopkeeper provides

- A dependency-free Python package (`src/loopkeeper`) with schemas, the pure
  arbiter, transport, redaction, truncation, manifests, and CLI.
- A GitHub adapter (Bash orchestration + pinned reusable workflows) for PR
  review and issue triage.
- Bounded execution with explicit byte/token ceilings and trust-boundary
  enforcement.

## Quick start

```bash
python3.12 -m pip install -e '.[dev]'
python -m loopkeeper --version   # -> loopkeeper 0.1.0
loopkeeper --version
python -m pytest -q
```

GitHub consumers should start with the posting template in
`examples/github/pr-review-posting-caller.yml` when they want the full review
to appear on the pull request. The posting entrypoint defaults to
`post_comments: true`; set it to `false` to keep the run artifact-only, or use
`pr-review-caller.yml` when the caller should request only read permissions.
Replace the fixture slug and full release SHA, then review the caller
permissions. The adapter still enforces `LOOPKEEPER_OPERATOR=1` for every
write. Generic CI consumers can run `examples/ci/generic-review.sh` or
`examples/ci/generic-triage.sh` with a caller-attested manifest and receive
artifacts only.

The trust model, release process, and staged dogfood gates are documented in
[`docs/security.md`](docs/security.md), [`docs/release.md`](docs/release.md),
and [`docs/dogfood-runbook.md`](docs/dogfood-runbook.md).

Releases are built with read-only permissions and published only after an
explicit `publish: true` approval through PyPI trusted publishing; no package
API token is required.

## Source ledger

See [`docs/source-ledger.md`](docs/source-ledger.md) for the 30-row source map
and the explicit exclusion for the consumer `.github/workflows/ci.yml`. The
ledger records the Relay source path at `e834773`, its line count, the
destination in this repository, and the retained behavior. The consumer CI
workflow remains outside the extraction; it is used only as a fixture for
workflow-name/file resolution tests.

## Version

Package version is `0.1.0` (see `src/loopkeeper/__init__.py`).

## Security

Loopkeeper runs model calls in CI against attacker-influenced input, in jobs
holding real credentials. The threat model is in
[`docs/security.md`](docs/security.md); to report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) and
[NOTICE](NOTICE) for attribution.

# Changelog

All notable changes to Loopkeeper are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-31

Loopkeeper is the standalone extraction of Relay's review-loop
harness: a provider-neutral, bounded, sanitized, trust-separated model-call
loop with a pure deterministic arbiter. Pull-request review is one reference
consumer, alongside issue triage and headless agent execution.

This is the first public release of Loopkeeper. There is no migration path
from an earlier version, and no compatibility fallback is carried for
pre-release behaviour.

### Added

- **Release hardening.** CI now enforces the explicit Ruff baseline, and the
  release workflow separates artifact construction from human-approved PyPI
  publication using job-scoped OIDC trusted publishing with checksum and
  provenance verification.
- **Deterministic arbiter.** A pure decision function — no environment,
  filesystem, subprocess, network, or model access — that reads the history of
  review rounds and returns a disposition in first-match rule order:
  `CLEAN`, `STUCK-P1`, `EXHAUSTED-NOVELTY`, `SOFT-GATE`, `HARD-CAP`,
  `MALFORMED-TRAILER`, `ACCOUNTING-GAP`, `AMBIGUOUS-IDENTITY`, `ORPHAN-STATE`.
  The model's verdict is advisory; the arbiter owns the disposition.
- **Trust separation.** Trusted control-plane material (policy, contract,
  reference files) is read from git objects at a forge-verified revision.
  Untrusted content is sanitized, then wrapped in delimiters it cannot forge —
  delimiter-shaped runs in the content are defanged, and bounded wrapping never
  truncates away a closing fence.
- **Bounded execution.** Explicit byte and token ceilings on input, output,
  response bodies, policy sections, context files, and per-file patches;
  bounded pagination in place of unbounded `--paginate`; deadline-aware
  transport that never retries an established response.
- **Provider-neutral transport.** Stdlib-only HTTP supporting both the
  Responses and Chat Completions wire styles, with the model id, wire style,
  and endpoint bound through `LOOPKEEPER_*` settings rather than code.
- **Schema-2 reviewer trailer.** A machine-readable output contract, preserved
  through sanitization and truncation so a bounded review stays parseable.
  Malformed output fails closed rather than reading as a clean result.
- **Consumer-defined policy categories.** A policy declares its own canonical
  category slugs under a single `## Categories` section, validated by the same
  grammar as Schema-2 finding identifiers. Any other section is preserved
  verbatim in source order. Generic core carries no product vocabulary.
- **Caller attestation for non-GitHub CI.** HMAC-SHA256 over a canonical
  manifest digest bound to repository, head SHA, and trusted revision. The
  protected key file is resolved from the environment only, never from a
  manifest, and is verified before any model invocation.
- **GitHub adapter.** Bash orchestration plus pinned reusable workflows for
  pull-request review and issue triage. Every write requires
  `LOOPKEEPER_OPERATOR=1`. Comment state is a serialized same-head machine:
  fallback evidence is replaced in place by exact-head CI evidence, duplicates
  are rewritten as superseded rather than deleted, and the head is re-read
  immediately before publication.
  Read-only issue triage has its own reusable entrypoint so cross-repository
  callers never load a write-capable job during artifact-only runs.
- **Headless agent runner** with five trusted agent definitions.
- **Zero runtime dependencies.** Pure standard library, Python 3.10–3.12.

### Security

- The consumer checkout is verified against the forge-confirmed default-branch
  tip before any trusted read, in both the review and triage adapters. There is
  no fallback to `HEAD`.
- The reviewed repository is never placed on `sys.path`, and every embedded
  Python block receives shell values through `argv` rather than interpolation,
  so a consumer repository cannot shadow trusted modules in a job holding write
  permission.
- Manifest path confinement fails closed on unexpected errors.
- The fork-eligibility job requests `issues: read`, and every caller grants it.
  The read-only issue-triage entrypoint contains no writer job; posting uses a
  separate write-capable entrypoint. This avoids GitHub rejecting an
  artifact-only cross-repository call at startup while preserving the
  least-privilege boundary.
- Package resources are read as content rather than as filesystem paths, which
  a zipimported install cannot provide.
- The account rule no longer requires word boundaries. `\b\d{8,}\b` never
  matched inside an alphanumeric token, so an identifier survived by being
  wrapped in letters -- the same evasion as wrapping a card in hex. The rule now
  redacts strictly more than before and never less.
- The generic redactor declares every placeholder it substituted, and both the
  Python CLI and GitHub adapters carry that provenance into the model prompt.
  Previously the shell adapters discarded the metadata entirely, so a redacted
  value reached the model with nothing to distinguish it from the file's own
  content and was reported as a defect in the reviewed code. Placeholder-shaped
  text supplied by the source is now visibly defanged into a separate,
  reviewable marker, so an attacker cannot borrow the trusted shape of a real
  substitution. Redaction strength is unchanged: no rule was relaxed.
- GitHub review and triage now select a dedicated `code-review` redaction
  profile. It preserves benign source sizes, IDs, timestamps, and hash-like
  literals while retaining broad payment redaction in the default `payments`
  profile.

### Known limitations

- Reviews are advisory evidence. A human owns every merge, release, and deploy
  decision, and `MALFORMED-TRAILER` is deliberately fail-closed to a human.
- Trailer compliance is a property of the configured model, not of the
  transport. A model or provider swap must be re-verified against a real
  review before it is trusted.
- When a diff exceeds the evidence budget, the review states the coverage
  limitation and must not be read as exhaustive.
- Callers handling payment messages should keep the default `payments` profile;
  callers handling source evidence should select `code-review`. The latter uses
  contextual account/card cues and preserves hash-like literals, so profile
  selection is part of the trust-boundary contract rather than an incidental
  formatting choice.

[Unreleased]: https://github.com/nifabulous/loopkeeper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nifabulous/loopkeeper/releases/tag/v0.1.0

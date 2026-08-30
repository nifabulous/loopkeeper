# Changelog

All notable changes to Loopkeeper are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Everything below is staged for `0.1.0`, which has **not been published**. There
is no `v0.1.0` tag and no PyPI release yet. At publication this section is
renamed to `## [0.1.0] - <date>` and the comparison links are added then.

Loopkeeper is the standalone extraction of Relay's review-loop
harness: a provider-neutral, bounded, sanitized, trust-separated model-call
loop with a pure deterministic arbiter. Pull-request review is one reference
consumer, alongside issue triage and headless agent execution.

Because this will be the first release, everything below is new. There is no
migration path from an earlier version, and no compatibility fallback is
carried for pre-release behaviour.

### Added

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
  A reusable workflow may not request a permission its caller withheld, so a
  caller without the scope fails the whole run at startup and produces no
  review at all. A contract test now compares each caller's grant against every
  job in the workflow it calls.
- Package resources are read as content rather than as filesystem paths, which
  a zipimported install cannot provide.
- The generic redactor declares the placeholders it substituted, and the prompt
  states what a placeholder means. Previously the core reported placeholders
  only when a plugin redactor was configured -- which the GitHub adapters never
  are -- so a redacted value reached the model with nothing to distinguish it
  from the file's own content, and was reported as a defect in the reviewed
  code. Redaction strength is unchanged: no rule was relaxed.
- Payment rules no longer fire inside a hexadecimal digest. A digit run within
  a hash is an artefact of the encoding, and rewriting part of a checksum
  destroyed evidence without protecting anything.

### Known limitations

- Reviews are advisory evidence. A human owns every merge, release, and deploy
  decision, and `MALFORMED-TRAILER` is deliberately fail-closed to a human.
- Trailer compliance is a property of the configured model, not of the
  transport. A model or provider swap must be re-verified against a real
  review before it is trusted.
- When a diff exceeds the evidence budget, the review states the coverage
  limitation and must not be read as exhaustive.
- Redaction is calibrated for payment traffic, inherited from Relay. Rules whose
  shape is ambiguous -- notably any run of eight or more digits -- still fire on
  ordinary source, so a byte size or a row count can be replaced. The prompt now
  states that placeholders are substitutions, which stops them being read as
  defects, but the substitution itself remains. Narrowing the rules is not
  simply an accuracy question: they are also what stops an identifier being
  smuggled through untrusted content, where an attacker controls the context.

<!-- Link definitions are added at publication. Until the v0.1.0 tag exists,
a compare or release link would resolve to nothing. -->

# Loopkeeper review policy

Loopkeeper reviews are advisory evidence. A human owns the decision to change,
merge, release, or deploy code. Never infer approval from a passing check or a
model verdict.

## Categories

- functional
- security
- trust-separation
- bounded-execution
- redaction
- release-integrity
- verification

## Scope

Review all changed production code, tests, documentation, CI workflows, and
security boundaries. Prioritize behavior that can weaken trust separation,
bounded execution, redaction, artifact privacy, immutable pinning, or the
deterministic arbiter.

Every finding needs concrete evidence, an affected file and line when
available, impact, and a focused remediation suggestion. Do not invent a
finding from formatting preference or unsupported speculation.

## Severity

- **P1:** likely security, data-integrity, or correctness defect that should
  block merge.
- **P2:** meaningful regression risk or missing coverage that should be fixed
  soon.
- **P3:** lower-risk improvement that does not block merge.

## Lifecycle

A finding is NEW on its first appearance for a head, OPEN while it is still
present in a later round, and RESOLVED only when the diff shows the change
that fixes it. Do not mark a finding RESOLVED from a claim in a comment or
from an absence of evidence; unavailable evidence is not a resolution.

## Data handling

Do not request, reproduce, or store API keys, credentials, model prompts,
customer data, or unbounded source payloads. Prefer paths, field names, counts,
hashes, and bounded redacted examples.

## Automation boundary

Loopkeeper may publish a bounded review comment because this repository
explicitly opts into the posting workflow. It must not edit files, push
branches, merge pull requests, deploy releases, or change repository settings.

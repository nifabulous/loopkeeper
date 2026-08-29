# Security policy

Loopkeeper runs model calls inside CI, in jobs that hold repository tokens and
a model API key, against input an attacker may control. Reports about that
boundary are welcome and taken seriously.

## Supported versions

| Version | Status |
|---|---|
| `0.1.x` | Will be supported once published; `0.1.0` is not yet released |
| earlier | Not applicable — `0.1.0` is the first release |

Until `0.1.0` is published, report against the current `main`.

## Reporting a vulnerability

Use this repository's **private vulnerability reporting** (Security tab →
Report a vulnerability). That channel is private to maintainers and does not
create a public record.

If private reporting is unavailable to you, open a minimal public issue asking
for a private channel. Do not include the details, a reproduction, or affected
paths in that issue.

Please include, in the private report:

- what boundary is crossed (trust separation, bounded execution, redaction,
  artifact privacy, write gating, or attestation)
- the smallest reproduction you have, and the Loopkeeper revision it applies to
- whether it requires an attacker to control a pull request, an issue, a fork,
  a policy file, or a consumer repository setting

Expect acknowledgement within **five business days**. Please do not disclose
publicly before we have coordinated a fix and a disclosure date.

## What we consider a vulnerability

Loopkeeper's threat model is documented in [`docs/security.md`](docs/security.md).
Reports in these areas are in scope:

- **Trust separation.** Any path where untrusted content — a pull request diff,
  an issue body, a fork's branch, a comment — reaches a trusted read, a policy
  decision, or executable code. This includes anything that lets a pull request
  influence the code that reviews it.
- **Bounded execution.** Any unbounded read, unbounded pagination, or missing
  byte ceiling that a reporter can drive.
- **Redaction.** Secrets or personal data surviving into a prompt, an artifact,
  a comment, or a log.
- **Write gating.** Any create or update path reachable without
  `LOOPKEEPER_OPERATOR=1`, or any write against stale state.
- **Attestation.** Forging or replaying a caller-attested manifest, or reading
  the protected key file from anywhere other than the environment.
- **Supply chain.** A mutable action reference, an unpinned reusable workflow,
  or a publication path that does not require the protected environment.

## What is not a vulnerability

- **A model producing a wrong or incomplete review.** Reviews are advisory
  evidence; a human owns every merge, release, and deploy decision. A model
  that misses a defect is a quality issue, not a security boundary failure.
- **Malformed model output.** This fails closed to `MALFORMED-TRAILER` and
  escalates to a human by design.
- **Unavailable evidence.** A failed, truncated, or oversized read is reported
  as unavailable rather than as an empty result. That is intended behaviour.
- **GitHub labels being unprotected.** Labels are not a security boundary.
  Loopkeeper authorizes fork review by verifying the *actor* who applied the
  approval label, not by trusting the label itself.

## Operator responsibilities

Loopkeeper is infrastructure you run. Some of the boundary is yours:

- Do not commit an attestation key file, and do not place a secret in a
  manifest, example, artifact, or workflow log.
- Pin every reusable workflow call to a full 40-hex commit SHA, and keep the
  `uses:` pin and the `loopkeeper_sha` input identical.
- Keep the self-review or consumer pin pointed at an already-merged commit. The
  reviewer's behaviour comes from that pinned revision, not from the pull
  request under review.
- Review the permissions in any caller template before enabling it. The posting
  entrypoint grants `pull-requests: write` to its writer job.

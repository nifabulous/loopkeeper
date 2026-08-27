"""Prompt composition for Loopkeeper.

The policy file is the only review matrix; the builder must not contain
product names, payment-domain placeholder lists, or a second
category/severity table.  Consumer wording lives in trusted policy Markdown.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy
from .redaction import RedactionResult
from .truncate import truncate_utf8
from .untrusted import wrap_untrusted

MAX_INPUT_BYTES = 120_000
MAX_SECTION_BYTES = 50_000
MAX_INSTRUCTIONS_BYTES = 100_000
MAX_ARTIFACT_BYTES = 100_000


@dataclass(frozen=True)
class UntrustedArtifacts:
    metadata: str
    diff: str
    previous_review: str | None
    checks: str | None


@dataclass(frozen=True)
class Prompt:
    instructions: str
    input_text: str


def _bound(text: str, limit: int) -> str:
    if len(text.encode("utf-8")) <= limit:
        return text
    return truncate_utf8(text, limit)


def render_review_prompt(
    policy: Policy,
    redaction: RedactionResult,
    artifacts: UntrustedArtifacts,
) -> Prompt:
    # Validate policy is trusted source; do not hardcode product names
    if not isinstance(policy, Policy):
        raise TypeError("policy must be Policy")
    if not isinstance(redaction, RedactionResult):
        raise TypeError("redaction must be RedactionResult")
    if not isinstance(artifacts, UntrustedArtifacts):
        raise TypeError("artifacts must be UntrustedArtifacts")

    # Build instructions from trusted policy plus active placeholders
    # No hard-coded product name or placeholder list here
    parts: list[str] = []
    parts.append(f"# {policy.display_name}")
    # Categories – deterministic order as in policy
    parts.append("## Categories")
    for cat in policy.categories:
        parts.append(f"- {cat}")
    parts.append("## Severity")
    parts.append(_bound(policy.severity_guidance, MAX_SECTION_BYTES))
    parts.append("## Lifecycle")
    parts.append(_bound(policy.lifecycle_rules, MAX_SECTION_BYTES))
    parts.append("## Data handling")
    # Data handling plus active redactor placeholders
    handling = _bound(policy.data_handling, MAX_SECTION_BYTES)
    if redaction.placeholders:
        placeholder_list = ", ".join(redaction.placeholders)
        handling = handling + f"\n\nActive redaction placeholders: {placeholder_list}."
    parts.append(handling)

    instructions = "\n\n".join(parts)
    # Bound whole instructions
    if len(instructions.encode("utf-8")) > MAX_INSTRUCTIONS_BYTES:
        instructions = truncate_utf8(instructions, MAX_INSTRUCTIONS_BYTES)

    # Build input_text from untrusted artifacts, each bounded and wrapped
    # Use untrusted blocks with defanging
    input_parts: list[str] = []
    for label, content in [
        ("metadata", artifacts.metadata),
        ("diff", artifacts.diff),
        ("previous_review", artifacts.previous_review),
        ("checks", artifacts.checks),
    ]:
        if content is None:
            continue
        if not isinstance(content, str):
            raise TypeError(f"artifact {label} must be str or None")
        bounded = _bound(content, MAX_ARTIFACT_BYTES)
        wrapped = wrap_untrusted(label, bounded)
        input_parts.append(wrapped)

    input_text = "\n".join(input_parts)
    if len(input_text.encode("utf-8")) > MAX_INPUT_BYTES:
        input_text = truncate_utf8(input_text, MAX_INPUT_BYTES)

    return Prompt(instructions=instructions, input_text=input_text)

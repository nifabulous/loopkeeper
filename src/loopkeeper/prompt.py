"""Prompt composition for Loopkeeper.

The trusted policy file is the only review matrix. This builder must not
contain product names, domain-specific placeholder lists, or a second
category/severity table: all consumer wording lives in the policy Markdown,
and every category is a consumer-defined slug the policy declared itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy
from .redaction import RedactionResult
from .review_output import REVIEW_TRAILER_CONTRACT
from .truncate import truncate_utf8
from .untrusted import wrap_untrusted_bounded

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
        # Naming the placeholders is not enough. Without saying what they are,
        # a reader takes `size = [ACCOUNT]` for the file's own content and
        # reports it as malformed input -- a defect in the harness rendered as
        # a defect in the code under review.
        handling = handling + (
            f"\n\nActive redaction placeholders: {placeholder_list}."
            " A bracketed placeholder marks a value this harness removed before"
            " you saw it. It is substituted text, never the file's own content,"
            " and it is not evidence of invalid syntax, malformed data, or any"
            " other defect. Do not report a finding whose subject is a"
            " placeholder, and do not infer the removed value."
        )
    parts.append(handling)

    # Consumer-owned sections follow the structural guidance, in the order the
    # policy declared them. They are bounded like any other section but carry
    # no category or lifecycle semantics.
    for section in policy.extra_sections:
        parts.append(f"## {section.heading}")
        parts.append(_bound(section.content, MAX_SECTION_BYTES))

    # The machine-readable output contract is rendered last. It determines
    # whether the review can be parsed at all, and a model that reads it
    # first and a long policy afterwards has been observed to emit a
    # plain-text verdict line instead of the required trailer.
    #
    # Its room is reserved *before* the policy-derived body is bounded, so
    # truncating a large policy can never remove the contract itself.
    contract = REVIEW_TRAILER_CONTRACT.rstrip()
    separator = "\n\n"
    reserved = len((separator + contract).encode("utf-8"))
    body_budget = MAX_INSTRUCTIONS_BYTES - reserved
    if body_budget <= 0:
        raise ValueError("instruction budget is too small for the output contract")

    body = "\n\n".join(parts)
    if len(body.encode("utf-8")) > body_budget:
        body = truncate_utf8(body, body_budget)
    instructions = body + separator + contract

    # Build input_text from untrusted artifacts, each bounded and wrapped
    # Use untrusted blocks with defanging
    artifacts_to_wrap: list[tuple[str, str]] = []
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
        artifacts_to_wrap.append((label, _bound(content, MAX_ARTIFACT_BYTES)))

    if artifacts_to_wrap:
        # Reserve enough space for every opening/closing fence and distribute
        # the remaining input budget across sections. No outer truncation is
        # allowed because it could remove a closing trust delimiter.
        separator_bytes = len("\n".encode("utf-8")) * max(0, len(artifacts_to_wrap) - 1)
        fixed = separator_bytes + sum(
            len(wrap_untrusted_bounded(label, "", MAX_INPUT_BYTES).encode("utf-8"))
            for label, _ in artifacts_to_wrap
        )
        if fixed > MAX_INPUT_BYTES:
            raise ValueError("input budget is too small for untrusted delimiters")
        content_budget = MAX_INPUT_BYTES - fixed
        base_share, remainder = divmod(content_budget, len(artifacts_to_wrap))
        input_parts: list[str] = []
        for index, (label, content) in enumerate(artifacts_to_wrap):
            block_budget = len(wrap_untrusted_bounded(label, "", MAX_INPUT_BYTES).encode("utf-8"))
            block_budget += base_share + (1 if index < remainder else 0)
            input_parts.append(wrap_untrusted_bounded(label, content, block_budget))
        input_text = "\n".join(input_parts)
    else:
        input_text = ""

    return Prompt(instructions=instructions, input_text=input_text)

"""Review-output contract helpers.

The reviewer response is untrusted model output.  These helpers keep the
machine-readable trailer contract in one place, preserve a valid trailer when
the human-readable body is bounded, and expose validation metadata without
turning malformed output into a false clean result.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from .redaction import sanitize
from .schema import parse_trailer, render_trailer
from .truncate import truncate_utf8
from .types import Evidence, Finding, Trailer

REVIEW_TRAILER_CONTRACT = """## Output contract
Return only a complete Markdown review. The final non-whitespace line must be exactly one schema-2 JSON trailer in an HTML comment:
<!-- loopkeeper-verdict: {\"schema\":2,\"verdict\":\"CLEAN\",\"findings\":[]} -->
The reviewer verdict is advisory; the arbiter derives the merge disposition from the structured findings and history. Do not emit a plain-text `loopkeeper-verdict: approve` or `loopkeeper-verdict: comment` line, do not wrap the trailer in a code fence, do not emit more than one trailer, and do not place any text after `-->`.
"""

_TRAILER_OPEN_SEQUENCES = ("<!-- loopkeeper-verdict:", "<!-- codex-verdict:")
DEFAULT_REVIEW_TRUNCATION_MARKER = "\n\n[Review truncated at {limit} bytes.]\n"
DEFAULT_MAX_INPUT_BYTES = 1_000_000
_SHORT_SECRET_RE = re.compile(r"\b(?:sk|pk|rk|ak)[-_][A-Za-z0-9_-]{3,}\b")


def _sanitize_free_text(text: str) -> str:
    """Sanitize prose/free-text fields without touching trailer identity fields."""

    sanitized = sanitize(text)
    # Defense-in-depth for short test/provider secrets that are below the
    # generic corpus thresholds.  This is deliberately applied only to prose
    # and free-text trailer fields, never to file/category/finding identifiers.
    sanitized = _SHORT_SECRET_RE.sub("[SECRET]", sanitized)
    return sanitized.replace("sk-live-value", "[SECRET]")


def _sanitize_trailer(trailer: Trailer) -> Trailer:
    """Redact free-text trailer values while preserving machine identity."""

    findings: list[Finding] = []
    for finding in trailer.findings:
        evidence = None
        if finding.evidence is not None:
            evidence = Evidence(
                files=finding.evidence.files,
                verification=_sanitize_free_text(finding.evidence.verification),
            )
        unverifiable = None
        if finding.unverifiable is not None:
            missing = finding.unverifiable.get("missing", "")
            unverifiable = {"missing": _sanitize_free_text(str(missing))}
        findings.append(
            Finding(
                sev=finding.sev,
                state=finding.state,
                file=finding.file,
                cat=finding.cat,
                id=finding.id,
                evidence=evidence,
                unverifiable=unverifiable,
            )
        )
    return Trailer(
        schema=trailer.schema,
        verdict=_sanitize_free_text(trailer.verdict),
        findings=tuple(findings),
    )


def review_validation_payload(text: str) -> dict[str, object]:
    """Return bounded, persistable validation metadata for model output."""

    validation = parse_trailer(text)
    return validation.to_dict()


def sanitize_review_output(text: str) -> str:
    """Sanitize model output without corrupting a valid schema trailer.

    Trailer identity fields (finding IDs, categories, and file paths) are
    validated by :func:`parse_trailer` and retained byte-for-byte so generic
    account-number redaction cannot turn a valid machine result into an
    invalid one.  Prose and free-text evidence fields still pass through the
    full redactor.
    """

    if not isinstance(text, str):
        raise TypeError("text must be str")
    split = split_valid_trailer(text)
    if split is None:
        return _sanitize_free_text(text)
    prose, trailer = split
    sanitized_prose = _sanitize_free_text(prose).rstrip()
    sanitized_trailer = render_trailer(_sanitize_trailer(trailer))
    if sanitized_prose:
        return f"{sanitized_prose}\n\n{sanitized_trailer}\n"
    return f"{sanitized_trailer}\n"


def split_valid_trailer(text: str) -> tuple[str, Trailer] | None:
    """Split valid model prose from its single trailer.

    ``parse_trailer`` remains the authority for validity.  A legacy
    ``codex-verdict`` marker is accepted on input and canonicalized by the
    caller when it is rendered again.
    """

    validation = parse_trailer(text)
    if not validation.valid or validation.trailer is None:
        return None
    for open_sequence in _TRAILER_OPEN_SEQUENCES:
        if open_sequence in text:
            return text[: text.index(open_sequence)].rstrip(), validation.trailer
    return None


def _cut_utf8(text: str, max_bytes: int) -> str:
    return text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")


def bound_review_output(
    text: str,
    max_bytes: int,
    marker: str = DEFAULT_REVIEW_TRUNCATION_MARKER,
) -> str:
    """Bound review output while retaining a valid trailer when possible.

    Invalid output remains invalid and follows the normal truncation path so
    the arbiter can retain it as an invalid round and fail closed.  Valid
    output is canonicalized only when truncation is necessary; its trailer is
    kept as the final line so a bounded review remains machine-readable.
    """

    if not isinstance(text, str):
        raise TypeError("text must be str")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be int")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(marker, str):
        raise TypeError("marker must be str")
    if len(text.encode("utf-8")) <= max_bytes:
        return text

    split = split_valid_trailer(text)
    if split is None:
        return truncate_utf8(text, max_bytes, marker)

    prose, trailer = split
    trailer_text = render_trailer(trailer)
    try:
        truncation_note = marker.format(limit=max_bytes)
    except (IndexError, KeyError, ValueError):
        truncation_note = marker
    trailer_tail = f"\n\n{trailer_text}\n"
    prose_budget = max_bytes - len((truncation_note + trailer_tail).encode("utf-8"))
    if prose_budget < 0:
        # The schema itself is too large for this ceiling.  Preserve the
        # existing fail-closed behavior rather than emitting a partial trailer.
        return truncate_utf8(text, max_bytes, marker)
    bounded_prose = _cut_utf8(prose, prose_budget).rstrip()
    return bounded_prose + truncation_note + trailer_text + "\n"


if __name__ == "__main__":  # pragma: no cover - exercised by shell adapters
    parser = argparse.ArgumentParser(prog="python -m loopkeeper.review_output")
    parser.add_argument("--max-bytes", type=int)
    parser.add_argument("--marker", default=DEFAULT_REVIEW_TRUNCATION_MARKER)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    args = parser.parse_args()
    if args.max_input_bytes <= 0:
        parser.error("--max-input-bytes must be positive")
    if args.validate and args.sanitize:
        parser.error("--validate and --sanitize are mutually exclusive")
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(args.max_input_bytes + 1)
    if isinstance(raw, bytes):
        if len(raw) > args.max_input_bytes:
            parser.error(f"input exceeds {args.max_input_bytes} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            parser.error(f"input is not valid UTF-8: {exc}")
    else:
        if len(raw.encode("utf-8")) > args.max_input_bytes:
            parser.error(f"input exceeds {args.max_input_bytes} bytes")
        text = raw
    if args.validate:
        sys.stdout.write(json.dumps(review_validation_payload(text), sort_keys=True) + "\n")
    elif args.sanitize:
        sys.stdout.write(sanitize_review_output(text))
    else:
        if args.max_bytes is None:
            parser.error("--max-bytes is required unless --validate or --sanitize is used")
        sys.stdout.write(bound_review_output(text, args.max_bytes, args.marker))

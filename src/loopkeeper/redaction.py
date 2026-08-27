"""Loopkeeper trust-boundary redaction.

Ported from Relay e834773 scripts/codex_sanitize.py and app/tutor/redaction.py.

Built-in sanitizer covers credentials, tokens, cookies, cards, and payment
identifiers.  A project redactor plugin is run before and after the generic
sanitizer is applied.  Plugin output is validated for byte length, placeholder
grammar, and deduplication.

BIC/SWIFT codes are preserved (public directory data), matching the codex
sanitizer corpus.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Protocol

from .errors import SecurityError

# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------


class RedactionResult(NamedTuple):
    text: str
    placeholders: tuple[str, ...]


class Redactor(Protocol):
    def redact(self, text: str) -> RedactionResult: ...


# ---------------------------------------------------------------------------
# Placeholder contract
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_MAX_OUTPUT_BYTES = 1_000_000


def _normalize_placeholders(placeholders: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for ph in placeholders:
        if ph not in seen:
            seen.add(ph)
            out.append(ph)
    return tuple(out)


def _validate_result(result: object) -> None:
    if isinstance(result, str):
        raise SecurityError("plugin returned string, expected RedactionResult")
    if not isinstance(result, RedactionResult):
        # Also accept duck-typed objects that look like RedactionResult but
        # check strictly: must be RedactionResult instance
        raise SecurityError("plugin must return RedactionResult")
    if not isinstance(result.text, str):
        raise SecurityError("plugin result text must be str")
    if not isinstance(result.placeholders, (tuple, list)):
        raise SecurityError("plugin placeholders must be tuple")
    for ph in result.placeholders:
        if not isinstance(ph, str):
            raise SecurityError("placeholder must be str")
        if not _PLACEHOLDER_RE.fullmatch(ph):
            raise SecurityError(f"unsafe placeholder token: {ph!r}")
    if len(result.text.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise SecurityError(f"plugin output exceeds byte ceiling: {len(result.text.encode('utf-8'))} > {_MAX_OUTPUT_BYTES}")


# ---------------------------------------------------------------------------
# Tutor redaction core (from app/tutor/redaction.py e834773)
# ---------------------------------------------------------------------------

_ISO_3166_ALPHA2 = frozenset(
    {
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW",
        "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN",
        "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG",
        "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ",
        "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI",
        "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
        "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR",
        "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
        "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA",
        "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME",
        "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU",
        "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
        "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR",
        "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD",
        "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
        "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
        "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE",
        "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
    }
)

_TUTOR_SECRET_RE = re.compile(
    r"""(?x)
    \b(?:sk|pk|rk|ak|api|key|tok)[-_](?:live|test|prod)?[-_]?[A-Za-z0-9_-]{16,}\b
    | \b(?:gh[pousr]|xox[baprs])_[A-Za-z0-9]{16,}\b
    | \bAKIA[0-9A-Z]{16}\b
    | \bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}
    | \b(?:[A-Za-z][A-Za-z0-9]*[_-]){0,8}
      (?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)
      \s*[:=]\s*
      \"?[A-Za-z0-9._~+/-]{8,}\"?
    """,
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_UETR_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_IBAN_RE = re.compile(
    r"\b[A-Z]{2}\d{2}"
    r"(?:"
    r"[A-Z0-9]{11,30}"
    r"|"
    r"(?:\s[A-Z0-9]{4}){2,7}(?:\s[A-Z0-9]{1,4})?"
    r")\b",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"\+?\(?\d[\d\s().-]{7,17}\d")
_ACCOUNT_RE = re.compile(r"\b\d{8,}\b")
_BIC_RE = re.compile(r"\b[A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?\b")
_BIC_CUE_RE = re.compile(r"(?:\bbic|\bswift\s+(?:code|codes|address|bic))\s*$", re.IGNORECASE)
_ENGLISH_INFLECTION_SUFFIXES = ("ES", "ED", "ING", "LY", "ION", "MENT", "NESS")


def _looks_like_bic(token: str, prefix: str) -> bool:
    token = token.upper()
    if token[4:6] not in _ISO_3166_ALPHA2:
        return False
    if any(character.isdigit() for character in token):
        return True
    if len(token) == 11 and token.endswith("XXX"):
        return True
    if token.endswith(_ENGLISH_INFLECTION_SUFFIXES):
        return False
    return _BIC_CUE_RE.search(prefix) is not None


def _redact_phone(match: re.Match[str]) -> str:
    token = match.group(0)
    digits = sum(character.isdigit() for character in token)
    if not 9 <= digits <= 15:
        return token
    if token.startswith("+") or any(character in " .-()" for character in token):
        return "[PHONE]"
    return token


def _redact_bic(match: re.Match[str]) -> str:
    token = match.group(0)
    if _looks_like_bic(token, match.string[: match.start()]):
        return "[BIC]"
    return token


def _apply_rules(value: str, *, include_bic: bool) -> str:
    value = _TUTOR_SECRET_RE.sub("[SECRET]", value)
    value = _EMAIL_RE.sub("[EMAIL]", value)
    value = _UETR_RE.sub("[UETR]", value)
    value = _IBAN_RE.sub("[IBAN]", value)
    if include_bic:
        value = _BIC_RE.sub(_redact_bic, value)
    value = _PHONE_RE.sub(_redact_phone, value)
    value = _ACCOUNT_RE.sub("[ACCOUNT]", value)
    return value


def redact_sensitive_text(value: str) -> str:
    return _apply_rules(value, include_bic=True)


def redact_sensitive_text_preserving_bic(value: str) -> str:
    return _apply_rules(value, include_bic=False)


# ---------------------------------------------------------------------------
# Codex sanitize corpus (from scripts/codex_sanitize.py e834773)
# ---------------------------------------------------------------------------

_HEADER_PREFIX = r"(?:[A-Za-z][A-Za-z0-9]*-){0,4}"
_AUTH_HEADER = rf"{_HEADER_PREFIX}auth(?:orization|entication)"
_AUTH_SCHEMES = (
    r"(?:bearer|basic|token|digest|negotiate|oauth|hoba|mutual|apikey|"
    r"scram-sha-1|scram-sha-256|aws4-hmac-sha256)"
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(rf"(?i)^([+\- ]*\s*{_AUTH_HEADER}\s*[:=]\s*)({_AUTH_SCHEMES}\s+)?.+$"),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(
            rf"(?i)(?<!^)(?<![+\- ])\b({_AUTH_HEADER}\s*[:=]\s*)"
            r"(?:[^\r\n]*?([\"'])(?=\s|$)|[^\r\n]*)"
        ),
        r"\1[REDACTED]\2",
    ),
    (
        re.compile(rf"(?i)^([+\- ]*\s*{_HEADER_PREFIX}cookie\s*[:=]\s*).+$"),
        r"\1[REDACTED_COOKIE]",
    ),
    (
        re.compile(
            rf"(?i)(?<!^)(?<![+\- ])\b({_HEADER_PREFIX}cookie\s*[:=]\s*)"
            r"(?:[^\r\n]*?([\"'])(?=\s|$)|[^\r\n]*)"
        ),
        r"\1[REDACTED_COOKIE]\2",
    ),
    (
        re.compile(r"\b(?:sk|rk|pk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b"),
        "[REDACTED_TOKEN]",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED_CLOUD_KEY]",
    ),
    (
        re.compile(
            r"(?i)\b(?:[A-Za-z][A-Za-z0-9]*[_-]){0,8}"
            r"(?:api[_-]?key|secret|token|password|passwd|pwd|credential)"
            r"\s*[:=]\s*(['\"])(?:(?!\1).)*\1"
        ),
        "[REDACTED_SECRET_ASSIGNMENT]",
    ),
    (
        re.compile(r"(?i)(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*(['\"]?)[^\s,'\"}]+\1"),
        "[REDACTED_SECRET_ASSIGNMENT]",
    ),
)

_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_GIT_METADATA_RE = re.compile(r"^index [0-9a-f]+\.\.[0-9a-f]+(?: \d+)?$")
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
_ISO_8601_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?"
)
_STANDARD_REFERENCE_RE = re.compile(r"\bISO[ /-]?\d{3,5}(?:[:-]\d{2,4})?\b", re.IGNORECASE)
_SVG_COORDINATES_RE = re.compile(r"\b(?:points|viewBox)\s*=\s*\"[0-9 .,+-]*\"")
_LONG_DIGIT_RUN_RE = re.compile(r"\d{8,}")
_GROUPED_IDENTIFIER_RE = re.compile(r"(?<![\d-])(?:\d{4}[ -])+\d{1,4}(?![\d-])")


def _is_coordinate_list(match: re.Match[str]) -> bool:
    return _LONG_DIGIT_RUN_RE.search(match.group(0)) is None


_EXEMPT_RULES = (
    (_ISO_8601_RE, None),
    (_STANDARD_REFERENCE_RE, None),
    (_SVG_COORDINATES_RE, _is_coordinate_list),
)


def _redact_card(match: re.Match[str]) -> str:
    digits = sum(character.isdigit() for character in match.group(0))
    if 13 <= digits <= 19:
        return "[REDACTED_CARD]"
    return match.group(0)


def _sanitize_exempt_literal(literal: str) -> str:
    literal = _CARD_RE.sub(_redact_card, literal)
    return _GROUPED_IDENTIFIER_RE.sub("[ACCOUNT]", literal)


def _sanitize_line(line: str) -> str:
    if _GIT_METADATA_RE.fullmatch(line.rstrip("\r\n")):
        return line
    hunk_prefix = ""
    hunk_match = _HUNK_HEADER_RE.match(line)
    if hunk_match:
        hunk_prefix = hunk_match.group(0)
        line = line[len(hunk_prefix) :]

    exempt: list[str] = []

    def _mask_with(predicate):
        def _mask(match: re.Match[str]) -> str:
            if predicate is not None and not predicate(match):
                return match.group(0)
            exempt.append(_sanitize_exempt_literal(match.group(0)))
            return f"[LITERAL_{len(exempt) - 1}]"

        return _mask

    masked = line
    for pattern, predicate in _EXEMPT_RULES:
        masked = pattern.sub(_mask_with(predicate), masked)
    for pattern, replacement in SECRET_PATTERNS[1:]:
        masked = pattern.sub(replacement, masked)
    masked = redact_sensitive_text_preserving_bic(masked)
    masked = _CARD_RE.sub(_redact_card, masked)
    for index, literal in enumerate(exempt):
        masked = masked.replace(f"[LITERAL_{index}]", literal)
    return hunk_prefix + masked


def _generic_redact(text: str) -> str:
    """Run the built-in generic sanitizer over ``text``."""
    # PEM spans lines, run globally first
    pem_pattern, pem_replacement = SECRET_PATTERNS[0]
    text = pem_pattern.sub(pem_replacement, text)
    return "".join(_sanitize_line(line) for line in text.splitlines(keepends=True))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_with_metadata(text: str, redactor: Redactor | None = None) -> RedactionResult:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    generic = _generic_redact(text)
    if redactor is None:
        return RedactionResult(generic, ())
    result = redactor.redact(generic)
    _validate_result(result)
    normalized = _normalize_placeholders(result.placeholders)
    final_text = _generic_redact(result.text)
    if len(final_text.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise SecurityError("sanitized output exceeds byte ceiling")
    return RedactionResult(final_text, normalized)


def sanitize(text: str, redactor: Redactor | None = None) -> str:
    return sanitize_with_metadata(text, redactor).text

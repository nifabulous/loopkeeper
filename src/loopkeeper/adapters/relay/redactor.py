"""Relay adapter for Loopkeeper redaction.

Wraps Relay's ``redact_sensitive_text_preserving_bic`` string redactor in the
Loopkeeper ``Redactor`` protocol, exposing a declared placeholder set.

Only the declared set may be emitted; the adapter is tested to ensure it does
not introduce unvalidated tokens.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# Declared placeholder set – covers every token the adapter can emit.
# Mirrors the tutor corpus minus BIC (preserved) – BIC is public directory data.
RELAY_PLACEHOLDERS: frozenset[str] = frozenset({"IBAN", "UETR", "ACCOUNT", "EMAIL", "PHONE", "SECRET"})
PLACEHOLDERS = RELAY_PLACEHOLDERS
ALLOWED_PLACEHOLDERS = RELAY_PLACEHOLDERS
DECLARED_PLACEHOLDERS = RELAY_PLACEHOLDERS

# Reuse the same tutor core as loopkeeper.redaction but isolated here so the
# adapter has no hard dependency on the package internals beyond the protocol.
# Vendor the minimal redaction logic needed for the relay corpus.

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
_UETR_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[A-Z0-9]{11,30}|(?:\s[A-Z0-9]{4}){2,7}(?:\s[A-Z0-9]{1,4})?)\b", re.IGNORECASE)
_PHONE_RE = re.compile(r"\+?\(?\d[\d\s().-]{7,17}\d")
_ACCOUNT_RE = re.compile(r"\b\d{8,}\b")
_BIC_RE = re.compile(r"\b[A-Za-z]{4}[A-Za-z]{2}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?\b")
_BIC_CUE_RE = re.compile(r"(?:\bbic|\bswift\s+(?:code|codes|address|bic))\s*$", re.IGNORECASE)
_ENGLISH_INFLECTION_SUFFIXES = ("ES", "ED", "ING", "LY", "ION", "MENT", "NESS")


def _looks_like_bic(token: str, prefix: str) -> bool:
    token = token.upper()
    if token[4:6] not in _ISO_3166_ALPHA2:
        return False
    if any(c.isdigit() for c in token):
        return True
    if len(token) == 11 and token.endswith("XXX"):
        return True
    if token.endswith(_ENGLISH_INFLECTION_SUFFIXES):
        return False
    return _BIC_CUE_RE.search(prefix) is not None


def _redact_phone(m: re.Match[str]) -> str:
    token = m.group(0)
    digits = sum(c.isdigit() for c in token)
    if not 9 <= digits <= 15:
        return token
    if token.startswith("+") or any(c in " .-()" for c in token):
        return "[PHONE]"
    return token


def _redact_bic(m: re.Match[str]) -> str:
    token = m.group(0)
    if _looks_like_bic(token, m.string[: m.start()]):
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
    """Relay's redactor: redact everything except BIC/SWIFT codes."""
    return _apply_rules(value, include_bic=False)


# ---------------------------------------------------------------------------
# Loopkeeper protocol wrapper
# ---------------------------------------------------------------------------

try:
    from loopkeeper.redaction import RedactionResult  # type: ignore
except Exception:
    # Fallback for isolated import (should not happen when package installed)
    class RedactionResult(NamedTuple):  # type: ignore
        text: str
        placeholders: tuple[str, ...]


_PLACEHOLDER_EXTRACT_RE = re.compile(r"\[(IBAN|UETR|ACCOUNT|EMAIL|PHONE|SECRET|BIC)\]")


class RelayRedactor:
    """Wraps ``redact_sensitive_text_preserving_bic`` in the Loopkeeper protocol."""

    def redact(self, text: str) -> RedactionResult:
        sanitized = redact_sensitive_text_preserving_bic(text)
        # Collect placeholders that actually appear, in first-seen order
        seen: list[str] = []
        seen_set: set[str] = set()
        for m in _PLACEHOLDER_EXTRACT_RE.finditer(sanitized):
            ph = m.group(1)
            if ph not in RELAY_PLACEHOLDERS:
                continue
            if ph not in seen_set:
                seen_set.add(ph)
                seen.append(ph)
        # Deduplicate and ensure grammar (already enforced by PLACEHOLDERS set)
        return RedactionResult(sanitized, tuple(seen))


# Exported instances for loader and tests
redactor = RelayRedactor()
default_redactor = RelayRedactor()
relay_redactor = RelayRedactor()

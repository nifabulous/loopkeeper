"""Wrap untrusted content in delimiters the content cannot forge.

Ported from Relay e834773 scripts/codex_untrusted.py.
"""

from __future__ import annotations

import re

OPEN_TEMPLATE = "<<<UNTRUSTED_DATA {label}>>>"
CLOSE_TEMPLATE = "<<<END_UNTRUSTED_DATA {label}>>>"

LABEL_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_DELIMITER_RE = re.compile(r"<<<\s*(?:END_)?UNTRUSTED_DATA[^\n>]*>*", re.IGNORECASE)
DEFANGED = "[DEFANGED_DELIMITER]"


def defang(text: str) -> str:
    """Neutralise delimiter-shaped runs so untrusted data cannot close its block."""
    return _DELIMITER_RE.sub(DEFANGED, text)


def wrap_untrusted(label: str, text: str) -> str:
    """Return ``text`` enclosed in a labelled, unforgeable untrusted-data block."""
    if not isinstance(label, str) or not LABEL_PATTERN.fullmatch(label):
        raise ValueError("label must match [A-Za-z0-9_-]{1,64}")
    if not isinstance(text, str):
        raise TypeError("text must be str")
    body = defang(text)
    if not body.endswith("\n"):
        body += "\n"
    return f"{OPEN_TEMPLATE.format(label=label)}\n{body}{CLOSE_TEMPLATE.format(label=label)}\n"


def wrap_untrusted_bounded(label: str, text: str, max_bytes: int) -> str:
    """Wrap untrusted text without ever truncating away its closing fence."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(text, str):
        raise TypeError("text must be str")

    opening = f"{OPEN_TEMPLATE.format(label=label)}\n"
    closing = f"{CLOSE_TEMPLATE.format(label=label)}\n"
    if not LABEL_PATTERN.fullmatch(label):
        raise ValueError("label must match [A-Za-z0-9_-]{1,64}")
    full = wrap_untrusted(label, text)
    if len(full.encode("utf-8")) <= max_bytes:
        return full

    marker = f"\n\n[Truncated at {max_bytes} bytes.]\n"
    fixed_bytes = len((opening + marker + closing).encode("utf-8"))
    if fixed_bytes > max_bytes:
        raise ValueError("max_bytes is too small for an untrusted block")
    body_budget = max_bytes - fixed_bytes
    body = defang(text)
    body = body.encode("utf-8")[:body_budget].decode("utf-8", errors="ignore")
    return f"{opening}{body}{marker}{closing}"

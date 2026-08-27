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

"""Truncate text to a byte ceiling without splitting a UTF-8 code point.

Ported from Relay e834773 scripts/codex_truncate.py.
"""

from __future__ import annotations

import argparse
import sys

DEFAULT_MARKER = "\n\n[Truncated at {limit} bytes.]\n"


def truncate_utf8(text: str, max_bytes: int, marker: str = DEFAULT_MARKER) -> str:
    """Return ``text`` encoded in at most ``max_bytes`` UTF-8 bytes."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be int")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if not isinstance(marker, str):
        raise TypeError("marker must be str")
    if len(text.encode("utf-8")) <= max_bytes:
        return text
    rendered = marker.format(limit=max_bytes) if "{limit}" in marker else marker
    # If marker itself contains unrelated format keys, fallback to raw marker
    # The format above only handles {limit}; if marker has other braces, keep as-is
    # To preserve original codex_truncate behaviour, we format only when {limit} present
    # Otherwise use marker verbatim.
    # But original code always did marker.format(limit=max_bytes) – if marker lacks
    # {limit}, format is no-op. So we mimic that safely.
    try:
        rendered = marker.format(limit=max_bytes)
    except Exception:
        rendered = marker
    budget = max_bytes - len(rendered.encode("utf-8"))
    if budget <= 0:
        return _cut(text, max_bytes)
    return _cut(text, budget) + rendered


def _cut(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")[:max_bytes]
    return encoded.decode("utf-8", errors="ignore")


if __name__ == "__main__":  # pragma: no cover - exercised by shell adapters
    parser = argparse.ArgumentParser(prog="python -m loopkeeper.truncate")
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    args = parser.parse_args()
    sys.stdout.write(truncate_utf8(sys.stdin.read(), args.max_bytes, args.marker))

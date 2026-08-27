"""Tests for loopkeeper truncate — ported from Relay tests/test_codex_truncate.py."""
from __future__ import annotations

import pytest

from loopkeeper.truncate import truncate_utf8


def test_text_within_the_ceiling_is_returned_unchanged():
    source = "a short review\n"
    assert truncate_utf8(source, 4096) == source


def test_truncation_never_splits_a_multi_byte_character():
    source = "€" * 20
    result = truncate_utf8(source, 40)
    assert result.encode("utf-8").decode("utf-8") == result
    assert len(result.encode("utf-8")) <= 40


def test_truncated_output_stays_within_the_byte_ceiling_including_the_marker():
    result = truncate_utf8("x" * 5000, 200)
    assert len(result.encode("utf-8")) <= 200
    assert "Truncated" in result


def test_a_ceiling_too_small_for_the_marker_still_returns_valid_utf8():
    result = truncate_utf8("é" * 100, 5)
    assert result.encode("utf-8").decode("utf-8") == result
    assert len(result.encode("utf-8")) <= 5


def test_non_positive_ceiling_is_rejected():
    with pytest.raises(ValueError):
        truncate_utf8("content", 0)
    with pytest.raises(ValueError):
        truncate_utf8("content", -1)


def test_truncate_marker_larger_than_ceiling_returns_truncated_marker():
    marker = "[Truncated at {limit} bytes.]\n"
    # Marker itself is longer than ceiling; should return truncated marker or cut text
    result = truncate_utf8("hello world hello world", 5, marker=marker)
    assert len(result.encode("utf-8")) <= 5
    assert result.encode("utf-8").decode("utf-8") == result


def test_truncate_does_not_exceed_ceiling_with_multibyte_marker():
    marker = "… truncated {limit} …"
    result = truncate_utf8("a" * 1000, 50, marker=marker)
    assert len(result.encode("utf-8")) <= 50


def test_every_returned_string_is_at_most_max_bytes():
    for text, limit in [("é" * 10, 5), ("€€€", 5), ("hello € world", 10), ("日本語のレビュー" * 20, 60)]:
        result = truncate_utf8(text, limit)
        assert len(result.encode("utf-8")) <= limit
        # also valid utf8
        result.encode("utf-8").decode("utf-8")

from __future__ import annotations

import subprocess
import sys

from loopkeeper.review_output import (
    bound_review_output,
    review_validation_payload,
    sanitize_review_output,
)
from loopkeeper.schema import parse_trailer, render_trailer


def test_bounded_review_preserves_a_valid_trailer_at_the_end():
    trailer = '<!-- loopkeeper-verdict: {"schema":2,"verdict":"CLEAN","findings":[]} -->'
    source = "x" * 500 + "\n\n" + trailer + "\n"

    bounded = bound_review_output(source, 220)

    assert len(bounded.encode("utf-8")) <= 220
    parsed = parse_trailer(bounded)
    assert parsed.valid is True
    assert parsed.trailer is not None
    assert bounded.rstrip().endswith(render_trailer(parsed.trailer))
    assert "[Review truncated at 220 bytes.]" in bounded


def test_review_validation_payload_keeps_malformed_output_explicit():
    payload = review_validation_payload("plain-text review")

    assert payload == {
        "valid": False,
        "schema": None,
        "error_code": "MALFORMED-TRAILER",
        "diagnostic": "no trailer found",
    }


def test_trailer_aware_sanitization_preserves_numeric_finding_identity():
    source = (
        "Summary with account 12345678\n\n"
        '<!-- loopkeeper-verdict: {"schema":2,"verdict":"BLOCK",'
        '"findings":[{"sev":"P2","state":"NEW","file":"fixtures/20260828.json",'
        '"cat":"security","id":"finding-12345678"}]} -->\n'
    )

    sanitized = sanitize_review_output(source)
    parsed = parse_trailer(sanitized)

    assert "[ACCOUNT]" in sanitized
    assert parsed.valid is True
    assert parsed.trailer is not None
    assert parsed.trailer.findings[0].id == "finding-12345678"
    assert parsed.trailer.findings[0].file == "fixtures/20260828.json"


def test_trailer_aware_sanitization_redacts_free_text_inside_trailer():
    source = (
        "Summary\n\n"
        '<!-- loopkeeper-verdict: {"schema":2,"verdict":"BLOCK",'
        '"findings":[{"sev":"P2","state":"RESOLVED","file":"app/a.py",'
        '"cat":"security","id":"finding-a","evidence":{"files":["app/a.py"],'
        '"verification":"Verification references account 12345678"}}]} -->\n'
    )

    sanitized = sanitize_review_output(source)
    parsed = parse_trailer(sanitized)

    assert "12345678" not in sanitized
    assert parsed.valid is True
    assert parsed.trailer is not None
    assert parsed.trailer.findings[0].evidence is not None
    assert "[ACCOUNT]" in parsed.trailer.findings[0].evidence.verification


def test_review_output_cli_rejects_input_over_configured_bound():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "loopkeeper.review_output",
            "--validate",
            "--max-input-bytes",
            "10",
        ],
        input="x" * 11,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "input exceeds 10 bytes" in result.stderr

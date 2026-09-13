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


# ---------------------------------------------------------------------------
# Output must be sanitized under the same profile as the input (issue #38)
# ---------------------------------------------------------------------------


def test_a_commit_sha_survives_code_review_sanitization():
    """The identifier binding a review to its commit must stay comparable.

    Under the payments profile the nine-digit run inside this SHA matched the
    account-number rule and was replaced, so the review's exact-head claim
    named a commit that cannot be found in git log -- while the same SHA stayed
    intact in the comment marker the harness writes two lines below it.
    """
    sha = "82f9a90c51a253a2f6ec48b5412ab360871504a7"
    text = f"Exact-head checks for {sha} report success.\n"

    assert sha in sanitize_review_output(text, profile="code-review")


def test_the_payments_profile_still_redacts_an_account_number():
    """Narrowing did not happen here: the profile split is doing the work."""
    text = "Credit account 100200300400 for the beneficiary.\n"

    assert "100200300400" not in sanitize_review_output(text)


def test_short_and_long_digest_forms_survive_code_review_sanitization():
    for digest in (
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ):
        assert digest in sanitize_review_output(
            f"checksum {digest}\n", profile="code-review"
        ), digest


def test_a_trailer_evidence_field_keeps_its_sha_under_code_review():
    """Trailer fields are sanitized too, and carry SHAs in verification text.

    The finding is RESOLVED because that is the state whose evidence the schema
    carries; a NEW finding's evidence is dropped on re-render, which would make
    this pass without testing anything.
    """
    sha = "82f9a90c51a253a2f6ec48b5412ab360871504a7"
    text = (
        "Review prose.\n\n"
        '<!-- loopkeeper-verdict: {"schema":2,"verdict":"COMMENT","findings":'
        '[{"sev":"P2","state":"RESOLVED","file":"a.py","cat":"functional","id":"x",'
        f'"evidence":{{"files":["a.py"],"verification":"checked at {sha}"}}}}]}} -->\n'
    )

    assert sha in sanitize_review_output(text, profile="code-review")

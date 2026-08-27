import pytest

from loopkeeper.errors import SchemaError
from loopkeeper.schema import parse_history, parse_trailer, render_trailer


def test_new_output_uses_loopkeeper_marker_and_legacy_input_is_accepted():
    source = '<!-- codex-verdict: {"schema":2,"verdict":"CLEAN","findings":[]} -->'
    parsed = parse_trailer(source)
    assert parsed.valid is True
    assert parsed.trailer.verdict == "CLEAN"
    assert render_trailer(parsed.trailer).startswith("<!-- loopkeeper-verdict:")


def test_invalid_trailer_is_retained_as_an_invalid_round():
    parsed = parse_trailer("model text without a trailer")
    assert parsed.valid is False
    assert parsed.error_code == "MALFORMED-TRAILER"
    history = parse_history({
        "schema": 1,
        "repo": "example/project",
        "pr": 24,
        "current_head_sha": "0" * 40,
        "current_diff_files": [],
        "rounds": [{"kind": "invalid", "validation": parsed.to_dict()}],
    })
    assert history.rounds[0].kind == "invalid"


def test_unknown_schema_is_rejected_without_guessing():
    with pytest.raises(SchemaError, match="unsupported schema"):
        parse_history({"schema": 99})

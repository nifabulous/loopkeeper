"""Reviewer -> collector -> core round-trip harness for Loopkeeper.

Ported from Relay tests/test_arbiter_roundtrip.py. Starts from a REVIEWER COMMENT BODY
and drives it through the trailer parse path into history the core accepts.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from loopkeeper.schema import parse_trailer, render_trailer, parse_history
from loopkeeper.types import Trailer
import loopkeeper.arbiter as arb

LIVE_CAPTURE = Path(__file__).parents[2] / "tests" / "fixtures" / "relay-e834773" / "live_reviewer_capture.md"

CANONICAL_COMMENT = """\
<!-- loopkeeper-pr-review:99:0000000000000000000000000000000000000000 -->

**Verdict: BLOCK**

### Findings
- P1 published-self-assert (app/models.py): still open.

<!-- loopkeeper-verdict: {"schema":2,"verdict":"BLOCK","findings":[
  {"sev":"P1","state":"OPEN","file":"app/models.py","cat":"authorization",
   "id":"published-self-assert"}]} -->
"""

# Also test codex-verdict compatibility
CODEX_CANONICAL_COMMENT = """\
<!-- codex-pr-review:99:0000000000000000000000000000000000000000 -->

**Verdict: BLOCK**

### Findings
- P1 published-self-assert (app/models.py): still open.

<!-- codex-verdict: {"schema":2,"verdict":"BLOCK","findings":[
  {"sev":"P1","state":"OPEN","file":"app/models.py","cat":"authorization",
   "id":"published-self-assert"}]} -->
"""


def _roundtrip(comment_body: str):
    parsed = parse_trailer(comment_body)
    assert parsed.valid, f"parse_trailer rejected: {parsed.error_code} {parsed.diagnostic}"
    assert parsed.trailer is not None
    return parsed.trailer


def test_canonical_reviewer_comment_round_trips_through_the_collector():
    trailer = _roundtrip(CANONICAL_COMMENT)
    assert trailer.schema == 2
    assert trailer.findings, "canonical trailer parsed to zero findings"
    ids = {f.id for f in trailer.findings}
    assert "published-self-assert" in ids


def test_codex_verdict_input_compatibility():
    # loopkeeper must accept codex-verdict on ingest for migration
    trailer = _roundtrip(CODEX_CANONICAL_COMMENT)
    assert trailer.schema == 2
    ids = {f.id for f in trailer.findings}
    assert "published-self-assert" in ids


def test_multiline_trailer_is_parsed_whole():
    assert "\n" in CANONICAL_COMMENT.split("loopkeeper-verdict:")[1].split("-->")[0]
    trailer = _roundtrip(CANONICAL_COMMENT)
    assert len(trailer.findings) == 1


def test_trailer_render_uses_loopkeeper_marker():
    trailer = _roundtrip(CANONICAL_COMMENT)
    rendered = render_trailer(trailer)
    assert rendered.startswith("<!-- loopkeeper-verdict:")
    # Round-trip again
    parsed2 = parse_trailer(rendered)
    assert parsed2.valid
    assert parsed2.trailer.findings[0].id == "published-self-assert"


def test_history_parse_accepts_valid_trailer():
    trailer = _roundtrip(CANONICAL_COMMENT)
    history = parse_history({
        "schema": 1,
        "repo": "example/project",
        "pr": 99,
        "current_head_sha": "0" * 40,
        "current_diff_files": ["app/models.py"],
        "rounds": [
            {
                "kind": "valid",
                "comment": {
                    "comment_id": 1,
                    "created_at": "2026-08-17T09:00:00Z",
                    "author_login": "github-actions[bot]",
                    "head_sha": "0" * 40,
                    "marker": "loopkeeper-pr-review:99:" + "0" * 40,
                    "body": CANONICAL_COMMENT,
                },
                "trailer": {"schema": 2, "verdict": "BLOCK", "findings": [{"sev": "P1", "state": "NEW", "file": "app/models.py", "cat": "authorization", "id": "published-self-assert"}]},
            }
        ],
    })
    assert len(history.rounds) == 1
    assert history.rounds[0].validation.valid is True
    assert history.rounds[0].validation.trailer is not None
    # Now decide should handle this history via dataclass
    decision = arb.decide(history, arb.ArbiterConfig())
    # Single P1 NEW should be CONTINUE, not merge or needs-human
    assert decision.recommendation == "CONTINUE"
    assert decision.round_count == 1


@pytest.mark.skipif(
    not LIVE_CAPTURE.exists(),
    reason="no live reviewer capture yet",
)
def test_live_capture_round_trips_through_the_collector():
    body = LIVE_CAPTURE.read_text(encoding="utf-8")
    parsed = parse_trailer(body)
    assert parsed.valid, f"live capture failed: {parsed.error_code} {parsed.diagnostic}"
    trailer = parsed.trailer
    assert trailer.schema == 2
    for finding in trailer.findings:
        assert finding.sev in ("P1", "P2", "P3")
        assert finding.state in ("NEW", "OPEN", "RESOLVED")
        assert finding.file and finding.cat and finding.id


def test_live_capture_if_present_is_verbatim():
    # Ensure fixture was copied verbatim from e834773
    assert LIVE_CAPTURE.exists()
    text = LIVE_CAPTURE.read_text()
    assert "gpt-5.6-luna" in text or "LIVE CAPTURE" in text
    assert "codex-verdict" in text or "loopkeeper-verdict" in text

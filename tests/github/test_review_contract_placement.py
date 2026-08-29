"""The Schema-2 output contract must be the last thing the model reads.

Found by the PR A dogfood run on pull request #10: the published review ended
with a plain-text ``loopkeeper-verdict: NO_FINDINGS_WITH_TRUNCATED_PATCH_CAVEAT``
line instead of the required JSON trailer, so ``parse_trailer`` returned
MALFORMED-TRAILER. The contract was rendered near the *start* of the
instructions, then followed by the policy, the branch contract, and up to
50 KB of trusted reference material.

These tests pin placement. They do not relax validation: a plain-text verdict
line must stay invalid, and that regression is asserted here so a future
change cannot make the run green by weakening the parser.
"""

from __future__ import annotations

import re
from pathlib import Path

from loopkeeper.review_output import REVIEW_TRAILER_CONTRACT
from loopkeeper.schema import parse_trailer

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / "adapters" / "github" / "review_pr.sh"

# The exact shape observed on pull request #10.
OBSERVED_MALFORMED_REVIEW = """## Review Summary

No actionable defects were identified from the provided evidence.

loopkeeper-verdict: NO_FINDINGS_WITH_TRUNCATED_PATCH_CAVEAT
"""


def _instruction_block() -> str:
    """Return the braced group that builds review-instructions.md."""
    source = REVIEW.read_text(encoding="utf-8")
    end = source.index('} >"$TEMP_DIR/review-instructions.md"')
    start = source.rindex("\n{\n", 0, end)
    return source[start:end]


def test_plain_text_verdict_line_is_still_malformed():
    """Regression: the observed failure must never be accepted as valid.

    Placement is the fix. Teaching the parser to accept a plain-text verdict
    would make the dogfood green by destroying the fail-closed property the
    arbiter depends on.
    """
    validation = parse_trailer(OBSERVED_MALFORMED_REVIEW)

    assert validation.valid is False
    assert validation.error_code == "MALFORMED-TRAILER"


def test_shell_adapter_emits_the_contract_after_policy_and_context():
    """In review_pr.sh the contract must follow every trusted section."""
    block = _instruction_block()

    contract_at = block.index("REVIEW_TRAILER_CONTRACT")
    for marker in (
        "## Trusted review policy",
        "## Contract",
        "## Trusted reference material (not policy)",
    ):
        assert marker in block, f"instruction block no longer emits {marker!r}"
        assert block.index(marker) < contract_at, (
            f"{marker!r} is emitted after the output contract; the contract "
            "must be the final instruction section"
        )


def test_shell_adapter_contract_is_the_final_emission():
    """Nothing may be appended to the instructions after the contract."""
    block = _instruction_block()
    tail = block[block.index("REVIEW_TRAILER_CONTRACT"):]

    # No further section headers may be printed after the contract.
    trailing_sections = re.findall(r"printf '\\n\\n## ", tail)
    assert trailing_sections == [], (
        f"{len(trailing_sections)} section(s) are emitted after the output contract"
    )


def test_contract_text_names_the_prohibited_plain_text_form():
    """The contract must explicitly rule out the shape the model produced."""
    assert "plain-text" in REVIEW_TRAILER_CONTRACT
    assert "loopkeeper-verdict" in REVIEW_TRAILER_CONTRACT
    assert "final non-whitespace line" in REVIEW_TRAILER_CONTRACT


# ---------------------------------------------------------------------------
# Diff-evidence budget
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 600_000          # workflow default
BUDGET_PERCENT = 50                # LOOPKEEPER_PR_FILE_BUDGET_PERCENT
MIN_PATCH_BYTES = 512              # LOOPKEEPER_PR_FILE_MIN_PATCH_BYTES
PATCH_CEILING = 32_768             # LOOPKEEPER_PR_FILE_PATCH_CEILING
MAX_RETRIEVABLE_FILES = 5 * 100    # PAGE_SIZE * MAX_PAGES


def _derived_cap(changed_files: int, max_input_bytes: int = MAX_INPUT_BYTES) -> int:
    """Mirror of the shell derivation in review_pr.sh."""
    share = max_input_bytes * BUDGET_PERCENT // 100
    cap = share // changed_files if changed_files > 0 else PATCH_CEILING
    return max(MIN_PATCH_BYTES, min(PATCH_CEILING, cap))


def test_derived_budget_is_far_larger_than_the_old_fixed_cap():
    """The observed 45-file PR should get real evidence, not 1000 bytes."""
    assert _derived_cap(45) > 1000 * 5


def test_aggregate_patch_bytes_can_never_reach_the_input_budget():
    """Exhaustive proof over every retrievable file count.

    The aggregate guard exits 4 on overflow rather than degrading, so a
    derived cap that could approach the input budget would convert large
    pull requests from truncated into failed. Assert headroom instead of
    choosing a comfortable-looking constant.
    """
    worst = max(
        count * _derived_cap(count)
        for count in range(1, MAX_RETRIEVABLE_FILES + 1)
    )
    assert worst < MAX_INPUT_BYTES, f"worst-case aggregate {worst} reaches the budget"
    # Leave room for the JSON envelope (filenames, statuses, counts).
    assert worst <= MAX_INPUT_BYTES // 2


def test_budget_scales_with_a_smaller_input_budget():
    """A consumer lowering the input budget lowers the per-file cap too."""
    assert _derived_cap(50, max_input_bytes=120_000) < _derived_cap(50)


def test_review_script_derives_the_budget_and_keeps_the_override():
    """The shell must derive when unset and honour an explicit override."""
    source = REVIEW.read_text(encoding="utf-8")

    assert "LOOPKEEPER_PR_FILE_BUDGET_PERCENT" in source
    assert 'if [[ -z "${LOOPKEEPER_PR_FILE_MAX_PATCH_BYTES:-}" ]]; then' in source
    assert "changedFiles" in source
    # The fixed default must be gone.
    assert ': "${LOOPKEEPER_PR_FILE_MAX_PATCH_BYTES:=1000}"' not in source


def test_truncation_disclosure_is_retained():
    """A wider budget does not license dropping the coverage caveat."""
    source = REVIEW.read_text(encoding="utf-8")

    assert "patch_truncated" in source
    assert "files_truncated" in source
    assert "Evidence coverage" in source
    assert "this review is not exhaustive" in source

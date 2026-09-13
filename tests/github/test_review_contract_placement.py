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
#
# The budget used to be divided by the changed-file count, which made each
# file's allowance a function of how wide the pull request was rather than of
# what any file needed. A 21-file change occupying a fifth of its budget still
# lost its two largest files while four fifths went unused (issue #37).
#
# These tests run the allocator that ships, extracted from review_pr.sh, rather
# than a mirror of it in Python. A mirror is a second copy of the rule, and a
# second copy is what let the writer state machine drift from its own
# decision function.
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 600_000          # workflow default
BUDGET_PERCENT = 50                # LOOPKEEPER_PR_FILE_BUDGET_PERCENT
MIN_PATCH_BYTES = 512              # LOOPKEEPER_PR_FILE_MIN_PATCH_BYTES
PATCH_CEILING = 32_768             # LOOPKEEPER_PR_FILE_PATCH_CEILING
MAX_RETRIEVABLE_FILES = 5 * 100    # PAGE_SIZE * MAX_PAGES
BUDGET_SHARE = MAX_INPUT_BYTES * BUDGET_PERCENT // 100


def _allocator_source() -> str:
    """The allocator body as it ships, lifted out of the shell heredoc."""
    source = REVIEW.read_text(encoding="utf-8")
    assert "<<'ALLOCATE'" in source, "allocator heredoc not found in review_pr.sh"
    return source.split("<<'ALLOCATE'\n", 1)[1].split("\nALLOCATE\n", 1)[0]


def _allocate(sizes: list[int], budget: int = BUDGET_SHARE) -> list[int]:
    """Run the shipped allocator over synthetic patches; return granted bytes."""
    import json
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as workdir:
        work = Path(workdir)
        script = work / "allocate.py"
        script.write_text(_allocator_source(), encoding="utf-8")
        source_file = work / "in.jsonl"
        destination = work / "out.jsonl"
        with source_file.open("w", encoding="utf-8") as handle:
            for index, size in enumerate(sizes):
                handle.write(
                    json.dumps(
                        {
                            "filename": f"file{index}",
                            "patch": "x" * size,
                            "patch_truncated": False,
                        }
                    )
                    + "\n"
                )
        subprocess.run(
            [sys.executable, str(script), str(source_file), str(destination), str(budget)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        granted = []
        for line in destination.read_text(encoding="utf-8").splitlines():
            if line.strip():
                granted.append(len(json.loads(line)["patch"].encode("utf-8")))
        return granted


def _repeat(size: int, count: int) -> list[int]:
    """A list of `count` patches of `size` bytes.

    Named rather than written as a bracketed constant repeated by `*`, on
    purpose. The harness rewrites any bracketed uppercase token in untrusted
    input so a pull request cannot forge a redaction placeholder, and that
    turns a list literal of a constant into text which no longer parses.
    Reviewers of this file -- human or model -- then read a NameError that is
    not there. This docstring avoids the shape for the same reason.
    """
    return [size] * count


def test_a_pull_request_inside_its_budget_loses_nothing():
    """Issue #37, with the sizes it reported.

    The whole diff was 122,450 bytes against a 300,000-byte share -- nothing
    was near a limit -- and the two files most worth reading were truncated.
    """
    sizes = [26_806, 18_394, 11_365] + [3_600] * 18
    assert sum(sizes) < BUDGET_SHARE

    granted = _allocate(sizes)

    assert granted == sizes, "a diff that fits must be delivered whole"


def test_a_wide_pull_request_is_not_penalised_for_its_width():
    """Width alone must not truncate anything while the budget has room."""
    sizes = _repeat(2_000, 100)
    assert sum(sizes) < BUDGET_SHARE

    assert _allocate(sizes) == sizes


def test_overflow_bounds_the_largest_files_and_keeps_the_small_ones_whole():
    sizes = [200_000, 150_000, 5_000, 1_000]
    assert sum(sizes) > BUDGET_SHARE

    granted = _allocate(sizes)

    assert granted[2] == 5_000 and granted[3] == 1_000, "small patches must survive intact"
    assert granted[0] < sizes[0] and granted[1] < sizes[1]
    assert granted[0] == granted[1], "the overflow is shared evenly between the large files"


def test_the_allocation_never_exceeds_the_budget_share():
    """The guard downstream exits 4 rather than degrading, so this is load-bearing.

    Asserted over shapes that previously produced the worst aggregates: many
    files at the ceiling, a single enormous file, and the maximum retrievable
    file count.
    """
    for sizes in (
        _repeat(PATCH_CEILING, MAX_RETRIEVABLE_FILES),
        [MAX_INPUT_BYTES * 2],
        _repeat(PATCH_CEILING, 100),
        _repeat(1, MAX_RETRIEVABLE_FILES),
        _repeat(MIN_PATCH_BYTES, MAX_RETRIEVABLE_FILES),
    ):
        granted = _allocate(sizes)
        assert sum(granted) <= BUDGET_SHARE, f"{len(sizes)} files overflowed the share"
        assert all(g >= 0 for g in granted)


def test_no_file_is_granted_more_than_it_needs():
    granted = _allocate([10, 20, 30])
    assert granted == [10, 20, 30]


def test_review_script_allocates_by_size_and_keeps_the_override():
    """The shell must allocate by size and still honour an operator ceiling."""
    source = REVIEW.read_text(encoding="utf-8")

    assert "LOOPKEEPER_PR_FILE_BUDGET_PERCENT" in source
    assert 'if [[ -z "${LOOPKEEPER_PR_FILE_MAX_PATCH_BYTES:-}" ]]; then' in source
    assert "allocate_patch_budget" in source
    # The fixed default must stay gone.
    assert ': "${LOOPKEEPER_PR_FILE_MAX_PATCH_BYTES:=1000}"' not in source
    # And the count division that caused issue #37 must not come back.
    assert "/ PR_CHANGED_FILES" not in source
    assert "patch_budget_share / " not in source


def test_the_allocation_runs_before_the_aggregate_guard():
    """Ordering is the whole reason the allocation is safe.

    capture_bounded_stream exits 4 rather than degrading. If the allocation ran
    after it, an overflowing pull request would fail instead of being bounded.
    """
    source = REVIEW.read_text(encoding="utf-8")

    allocate_at = source.index('allocate_patch_budget "$TEMP_DIR/pr-files.jsonl"')
    guard_at = source.index('capture_bounded_stream "$LOOPKEEPER_MAX_INPUT_BYTES" "pull-request file changes"')
    assert allocate_at < guard_at


def test_truncation_disclosure_is_retained():
    """A wider budget does not license dropping the coverage caveat."""
    source = REVIEW.read_text(encoding="utf-8")

    assert "patch_truncated" in source
    assert "files_truncated" in source
    assert "Evidence coverage" in source
    assert "this review is not exhaustive" in source


# ---------------------------------------------------------------------------
# The contract must document a shape the parser accepts
#
# On pull request #13 the model emitted a correctly-wrapped HTML-comment
# trailer -- placement worked -- but used `severity`/`category`/`lines`/`title`
# for the finding fields instead of `sev`/`state`/`file`/`cat`/`id`. The
# contract only ever showed `"findings":[]`, so the finding shape was never
# demonstrated and the model guessed. Diagnostic was `bad-sev`.
# ---------------------------------------------------------------------------


def _contract_trailers() -> list[str]:
    return re.findall(r"<!-- loopkeeper-verdict:.*?-->", REVIEW_TRAILER_CONTRACT)


def test_contract_shows_both_an_empty_and_a_populated_example():
    """A model cannot infer the finding shape from an empty array alone."""
    trailers = _contract_trailers()
    assert len(trailers) >= 2, "the contract must show a populated finding example"
    assert any('"findings":[]' in t for t in trailers)
    assert any('"findings":[{' in t for t in trailers)


def test_every_example_in_the_contract_actually_parses():
    """The contract may never document a shape the parser rejects."""
    for trailer in _contract_trailers():
        validation = parse_trailer(f"Review body.\n\n{trailer}\n")
        assert validation.valid, (
            f"contract example does not parse: {validation.error_code} "
            f"({validation.diagnostic}) for {trailer[:80]}"
        )


def test_contract_names_the_exact_finding_fields():
    """The field names the parser requires must be stated, not implied."""
    for field in ('"sev"', '"state"', '"file"', '"cat"', '"id"'):
        assert field in REVIEW_TRAILER_CONTRACT, f"contract omits {field}"
    # And the wrong names the model actually reached for are called out.
    assert "`severity`" in REVIEW_TRAILER_CONTRACT
    assert "`category`" in REVIEW_TRAILER_CONTRACT


def test_contract_is_pure_ascii():
    """A stray non-ASCII character in the contract reaches the model verbatim."""
    offenders = [c for c in REVIEW_TRAILER_CONTRACT if ord(c) > 127]
    assert offenders == [], f"non-ASCII in contract: {offenders}"

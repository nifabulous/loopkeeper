import pathlib
import re


def test_source_ledger_has_30_rows_and_correct_totals():
    ledger_path = pathlib.Path(__file__).parents[1] / "docs" / "source-ledger.md"
    assert ledger_path.exists(), f"source ledger not found at {ledger_path}"

    text = ledger_path.read_text(encoding="utf-8")

    # Find the markdown table rows that look like: | `path` | digits | `dest` | ... |
    # The ledger table header is: | Relay source at `e834773` | Lines | Destination | Responsibility after extraction |
    # Followed by separator row and then 30 data rows.
    lines = text.splitlines()

    # Locate table start
    header_idx = None
    for i, line in enumerate(lines):
        if "Relay source at" in line and "Lines" in line and "Destination" in line:
            header_idx = i
            break
    assert header_idx is not None, "ledger markdown table header not found"

    # Rows after separator
    # header_idx+1 is separator row (|---|...), data rows start at header_idx+2
    data_rows = []
    for line in lines[header_idx + 2 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            break
        # Skip empty or separator-only lines
        if re.match(r"^\|\s*-+", stripped):
            continue
        data_rows.append(stripped)

    assert len(data_rows) == 30, f"expected 30 source rows, got {len(data_rows)}"

    total = 0
    for row in data_rows:
        # Split by '|' – markdown table row is | col1 | col2 | col3 | col4 |
        # After split, first and last are empty strings
        cols = [c.strip() for c in row.split("|")]
        # cols = ['', ' source ', ' lines ', ' destination ', ' responsibility ', '']
        # Remove empties from leading/trailing split
        if cols and cols[0] == "":
            cols = cols[1:]
        if cols and cols[-1] == "":
            cols = cols[:-1]
        assert len(cols) >= 4, f"expected at least 4 columns, got {cols}"
        source_col, lines_col, dest_col, responsibility_col = cols[0], cols[1], cols[2], cols[3]
        # Destination must be non-empty
        assert dest_col.strip() and dest_col.strip() != "-", f"destination empty in row: {row}"
        # Responsibility / parity owner must be non-empty (4th column)
        assert responsibility_col.strip() and responsibility_col.strip() != "-", f"parity owner empty in row: {row}"
        # Lines column should be integer
        m = re.search(r"\d+", lines_col)
        assert m, f"line count not found in row: {row}"
        total += int(m.group(0))
        # Source should look like a path with backticks or at least contain slash or dot
        assert source_col.strip(), f"source path empty in row: {row}"
        # Ensure ci.yml is not a source row
        assert "ci.yml" not in source_col, f"ci.yml must not appear as a source row, found in: {row}"

    assert total == 10801, f"expected total 10801 lines, got {total}"

    # .github/workflows/ci.yml must appear only in exclusion note, not as table row
    # Verify it appears exactly once in the document outside the table, or at least once in exclusion note
    # Count occurrences in the entire text
    ci_occurrences = text.count(".github/workflows/ci.yml")
    assert ci_occurrences >= 1, ".github/workflows/ci.yml should appear in exclusion note"
    # Ensure it does not appear inside the 30 table rows (already checked)
    # Additionally, ensure the exclusion note mentions it
    assert "ci.yml" in text, "exclusion note for ci.yml not found"
    # The note should say it's intentionally not ported / excluded
    lower = text.lower()
    assert (
        "not ported" in lower or "intentionally" in lower or "excluded" in lower or "outside" in lower
    ), "exclusion note should state ci.yml is not ported/excluded"

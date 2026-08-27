from __future__ import annotations

import json
from glob import glob
from pathlib import Path

from loopkeeper.arbiter import ArbiterConfig, decide
from loopkeeper.schema import parse_history

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_DISPOSITIONS = {
    "pr21_history.json": "ESCALATE-TO-SCOPING",
    "pr22_history.json": "MERGE-CLEAN",
    "pr24_history.json": "ESCALATE-TO-SCOPING",
}


def test_frozen_histories_preserve_decisions():
    fixture_dir = ROOT / "tests/fixtures/relay-e834773"
    for fixture in sorted(fixture_dir.glob("*_history.json")):
        history = parse_history(json.loads(fixture.read_text(encoding="utf-8")))
        assert decide(history, ArbiterConfig()).recommendation == EXPECTED_DISPOSITIONS[fixture.name]


def test_frozen_histories_are_not_mutable_relay_fetches():
    fixture_dir = ROOT / "tests/fixtures/relay-e834773"
    for fixture in fixture_dir.glob("*_history.json"):
        assert "DOCUMENTED RECONSTRUCTION" in fixture.read_text(encoding="utf-8")


def test_source_ledger_destinations_exist_after_extraction():
    ledger = (ROOT / "docs/source-ledger.md").read_text(encoding="utf-8")
    for line in ledger.splitlines():
        if not line.startswith("|") or line.startswith("| Relay source") or line.startswith("|---"):
            continue
        columns = [part.strip() for part in line.strip("|").split("|")]
        if len(columns) < 3:
            continue
        destinations = [item.strip().strip("`") for item in columns[2].split(";")]
        for destination in destinations:
            if destination.startswith("docs/") or destination.startswith("src/") or destination.startswith("adapters/") or destination.startswith("tests/") or destination.startswith("examples/"):
                matches = glob(str(ROOT / destination))
                assert matches, destination

"""Behavioral tests for the bounded GitHub job-summary renderer."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "adapters/github/render_summary.sh"


def _run(mode: str, summary: Path, env: dict[str, str]) -> None:
    merged = os.environ.copy()
    merged.update(env)
    merged["GITHUB_STEP_SUMMARY"] = str(summary)
    subprocess.run([str(RENDERER), mode], cwd=ROOT, env=merged, check=True)


def test_review_summary_discloses_partial_coverage_and_writer_state(tmp_path: Path):
    artifact_dir = tmp_path / "review-artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "review-metadata.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "head_sha": "a" * 40,
                "evidence_state": "fallback",
                "coverage": {"state": "partial"},
            }
        ),
        encoding="utf-8",
    )
    (artifact_dir / "trailer.json").write_text(
        json.dumps({"valid": True, "schema": 2, "error_code": None}),
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"

    _run(
        "review",
        summary,
        {
            "EVENT_NAME": "pull_request_target",
            "PR_NUMBER": "7",
            "REVIEW_OUTCOME": "success",
            "ARTIFACT_AVAILABLE": "true",
            "ARTIFACT_NAME": "loopkeeper-review-7",
            "ARTIFACT_DIR": str(artifact_dir),
            "POST_COMMENTS": "true",
        },
    )

    rendered = summary.read_text(encoding="utf-8")
    assert "Evidence | `fallback`" in rendered
    assert "Coverage | `partial`" in rendered
    assert "Writer | eligible in writer job" in rendered
    assert "Trailer | `valid`" in rendered


def test_writer_summary_reports_recorded_comment_action(tmp_path: Path):
    artifact_dir = tmp_path / "writer-artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "write-metadata.json").write_text(
        json.dumps({"schema": 1, "action": "replaced_fallback"}),
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"

    _run(
        "writer",
        summary,
        {
            "EVENT_NAME": "workflow_run",
            "PR_NUMBER": "7",
            "EXPECTED_HEAD_SHA": "b" * 40,
            "WRITER_OUTCOME": "success",
            "WRITER_ARTIFACT_DIR": str(artifact_dir),
        },
    )

    rendered = summary.read_text(encoding="utf-8")
    assert "Writer step | `success`" in rendered
    assert "Comment action | `replaced_fallback`" in rendered

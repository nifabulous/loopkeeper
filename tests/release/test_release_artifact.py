from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_release_artifact", ROOT / "release" / "verify_artifact.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

EXPECTED_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _write_release_fixture(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = dist / "loopkeeper-0.1.0-py3-none-any.whl"
    sdist = dist / "loopkeeper-0.1.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    (dist / "COMMIT_SHA").write_text(EXPECTED_COMMIT + "\n", encoding="utf-8")
    (dist / "release-manifest.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "version": "0.1.0",
                "commit_sha": EXPECTED_COMMIT,
                "package_sha256": MODULE.sha256(wheel),
                "artifacts": [
                    {"filename": wheel.name, "sha256": MODULE.sha256(wheel)},
                    {"filename": sdist.name, "sha256": MODULE.sha256(sdist)},
                ],
                "workflow_paths": [
                    ".github/workflows/pr-review.yml",
                    ".github/workflows/pr-review-posting.yml",
                    ".github/workflows/issue-triage.yml",
                    ".github/workflows/agent.yml",
                ],
                "provenance": {"source": "Loopkeeper release pipeline", "builder": "GitHub Actions"},
            }
        ),
        encoding="utf-8",
    )
    return dist


def test_release_artifact_verifier_accepts_bound_artifacts(tmp_path):
    MODULE.verify_release_artifact(_write_release_fixture(tmp_path), EXPECTED_COMMIT)


def test_release_artifact_verifier_rejects_mismatched_commit_file(tmp_path):
    dist = _write_release_fixture(tmp_path)
    (dist / "COMMIT_SHA").write_text("f" * 40 + "\n", encoding="utf-8")

    with pytest.raises(MODULE.ReleaseArtifactError, match="COMMIT_SHA"):
        MODULE.verify_release_artifact(dist, EXPECTED_COMMIT)


def test_release_artifact_verifier_rejects_mismatched_manifest_commit(tmp_path):
    dist = _write_release_fixture(tmp_path)
    manifest_path = dist / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["commit_sha"] = "f" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(MODULE.ReleaseArtifactError, match="manifest commit_sha"):
        MODULE.verify_release_artifact(dist, EXPECTED_COMMIT)


def test_release_artifact_verifier_rejects_mismatched_package_digest(tmp_path):
    dist = _write_release_fixture(tmp_path)
    manifest_path = dist / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(MODULE.ReleaseArtifactError, match="digest"):
        MODULE.verify_release_artifact(dist, EXPECTED_COMMIT)

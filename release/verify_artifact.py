"""Verify the release artifact produced by the GitHub release workflow."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


class ReleaseArtifactError(ValueError):
    """Raised when release metadata does not bind to the downloaded files."""


_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.-]+)?")
_WORKFLOW_PATHS = [
    ".github/workflows/pr-review.yml",
    ".github/workflows/pr-review-posting.yml",
    ".github/workflows/issue-triage.yml",
    ".github/workflows/issue-triage-readonly.yml",
    ".github/workflows/agent.yml",
]
_MANIFEST_KEYS = {
    "schema",
    "version",
    "commit_sha",
    "package_sha256",
    "artifacts",
    "workflow_paths",
    "provenance",
}


def sha256(path: Path) -> str:
    """Return the SHA-256 digest for a bounded release file."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseArtifactError(message)


def verify_release_artifact(dist: Path, expected_commit: str) -> None:
    """Fail closed unless metadata and package files describe the same release."""

    dist = Path(dist)
    _require(dist.is_dir(), f"release directory is missing: {dist}")
    _require(bool(_COMMIT_RE.fullmatch(expected_commit)), "expected commit is not a full SHA")

    commit_path = dist / "COMMIT_SHA"
    manifest_path = dist / "release-manifest.json"
    _require(commit_path.is_file(), "COMMIT_SHA is missing")
    _require(manifest_path.is_file(), "release-manifest.json is missing")

    recorded_commit = commit_path.read_text(encoding="utf-8").strip()
    _require(bool(_COMMIT_RE.fullmatch(recorded_commit)), "COMMIT_SHA is not a full SHA")
    _require(recorded_commit == expected_commit, "COMMIT_SHA does not match the reviewed commit")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseArtifactError("release manifest is malformed") from exc

    _require(isinstance(manifest, dict), "release manifest must be an object")
    _require(set(manifest) == _MANIFEST_KEYS, "release manifest has unexpected metadata")
    _require(manifest["schema"] == 1, "release manifest schema is unsupported")

    version = manifest["version"]
    _require(isinstance(version, str) and bool(_VERSION_RE.fullmatch(version)), "release manifest version is invalid")
    manifest_commit = manifest["commit_sha"]
    _require(isinstance(manifest_commit, str) and bool(_COMMIT_RE.fullmatch(manifest_commit)), "manifest commit_sha is invalid")
    _require(manifest_commit == expected_commit, "manifest commit_sha does not match the reviewed commit")

    _require(manifest["workflow_paths"] == _WORKFLOW_PATHS, "release workflow paths are unexpected")
    _require(manifest["provenance"] == {"source": "Loopkeeper release pipeline", "builder": "GitHub Actions"}, "release provenance is unexpected")

    package_files = sorted([*dist.glob("*.whl"), *dist.glob("*.tar.gz")])
    _require(len(package_files) == 2, "release must contain exactly one wheel and one sdist")
    _require(sum(path.suffix == ".whl" for path in package_files) == 1, "release must contain exactly one wheel")
    _require(sum(path.name.endswith(".tar.gz") for path in package_files) == 1, "release must contain exactly one sdist")

    expected_wheel_prefix = f"loopkeeper-{version}-"
    expected_sdist_name = f"loopkeeper-{version}.tar.gz"
    for path in package_files:
        if path.suffix == ".whl":
            valid_name = path.name.startswith(expected_wheel_prefix)
        else:
            valid_name = path.name == expected_sdist_name
        _require(valid_name, f"unexpected package filename: {path.name}")

    artifacts = manifest["artifacts"]
    _require(isinstance(artifacts, list) and len(artifacts) == len(package_files), "release artifact inventory is invalid")
    inventory: dict[str, str] = {}
    for entry in artifacts:
        _require(isinstance(entry, dict) and set(entry) == {"filename", "sha256"}, "release artifact inventory entry is invalid")
        filename = entry["filename"]
        digest = entry["sha256"]
        _require(isinstance(filename, str) and Path(filename).name == filename, "release artifact filename is invalid")
        _require(isinstance(digest, str) and bool(_DIGEST_RE.fullmatch(digest)), f"release digest is invalid for {filename}")
        _require(filename not in inventory, f"release artifact is duplicated: {filename}")
        inventory[filename] = digest

    _require(set(inventory) == {path.name for path in package_files}, "release artifact inventory does not match package files")
    for path in package_files:
        actual_digest = sha256(path)
        _require(actual_digest == inventory[path.name], f"release artifact digest does not match {path.name}")

    wheel = next(path for path in package_files if path.suffix == ".whl")
    _require(manifest["package_sha256"] == inventory[wheel.name], "package_sha256 does not match the wheel digest")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: verify_artifact.py DIST EXPECTED_COMMIT", file=sys.stderr)
        return 2
    try:
        verify_release_artifact(Path(args[0]), args[1])
    except ReleaseArtifactError as exc:
        print(f"release artifact verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import re
import tarfile
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


def _project() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)["project"]


def _workflow_refs(root: Path) -> list[str]:
    refs: list[str] = []
    for path in root.rglob("*.yml"):
        refs.extend(re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", path.read_text(encoding="utf-8")))
    return refs


def test_runtime_dependencies_are_empty():
    assert _project()["dependencies"] == []


def test_ci_enforces_explicit_ruff_baseline():
    project = _project()
    ruff = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8")).get("tool", {}).get("ruff", {})
    assert project["optional-dependencies"]["dev"]
    assert ruff["target-version"] == "py310"
    assert ruff["line-length"] == 120
    assert ruff["lint"]["select"] == ["E4", "E7", "E9", "F"]
    raw = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python -m ruff check src tests" in raw


def test_all_workflow_refs_are_full_sha_pinned():
    refs = _workflow_refs(ROOT / ".github/workflows") + _workflow_refs(ROOT / "examples/github")
    assert refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in refs)


def test_non_publishable_templates_are_explicitly_marked():
    for path in (ROOT / "examples/github").rglob("*.yml"):
        raw = path.read_text(encoding="utf-8")
        if "# LOOPKEEPER-PUBLISHABLE" not in raw:
            assert "# LOOPKEEPER-TEMPLATE" in raw
            assert "example-org/loopkeeper" in raw


def test_source_and_release_manifest_versions_have_one_source_of_truth():
    source = (ROOT / "src/loopkeeper/__init__.py").read_text(encoding="utf-8")
    version = re.search(r"__version__\s*=\s*['\"]([^'\"]+)", source)
    assert version and version.group(1) == "0.1.1"
    release = json.loads((ROOT / "release/release-manifest.json").read_text(encoding="utf-8"))
    assert release["version"] == version.group(1)
    assert re.fullmatch(r"[0-9a-f]{40}", release["commit_sha"])
    assert re.fullmatch(r"[0-9a-f]{64}", release["package_sha256"])


def test_license_notice_and_source_ledger_are_present():
    assert (ROOT / "LICENSE").is_file()
    assert (ROOT / "NOTICE").is_file()
    assert (ROOT / "docs/source-ledger.md").is_file()


def test_wheel_contains_cli_resources_and_no_attestation_key():
    wheels = sorted((ROOT / "dist").glob("loopkeeper-*.whl"))
    assert wheels, "build the wheel before running release tests"
    with zipfile.ZipFile(wheels[-1]) as archive:
        names = archive.namelist()
    assert "loopkeeper/resources/schemas/manifest.schema.json" in names
    assert "loopkeeper/resources/manifests/review.json" in names
    assert "loopkeeper/resources/agents/domain-researcher.md" in names
    assert not any(name.endswith("trust-keys.json") for name in names)


def test_sdist_excludes_attestation_key_fixture():
    sdists = sorted((ROOT / "dist").glob("loopkeeper-*.tar.gz"))
    assert sdists, "build the sdist before running release tests"
    with tarfile.open(sdists[-1], "r:gz") as archive:
        assert not any(name.endswith("tests/fixtures/attestation/trust-keys.json") for name in archive.getnames())


def test_release_workflow_publishes_package_and_provenance():
    raw = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@" in raw
    assert "release-manifest.json" in raw
    assert "sha256sum" in raw


def test_release_workflow_uses_job_scoped_oidc_trusted_publishing():
    raw = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    publish = raw.split("\n  publish:\n", 1)[1]
    top_level = raw.split("jobs:", 1)[0]

    assert "if: ${{ inputs.publish }}" in publish
    assert "needs: build" in publish
    assert "permissions:\n      contents: read\n      id-token: write" in publish
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in publish
    assert "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in publish
    assert "TWINE_PASSWORD" not in raw
    assert "twine upload" not in raw
    assert "id-token: write" not in top_level


def test_release_workflow_verifies_commit_and_artifact_bindings_before_publish():
    raw = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    publish = raw.split("\n  publish:\n", 1)[1]

    assert "ref: ${{ github.sha }}" in publish
    assert "persist-credentials: false" in publish
    assert "EXPECTED_COMMIT: ${{ github.sha }}" in publish
    assert "python3 release/verify_artifact.py dist \"$EXPECTED_COMMIT\"" in publish
    assert '"artifacts": artifacts' in raw


def test_release_workflow_publishes_only_distribution_files():
    raw = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    publish = raw.split("\n  publish:\n", 1)[1]

    assert "mkdir -p publish-dist" in publish
    assert "cp dist/*.whl dist/*.tar.gz publish-dist/" in publish
    assert "packages-dir: publish-dist/" in publish


def test_release_tree_contains_no_fixture_secret():
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "tests" in path.parts or "test_release_contract.py" in path.name:
            continue
        if path.suffix in {".pyc", ".lock"}:
            continue
        raw = path.read_text(encoding="utf-8", errors="ignore")
        assert "base64-secret" not in raw

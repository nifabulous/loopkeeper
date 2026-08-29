"""Package resources must be readable from source, wheel, and zipimport.

``resource_path`` returned a filesystem ``Path``. For a zipimported package
that path can only come from ``importlib.resources.as_file()``, whose
extracted file is deleted when its context manager exits — so the returned
path dangles. These tests pin the content-reader contract instead, and the
zipimport case is the one that a path-returning API cannot satisfy.
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

RESOURCES = (
    "manifests/review.json",
    "manifests/review-invalid.json",
    "manifests/triage.json",
    "manifests/agent.json",
    "manifests/history.json",
    "schemas/manifest.schema.json",
    "schemas/history.schema.json",
    "schemas/reviewer-trailer.schema.json",
    "schemas/verification.schema.json",
)

AGENT_DEFINITION = "agents/domain-researcher.md"

# Reads every resource through the public content API and reports sizes, so a
# silently empty read cannot pass as success.
_PROBE = """
import json
from loopkeeper.artifacts import read_resource_bytes, read_resource_text

names = {names!r}
sizes = {{}}
for name in names:
    raw = read_resource_bytes(name)
    text = read_resource_text(name)
    assert raw, name
    assert text, name
    json.loads(text)
    sizes[name] = len(raw)

markdown = read_resource_text({agent!r})
assert markdown.strip(), "agent definition was empty"
sizes[{agent!r}] = len(markdown.encode("utf-8"))
print(json.dumps(sizes))
"""


def _probe_source() -> str:
    return _PROBE.format(names=list(RESOURCES), agent=AGENT_DEFINITION)


def _run_isolated(script: str, pythonpath: Path, workdir: Path) -> dict[str, int]:
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(workdir),
        env={
            "PYTHONPATH": str(pythonpath),
            "PATH": "/usr/bin:/bin",
            "HOME": str(workdir),
            "PYTHONSAFEPATH": "1",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def unpacked_wheel(tmp_path_factory) -> Path:
    """Build the wheel and unpack it into an isolated directory."""
    build_dir = tmp_path_factory.mktemp("resource-wheel")
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(build_dir)],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    wheels = sorted(build_dir.glob("loopkeeper-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"

    target = tmp_path_factory.mktemp("resource-site")
    with zipfile.ZipFile(wheels[0]) as archive:
        archive.extractall(target)
    return target


def test_resources_are_readable_from_source():
    """The in-repo checkout can read every packaged resource."""
    from loopkeeper.artifacts import read_resource_bytes, read_resource_text

    for name in RESOURCES:
        raw = read_resource_bytes(name)
        assert raw, name
        json.loads(read_resource_text(name))

    assert read_resource_text(AGENT_DEFINITION).strip()


def test_resources_are_readable_from_an_installed_wheel(unpacked_wheel, tmp_path):
    """The shipped artifact carries and exposes its own resources."""
    sizes = _run_isolated(_probe_source(), unpacked_wheel, tmp_path)

    assert set(sizes) == set(RESOURCES) | {AGENT_DEFINITION}
    assert all(size > 0 for size in sizes.values())


def test_resources_are_readable_through_zipimport(unpacked_wheel, tmp_path):
    """A zipimported package must still serve its resources.

    This is the case a Path-returning API cannot satisfy: there is no real
    file on disk, and as_file() deletes its extraction on context exit.
    """
    archive_path = tmp_path / "loopkeeper-zipimport.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in sorted((unpacked_wheel / "loopkeeper").rglob("*")):
            if item.is_file() and item.suffix != ".pyc":
                archive.write(item, item.relative_to(unpacked_wheel).as_posix())

    workdir = tmp_path / "zipimport-run"
    workdir.mkdir()
    sizes = _run_isolated(_probe_source(), archive_path, workdir)

    assert set(sizes) == set(RESOURCES) | {AGENT_DEFINITION}
    assert all(size > 0 for size in sizes.values())


def test_resource_reader_rejects_escaping_names():
    """Resource names stay confined regardless of the loader in use."""
    from loopkeeper.artifacts import read_resource_bytes

    for bad in ("../pyproject.toml", "/etc/passwd", "manifests/../../setup.py", ""):
        with pytest.raises(ValueError):
            read_resource_bytes(bad)

"""Wheel-level proof that policy categories are consumer-defined.

A consumer installs Loopkeeper as a package, not as this source checkout.
These tests build the wheel, install it into an isolated target directory,
and drive it in a subprocess whose ``PYTHONPATH`` contains only that target
and whose working directory is outside the repository. Nothing here can pass
by accidentally importing the source tree.
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

CONSUMER_POLICY = """# Consumer Review Policy

## Categories

- database-migrations
- accessibility
- ml-safety

## Severity

P1 blocks the merge.

## Lifecycle

Track findings across rounds.

## Data handling

Do not store secrets.

## Scope

Review migrations with particular care.

## Deployment constraints

No Friday deploys.
"""

# Vocabulary that belonged to the extraction source and must not survive in
# generic core. A consumer's own policy may of course use any of it.
FORBIDDEN_IN_CORE = ("payment-domain", "tutor/ai", "tutor-ai", "relay")


@pytest.fixture(scope="module")
def installed_package(tmp_path_factory) -> Path:
    """Build the wheel and unpack it into an isolated target directory."""
    build_dir = tmp_path_factory.mktemp("wheel-build")
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

    # Unpack rather than shelling out to pip. A wheel is a zip, and this
    # package declares no runtime dependencies, so extraction produces exactly
    # the layout pip would install. It also keeps this test runnable in a
    # pip-less virtualenv, so the same command works locally and in CI.
    target = tmp_path_factory.mktemp("wheel-site")
    with zipfile.ZipFile(wheels[0]) as archive:
        archive.extractall(target)
    assert (target / "loopkeeper" / "policy.py").is_file()
    return target


def _run_against_wheel(installed_package: Path, workdir: Path, script: str) -> str:
    """Execute *script* with only the installed package importable."""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(workdir),
        env={
            "PYTHONPATH": str(installed_package),
            "PATH": "/usr/bin:/bin",
            "HOME": str(workdir),
            # Keep the source checkout out of sys.path entirely.
            "PYTHONSAFEPATH": "1",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout


def test_installed_wheel_accepts_consumer_categories_and_extra_sections(
    installed_package, tmp_path
):
    """A consumer policy round-trips through the installed package."""
    workdir = tmp_path / "consumer"
    workdir.mkdir()
    (workdir / "policy.md").write_text(CONSUMER_POLICY, encoding="utf-8")

    script = """
import json
from pathlib import Path

from loopkeeper.policy import load_policy
from loopkeeper.prompt import UntrustedArtifacts, render_review_prompt
from loopkeeper.redaction import RedactionResult


class Reader:
    def read_text(self, path, max_bytes):
        return Path(path).read_text(encoding="utf-8")


root = Path.cwd()
policy = load_policy(root / "policy.md", root, Reader())
prompt = render_review_prompt(
    policy,
    RedactionResult("safe", ()),
    UntrustedArtifacts(metadata="m", diff="d", previous_review=None, checks=None),
)
print(json.dumps({
    "categories": list(policy.categories),
    "extra": [s.heading for s in policy.extra_sections],
    "instructions": prompt.instructions,
}))
"""
    payload = json.loads(_run_against_wheel(installed_package, workdir, script))

    assert payload["categories"] == ["database-migrations", "accessibility", "ml-safety"]
    assert payload["extra"] == ["Scope", "Deployment constraints"]

    instructions = payload["instructions"]
    for category in payload["categories"]:
        assert instructions.count(category) == 1, f"{category} not rendered exactly once"
    for heading in payload["extra"]:
        assert instructions.count(f"## {heading}") == 1, f"{heading} not rendered exactly once"


def test_installed_wheel_rejects_a_policy_without_explicit_categories(
    installed_package, tmp_path
):
    """Implicit category discovery is gone; the failure names the fix."""
    workdir = tmp_path / "legacy"
    workdir.mkdir()
    (workdir / "policy.md").write_text(
        "# Legacy Policy\n"
        "## functional\nimplicit category heading\n"
        "## Severity\nsev\n"
        "## Lifecycle\nlife\n"
        "## Data handling\nhandle\n",
        encoding="utf-8",
    )

    script = """
from pathlib import Path

from loopkeeper.errors import ConfigError
from loopkeeper.policy import load_policy


class Reader:
    def read_text(self, path, max_bytes):
        return Path(path).read_text(encoding="utf-8")


root = Path.cwd()
try:
    load_policy(root / "policy.md", root, Reader())
except ConfigError as exc:
    print(str(exc))
else:
    raise SystemExit("legacy implicit categories were accepted")
"""
    message = _run_against_wheel(installed_package, workdir, script)

    assert "Categories" in message


def test_installed_generic_core_contains_no_extraction_vocabulary(installed_package):
    """The shipped package must not carry the extraction source's domain."""
    for module in ("policy.py", "prompt.py"):
        source = (installed_package / "loopkeeper" / module).read_text(encoding="utf-8").lower()
        for forbidden in FORBIDDEN_IN_CORE:
            assert forbidden not in source, f"{module} ships {forbidden!r}"

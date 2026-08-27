import subprocess
import sys


def test_package_import_and_version_without_runtime_dependencies():
    result = subprocess.run(
        [sys.executable, "-c", "import loopkeeper; print(loopkeeper.__version__)"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "0.1.0"


def test_module_entrypoint_prints_version():
    result = subprocess.run(
        [sys.executable, "-m", "loopkeeper", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.strip() == "loopkeeper 0.1.0"

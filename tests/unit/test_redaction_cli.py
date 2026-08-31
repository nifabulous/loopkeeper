import json
import subprocess
import sys


def test_redaction_cli_writes_input_provenance_metadata(tmp_path):
    metadata_path = tmp_path / "redaction.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "loopkeeper.redaction",
            "--metadata-file",
            str(metadata_path),
        ],
        input='cfg = "[ACCOUNT]"\nsize = 12345678\n',
        text=True,
        capture_output=True,
        check=True,
    )

    assert completed.stdout == (
        'cfg = "[source-placeholder-literal]"\n'
        "size = [ACCOUNT]\n"
    )
    assert json.loads(metadata_path.read_text(encoding="utf-8")) == {
        "placeholders": ["ACCOUNT"],
        "source_placeholders_defanged": True,
    }


def test_redaction_cli_applies_profile_without_metadata_file():
    large_size = "1234" + "5678"
    completed = subprocess.run(
        [sys.executable, "-m", "loopkeeper.redaction", "--profile", "code-review"],
        input=f"size = {large_size}\n",
        text=True,
        capture_output=True,
        check=True,
    )

    assert completed.stdout == f"size = {large_size}\n"

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

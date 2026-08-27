from __future__ import annotations

import json
from pathlib import Path

from loopkeeper.cli import main as cli_main
from loopkeeper.transport import ModelResponse

from .helpers import fixture_manifest, sign_manifest


def _fake_model(request, config, opener=None):
    return ModelResponse(text="bounded generic result", raw_bytes=b"bounded", truncated=False, request_id="integration")


def test_generic_review_requires_attestation_and_writes_sanitized_artifacts(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("loopkeeper.transport.request_model", _fake_model)
    manifest_path = sign_manifest(tmp_path, fixture_manifest("review-invalid"))
    output = tmp_path / "artifacts"
    assert cli_main(["review", "--manifest", str(manifest_path), "--output-dir", str(output)]) == 0
    assert (output / "review.md").exists()
    assert (output / "trailer.json").exists()
    assert "raw" not in (output / "review.md").read_text(encoding="utf-8")


def test_generic_review_without_attestation_exits_four(tmp_path: Path, monkeypatch):
    manifest = fixture_manifest("review-invalid")
    manifest["trust"].pop("verification", None)
    manifest_path = tmp_path / "unsigned.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert cli_main(["review", "--manifest", str(manifest_path), "--output-dir", str(tmp_path / "out")]) == 4


def test_generic_triage_uses_same_attestation_and_artifact_envelope(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("loopkeeper.transport.request_model", _fake_model)
    manifest_path = sign_manifest(tmp_path, fixture_manifest("triage"))
    output = tmp_path / "artifacts"
    assert cli_main(["triage", "--manifest", str(manifest_path), "--output-dir", str(output)]) == 0
    triage = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert triage["trust_mode"] == "caller-attested"
    assert triage["artifact"] == 1


def test_generic_agent_is_artifact_only_and_refuses_executor(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("loopkeeper.agent.request_model", _fake_model)
    manifest = fixture_manifest("agent")
    manifest_path = sign_manifest(tmp_path, manifest)
    definition = tmp_path / "trusted" / "agents" / "domain-researcher.md"
    definition.parent.mkdir(parents=True, exist_ok=True)
    definition.write_text("---\nname: domain-researcher\ndescription: test\n---\nTrusted instructions\n", encoding="utf-8")
    assert cli_main([
        "agent", "--manifest", str(manifest_path), "--agent-name", "domain-researcher",
        "--task-text", "untrusted task", "--output-dir", str(tmp_path / "agent-artifacts"),
    ]) == 0

    executor_manifest = sign_manifest(tmp_path / "executor", fixture_manifest("agent"))
    assert cli_main([
        "agent", "--manifest", str(executor_manifest), "--agent-name", "verifying-executor",
        "--task-text", "run command", "--output-dir", str(tmp_path / "executor-out"),
    ]) == 4

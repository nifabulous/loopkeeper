from __future__ import annotations

import json
from pathlib import Path

from loopkeeper.cli import main as cli_main
from loopkeeper.transport import ModelResponse

from .helpers import fixture_manifest, prepare_roots, sign_manifest


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


def test_generic_cli_rejects_forge_verified_mode_before_model_call(tmp_path: Path, monkeypatch):
    manifest = fixture_manifest("review")
    prepare_roots(tmp_path, manifest)
    manifest_path = tmp_path / "forge-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def unexpected_model_call(*args, **kwargs):
        raise AssertionError("generic CLI must not invoke the model for forge-verified manifests")

    monkeypatch.setattr("loopkeeper.transport.request_model", unexpected_model_call)
    assert cli_main(["review", "--manifest", str(manifest_path), "--output-dir", str(tmp_path / "out")]) == 4


def test_generic_review_uses_manifest_policy_and_fails_without_model_binding(tmp_path: Path, monkeypatch):
    manifest = fixture_manifest("review-invalid")
    manifest_path = sign_manifest(tmp_path, manifest)
    policy_path = tmp_path / "trusted" / "policy.md"
    policy_path.write_text(
        "# Consumer Review Policy\n"
        "## Categories\n- functional\n- security\n"
        "## Severity\nCUSTOM SEVERITY\n"
        "## Lifecycle\nCUSTOM LIFECYCLE\n"
        "## Data handling\nCUSTOM DATA\n",
        encoding="utf-8",
    )
    (tmp_path / "untrusted" / "metadata.json").write_text(
        "Authorization: Bearer generic-secret-token-value\n", encoding="utf-8"
    )
    monkeypatch.delenv("LOOPKEEPER_MODEL", raising=False)
    monkeypatch.delenv("LOOPKEEPER_API_KEY", raising=False)
    assert cli_main(["review", "--manifest", str(manifest_path), "--output-dir", str(tmp_path / "out")]) == 2

    captured: dict[str, str] = {}

    def fake_model(request, config, opener=None):
        captured["instructions"] = request.instructions
        captured["input"] = request.input_text
        return ModelResponse(text="bounded generic result", raw_bytes=b"bounded", truncated=False, request_id="integration")

    monkeypatch.setenv("LOOPKEEPER_MODEL", "test-model")
    monkeypatch.setenv("LOOPKEEPER_API_KEY", "test-key")
    monkeypatch.setattr("loopkeeper.transport.request_model", fake_model)
    assert cli_main(["review", "--manifest", str(manifest_path), "--output-dir", str(tmp_path / "out")]) == 0
    assert "Consumer Review Policy" in captured["instructions"]
    assert "CUSTOM SEVERITY" in captured["instructions"]
    assert "generic-secret-token-value" not in captured["input"]


def test_generic_triage_uses_same_attestation_and_artifact_envelope(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("loopkeeper.transport.request_model", _fake_model)
    manifest_path = sign_manifest(tmp_path, fixture_manifest("triage"))
    output = tmp_path / "artifacts"
    assert cli_main(["triage", "--manifest", str(manifest_path), "--output-dir", str(output)]) == 0
    triage = json.loads((output / "triage.json").read_text(encoding="utf-8"))
    assert triage["trust_mode"] == "caller-attested"
    assert triage["artifact"] == 1


def test_generic_triage_sanitizes_untrusted_metadata_before_model_call(tmp_path: Path, monkeypatch):
    manifest_path = sign_manifest(tmp_path, fixture_manifest("triage"))
    (tmp_path / "untrusted" / "metadata.json").write_text(
        "Authorization: Bearer triage-secret-token-value\n", encoding="utf-8"
    )
    captured: dict[str, str] = {}

    def fake_model(request, config, opener=None):
        captured["input"] = request.input_text
        return ModelResponse(text="triage result", raw_bytes=b"bounded", truncated=False, request_id="integration")

    monkeypatch.setenv("LOOPKEEPER_MODEL", "test-model")
    monkeypatch.setenv("LOOPKEEPER_API_KEY", "test-key")
    monkeypatch.setattr("loopkeeper.transport.request_model", fake_model)
    assert cli_main(["triage", "--manifest", str(manifest_path), "--output-dir", str(tmp_path / "out")]) == 0
    assert "triage-secret-token-value" not in captured["input"]


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

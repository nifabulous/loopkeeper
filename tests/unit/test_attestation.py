"""Tests for attestation verification, canonical digest, and key file handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from loopkeeper.attestation import AttestationVerifier, unsigned_manifest_digest, verify_caller_attestation
from loopkeeper.errors import ManifestError, TrustError
from loopkeeper.manifest import load_manifest, validate_manifest
from loopkeeper.paths import resolve_bounded_path


def review_manifest(mode: str, verification: dict[str, object] | None) -> dict[str, object]:
    trust = {
        "mode": mode,
        "repo": "example/project",
        "head_sha": "0" * 40,
        "trusted_revision": "1" * 40,
    }
    if verification is not None:
        trust["verification"] = verification
    return {
        "manifest": 1,
        "kind": "review",
        "trust": trust,
        "trusted": {"policy": "policy.md", "contract": None, "context_files": []},
        "untrusted": {"metadata": "metadata.json", "diff": "diff.patch"},
        "limits": {"max_input_bytes": 200000, "max_output_bytes": 50000},
    }


def test_caller_attested_requires_verification_record(tmp_path):
    manifest = review_manifest(mode="caller-attested", verification=None)
    with pytest.raises(TrustError, match="verification"):
        validate_manifest(manifest, tmp_path / "trusted", tmp_path / "untrusted")


def test_symlink_escape_is_rejected(tmp_path):
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir()
    untrusted.mkdir()
    (trusted / "escape").symlink_to(untrusted, target_is_directory=True)
    with pytest.raises(ManifestError, match="leaves declared root"):
        resolve_bounded_path("escape/input.json", trusted, 1000)


def test_canonical_manifest_digest_includes_the_required_trailing_newline():
    unsigned = review_manifest(mode="caller-attested", verification=None)
    assert unsigned_manifest_digest(unsigned) == sha256(
        (json.dumps(unsigned, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    ).hexdigest()


def test_attestation_canonicalization_is_utf8_and_key_order_independent():
    left = {"z": "é", "a": {"b": 2, "a": 1}}
    right = {"a": {"a": 1, "b": 2}, "z": "é"}
    assert unsigned_manifest_digest(left) == unsigned_manifest_digest(right)


def _make_key_file(tmp_path: Path, key_id: str = "test-key-1") -> tuple[Path, bytes]:
    secret = b"test-secret-32-bytes-long-00000000"[:32]
    assert len(secret) >= 32
    encoded = base64.b64encode(secret).decode("utf-8")
    key_data = {"schema": 1, "keys": {key_id: encoded}}
    key_file = tmp_path / "trust-keys.json"
    key_file.write_text(json.dumps(key_data), encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return key_file, secret


def _compute_signature(secret: bytes, manifest_sha256: str, repo: str, head_sha: str, trusted_revision: str) -> str:
    msg = f"loopkeeper-manifest-v1\n{manifest_sha256}\n{repo}\n{head_sha}\n{trusted_revision}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def signed_review_manifest(tmp_path: Path, signature: str | None = None, key_id: str = "test-key-1") -> Path:
    key_file, secret = _make_key_file(tmp_path, key_id=key_id)
    unsigned = review_manifest(mode="caller-attested", verification=None)
    digest = unsigned_manifest_digest(unsigned)
    repo = unsigned["trust"]["repo"]  # type: ignore[index]
    head_sha = unsigned["trust"]["head_sha"]  # type: ignore[index]
    trusted_revision = unsigned["trust"]["trusted_revision"]  # type: ignore[index]
    if signature is None:
        signature = _compute_signature(secret, digest, repo, head_sha, trusted_revision)  # type: ignore[arg-type]
    verification_record = {
        "schema": 1,
        "method": "hmac-sha256",
        "key_id": key_id,
        "repo": repo,
        "head_sha": head_sha,
        "trusted_revision": trusted_revision,
        "manifest_sha256": digest,
        "signature": signature,
    }
    verification = {"method": "hmac-sha256", "record": verification_record}
    signed = review_manifest(mode="caller-attested", verification=verification)  # type: ignore[arg-type]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(signed), encoding="utf-8")
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir(exist_ok=True)
    untrusted.mkdir(exist_ok=True)
    (trusted / "policy.md").write_text("# Policy\n## Categories\nfunctional\n## Severity\nlow\n## Lifecycle\nopen\n## Data handling\nnone\n", encoding="utf-8")
    (untrusted / "metadata.json").write_text("{}", encoding="utf-8")
    (untrusted / "diff.patch").write_text("diff", encoding="utf-8")
    return manifest_path


def mutate(manifest_path: Path, mutation: str) -> None:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    rec = data["trust"]["verification"]["record"]
    if mutation == "repo":
        rec["repo"] = "example/other"
    elif mutation == "head_sha":
        rec["head_sha"] = "f" * 40
    elif mutation == "trusted_revision":
        rec["trusted_revision"] = "f" * 40
    elif mutation == "manifest_sha256":
        rec["manifest_sha256"] = "0" * 64
    elif mutation == "signature":
        rec["signature"] = "00" * 32
    elif mutation == "key_id":
        rec["key_id"] = "unknown-key"
    elif mutation == "method":
        rec["method"] = "hmac-sha512"
        data["trust"]["verification"]["method"] = "hmac-sha512"
    else:
        raise ValueError(mutation)
    manifest_path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def fake_model():
    ns = SimpleNamespace(call_count=0)
    return ns


def load_manifest_and_verify(manifest_path: Path, fake_model) -> None:
    key_file = manifest_path.parent / "trust-keys.json"
    trusted_root = manifest_path.parent / "trusted"
    untrusted_root = manifest_path.parent / "untrusted"
    os.environ["LOOPKEEPER_TRUST_KEY_FILE"] = str(key_file)
    manifest = load_manifest(manifest_path, trusted_root, untrusted_root)
    verification = manifest["trust"]["verification"]  # type: ignore[index]
    record = verification["record"]  # type: ignore[index]
    verifier = AttestationVerifier()
    verifier.verify(record, manifest, key_file)  # type: ignore[arg-type]
    verify_caller_attestation(manifest, record, verifier)  # type: ignore[arg-type]
    fake_model.call_count += 1


def test_bad_attestation_never_invokes_the_model(tmp_path, fake_model):
    manifest = signed_review_manifest(tmp_path, signature="00" * 32)
    with pytest.raises(TrustError):
        load_manifest_and_verify(manifest, fake_model=fake_model)
    assert fake_model.call_count == 0


@pytest.mark.parametrize("mutation", ["repo", "head_sha", "trusted_revision", "manifest_sha256", "signature", "key_id", "method"])
def test_each_attestation_subject_or_signature_mutation_exits_four(tmp_path, fake_model, mutation):
    manifest = signed_review_manifest(tmp_path)
    mutate(manifest, mutation)
    with pytest.raises(TrustError):
        load_manifest_and_verify(manifest, fake_model=fake_model)
    assert fake_model.call_count == 0


# Additional attestation edge cases

def test_key_file_rejects_group_readable(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission check only")
    secret = b"a" * 32
    encoded = base64.b64encode(secret).decode()
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"schema": 1, "keys": {"k1": encoded}}))
    os.chmod(key_file, 0o644)
    # attempt verify should fail due to perms
    verifier = AttestationVerifier()
    manifest = review_manifest(mode="caller-attested", verification=None)
    # we need a record to feed, but permission check happens first
    rec = {"schema": 1, "method": "hmac-sha256", "key_id": "k1", "repo": "example/project", "head_sha": "0"*40, "trusted_revision": "1"*40, "manifest_sha256": "0"*64, "signature": "00"*32}
    with pytest.raises(TrustError):
        verifier.verify(rec, manifest, key_file)  # type: ignore[arg-type]


def test_key_file_rejects_symlink(tmp_path):
    if os.name != "posix":
        pytest.skip("symlink check only meaningful on POSIX")
    real = tmp_path / "real-keys.json"
    secret = b"b" * 32
    encoded = base64.b64encode(secret).decode()
    real.write_text(json.dumps({"schema": 1, "keys": {"k1": encoded}}))
    os.chmod(real, 0o600)
    link = tmp_path / "link-keys.json"
    link.symlink_to(real)
    verifier = AttestationVerifier()
    manifest = review_manifest(mode="caller-attested", verification=None)
    rec = {"schema": 1, "method": "hmac-sha256", "key_id": "k1", "repo": "example/project", "head_sha": "0"*40, "trusted_revision": "1"*40, "manifest_sha256": "0"*64, "signature": "00"*32}
    with pytest.raises(TrustError):
        verifier.verify(rec, manifest, link)  # type: ignore[arg-type]


def test_short_secret_is_rejected(tmp_path):
    secret = b"short"
    encoded = base64.b64encode(secret).decode()
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"schema": 1, "keys": {"k1": encoded}}))
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    verifier = AttestationVerifier()
    manifest = review_manifest(mode="caller-attested", verification=None)
    rec = {"schema": 1, "method": "hmac-sha256", "key_id": "k1", "repo": "example/project", "head_sha": "0"*40, "trusted_revision": "1"*40, "manifest_sha256": "0"*64, "signature": "00"*32}
    with pytest.raises(TrustError):
        verifier.verify(rec, manifest, key_file)  # type: ignore[arg-type]


def test_malformed_base64_is_rejected(tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"schema": 1, "keys": {"k1": "!!!not-base64"}}))
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    verifier = AttestationVerifier()
    manifest = review_manifest(mode="caller-attested", verification=None)
    rec = {"schema": 1, "method": "hmac-sha256", "key_id": "k1", "repo": "example/project", "head_sha": "0"*40, "trusted_revision": "1"*40, "manifest_sha256": "0"*64, "signature": "00"*32}
    with pytest.raises(TrustError):
        verifier.verify(rec, manifest, key_file)  # type: ignore[arg-type]


def test_unknown_key_id_is_rejected(tmp_path):
    key_file, _ = _make_key_file(tmp_path, key_id="known")
    verifier = AttestationVerifier()
    manifest = review_manifest(mode="caller-attested", verification=None)
    rec = {"schema": 1, "method": "hmac-sha256", "key_id": "unknown", "repo": "example/project", "head_sha": "0"*40, "trusted_revision": "1"*40, "manifest_sha256": "0"*64, "signature": "00"*32}
    with pytest.raises(TrustError):
        verifier.verify(rec, manifest, key_file)  # type: ignore[arg-type]


def test_unsigned_digest_removes_verification():
    m = review_manifest(mode="caller-attested", verification={"method": "hmac-sha256", "record": {"x": 1}})
    d1 = unsigned_manifest_digest(m)
    m2 = review_manifest(mode="caller-attested", verification=None)
    d2 = unsigned_manifest_digest(m2)
    assert d1 == d2

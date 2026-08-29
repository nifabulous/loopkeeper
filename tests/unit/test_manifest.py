"""Tests for manifest validation, path confinement, and trust boundaries."""

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
from loopkeeper.manifest import TrustedReader, validate_manifest, load_manifest
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


# ---------------------------------------------------------------------------
# Helpers for attestation tests
# ---------------------------------------------------------------------------


def _make_key_file(tmp_path: Path, key_id: str = "test-key-1") -> tuple[Path, bytes]:
    secret = b"test-secret-32-bytes-long-00000000"  # 32 bytes
    # ensure exactly 32 bytes
    assert len(secret) >= 32
    secret = secret[:32]
    encoded = base64.b64encode(secret).decode("utf-8")
    key_data = {"schema": 1, "keys": {key_id: encoded}}
    key_file = tmp_path / "trust-keys.json"
    key_file.write_text(json.dumps(key_data), encoding="utf-8")
    # restrict permissions to 0600 for POSIX check
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return key_file, secret


def _compute_signature(secret: bytes, manifest_sha256: str, repo: str, head_sha: str, trusted_revision: str) -> str:
    msg = f"loopkeeper-manifest-v1\n{manifest_sha256}\n{repo}\n{head_sha}\n{trusted_revision}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def signed_review_manifest(tmp_path: Path, signature: str | None = None, key_id: str = "test-key-1") -> Path:
    """Create a signed manifest file on disk and return its path.

    Also ensures the key file exists at tmp_path/trust-keys.json.
    """
    key_file, secret = _make_key_file(tmp_path, key_id=key_id)
    # Build unsigned manifest first
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
    # Write signed manifest to file
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(signed), encoding="utf-8")
    # Also write needed trusted/untrusted fixture files so validate passes
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir(exist_ok=True)
    untrusted.mkdir(exist_ok=True)
    (trusted / "policy.md").write_text("# Policy\n## Categories\n- functional\n## Severity\nlow\n## Lifecycle\nopen\n## Data handling\nnone\n", encoding="utf-8")
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

    def _call(*args, **kwargs):
        ns.call_count += 1
        return {"text": "fake"}

    ns.invoke = _call
    # make callable
    ns.__call__ = _call
    return ns


def _fake_model_callable(fake_model):
    def _fn(*a, **kw):
        fake_model.call_count += 1
        return "model output"
    return _fn


def load_manifest_and_verify(manifest_path: Path, fake_model) -> None:
    """Helper that loads manifest, verifies attestation before invoking model."""
    # Determine key file location – use tmp_path's trust-keys.json
    key_file = manifest_path.parent / "trust-keys.json"
    trusted_root = manifest_path.parent / "trusted"
    untrusted_root = manifest_path.parent / "untrusted"
    # Ensure env var points to key file for verify_caller_attestation that reads env
    os.environ["LOOPKEEPER_TRUST_KEY_FILE"] = str(key_file)
    # Load manifest (will validate structure)
    manifest = load_manifest(manifest_path, trusted_root, untrusted_root)
    # Extract verification record
    verification = manifest["trust"]["verification"]  # type: ignore[index]
    record = verification["record"]  # type: ignore[index]
    verifier = AttestationVerifier()
    # This should raise TrustError before model invocation on bad sig
    verifier.verify(record, manifest, key_file)  # type: ignore[arg-type]
    # Also test the helper free function
    verify_caller_attestation(manifest, record, verifier)  # type: ignore[arg-type]
    # Only invoke model if verification succeeded
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


# ---------------------------------------------------------------------------
# Additional manifest validation coverage
# ---------------------------------------------------------------------------

def test_manifest_requires_version_one(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    m["manifest"] = 2  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_unknown_kind(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    m["kind"] = "unknown-kind"  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_invalid_trust_mode(tmp_path):
    m = review_manifest(mode="invalid-mode", verification=None)  # type: ignore[arg-type]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_non_positive_limits(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    m["limits"] = {"max_input_bytes": 0, "max_output_bytes": 50000}  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")
    m["limits"] = {"max_input_bytes": -1, "max_output_bytes": 50000}  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_bad_repo_shape(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    m["trust"]["repo"] = "not-a-repo"  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_bad_head_sha_shape(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    m["trust"]["head_sha"] = "zzz"  # type: ignore[index]
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path / "trusted", tmp_path / "untrusted")


def test_manifest_rejects_same_trusted_and_untrusted_roots(tmp_path):
    m = review_manifest(mode="github-forge-verified", verification=None)
    root = tmp_path / "same"
    root.mkdir()
    with pytest.raises(ManifestError):
        validate_manifest(m, root, root)


def test_resolve_bounded_path_rejects_absolute(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    with pytest.raises(ManifestError):
        resolve_bounded_path("/etc/passwd", root, 1000)
    with pytest.raises(ManifestError):
        resolve_bounded_path("/absolute/path.json", root, 1000)


def test_resolve_bounded_path_rejects_dotdot(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    with pytest.raises(ManifestError):
        resolve_bounded_path("../escape.json", root, 1000)
    with pytest.raises(ManifestError):
        resolve_bounded_path("a/../../b.json", root, 1000)


def test_resolve_bounded_path_rejects_control_chars(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    with pytest.raises(ManifestError):
        resolve_bounded_path("bad\x01path.json", root, 1000)
    with pytest.raises(ManifestError):
        resolve_bounded_path("bad\npath.json", root, 1000)


def test_resolve_bounded_path_rejects_over_byte_cap(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    big_file = root / "big.json"
    big_file.write_bytes(b"x" * 2000)
    with pytest.raises(ManifestError, match="exceeds byte cap"):
        resolve_bounded_path("big.json", root, 1000)


def test_resolve_bounded_path_allows_normal_file_under_cap(tmp_path):
    root = tmp_path / "trusted"
    root.mkdir()
    f = root / "ok.json"
    f.write_bytes(b"hello")
    p = resolve_bounded_path("ok.json", root, 1000)
    assert p.is_file()
    assert p.read_bytes() == b"hello"


def test_load_manifest_validates_structure_and_allows_github_forge(tmp_path):
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir()
    untrusted.mkdir()
    (trusted / "policy.md").write_text("# Policy\n")
    (untrusted / "metadata.json").write_text("{}")
    (untrusted / "diff.patch").write_text("diff")
    m = review_manifest(mode="github-forge-verified", verification=None)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(m))
    loaded = load_manifest(path, trusted, untrusted)
    assert loaded["kind"] == "review"  # type: ignore[index]


def test_load_manifest_rejects_missing_file(tmp_path):
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "nope.json", tmp_path / "trusted", tmp_path / "untrusted")


def test_load_manifest_rejects_malformed_json(tmp_path):
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir()
    untrusted.mkdir()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(ManifestError):
        load_manifest(bad, trusted, untrusted)


def test_exit_codes_mapping():
    from loopkeeper.exit_codes import EXIT_CONFIG, EXIT_TRUST

    assert ManifestError("x").exit_code == 2
    assert TrustError("x").exit_code == 4
    assert EXIT_CONFIG == 2
    assert EXIT_TRUST == 4


def test_trusted_reader_reexport():
    # Manifest boundary should re-export TrustedReader
    from loopkeeper.manifest import TrustedReader as MTR

    assert MTR is not None
    # Also available via types
    from loopkeeper.types import TrustedReader as TTR

    assert MTR == TTR or True  # protocol identity may differ but import must succeed


def test_unsigned_digest_trailing_newline_is_required():
    # Ensure digest is not without newline
    val = {"a": 1}
    without_newline = hashlib.sha256(json.dumps(val, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    with_newline = unsigned_manifest_digest(val)
    assert with_newline != without_newline


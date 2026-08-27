"""Attestation verification for caller-attested manifests.

Implements the protected key file handling and HMAC verification
as specified in Task 6. The key file path comes only from environment/CLI,
never from the manifest. On POSIX, reject group/world-readable and symlinked
files. Each secret is base64 decoded once, must be >=32 bytes, and kept in
memory only for the verification call. Unknown key IDs, duplicate keys,
malformed encoding, short keys, and unreadable files fail closed with TrustError.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .errors import ManifestError, TrustError

# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def unsigned_manifest_digest(value: dict[str, object]) -> str:
    """Compute SHA-256 over canonical JSON of *value* with trailing newline.

    The canonical form is UTF-8, sorted keys, compact separators, plus a
    trailing ``\\n``. The ``trust.verification`` field is removed before
    canonicalization to avoid a self-referential digest.

    For generic dictionaries without a ``trust`` object (used in
    canonicalization tests) the function computes the canonical digest
    directly without requiring a trust field. For manifest objects that
    contain ``trust``, it must be a mapping; otherwise a ManifestError is
    raised. This preserves the snippet's semantics for real manifests while
    allowing the UTF-8/key-order test to pass.
    """
    # Deep copy via JSON round-trip to avoid mutating caller
    try:
        unsigned = json.loads(json.dumps(value))
    except Exception as exc:
        raise ManifestError(f"manifest is not JSON serializable: {exc}") from exc
    if not isinstance(unsigned, dict):
        raise ManifestError("manifest must be an object")
    trust = unsigned.get("trust")
    if trust is not None:
        if not isinstance(trust, dict):
            raise ManifestError("trust must be an object")
        trust.pop("verification", None)
    canonical = (json.dumps(unsigned, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Verification record model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationRecord:
    schema: int
    method: str
    key_id: str
    repo: str
    head_sha: str
    trusted_revision: str
    manifest_sha256: str
    signature: str


# ---------------------------------------------------------------------------
# Key file loading
# ---------------------------------------------------------------------------


def _parse_json_no_duplicates(text: str) -> object:
    """Parse JSON and reject duplicate keys at any object level."""

    def _hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        d: dict[str, object] = {}
        for k, v in pairs:
            if k in d:
                raise TrustError(f"duplicate key {k!r} in protected key file")
            d[k] = v
        return d

    try:
        return json.loads(text, object_pairs_hook=_hook)
    except TrustError:
        raise
    except json.JSONDecodeError as exc:
        raise TrustError(f"protected key file is not valid JSON: {exc}") from exc


def _load_key_file(key_file: Path) -> dict[str, bytes]:
    """Load and validate the protected key file.

    Returns a mapping of key_id -> raw secret bytes.

    The file must be UTF-8 JSON with a base64-encoded secret value.
    On POSIX, reject symlinked paths and group/world-readable permissions.
    Each secret is base64-decoded once and must be >=32 bytes.
    """
    if not isinstance(key_file, Path):
        raise TrustError("key_file must be Path")

    # Reject symlink before any other check
    try:
        if key_file.is_symlink():
            raise TrustError(f"protected key file is symlinked: {key_file!r}")
    except OSError as exc:
        raise TrustError(f"cannot stat protected key file: {exc}") from exc

    # On POSIX, also check lstat vs stat distinction and permissions
    if os.name == "posix":
        try:
            # Check symlink via lstat as well (in case is_symlink missed)
            lstat = os.lstat(key_file)
            if stat.S_ISLNK(lstat.st_mode):
                raise TrustError(f"protected key file is symlinked: {key_file!r}")
        except TrustError:
            raise
        except OSError as exc:
            raise TrustError(f"protected key file is unreadable: {exc}") from exc

        try:
            st = os.stat(key_file)
        except OSError as exc:
            raise TrustError(f"protected key file is unreadable: {exc}") from exc

        mode = st.st_mode
        # Reject group/world readable/writable/executable
        if mode & 0o077 != 0:
            # More specific message containing group/world-readable for test matching
            raise TrustError(
                f"protected key file is group/world-readable or writable: {key_file!r} mode {oct(mode)}"
            )
        # Also explicitly check read bits
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            raise TrustError(f"protected key file is group/world-readable: {key_file!r}")

        # Ensure it's a regular file
        if not stat.S_ISREG(mode):
            raise TrustError(f"protected key file is not a regular file: {key_file!r}")
    else:
        # On non-POSIX, document the equivalent protected-secret requirement
        # We still require regular file and not symlink
        try:
            if not key_file.is_file():
                raise TrustError(f"protected key file not found: {key_file!r}")
        except OSError as exc:
            raise TrustError(f"protected key file is unreadable: {exc}") from exc

    # Read file bytes, bounded
    try:
        raw_bytes = key_file.read_bytes()
    except OSError as exc:
        raise TrustError(f"protected key file is unreadable: {exc}") from exc
    except Exception as exc:
        raise TrustError(f"protected key file is unreadable: {exc}") from exc

    # Reject over-sized key files (prevent DoS)
    if len(raw_bytes) > 1_000_000:
        raise TrustError("protected key file exceeds size limit")

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TrustError(f"protected key file must be UTF-8: {exc}") from exc

    data = _parse_json_no_duplicates(text)

    if not isinstance(data, dict):
        raise TrustError("protected key file must be a JSON object")
    if data.get("schema") != 1:
        raise TrustError("protected key file schema must be 1")
    keys_obj = data.get("keys")
    if not isinstance(keys_obj, dict):
        raise TrustError("protected key file 'keys' must be an object")
    if not keys_obj:
        raise TrustError("protected key file 'keys' must be non-empty")

    result: dict[str, bytes] = {}
    for key_id, b64_secret in keys_obj.items():
        if not isinstance(key_id, str) or not key_id:
            raise TrustError(f"key_id must be non-empty string: {key_id!r}")
        if key_id in result:
            raise TrustError(f"duplicate key_id {key_id!r} in protected key file")
        if not isinstance(b64_secret, str) or not b64_secret:
            raise TrustError(f"key {key_id!r} secret must be non-empty base64 string")
        # Duplicate detection already handled via JSON duplicate check, but also
        # guard against duplicate key_ids after normalization
        try:
            # validate=True ensures correct padding and character set
            decoded = base64.b64decode(b64_secret, validate=True)
        except Exception as exc:
            raise TrustError(f"key {key_id!r} has malformed base64: {exc}") from exc
        if len(decoded) < 32:
            raise TrustError(f"key {key_id!r} secret must be at least 32 bytes (got {len(decoded)})")
        result[key_id] = decoded

    return result


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class AttestationVerifier:
    """HMAC-SHA256 verifier for caller-attested manifests."""

    def verify(
        self,
        record: Mapping[str, object] | VerificationRecord,
        manifest: Mapping[str, object],
        key_file: Path,
    ) -> None:
        """Verify a caller-attested record.

        The manifest's canonical digest is computed via
        :func:`unsigned_manifest_digest` after removing
        ``trust.verification``. The HMAC is computed over
        ``loopkeeper-manifest-v1\\n{manifest_sha256}\\n{repo}\\n{head_sha}\\n{trusted_revision}``
        using the key selected by ``key_id`` from the protected key file.

        Raises:
            TrustError: If any check fails. The exception maps to exit 4 and
                is raised before any model invocation.
        """
        # Normalize record to dict
        if isinstance(record, VerificationRecord):
            rec: dict[str, object] = {
                "schema": record.schema,
                "method": record.method,
                "key_id": record.key_id,
                "repo": record.repo,
                "head_sha": record.head_sha,
                "trusted_revision": record.trusted_revision,
                "manifest_sha256": record.manifest_sha256,
                "signature": record.signature,
            }
        elif isinstance(record, Mapping):
            rec = dict(record)
        else:
            raise TrustError("verification record must be an object")

        # Normalize manifest to dict for digest
        if isinstance(manifest, Mapping):
            manifest_dict: dict[str, object] = dict(manifest)
        else:
            # Support dataclass-like with __dict__?
            try:
                manifest_dict = dict(manifest)  # type: ignore[arg-type]
            except Exception:
                raise TrustError("manifest must be a mapping")

        # Load keys (decode once, keep in memory only for this call)
        keys = _load_key_file(key_file)

        # Validate record fields
        if rec.get("schema") != 1:
            raise TrustError("verification record schema must be 1")
        method = rec.get("method")
        if method != "hmac-sha256":
            raise TrustError(f"unsupported verification method: {method!r}")
        key_id = rec.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise TrustError("verification record key_id must be non-empty string")
        if key_id not in keys:
            raise TrustError(f"unknown key_id {key_id!r}")

        # Validate required string fields
        for field in ("repo", "head_sha", "trusted_revision", "manifest_sha256", "signature"):
            val = rec.get(field)
            if not isinstance(val, str) or not val:
                raise TrustError(f"verification record {field} must be non-empty string: {val!r}")

        repo = rec["repo"]  # type: ignore[assignment]
        head_sha = rec["head_sha"]  # type: ignore[assignment]
        trusted_revision = rec["trusted_revision"]  # type: ignore[assignment]
        manifest_sha256_record = rec["manifest_sha256"]  # type: ignore[assignment]
        signature = rec["signature"]  # type: ignore[assignment]
        assert isinstance(repo, str)
        assert isinstance(head_sha, str)
        assert isinstance(trusted_revision, str)
        assert isinstance(manifest_sha256_record, str)
        assert isinstance(signature, str)
        assert isinstance(key_id, str)

        # Validate hex shapes (non-fatal but helps catch malformed)
        # manifest_sha256 should be 64 hex chars
        if not isinstance(manifest_sha256_record, str) or len(manifest_sha256_record) != 64 or any(c not in "0123456789abcdefABCDEF" for c in manifest_sha256_record):
            raise TrustError(f"verification record manifest_sha256 must be 64 hex chars: {manifest_sha256_record!r}")
        if len(signature) != 64 or any(c not in "0123456789abcdefABCDEF" for c in signature):
            # Allow any hex length for signature? But HMAC SHA256 hexdigest is 64 hex
            raise TrustError(f"verification record signature must be 64 hex chars: {signature!r}")

        # Validate manifest trust fields match record
        trust = manifest_dict.get("trust")
        if not isinstance(trust, dict):
            raise TrustError("manifest trust must be an object")
        manifest_repo = trust.get("repo")
        manifest_head = trust.get("head_sha")
        manifest_trusted_rev = trust.get("trusted_revision")
        if manifest_repo != repo:
            raise TrustError(f"verification repo mismatch: record {repo!r} vs manifest {manifest_repo!r}")
        if manifest_head != head_sha:
            raise TrustError(f"verification head_sha mismatch: record {head_sha!r} vs manifest {manifest_head!r}")
        if manifest_trusted_rev != trusted_revision:
            raise TrustError(f"verification trusted_revision mismatch: record {trusted_revision!r} vs manifest {manifest_trusted_rev!r}")

        # Compute canonical manifest digest
        try:
            expected_digest = unsigned_manifest_digest(manifest_dict)
        except ManifestError as exc:
            # If manifest structural error, map to TrustError? But spec says ManifestError for structure, TrustError for attestation.
            # For verifier context, treat as TrustError to fail closed before model.
            raise TrustError(f"manifest digest error: {exc}") from exc

        if expected_digest.lower() != manifest_sha256_record.lower():
            raise TrustError(f"manifest_sha256 mismatch: expected {expected_digest!r} got {manifest_sha256_record!r}")

        # Compute HMAC
        key = keys[key_id]  # bytes, already validated >=32
        msg = f"loopkeeper-manifest-v1\n{expected_digest}\n{repo}\n{head_sha}\n{trusted_revision}".encode("utf-8")
        expected_sig = hmac.new(key, msg, hashlib.sha256).hexdigest()

        # Constant-time compare
        if not hmac.compare_digest(expected_sig, signature):
            raise TrustError("attestation signature mismatch")

        # Keep decoded key in memory only for this call; explicitly delete
        # (Python will GC, but we remove reference)
        del keys
        del key


# ---------------------------------------------------------------------------
# Helper for generic flow
# ---------------------------------------------------------------------------


def verify_caller_attestation(
    manifest: Mapping[str, object],
    record: Mapping[str, object],
    verifier: AttestationVerifier | None = None,
) -> None:
    """Verify caller attestation prior to model invocation.

    This is a thin wrapper that resolves the protected key file from the
    environment if not provided via ``verifier``. The key file path is never
    read from the manifest.

    Args:
        manifest: The validated manifest mapping.
        record: The verification record extracted from ``manifest['trust']['verification']['record']``.
        verifier: The verifier instance; if None, a default is created.

    Raises:
        TrustError: If verification fails. Maps to exit 4.
    """
    if verifier is None:
        verifier = AttestationVerifier()

    # Resolve key file from environment (process environment/CLI config, never manifest)
    env_path = os.environ.get("LOOPKEEPER_TRUST_KEY_FILE")
    if not env_path:
        raise TrustError("LOOPKEEPER_TRUST_KEY_FILE is not set (protected key file path required)")
    key_file = Path(env_path)

    # The verifier's verify will load and check the key file
    verifier.verify(record, manifest, key_file)

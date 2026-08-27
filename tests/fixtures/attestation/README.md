# Attestation Fixture

This fixture demonstrates the protected key file format for caller-attested
manifests. It is **test-only** and must never be used in production.

## Format

The protected key file is a UTF-8 JSON object:

```json
{
  "schema": 1,
  "keys": {
    "key_id": "base64-secret"
  }
}
```

- `schema` must be `1`.
- `keys` is an object mapping `key_id` → base64-encoded secret.
- Each secret is base64 decoded once, must be at least 32 bytes, and is kept
  in memory only for the verification call.
- Unknown key IDs, duplicate keys, malformed/short encoding, and unreadable
  files fail closed (`TrustError`, exit 4).

## Protected path

The key file path comes **only** from the process environment or CLI
configuration (`LOOPKEEPER_TRUST_KEY_FILE` or `--trust-key-file`), never from
the manifest or PR-controlled content.

On POSIX, the file must be a regular file, not a symlink, and must not be
group/world-readable or writable (mode `0600` or `0400` recommended). On
other platforms, the equivalent protected-secret requirement applies: the file
must be stored with OS-appropriate ACLs that restrict access to the owning
user/service account.

## This fixture

`trust-keys.json` contains a single test key `test-key-1` with a 34-byte
secret (`test-secret-32-bytes-long-00000000`) base64-encoded. It exists for
unit tests and documentation; it is excluded from built wheels and sdists via
`MANIFEST.in` (`exclude tests/fixtures/attestation/trust-keys.json`).

Never commit a production key, and never embed a secret in a manifest,
artifact, or workflow log.

## Canonical digest and HMAC

- `manifest_sha256` is the SHA-256 hex digest over the canonical manifest
  JSON: UTF-8, sorted keys, compact separators (`","`, `":"`), plus a
  trailing newline (`\n`), after removing `trust.verification` to avoid a
  self-referential digest.
- The HMAC is computed over:

  ```
  loopkeeper-manifest-v1\n{manifest_sha256}\n{repo}\n{head_sha}\n{trusted_revision}
  ```

  using the key selected by `key_id`, with constant-time comparison of the
  hex signature.

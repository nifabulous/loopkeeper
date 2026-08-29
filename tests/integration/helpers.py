from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from loopkeeper.artifacts import read_resource_text
from loopkeeper.attestation import unsigned_manifest_digest


def prepare_roots(tmp_path: Path, manifest: dict) -> None:
    trusted = tmp_path / "trusted"
    untrusted = tmp_path / "untrusted"
    trusted.mkdir(exist_ok=True)
    untrusted.mkdir(exist_ok=True)
    trusted_cfg = manifest.get("trusted", {})
    if isinstance(trusted_cfg, dict):
        policy = trusted_cfg.get("policy")
        if isinstance(policy, str) and policy:
            path = trusted / policy
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "# Policy\n"
                "## Categories\n- functional\n- security\n"
                "## Severity\nP1 blocks merge.\n"
                "## Lifecycle\nTrack findings across rounds.\n"
                "## Data handling\nDo not store secrets.\n",
                encoding="utf-8",
            )
        for rel in trusted_cfg.get("context_files", []) or []:
            if isinstance(rel, str) and rel:
                path = trusted / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("trusted context\n", encoding="utf-8")
    untrusted_cfg = manifest.get("untrusted", {})
    if isinstance(untrusted_cfg, dict):
        for key, value in (("metadata", "{}\n"), ("diff", "diff --git a/app.py b/app.py\n+safe\n")):
            rel = untrusted_cfg.get(key)
            if isinstance(rel, str) and rel:
                path = untrusted / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value, encoding="utf-8")


def sign_manifest(tmp_path: Path, manifest: dict, key_id: str = "integration-v1") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(json.dumps(manifest))
    manifest.setdefault("trust", {})["mode"] = "caller-attested"
    manifest["trust"].pop("verification", None)
    prepare_roots(tmp_path, manifest)
    secret = b"integration-secret-32-bytes-000000"[:32]
    key_file = tmp_path / "trust-keys.json"
    key_file.write_text(
        json.dumps({"schema": 1, "keys": {key_id: base64.b64encode(secret).decode()}}),
        encoding="utf-8",
    )
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    os.environ["LOOPKEEPER_TRUST_KEY_FILE"] = str(key_file)
    os.environ.setdefault("LOOPKEEPER_MODEL", "test-model")
    os.environ.setdefault("LOOPKEEPER_API_KEY", "test-key")
    digest = unsigned_manifest_digest(manifest)
    trust = manifest["trust"]
    message = f"loopkeeper-manifest-v1\n{digest}\n{trust['repo']}\n{trust['head_sha']}\n{trust['trusted_revision']}".encode()
    manifest["trust"]["verification"] = {
        "method": "hmac-sha256",
        "record": {
            "schema": 1,
            "method": "hmac-sha256",
            "key_id": key_id,
            "repo": trust["repo"],
            "head_sha": trust["head_sha"],
            "trusted_revision": trust["trusted_revision"],
            "manifest_sha256": digest,
            "signature": hmac.new(secret, message, hashlib.sha256).hexdigest(),
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def fixture_manifest(kind: str) -> dict:
    return json.loads(read_resource_text(f"manifests/{kind}.json"))

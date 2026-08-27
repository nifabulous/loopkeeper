"""Typed data model for Loopkeeper schemas.

This module defines the normative dataclasses and protocols shared across
schema parsing, history handling, contracts, policies, manifests, and agents.
See docs/schemas.md for the human-readable tiebreaker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

# ---------------------------------------------------------------------------
# TrustedReader seam
# ---------------------------------------------------------------------------


class TrustedReader(Protocol):
    """Dependency-neutral trusted file reader.

    Defined with shared types and reused by contract, policy, manifest,
    and agent loaders. Implementations bind it to the verified trust root,
    e.g. ``git show "$TRUSTED_SHA:$path"`` on GitHub, or a filesystem read
    under the manifest's trusted root for generic runs.
    """

    def read_text(self, path: str, max_bytes: int) -> str:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# Trailer model (Schema 2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    files: tuple[str, ...]
    verification: str


@dataclass(frozen=True)
class Finding:
    sev: str
    state: str
    file: str
    cat: str
    id: str
    evidence: Evidence | None = None
    unverifiable: dict | None = None  # {"missing": str} when present


@dataclass(frozen=True)
class Trailer:
    schema: int
    verdict: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class TrailerValidation:
    valid: bool
    trailer: Trailer | None
    error_code: str | None
    diagnostic: str

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "schema": self.trailer.schema if self.trailer else None,
            "error_code": self.error_code,
            "diagnostic": self.diagnostic[:512],
        }


# ---------------------------------------------------------------------------
# History model (Schema 1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Comment:
    comment_id: int
    created_at: str
    author_login: str
    head_sha: str
    marker: str = ""
    body: str = ""
    # trailer is not stored separately; validation.trailer holds it when valid
    # but we keep body for re-parsing if needed


@dataclass(frozen=True)
class HistoryRound:
    kind: Literal["valid", "invalid"]
    comment: Comment | None
    validation: TrailerValidation | None


@dataclass(frozen=True)
class History:
    schema: int
    repo: str
    pr: int
    current_head_sha: str
    current_diff_files: tuple[str, ...]
    rounds: tuple[HistoryRound, ...]

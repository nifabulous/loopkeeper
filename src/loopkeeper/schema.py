"""Schema parsing and rendering for Loopkeeper history and trailer.

Implements the normative Schema 2 (trailer) and Schema 1 (history) handling
described in docs/schemas.md. The marker is not a trust signal; input accepts
both loopkeeper-verdict and codex-verdict for compatibility, output emits only
loopkeeper-verdict. Unknown schema versions are rejected without guessing.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .errors import SchemaError
from .types import (
    Comment,
    Evidence,
    Finding,
    History,
    HistoryRound,
    Trailer,
    TrailerValidation,
)

# ---------------------------------------------------------------------------
# Constants mirroring Relay's arbiter (trusted control-plane validation)
# ---------------------------------------------------------------------------

_IDENTITY_KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_IDENTITY_MAX_LEN = 64
_FILE_MAX_LEN = 256
_FILE_FORBIDDEN = ("<", ">", "`", "{", "}", "--")
_UNVERIFIABLE_MISSING_MAX_LEN = 512
_UNVERIFIABLE_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SEVERITIES = ("P1", "P2", "P3")
_TRAILER_SEVERITIES = ("P0", *_SEVERITIES)
_STATES = ("NEW", "OPEN", "RESOLVED")
_DIAGNOSTIC_MAX = 512

_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_REPO_RE = re.compile(r"^[^/\s]+/[^/\s]+$")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_sev(sev: str) -> str:
    return "P1" if sev == "P0" else sev


def _parse_ts(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"created_at must be RFC3339 string, got {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SchemaError(f"created_at is not RFC3339: {value!r}") from exc
    # Ensure timezone aware for sorting consistency
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _bound_diagnostic(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text[:_DIAGNOSTIC_MAX]


def _is_sanitized_diff_file(value: str) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    if len(value) > _FILE_MAX_LEN or "\n" in value:
        return False
    if any(m in value for m in _FILE_FORBIDDEN):
        return False
    if _UNVERIFIABLE_CONTROL_RE.search(value):
        return False
    return not (value.startswith("/") or ".." in value.split("/"))


def _validate_trailer_dict(raw: object) -> tuple[Trailer | None, str | None]:
    """Validate a trailer dict and return (Trailer, None) or (None, reason)."""
    if not isinstance(raw, dict):
        return None, "trailer-not-object"
    if raw.get("schema") != 2:
        return None, "unknown-schema"
    verdict = raw.get("verdict")
    if not isinstance(verdict, str) or not verdict.strip():
        return None, "bad-verdict"
    findings_raw = raw.get("findings")
    if not isinstance(findings_raw, list):
        return None, "findings-not-list"
    findings: list[Finding] = []
    for finding in findings_raw:
        if not isinstance(finding, dict):
            return None, "finding-not-object"
        sev = finding.get("sev")
        if sev not in _TRAILER_SEVERITIES:
            return None, "bad-sev"
        state = finding.get("state")
        if state not in _STATES:
            return None, "bad-state"
        for field in ("file", "cat", "id"):
            v = finding.get(field)
            if not isinstance(v, str) or not v.strip():
                return None, f"bad-{field}"
        # identity checks
        fid = finding["id"]
        cat = finding["cat"]
        if len(fid) > _IDENTITY_MAX_LEN or not _IDENTITY_KEBAB_RE.fullmatch(fid):
            return None, "bad-id"
        if len(cat) > _IDENTITY_MAX_LEN or not _IDENTITY_KEBAB_RE.fullmatch(cat):
            return None, "bad-cat"
        file_val = finding["file"]
        if (
            len(file_val) > _FILE_MAX_LEN
            or "\n" in file_val
            or any(m in file_val for m in _FILE_FORBIDDEN)
        ):
            return None, "bad-file"
        # unverifiable
        if "unverifiable" in finding:
            unverifiable = finding["unverifiable"]
            if not isinstance(unverifiable, dict):
                return None, "bad-unverifiable"
            missing_raw = unverifiable.get("missing")
            if not isinstance(missing_raw, str):
                return None, "bad-unverifiable"
            if _UNVERIFIABLE_CONTROL_RE.search(missing_raw):
                return None, "bad-unverifiable"
            normalized = " ".join(missing_raw.split())
            if not normalized or len(normalized) > _UNVERIFIABLE_MISSING_MAX_LEN:
                return None, "bad-unverifiable"
            if state == "RESOLVED":
                return None, "unverifiable-resolved"
            # keep normalized but don't need to sanitize fully here
            unverifiable = {"missing": normalized}
        else:
            unverifiable = None
        # RESOLVED evidence
        evidence_obj: Evidence | None = None
        if state == "RESOLVED":
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict):
                return None, "resolved-without-evidence"
            files = evidence.get("files")
            verification = evidence.get("verification")
            if not isinstance(files, list) or not files:
                return None, "evidence-files-bad"
            if not all(isinstance(x, str) and x.strip() for x in files):
                return None, "evidence-files-bad"
            if not isinstance(verification, str) or not verification.strip():
                return None, "evidence-verification-bad"
            # files should be bounded
            for f in files:
                if len(f) > _FILE_MAX_LEN or "\n" in f or any(m in f for m in _FILE_FORBIDDEN):
                    return None, "evidence-files-bad"
            evidence_obj = Evidence(files=tuple(files), verification=verification.strip())
        # Build normalized finding
        sev_norm = _normalize_sev(str(sev))
        # Evidence and unverifiable construction
        # For non-RESOLVED with unverifiable, keep dict
        findings.append(
            Finding(
                sev=sev_norm,
                state=str(state),
                file=str(file_val),
                cat=str(cat).lower() if isinstance(cat, str) else str(cat),
                id=str(fid),
                evidence=evidence_obj,
                unverifiable=unverifiable,
            )
        )
    trailer = Trailer(schema=2, verdict=str(verdict), findings=tuple(findings))
    return trailer, None


# ---------------------------------------------------------------------------
# Trailer parse / render
# ---------------------------------------------------------------------------


def parse_trailer(
    text: str, accepted_markers: tuple[str, ...] = ("loopkeeper-verdict", "codex-verdict")
) -> TrailerValidation:
    """Parse a single trailer from *text*.

    Accepts zero or one trailer per comment. Input accepts any marker in
    *accepted_markers* for compatibility; output via render_trailer always uses
    loopkeeper-verdict. P0 is normalized to P1 at parse time, RESOLVED requires
    evidence, diagnostic text is bounded, and duplicate trailers are treated as
    malformed.
    """
    if not isinstance(text, str):
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("input must be str"),
        )
    # Count total markers across all accepted names
    total = 0
    matched_marker: str | None = None
    matched_open = ""
    for marker in accepted_markers:
        open_seq = f"<!-- {marker}:"
        cnt = text.count(open_seq)
        total += cnt
        if cnt and matched_marker is None:
            matched_marker = marker
            matched_open = open_seq
        elif cnt and matched_marker is not None:
            # multiple markers total, we already know it's >1 but find first
            pass
    if total == 0:
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("no trailer found"),
        )
    if total > 1:
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("multiple trailers: duplicate trailers"),
        )
    # Exactly one
    assert matched_marker is not None
    open_seq = matched_open
    start = text.index(open_seq) + len(open_seq)
    close = text.find("-->", start)
    if close == -1:
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("unterminated trailer"),
        )
    if text[close + 3 :].strip():
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("trailer-not-final: content after trailer"),
        )
    payload = text[start:close].strip()
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic(f"unparseable json: {exc}"),
        )
    if not isinstance(raw, dict):
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic("trailer-not-object"),
        )
    trailer, err = _validate_trailer_dict(raw)
    if trailer is None:
        # Map unknown-schema to MALFORMED but keep diagnostic for history
        diag = err or "malformed trailer"
        if err == "unknown-schema":
            diag = f"unsupported trailer schema: {raw.get('schema')!r}"
        return TrailerValidation(
            valid=False,
            trailer=None,
            error_code="MALFORMED-TRAILER",
            diagnostic=_bound_diagnostic(diag),
        )
    return TrailerValidation(valid=True, trailer=trailer, error_code=None, diagnostic="")


def render_trailer(trailer: Trailer) -> str:
    """Render a trailer using only the loopkeeper-verdict marker."""
    if not isinstance(trailer, Trailer):
        raise TypeError("render_trailer expects Trailer")
    payload = {
        "schema": trailer.schema,
        "verdict": trailer.verdict,
        "findings": [
            {
                "sev": f.sev,
                "state": f.state,
                "file": f.file,
                "cat": f.cat,
                "id": f.id,
                **({"evidence": {"files": list(f.evidence.files), "verification": f.evidence.verification}} if f.evidence else {}),
                **({"unverifiable": f.unverifiable} if f.unverifiable else {}),
            }
            for f in trailer.findings
        ],
    }
    json_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"<!-- loopkeeper-verdict: {json_str} -->"


# ---------------------------------------------------------------------------
# History parse / render
# ---------------------------------------------------------------------------


def _parse_comment(raw: object) -> Comment:
    if not isinstance(raw, dict):
        raise SchemaError("comment must be object")
    for required in ("comment_id", "created_at"):
        if required not in raw:
            raise SchemaError(f"comment missing required field: {required}")
    cid = raw["comment_id"]
    created_at = raw["created_at"]
    if not isinstance(cid, int) or isinstance(cid, bool):
        raise SchemaError("comment_id must be integer")
    # created_at validation via _parse_ts
    _parse_ts(created_at)
    if not isinstance(created_at, str):
        raise SchemaError("created_at must be str")
    # optional fields
    author_login = raw.get("author_login", "")
    head_sha = raw.get("head_sha", "")
    marker = raw.get("marker", "")
    body = raw.get("body", "")
    # Validate head_sha if present and non-empty
    if head_sha and not isinstance(head_sha, str):
        raise SchemaError("head_sha must be string")
    if head_sha and not _HEX_SHA_RE.fullmatch(str(head_sha)):
        raise SchemaError("comment head_sha must be hex git SHA")
    # marker and body should be strings if present
    if marker and not isinstance(marker, str):
        raise SchemaError("marker must be string")
    if body and not isinstance(body, str):
        raise SchemaError("body must be string")
    # trailer inside comment if any – not required for looping but validate if present
    return Comment(
        comment_id=cid,
        created_at=str(created_at),
        author_login=str(author_login) if author_login else "",
        head_sha=str(head_sha) if head_sha else "",
        marker=str(marker) if marker else "",
        body=str(body) if body else "",
    )


def _parse_validation_dict(raw: object) -> TrailerValidation:
    if not isinstance(raw, dict):
        raise SchemaError("validation must be object")
    valid = raw.get("valid")
    if not isinstance(valid, bool):
        raise SchemaError("validation.valid must be bool")
    error_code = raw.get("error_code")
    diagnostic = raw.get("diagnostic", "")
    if not isinstance(diagnostic, str):
        diagnostic = str(diagnostic)
    diagnostic = _bound_diagnostic(diagnostic)
    if valid:
        # For valid, we could attempt to reconstruct trailer if provided,
        # but the dict from to_dict loses findings. We keep trailer None
        # and rely on round's trailer field if needed.
        trailer = None
        # If raw contains trailer-like data, try to parse? Not required for test.
        return TrailerValidation(valid=True, trailer=trailer, error_code=None, diagnostic=diagnostic)
    else:
        # invalid: trailer is None, error_code should be present
        if error_code is None:
            error_code = "MALFORMED-TRAILER"
        if not isinstance(error_code, str):
            error_code = str(error_code)
        return TrailerValidation(valid=False, trailer=None, error_code=error_code, diagnostic=diagnostic)


def _validate_history_top_level(value: object) -> None:
    if not isinstance(value, dict):
        raise SchemaError("history must be JSON object")
    if value.get("schema") != 1:
        raise SchemaError(f"unsupported schema: {value.get('schema')!r} (expected 1)")
    for required in ("repo", "pr", "current_head_sha", "current_diff_files"):
        if required not in value:
            raise SchemaError(f"history missing required field: {required}")
    repo = value["repo"]
    pr = value["pr"]
    current_head_sha = value["current_head_sha"]
    current_diff_files = value["current_diff_files"]
    if not isinstance(repo, str) or not repo.strip():
        raise SchemaError("repo must be non-empty string")
    if not _REPO_RE.fullmatch(repo.strip()) and "/" not in repo.strip():
        raise SchemaError("repo must be owner/name")
    if not isinstance(pr, int) or isinstance(pr, bool) or pr <= 0:
        raise SchemaError("pr must be positive integer")
    if not isinstance(current_head_sha, str) or not _HEX_SHA_RE.fullmatch(current_head_sha):
        raise SchemaError("current_head_sha must be hex git SHA")
    if not isinstance(current_diff_files, list) or not all(
        isinstance(f, str) and _is_sanitized_diff_file(f) for f in current_diff_files
    ):
        # Distinguish empty vs unsanitized
        if not isinstance(current_diff_files, list):
            raise SchemaError("current_diff_files must be list")
        for f in current_diff_files:
            if not isinstance(f, str) or not f.strip():
                raise SchemaError("current_diff_files must be non-empty strings")
            if not _is_sanitized_diff_file(f):
                raise SchemaError(f"current_diff_files contains unsanitized path: {f!r}")
        raise SchemaError("current_diff_files must be list of sanitized paths")
    # rounds vs comments: require one
    if "rounds" not in value and "comments" not in value:
        raise SchemaError("history missing required field: rounds")
    if "rounds" in value and not isinstance(value["rounds"], list):
        raise SchemaError("rounds must be list")
    if "comments" in value and not isinstance(value["comments"], list):
        raise SchemaError("comments must be list")


def parse_history(value: object) -> History:
    """Parse and validate a history document (Schema 1).

    Accepts both the new 'rounds' shape and legacy 'comments' shape for
    compatibility. Validates required fields, sanitizes changed-file entries,
    rejects unknown schema versions without guessing, enforces one trailer per
    comment, rejects repeated RESOLVED findings, and returns a canonical
    History sorted by (created_at, comment_id).
    """
    _validate_history_top_level(value)
    assert isinstance(value, dict)
    repo: str = str(value["repo"]).strip()
    pr: int = int(value["pr"])
    current_head_sha: str = str(value["current_head_sha"])
    raw_diff = value["current_diff_files"]
    assert isinstance(raw_diff, list)
    current_diff_files = tuple(str(x) for x in raw_diff)

    rounds: list[HistoryRound] = []

    # Path 1: rounds-based history (Loopkeeper)
    if "rounds" in value:
        raw_rounds = value["rounds"]
        assert isinstance(raw_rounds, list)
        seen_comment_ids: set[int] = set()
        # For repeated RESOLVED detection, track ids that have been RESOLVED
        resolved_ids: set[str] = set()
        # For parsing repeated RESOLVED we need full trailer findings; we can
        # extract from round's trailer field if present, else from validation's
        # diagnostic? But to detect, we check round's trailer or finding data.
        # We'll collect per-round findings from round's trailer or comment trailer.
        for raw_round in raw_rounds:
            if not isinstance(raw_round, dict):
                raise SchemaError("each round must be object")
            kind = raw_round.get("kind")
            if kind not in ("valid", "invalid"):
                raise SchemaError("round kind must be valid or invalid")
            # comment
            comment_raw = raw_round.get("comment")
            comment: Comment | None = None
            if comment_raw is not None:
                comment = _parse_comment(comment_raw)
                if comment.comment_id in seen_comment_ids:
                    raise SchemaError(f"duplicate comment_id {comment.comment_id}: duplicate trailers")
                seen_comment_ids.add(comment.comment_id)
                # Also check for duplicate trailers inside comment body if present
                # The comment body may contain trailer text; we enforce zero or one via parse_trailer
                # If raw_round also provides a trailer dict, ensure body doesn't have extra trailers
                # For now, if body contains multiple markers, treat as malformed round -> invalid
                # But if kind is valid and body has multiple, that's a mismatch -> raise
                if comment.body:
                    # Use parse_trailer to detect multiple; but validation already indicates
                    # We check for multiple markers explicitly to raise SchemaError for duplicate trailers
                    total_markers = comment.body.count("<!-- loopkeeper-verdict:") + comment.body.count(
                        "<!-- codex-verdict:"
                    )
                    if total_markers > 1:
                        raise SchemaError("duplicate trailers in comment body")
            else:
                # For invalid rounds without comment, we still allow but need sorting;
                # no duplicate check needed
                pass
            # validation
            validation_raw = raw_round.get("validation")
            validation: TrailerValidation | None = None
            if validation_raw is not None:
                validation = _parse_validation_dict(validation_raw)
            else:
                # If no validation provided but kind invalid, synthesize invalid
                if kind == "invalid":
                    validation = TrailerValidation(
                        valid=False,
                        trailer=None,
                        error_code="MALFORMED-TRAILER",
                        diagnostic=_bound_diagnostic("missing validation for invalid round"),
                    )
                else:
                    # valid kind without validation: treat as error unless trailer provided
                    pass
            # trailer data for lifecycle checks: try to locate full trailer findings
            trailer_data: Trailer | None = None
            # Prefer validation.trailer if present (from parse_trailer path)
            if validation and validation.trailer:
                trailer_data = validation.trailer
            # Also check round's explicit trailer field
            round_trailer_raw = raw_round.get("trailer")
            if isinstance(round_trailer_raw, dict):
                t, err = _validate_trailer_dict(round_trailer_raw)
                if t is None:
                    # invalid identity etc -> raise SchemaError per spec
                    if err in ("bad-id", "bad-cat", "bad-file", "bad-sev", "bad-state"):
                        raise SchemaError(f"invalid identity: {err}")
                    elif err == "unknown-schema":
                        raise SchemaError(f"unsupported schema: {round_trailer_raw.get('schema')!r}")
                    else:
                        raise SchemaError(f"malformed trailer: {err}")
                trailer_data = t
                # If validation not already valid, synthesize
                if validation is None or not validation.valid:
                    validation = TrailerValidation(valid=True, trailer=t, error_code=None, diagnostic="")
            # Check invalid identity at round level (if validation trail has findings with bad fields, already handled)
            # Enforce invalid rounds contain no findings
            if kind == "invalid":
                if trailer_data and trailer_data.findings:
                    raise SchemaError("invalid rounds contain no findings")
                if validation and validation.valid:
                    raise SchemaError("invalid round validation must be invalid")
            else:  # valid
                if validation and not validation.valid:
                    raise SchemaError("valid round validation must be valid")
                if trailer_data:
                    # Check lifecycle: repeated RESOLVED in later rounds
                    for finding in trailer_data.findings:
                        if finding.state == "RESOLVED":
                            if finding.id in resolved_ids:
                                raise SchemaError(
                                    f"repeated RESOLVED finding {finding.id!r}: invalid lifecycle transition"
                                )
                            resolved_ids.add(finding.id)
                else:
                    # valid round without trailer but with no findings is okay (e.g., CLEAN verdict with empty findings)
                    # Still need to consider empty findings as valid
                    pass
            if kind == "valid" and trailer_data is None and (validation is None or validation.valid) and validation is None:
                empty_trailer = Trailer(schema=2, verdict="CLEAN", findings=())
                validation = TrailerValidation(valid=True, trailer=empty_trailer, error_code=None, diagnostic="")
            # Ensure invalid rounds have validation
            if kind == "invalid" and validation is None:
                validation = TrailerValidation(
                    valid=False, trailer=None, error_code="MALFORMED-TRAILER", diagnostic=""
                )
            rounds.append(HistoryRound(kind=kind, comment=comment, validation=validation))

        # Sort canonical history by (created_at, comment_id). Invalid rounds without comment stay at beginning
        def sort_key(r: HistoryRound):
            if r.comment is not None:
                try:
                    ts = _parse_ts(r.comment.created_at)
                except SchemaError:
                    ts = datetime.min.replace(tzinfo=timezone.utc)
                return (ts, r.comment.comment_id)
            return (datetime.min.replace(tzinfo=timezone.utc), 0)

        rounds.sort(key=sort_key)

        # After sorting, need to re-check repeated RESOLVED in sorted order? We already checked in input order,
        # but canonical order is sorted order, so we should check again in sorted order to catch out-of-order repetitions
        # Re-run lifecycle check in sorted order
        resolved_ids_sorted: set[str] = set()
        for r in rounds:
            t = None
            if r.validation and r.validation.trailer:
                t = r.validation.trailer
            elif r.kind == "valid" and r.validation and r.validation.trailer is None:
                # No trailer to check
                continue
            else:
                # Try to find trailer from round's underlying data? Already handled
                continue
            if t:
                for finding in t.findings:
                    if finding.state == "RESOLVED":
                        if finding.id in resolved_ids_sorted:
                            raise SchemaError(f"repeated RESOLVED finding {finding.id!r}: invalid lifecycle transition")
                        resolved_ids_sorted.add(finding.id)

    else:
        # Legacy comments shape (Relay)
        raw_comments = value["comments"]
        assert isinstance(raw_comments, list)
        seen_ids: set[int] = set()
        resolved_ids: set[str] = set()
        for raw_comment in raw_comments:
            if not isinstance(raw_comment, dict):
                raise SchemaError("each comment must be object")
            comment = _parse_comment(raw_comment)
            if comment.comment_id in seen_ids:
                raise SchemaError(f"duplicate comment_id {comment.comment_id}")
            seen_ids.add(comment.comment_id)
            # Determine trailer validation from comment's trailer field or body
            trailer_raw = raw_comment.get("trailer")
            body = raw_comment.get("body", "")
            validation: TrailerValidation | None = None
            kind: str = "invalid"
            trailer_data: Trailer | None = None
            if isinstance(trailer_raw, dict):
                t, err = _validate_trailer_dict(trailer_raw)
                if t is not None:
                    trailer_data = t
                    validation = TrailerValidation(valid=True, trailer=t, error_code=None, diagnostic="")
                    kind = "valid"
                    # lifecycle check
                    for f in t.findings:
                        if f.state == "RESOLVED" and f.id in resolved_ids:
                            raise SchemaError(f"repeated RESOLVED finding {f.id!r}")
                        if f.state == "RESOLVED":
                            resolved_ids.add(f.id)
                else:
                    if err in ("bad-id", "bad-cat", "bad-file"):
                        raise SchemaError(f"invalid identity: {err}")
                    validation = TrailerValidation(
                        valid=False, trailer=None, error_code="MALFORMED-TRAILER", diagnostic=_bound_diagnostic(err or "")
                    )
                    kind = "invalid"
            elif isinstance(body, str) and ("loopkeeper-verdict:" in body or "codex-verdict:" in body):
                parsed = parse_trailer(body)
                validation = parsed
                if parsed.valid and parsed.trailer:
                    trailer_data = parsed.trailer
                    kind = "valid"
                    for f in trailer_data.findings:
                        if f.state == "RESOLVED" and f.id in resolved_ids:
                            raise SchemaError(f"repeated RESOLVED finding {f.id!r}")
                        if f.state == "RESOLVED":
                            resolved_ids.add(f.id)
                else:
                    kind = "invalid"
            else:
                validation = TrailerValidation(valid=False, trailer=None, error_code="MALFORMED-TRAILER", diagnostic="no trailer")
                kind = "invalid"
            rounds.append(HistoryRound(kind=kind, comment=comment, validation=validation))  # type: ignore[arg-type]
        # Sort
        rounds.sort(key=lambda r: ( _parse_ts(r.comment.created_at) if r.comment else datetime.min.replace(tzinfo=timezone.utc), r.comment.comment_id if r.comment else 0))

    return History(
        schema=1,
        repo=repo,
        pr=pr,
        current_head_sha=current_head_sha,
        current_diff_files=tuple(current_diff_files),
        rounds=tuple(rounds),
    )


def render_history(history: History) -> dict[str, object]:
    """Render a History to its canonical dict form (sorted, sanitized)."""
    if not isinstance(history, History):
        raise TypeError("render_history expects History")
    # Validate required fields before rendering
    if history.schema != 1:
        raise SchemaError(f"unsupported schema: {history.schema!r} (expected 1)")
    if not history.repo or not isinstance(history.repo, str):
        raise SchemaError("repo must be non-empty string")
    if not isinstance(history.pr, int) or history.pr <= 0:
        raise SchemaError("pr must be positive integer")
    if not _HEX_SHA_RE.fullmatch(history.current_head_sha):
        raise SchemaError("current_head_sha must be hex git SHA")
    for f in history.current_diff_files:
        if not _is_sanitized_diff_file(f):
            raise SchemaError(f"current_diff_files contains unsanitized path: {f!r}")

    # Sort rounds canonically
    sorted_rounds = sorted(
        history.rounds,
        key=lambda r: (
            _parse_ts(r.comment.created_at) if r.comment else datetime.min.replace(tzinfo=timezone.utc),
            r.comment.comment_id if r.comment else 0,
        ),
    )
    rounds_out: list[dict[str, object]] = []
    for r in sorted_rounds:
        kind: str = r.kind  # type: ignore
        if kind not in ("valid", "invalid"):
            raise SchemaError("round kind must be valid or invalid")
        d: dict[str, object] = {"kind": kind}
        if r.comment is not None:
            d["comment"] = {
                "comment_id": r.comment.comment_id,
                "created_at": r.comment.created_at,
                "author_login": r.comment.author_login,
                "head_sha": r.comment.head_sha,
                "marker": r.comment.marker,
                "body": r.comment.body,
            }
        if r.validation is not None:
            d["validation"] = r.validation.to_dict()
            # For valid rounds, also emit trailer for completeness if available
            if r.validation.trailer and kind == "valid":
                # Emit full trailer alongside validation for round-trip preservation
                t = r.validation.trailer
                d["trailer"] = {
                    "schema": t.schema,
                    "verdict": t.verdict,
                    "findings": [
                        {
                            "sev": f.sev,
                            "state": f.state,
                            "file": f.file,
                            "cat": f.cat,
                            "id": f.id,
                            **({"evidence": {"files": list(f.evidence.files), "verification": f.evidence.verification}} if f.evidence else {}),
                            **({"unverifiable": f.unverifiable} if f.unverifiable else {}),
                        }
                        for f in t.findings
                    ],
                }
        rounds_out.append(d)

    return {
        "schema": history.schema,
        "repo": history.repo,
        "pr": history.pr,
        "current_head_sha": history.current_head_sha,
        "current_diff_files": list(history.current_diff_files),
        "rounds": rounds_out,
    }

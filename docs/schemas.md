# Loop schemas

This is the normative reference for the two JSON shapes the review loop
passes between its components. The reviewer prompt (structured trailer
output) and the arbiter (collector output, and the trailer it parses) both
cite this document rather than restating the shapes; if the two ever drift,
**this file is the tiebreaker**.

> **Marker is not a trust signal.** `loopkeeper-verdict` and the legacy
> `codex-verdict` markers are configuration, not security boundaries. A PR
> cannot claim a round by forging a marker; the arbiter counts rounds and
> derives identity independently. The marker exists only to locate the
> machine-readable trailer within a comment body.

> **Codex-verdict is input-only compatibility.** The parser accepts both
> `loopkeeper-verdict` and `codex-verdict` on ingest so a migrating Relay
> installation can be read, but new output always uses `loopkeeper-verdict`
> via `render_trailer`. Do not emit `codex-verdict` from new code.

There are two schemas:

- **Schema 2 — the trailer.** Emitted by the reviewer at the end of each
  review comment. Carries the findings for that round.
- **Schema 1 — canonical history.** Emitted by the arbiter's collector.
  Carries the full, validated comment history for a PR, including every
  parsed trailer.

Both are versioned by an explicit `schema` field so a consumer can refuse
input it does not understand rather than guess.

## Schema 2: the trailer

The machine-readable trailer carries structured fields, not just a slug:

```json
<!-- loopkeeper-verdict: {"schema":2,"verdict":"BLOCK","findings":[
  {"sev":"P1","state":"OPEN","file":"app/models.py","cat":"authorization",
   "id":"published-self-assert"},
  {"sev":"P2","state":"NEW","file":"alembic/versions/20260816_ssi_verified_by.py",
   "cat":"tz-consistency","id":"utc-preflight"},
  {"sev":"P2","state":"RESOLVED","file":"scripts/codex_sanitize.py",
   "cat":"redaction","id":"cookie-header",
   "evidence":{"files":["scripts/codex_sanitize.py"],
              "verification":"tests/test_codex_sanitize.py::test_cookie_header"}}]} -->
```

**Compatibility:** `<!-- codex-verdict: ... -->` is accepted on input and
treated identically, but never emitted. `P0` is accepted on ingest and
normalized to the internal `P1` tier at parse time, so the highest blocking
tier covers prompt-injection findings without introducing a fourth severity
into the arbiter.

When a finding cannot be verified from the supplied artifacts, it remains
`NEW` or `OPEN` and names the absent artifact with the backward-compatible
optional `unverifiable` object:

```json
{"sev":"P2","state":"OPEN","file":"app/a.py","cat":"verification",
 "id":"missing-proof",
 "unverifiable":{"missing":"exact-head check result was not available at review time"}}
```

The `missing` value must be a non-empty, single-line, bounded string
(max 512 characters, no control characters). Do not use `unverifiable` for
uncertainty that the supplied artifacts can resolve, never pair it with
`RESOLVED`, and continue accounting for the finding in every round until
resolution or arbiter termination. The schema remains version 2.

`schema` is versioned so the arbiter can refuse trailers it does not
understand. Note what is *not* here: no `rounds` count. The reviewer marks
identity and lifecycle; the arbiter counts, verifies the accounting, and
derives identity — `id` is a proposal, `file`+`cat` are what the arbiter
checks it against. `RESOLVED` always carries an evidence object. The arbiter
checks that every evidence file is changed in the current head and that the
verification reference is non-empty. This is a bounded consistency check,
not semantic proof: a P1 resolution therefore becomes `pending-human` and
can never produce `MERGE-CLEAN` by itself. A maintainer decides whether the
cited evidence actually closes a P1 while reviewing the same head.

Trailer parsing enforces:

- Zero or one trailer per comment; more than one is `MALFORMED-TRAILER`.
- The trailer must close the comment (nothing but whitespace after `-->`).
- `P0` is folded to `P1` at the parser boundary.
- `RESOLVED` requires bounded evidence (`files` non-empty, `verification` non-empty).
- Diagnostic text is bounded to 512 characters (`TrailerValidation.to_dict()` truncates).
- Invalid trailers are retained as invalid rounds for hard-cap accounting; they never satisfy finding accounting.

### Finding lifecycle states

Every finding the reviewer has previously raised on a PR and not yet resolved
must appear in the new trailer with a lifecycle state — a full accounting of
what is still open. Silence is not resolution: an unresolved finding the model
simply stops mentioning must never read as fixed.

```
NEW        first appearance
OPEN       previously raised, still present (with one line on whether the
           last fix attempt changed anything)
RESOLVED   previously raised, verified fixed in this diff (with the evidence);
           emitted in that round only, then never repeated
```

A resolution is terminal and is emitted exactly once. Re-listing a
`RESOLVED` finding in a later trailer matches nothing open and fails closed
as `ORPHAN-STATE` (or at the schema boundary as `repeated RESOLVED`: invalid
lifecycle transition), which makes the disposition `needs-human`. History
validation rejects repeated `RESOLVED` findings in later rounds. The reviewer
prompt states this in the same terms; the trailer and the comment body agree,
so a closed finding disappears from both at once and the comment does not grow
round over round.

Closed is not untouchable. When a resolution turns out to be mistaken, or a
later commit regresses the fix, the reviewer raises the defect again as `NEW`
under a fresh `id`. That is accepted: the key left the open-set at resolution,
so this is neither `ORPHAN-STATE` nor the `AMBIGUOUS-IDENTITY` rename, which is
refused only while the original is still open. Silence about a live defect is
never the cheaper comment.

## Schema 1: canonical history

The collector emits a versioned JSON document. The core accepts only this
shape, so the network-facing collector and the pure decision function cannot
silently drift:

```json
{
  "schema": 1,
  "repo": "owner/name",
  "pr": 24,
  "current_head_sha": "40-hex-head-sha",
  "current_diff_files": ["app/models.py"],
  "rounds": [
    {
      "kind": "valid",
      "comment": {
        "comment_id": 12345,
        "created_at": "2026-08-17T09:00:00Z",
        "author_login": "github-actions[bot]",
        "head_sha": "40-hex-head-sha",
        "marker": "loopkeeper-pr-review:24:40-hex-head-sha",
        "body": "sanitized comment body"
      },
      "validation": {"valid": true, "schema": 2, "error_code": null, "diagnostic": ""},
      "trailer": {"schema": 2, "verdict": "BLOCK", "findings": []}
    },
    {
      "kind": "invalid",
      "comment": {
        "comment_id": 12346,
        "created_at": "2026-08-17T09:01:00Z",
        "author_login": "github-actions[bot]",
        "head_sha": "40-hex-head-sha",
        "marker": "loopkeeper-pr-review:24:40-hex-head-sha",
        "body": "model text without a trailer"
      },
      "validation": {"valid": false, "schema": null, "error_code": "MALFORMED-TRAILER", "diagnostic": "no trailer found"}
    }
  ]
}
```

The collector requires a valid PR number, repository (`owner/name`), head
SHA (7-64 hex), marker, RFC-3339 timestamp, sanitized changed-file entries,
and zero or one trailer per canonical comment; zero is retained as an
invalid round and more than one is malformed. It sorts by `created_at`,
then `comment_id` as a stable tie-breaker. Two bot comments for the same
PR head SHA are an ambiguous history and make the whole disposition
`needs-human`; the collector never silently chooses one. A comment with no
valid trailer remains in history as an invalid round, counts toward the hard
cap, and prevents merge recommendations until a later valid round is
available. `current_diff_files` is the sanitized path set used for the
bounded `RESOLVED` evidence check above; it is not treated as proof of
semantic correctness.

**History invariants enforced by `parse_history`:**

- Unknown schema versions raise `SchemaError` with `unsupported schema` and are never guessed.
- `repo`, `pr`, `current_head_sha`, and `current_diff_files` are required and sanitized; unsanitized paths raise `SchemaError`.
- Rounds are sorted canonically by `(created_at, comment_id)`.
- Duplicate `comment_id` values raise `SchemaError` (duplicate trailers).
- Invalid identity (`bad-file`, `bad-cat`, `bad-id`) raises `SchemaError`.
- Repeated `RESOLVED` findings in later rounds raise `SchemaError` (invalid lifecycle transition).
- Invalid rounds contain no findings and their `validation.valid` is false; they count toward hard-cap accounting.

JSON Schemas for both shapes live under `src/loopkeeper/resources/schemas/`
and have `additionalProperties: false` on every trusted control-plane record
so they are machine-checkable.

## Tiebreaker and compatibility notes

- If prompts and validators drift, `docs/schemas.md` (this file) is authoritative.
- The marker string (`loopkeeper-verdict` vs `codex-verdict`) is never a trust boundary; trust is enforced by the collector/arbiter, not by marker presence.
- `codex-verdict` is accepted only on input for Relay migration; new code must not emit it.
- Diagnostic strings in `TrailerValidation` are bounded to 512 characters; longer values are truncated via `to_dict()` so persisted artifacts remain bounded.


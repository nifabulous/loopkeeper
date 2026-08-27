# Source ledger — Relay `e834773` → Loopkeeper

This ledger records the 30 extraction-scope files from Relay at `e834773`,
their line counts, the destination in this repository, and the retained
behavior. The consumer CI workflow is **intentionally not ported**; it
remains outside the extraction and is used only as a fixture for
workflow-name/file resolution and trigger sequencing tests.

| Relay source at `e834773` | Lines | Destination | Responsibility after extraction |
|---|---:|---|---|
| `scripts/codex_arbiter.py` | 1446 | `src/loopkeeper/arbiter.py`; `adapters/github/arbiter_io.py` | Pure decisions in the package; GitHub collection/posting in the adapter |
| `scripts/codex_review_pr.sh` | 734 | `adapters/github/review_pr.sh` | GitHub event selection, trusted reads, collection, model invocation, and reviewer comment upsert |
| `scripts/codex_responses.py` | 488 | `src/loopkeeper/transport.py` | Responses/Chat HTTP transport and budget enforcement |
| `scripts/codex_sanitize.py` | 244 | `src/loopkeeper/redaction.py`; `adapters/relay/redactor.py` | Generic redaction core and Relay-specific compatibility hook |
| `scripts/agent_runner.py` | 233 | `src/loopkeeper/agent.py` | Trusted definition loading and headless agent execution |
| `scripts/codex_triage_issue.sh` | 154 | `adapters/github/triage_issue.sh` | GitHub issue selection, sanitization, model call, and triage comment upsert |
| `scripts/codex_untrusted.py` | 61 | `src/loopkeeper/untrusted.py` | Delimiter defanging and labelled untrusted blocks |
| `scripts/codex_truncate.py` | 60 | `src/loopkeeper/truncate.py` | UTF-8-safe byte ceilings |
| `tests/test_codex_arbiter.py` | 2272 | `tests/unit/test_arbiter.py` | Full pure-rule and lifecycle coverage |
| `tests/test_codex_automation.sh` | 2073 | `tests/github/test_automation.sh` | Stubbed `gh`/`git` integration and mutation guards |
| `tests/test_codex_responses.py` | 650 | `tests/unit/test_transport.py` | Wire shapes, limits, timeouts, and endpoint validation |
| `tests/test_codex_sanitize.py` | 319 | `tests/unit/test_redaction.py` | Secret, identifier, plugin, and placeholder corpus |
| `tests/test_model_pinning.py` | 253 | `tests/unit/test_model_binding.py` | Settings-based model binding and unsupported model-shape rejection |
| `tests/test_agent_runner.py` | 236 | `tests/unit/test_agent.py` | Definition parsing, model precedence, channel separation, and refusal |
| `tests/test_arbiter_roundtrip.py` | 96 | `tests/unit/test_roundtrip.py` | Collector-to-core history round trip |
| `tests/test_codex_untrusted.py` | 74 | `tests/unit/test_untrusted.py` | Delimiter and label safety |
| `tests/test_codex_truncate.py` | 63 | `tests/unit/test_truncate.py` | Multibyte truncation and marker bounds |
| `tests/fixtures/arbiter/live_reviewer_capture.md` | 20 | `tests/fixtures/relay-e834773/live_reviewer_capture.md` | Frozen live reviewer capture |
| `tests/fixtures/arbiter/pr21_history.json` | 125 | `tests/fixtures/relay-e834773/pr21_history.json` | Frozen Schema-1 history |
| `tests/fixtures/arbiter/pr22_history.json` | 79 | `tests/fixtures/relay-e834773/pr22_history.json` | Frozen Schema-1 history |
| `tests/fixtures/arbiter/pr24_history.json` | 105 | `tests/fixtures/relay-e834773/pr24_history.json` | Frozen Schema-1 history |
| `.github/workflows/codex-pr-review.yml` | 270 | `.github/workflows/pr-review.yml` | Pinned reusable PR-review entrypoint; no direct consumer triggers |
| `.github/workflows/codex-issue-triage.yml` | 126 | `.github/workflows/issue-triage.yml` | Pinned reusable issue-triage entrypoint; no direct consumer triggers |
| `docs/loop/schemas.md` | 129 | `docs/schemas.md`; `src/loopkeeper/resources/schemas/*.schema.json` | Normative Schema-1/Schema-2 and invalid-round contract |
| `.github/codex/review-policy.md` | 114 | `examples/relay/review-policy.md` | Relay fixture policy, never the package default policy |
| `docs/CODEX_GITHUB_AUTOMATION.md` | 104 | `docs/github-adapter.md` | GitHub adapter operations, trust, permissions, and writes |
| `docs/contracts/README.md` | 94 | `docs/contracts/README.md` | Contract derivation and trusted-default-branch rules |
| `docs/loop/model-binding.md` | 72 | `docs/model-binding.md` | Public model/environment binding contract |
| `.github/codex/context-files.txt` | 2 | `examples/relay/context-files.txt` | Relay fixture context allowlist |
| `docs/contracts/feat-loop-arbiter-564bdc00f842.md` | 105 | `examples/relay/contracts/feat-loop-arbiter-564bdc00f842.md` | Frozen contract-format fixture |

These 30 rows sum to 10801 source lines at `e834773`.

**Exclusion:** The Relay consumer workflow `.github/workflows/ci.yml` (with `name: CI` and path `ci.yml`) is explicitly excluded from the extraction. It is not copied into the Loopkeeper package; it remains consumer-owned and is used only as a test fixture to prove that GitHub trigger names are resolved to workflow IDs before the discovery probe queries a file/path. No `ci.yml` from the consumer is bundled into the reusable project.

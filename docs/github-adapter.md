# GitHub adapter

The GitHub adapter is the only place in Loopkeeper that can claim
`github-forge-verified`. It verifies the default-branch checkout against the
forge API, reads policy/contract/context with `git show "$TRUSTED_SHA:$path"`,
and passes PR content only through the untrusted channel.

## Trust roots

- `consumer_trusted_sha` is resolved from the forge's default-branch ref
  (`GET repos/{owner}/{repo}/git/ref/heads/{default_branch}`) and compared with
  the checkout (`git rev-parse HEAD`) before any trusted file is read. If the
  default branch moves between resolution and checkout, the run fails closed and
  the next trigger retries.
- `loopkeeper_sha` is declared twice in each protected caller:
  once in the `uses:` pin and once as a `workflow_call` input. A static caller
  test requires those literals to match, while the called workflow verifies its
  Loopkeeper checkout SHA before invoking scripts. Release-time provenance is
  generated and retained as a separate build artifact; a self-referential
  manifest from the checkout is not treated as a trust anchor. The called
  workflow must not accept a branch, tag, or mutable ref as a substitute for
  either SHA.
- The adapter records both verified roots in the artifact provenance.

## Bounded reads and retry

- Read-only GitHub API calls may retry bounded 5xx/429 responses with a
  deadline-aware backoff, but a failed or truncated read is never interpreted
  as “no CI run” or “no comments.” The fallback path records unavailable
  evidence; write calls are handled only by the idempotent writer state machine.
- Every `gh` query is bounded (`per_page=100&page={page}` capped at `max_pages`);
  no unbounded `--paginate` is used. Pull-request file pages use a smaller
  configurable page size and each patch is byte-capped before the aggregate
  input bound is applied, preserving file coverage for large asset/data PRs.
  When the configured file-page cap is reached, the diff carries
  `files_truncated: true` so the model must disclose incomplete evidence rather
  than claiming an exhaustive review. Malformed or truncated comment evidence
  disables suppression and takes the fail-closed fallback path.
- `GH_REPO` is validated as `owner/name` before interpolation, and every API
  path and `git show` argument is quoted. Metacharacter/branch/path inputs are
  tested against the stub harness.

## Comment upsert state machine

- Same-head fallback plus new fallback suppresses (`SUPPRESS_FALLBACK`).
- Same-head fallback plus CI evidence updates the existing comment in place and
  changes the adapter-generated evidence state to `ci` (`REPLACE_FALLBACK`).
- Same-head CI plus any duplicate suppresses (`SUPPRESS_DUPLICATE`).
- No existing state performs a create (`CREATE`).
- Duplicate current-head comments already exist → keep the oldest qualifying
  bot-authored comment as canonical and rewrite every other qualifying marker
  to a bounded `loopkeeper-superseded:{pr}:{head_sha}:{comment_id}` marker in
  the same operator-gated transaction; never silently delete review history.
- The adapter-generated marker (`<!-- loopkeeper-pr-review:{pr}:{head_sha} -->`)
  and evidence state (`<!-- loopkeeper-evidence:{fallback|ci} -->`) are appended
  outside the model body, so model text cannot forge or change the state.
  The rendered body is sanitized and bounded, including the marker/footer
  reservation. Marker-like text in model output is escaped and cannot satisfy
  suppression.

## Writer serialization

- Run a dedicated PR-scoped writer job with `cancel-in-progress: false`,
  re-read the PR head and comments immediately before the write, and retry
  only the reconciliation read when the head moved. Collection/model jobs may
  cancel stale work, but the writer cannot be canceled after it owns the group.
- `LOOPKEEPER_OPERATOR=1` is required inside every write function.
- `LOOPKEEPER_GAP_LABEL` must resolve to an existing label before
  `--gap-issues`; otherwise emit `GAP_LABEL_UNAVAILABLE` and perform no write.

## Permissions

- Workflows require `contents: read`, `actions: read`, `checks: read`,
  `issues: write`, `pull-requests: write` and no more.
- No artifact or cache downloads of PR code are performed; all PR content is
  read via the GitHub API and passed through the untrusted channel.

## Interfaces

- `collect_history(repo: str, pr: int, trusted_sha: str, bot_login: str) -> History`
- `CommentWriter` protocol with bounded `read_head`, `read_comments`, `create`, `update`
- `upsert_review_comment(repo: str, pr: int, head_sha: str, evidence_state: Literal["fallback","ci"], body: str, writer: CommentWriter) -> None`
- `post_arbiter_comment(repo: str, pr: int, decision: Decision, operator: bool) -> None`
- `resolve_consumer_trusted_sha(repo: str, default_branch: str, api: GitHubApi) -> str`
- `verify_loopkeeper_checkout(root: Path, expected_sha: str, release_manifest: Path) -> None`
- `resolve_workflow_target(repo: str, display_name: str, expected_file: str, api: GitHubApi, max_pages: int=10) -> WorkflowTarget`
- `select_workflow_run_target(event: str, source_event: str, run_head_sha: str, current_pr_head_sha: str, pr_state: str, target_pr: int, run_pull_request_numbers: Sequence[int]) -> Reviewability`
- `decide_comment_action(existing: Sequence[CommentState], evidence_state: Literal["fallback","ci"], head_sha: str) -> CommentAction`
- `render_comment(model_markdown: str, marker: str, evidence_state: Literal["fallback","ci"], max_bytes: int) -> str`
- `verify_gap_label(repo: str, label: str, api: GitHubApi) -> None`

All API paths and git show arguments are quoted; `GH_REPO` is validated as
`owner/name`; pagination is bounded, not unbounded `--paginate`.

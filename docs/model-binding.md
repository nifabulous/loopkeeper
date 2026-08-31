# Model binding — where every slot's model comes from

Loopkeeper keeps every model slot swappable with a settings change, never a refactor. This is the binding table that promise resolves to: for each slot, where the default lives, what overrides it, and what keeps the binding honest.

No slot names a versioned model id anywhere a test can't see one (`tests/unit/test_model_binding.py` bans version-pinned ids outright, and hardcoded vendor ids outside a `|| '<fallback>'` shape).

## Automation slots (run in CI)

| Slot | Default | Binding point | Notes |
|---|---|---|---|
| PR reviewer | `gpt-5.6-luna` | `LOOPKEEPER_MODEL` (fallback) | Also `LOOPKEEPER_REASONING_EFFORT`, `LOOPKEEPER_API_STYLE`, `LOOPKEEPER_API_BASE_URL`, byte/token budgets, timeouts |
| Issue triage | `gpt-5.6-luna` | `LOOPKEEPER_MODEL` (fallback) | Same shape as the reviewer |

Both slots call through `src/loopkeeper/transport.py`, whose endpoint and wire format are themselves bound, not hardcoded:

| Setting | Default | Binding point |
|---|---|---|
| Wire style | `responses` | flag, else `LOOPKEEPER_API_STYLE` (`responses` \| `chat`) |
| Endpoint URL | provider per-style default | flag, else `LOOPKEEPER_API_BASE_URL`, else per-style default |

`chat` speaks the OpenAI-compatible chat completions shape most third-party providers and gateways expose, so a cross-vendor swap is: set `LOOPKEEPER_MODEL` to the provider's model id, set `LOOPKEEPER_API_STYLE=chat`, set `LOOPKEEPER_API_BASE_URL` to its chat-completions endpoint, and put its key in the `LOOPKEEPER_API_KEY` secret (used as a bearer token). Set `LOOPKEEPER_REASONING_EFFORT=none` unless the provider explicitly accepts that OpenAI extension; providers such as DeepSeek and GLM reject the `reasoning_effort` key on chat completions. The base URL must be https outside loopback — the key travels as a header — and may not carry a query or fragment. `OPENAI_API_KEY` is accepted only through the Relay adapter, never inside the provider-neutral package.

## Research agents (`.claude/agents/*.md` style)

Five definitions: `domain-researcher`, `feasibility-researcher`, `precedent-researcher`, `impact-researcher`, `verifying-executor`.

- **Flag precedence.** Explicit `--model` flag wins.
- **Per-agent env.** Derived from the filename: `domain-researcher` binds through `LOOPKEEPER_AGENT_DOMAIN_RESEARCHER_MODEL`. Normalization upper-cases and replaces hyphens with underscores.
- **Shared env.** `LOOPKEEPER_MODEL` is the fallback for all agents.

No model bound at all is a loud failure naming every source it tried — an agent silently running on whatever the process happens to have is the failure mode this chain exists to prevent. Unsupported or version-pinned shapes (e.g., `claude-opus-4-20250101`) are rejected with `ConfigError`, never coerced to a default.

## Settings precedence (one rule for all operational values)

`resolve_settings(flags, env)` applies a single precedence for every operational value:

1. Explicit CLI flag (`flags` mapping)
2. Validated `LOOPKEEPER_*` environment value (`env` mapping)
3. Built-in default

Invalid environment values fail with `ConfigError`; they are never silently coerced. Coherence is enforced after resolution:

- `max_output_bytes` must be reachable at `max_output_tokens` (`<= tokens * 4`)
- `request_timeout` must cover the token budget (`tokens * 20ms per 1k`)
- `LOOPKEEPER_API_BASE_URL` must be https outside loopback, no query/fragment
- `reasoning_effort` and `api_style` must be in their allowlists

Example:

```python
from loopkeeper.model_binding import resolve_settings

# flag wins over env
settings = resolve_settings({"max_input_bytes": 10}, {"LOOPKEEPER_MAX_INPUT_BYTES": "20"})
assert settings.max_input_bytes == 10
```

## Transport guarantees

`src/loopkeeper/transport.py` uses only stdlib `urllib` and enforces:

- Responses (`store: false`) preserves the trusted `instructions` / untrusted `input` channel split; chat preserves `system` / `user` and omits `store`.
- Response envelope is bounded via `response_body_limit` (output bytes + `tokens * 8` + 64 KiB overhead); oversized bodies are rejected before parsing.
- Output bytes are checked after extraction; `incomplete` / `length` truncation with text is marked, without text is fatal.
- Endpoint validation, bearer auth, and deadline calculation (`deadline = min(request_timeout, remaining_until_job_deadline - headroom)`).
- Never retries a completed request; when `retry_unestablished_connection=True` allows one retry only before a response is established and only if the job deadline still has room. The fake `UrlOpener` records every timeout and call count so retries and deadlines cannot hide.

## Prompt composition

`src/loopkeeper/policy.py` loads the review policy from the trusted path (`TrustedReader` bound to the verified root) and is the single source for categories, severity guidance, lifecycle rules, data handling, and display name. It rejects a path outside the trusted root, bounds each Markdown section, and preserves deterministic section order.

Categories are consumer-defined. A policy declares its own canonical slugs as Markdown bullets under exactly one `## Categories` section:

```markdown
## Categories

- functional
- security
- database-migrations
```

Between 1 and 32 entries are accepted. Each must be a canonical slug — 1-64 characters of lowercase kebab-case matching `^[a-z0-9]+(-[a-z0-9]+)*$`. That grammar is `loopkeeper.schema.is_identity_slug`, the same check applied to Schema-2 finding `cat` and `id` values, so a policy can never declare a category that the reviewer trailer would then reject.

Four headings are structural: `Categories`, `Severity`, `Lifecycle`, and `Data handling` (with the aliases `Severity guidance`, `Lifecycle rules`, and `Finding lifecycle`). **Every other `##` section is preserved verbatim**, in source order, as `Policy.extra_sections`, and is rendered into the prompt after the structural guidance. A consumer can keep `## Scope` or `## Deployment constraints` in its policy without the loader reinterpreting or discarding it.

### Migrating a pre-0.1.0 policy

Implicit category discovery is gone. Two older forms now fail with a `ConfigError` naming the fix rather than being silently reinterpreted:

- a per-category H2 heading, such as `## functional`, used to declare a category
- prose inside `## Categories`, such as `functional security` on one line

Before:

```markdown
## functional
Check behavior.

## Categories
functional security
```

After:

```markdown
## Categories

- functional
- security
```

There is no compatibility fallback. Loopkeeper 0.1.0 is publicly released, so
the previous fixed vocabulary — which accepted only one extraction source's
categories and rejected everything else, including this repository's own
`## Scope` section — was removed outright rather than carried forward.

`src/loopkeeper/prompt.py` renders the review prompt from that policy plus the active `RedactionResult`. The builder contains no product name, no domain-specific placeholder list, and no second category table — consumer wording lives in trusted Markdown, not in adapter heredoc.
Contract placement is load-bearing. The contract is rendered as the **final**
instruction section, after the policy and all trusted reference material, in
both `prompt.py` and the GitHub adapter. When it was rendered first and a long
policy followed, a model was observed ending its review with a plain-text
verdict line, which fails closed as `MALFORMED-TRAILER`. Any provider or model
swap must be re-verified against a real review, because trailer compliance is a
property of the model, not of the transport.

The shared `REVIEW_TRAILER_CONTRACT` requires one final Schema-2 JSON trailer;
the GitHub adapter uses the same contract and records bounded validation
metadata before publishing a comment.

```python
prompt = render_review_prompt(policy, redaction, artifacts)
# prompt.instructions contains active placeholders like "ACCOUNT"
# prompt.input_text contains bounded, untrusted-wrapped artifacts
```

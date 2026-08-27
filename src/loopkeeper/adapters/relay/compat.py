"""Relay compatibility adapter for Loopkeeper.

Keeps Relay legacy names only in this module. The package and new workflows emit
only Loopkeeper names. This module maps legacy CODEX_*, ARBITER_*, RELAY_AGENT_*,
and OPENAI_API_KEY, parses legacy markers, and translates exit codes.
"""

from __future__ import annotations

import re
from typing import Mapping

# ---------------------------------------------------------------------------
# Environment mapping
# ---------------------------------------------------------------------------

# Legacy -> canonical mapping
_ENV_MAP: dict[str, str] = {
    # Model / reasoning / limits
    "CODEX_MODEL": "LOOPKEEPER_MODEL",
    "CODEX_REASONING_EFFORT": "LOOPKEEPER_REASONING_EFFORT",
    "CODEX_MAX_INPUT_BYTES": "LOOPKEEPER_MAX_INPUT_BYTES",
    "CODEX_MAX_OUTPUT_TOKENS": "LOOPKEEPER_MAX_OUTPUT_TOKENS",
    "CODEX_MAX_OUTPUT_BYTES": "LOOPKEEPER_MAX_OUTPUT_BYTES",
    "CODEX_REQUEST_TIMEOUT": "LOOPKEEPER_REQUEST_TIMEOUT",
    "CODEX_JOB_TIMEOUT_SECONDS": "LOOPKEEPER_JOB_TIMEOUT_SECONDS",
    "CODEX_JOB_DEADLINE_EPOCH": "LOOPKEEPER_JOB_DEADLINE_EPOCH",
    "CODEX_BOT_LOGIN": "LOOPKEEPER_BOT_LOGIN",
    "CODEX_CI_WORKFLOW_FILE": "LOOPKEEPER_CI_WORKFLOW_FILE",
    "CODEX_CI_DISCOVERY_SECONDS": "LOOPKEEPER_CI_DISCOVERY_SECONDS",
    "CODEX_CI_DISCOVERY_POLL_SECONDS": "LOOPKEEPER_CI_DISCOVERY_POLL_SECONDS",
    "CODEX_CHECK_MAX_ITEMS": "LOOPKEEPER_CHECK_MAX_ITEMS",
    "CODEX_CHECK_MAX_BYTES": "LOOPKEEPER_CHECK_MAX_BYTES",
    "CODEX_CHECK_MAX_PAGES": "LOOPKEEPER_CHECK_MAX_PAGES",
    "CODEX_CHECK_MAX_RAW_BYTES": "LOOPKEEPER_CHECK_MAX_RAW_BYTES",
    "CODEX_CONTEXT_MAX_FILES": "LOOPKEEPER_CONTEXT_MAX_FILES",
    "CODEX_CONTEXT_MAX_BYTES": "LOOPKEEPER_CONTEXT_MAX_BYTES",
    "CODEX_REVIEW_ENABLED": "LOOPKEEPER_REVIEW_ENABLED",
    "CODEX_TRUSTED_SHA": "LOOPKEEPER_TRUSTED_SHA",
    "CODEX_DEFAULT_BRANCH": "LOOPKEEPER_DEFAULT_BRANCH",
    "CODEX_MAX_ITEMS": "LOOPKEEPER_MAX_ITEMS",
    "CODEX_EVENT_NAME": "LOOPKEEPER_EVENT_NAME",
    "CODEX_PR_ACTION": "LOOPKEEPER_PR_ACTION",
    "CODEX_EXPECTED_HEAD_SHA": "LOOPKEEPER_EXPECTED_HEAD_SHA",
    "ARBITER_SOFT_GATE": "LOOPKEEPER_ARBITER_SOFT_GATE",
    "ARBITER_HARD_CAP": "LOOPKEEPER_ARBITER_HARD_CAP",
    "ARBITER_STUCK_P1_ROUNDS": "LOOPKEEPER_ARBITER_STUCK_P1_ROUNDS",
    "ARBITER_UNVERIFIABLE_ROUNDS": "LOOPKEEPER_ARBITER_UNVERIFIABLE_ROUNDS",
    "ARBITER_OPERATOR": "LOOPKEEPER_OPERATOR",
    "ARBITER_AUTOPOST": "LOOPKEEPER_OPERATOR",
    "RELAY_AGENT_MODEL": "LOOPKEEPER_AGENT_MODEL",
    "RELAY_AGENT_DOMAIN_RESEARCHER_MODEL": "LOOPKEEPER_AGENT_DOMAIN_RESEARCHER_MODEL",
    "RELAY_AGENT_FEASIBILITY_RESEARCHER_MODEL": "LOOPKEEPER_AGENT_FEASIBILITY_RESEARCHER_MODEL",
    "RELAY_AGENT_IMPACT_RESEARCHER_MODEL": "LOOPKEEPER_AGENT_IMPACT_RESEARCHER_MODEL",
    "RELAY_AGENT_PRECEDENT_RESEARCHER_MODEL": "LOOPKEEPER_AGENT_PRECEDENT_RESEARCHER_MODEL",
    "RELAY_AGENT_VERIFYING_EXECUTOR_MODEL": "LOOPKEEPER_AGENT_VERIFYING_EXECUTOR_MODEL",
    # OPENAI_API_KEY is kept as is but also exposed as LOOPKEEPER_API_KEY for consistency
    "OPENAI_API_KEY": "LOOPKEEPER_API_KEY",
    # Gap label
    "CODEX_GAP_LABEL": "LOOPKEEPER_GAP_LABEL",
}

# Reverse map for completeness (not used for mapping, but for documentation)
_CANONICAL_TO_LEGACY = {v: k for k, v in _ENV_MAP.items()}

# For per-agent env vars, pattern LOOPKEEPER_AGENT_<NORM>_MODEL vs CODEX_AGENT etc?
_AGENT_MODEL_RE = re.compile(r"^(?:CODEX|RELAY)_AGENT_([A-Z0-9_]+)_MODEL$")
_LOOPKEEPER_AGENT_MODEL_RE = re.compile(r"^LOOPKEEPER_AGENT_([A-Z0-9_]+)_MODEL$")


def map_relay_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Map legacy Relay environment to canonical Loopkeeper environment.

    Args:
        env: Mapping of env vars (typically os.environ)

    Returns:
        New dict with LOOPKEEPER_* keys. Legacy CODEX_*/ARBITER_*/RELAY_*
        entries are translated if canonical not already present. Existing
        LOOPKEEPER_* values are never overridden by legacy.

        Also handles per-agent model vars: CODEX_AGENT_FOO_MODEL ->
        LOOPKEEPER_AGENT_FOO_MODEL (normalized).

    The package and workflows emit only Loopkeeper names; this adapter is the
    only place that understands Relay legacy names.
    """
    if not isinstance(env, Mapping):
        raise TypeError("env must be Mapping[str, str]")
    out: dict[str, str] = {}
    # First copy all LOOPKEEPER_* and LOOPKEEPER_API_KEY etc directly
    for k, v in env.items():
        if k.startswith("LOOPKEEPER_") or k == "OPENAI_API_KEY":
            # Also keep OPENAI_API_KEY as is for transport compatibility
            out[k] = v
        # Also keep LOOPKEEPER_API_KEY if present
        if k == "LOOPKEEPER_API_KEY":
            out[k] = v

    # Now translate legacy where canonical not already present
    for legacy, canonical in _ENV_MAP.items():
        if legacy in env and canonical not in out:
            out[canonical] = env[legacy]

    # Handle per-agent legacy vars that match pattern but not in explicit map
    for k, v in env.items():
        m = _AGENT_MODEL_RE.match(k)
        if m:
            norm = m.group(1)
            canonical = f"LOOPKEEPER_AGENT_{norm}_MODEL"
            if canonical not in out:
                out[canonical] = v

    # Ensure OPENAI_API_KEY is also available as LOOPKEEPER_API_KEY if only OPENAI present
    if "OPENAI_API_KEY" in env and "LOOPKEEPER_API_KEY" not in out:
        out["LOOPKEEPER_API_KEY"] = env["OPENAI_API_KEY"]
    # And vice versa? If only LOOPKEEPER_API_KEY present, expose as OPENAI for legacy transport
    if "LOOPKEEPER_API_KEY" in out and "OPENAI_API_KEY" not in out:
        out["OPENAI_API_KEY"] = out["LOOPKEEPER_API_KEY"]

    return out


def parse_legacy_marker(body: str) -> tuple[str, int, str] | None:
    """Parse legacy Codex markers for compatibility.

    Supports:
      <!-- codex-pr-review:{pr}:{sha} -->
      <!-- codex-pr-review-no-ci:{pr}:{sha} -->
      <!-- codex-verdict: ... -->

    Returns:
        Tuple of (type, pr, sha) or None
    """
    if not isinstance(body, str):
        return None
    m = re.search(r"<!-- codex-pr-review:(\d+):([0-9a-f]{40}) -->", body)
    if m:
        return ("pr-review", int(m.group(1)), m.group(2))
    m2 = re.search(r"<!-- codex-pr-review-no-ci:(\d+):([0-9a-f]{40}) -->", body)
    if m2:
        return ("pr-review-no-ci", int(m2.group(1)), m2.group(2))
    if "<!-- codex-verdict:" in body:
        return ("verdict", 0, "")
    return None


def translate_legacy_marker_to_canonical(body: str) -> str:
    """Translate legacy markers in body to canonical Loopkeeper markers."""
    if not isinstance(body, str):
        return body
    # Replace codex-pr-review with loopkeeper-pr-review
    body = re.sub(
        r"<!-- codex-pr-review:(\d+):([0-9a-f]{40}) -->",
        r"<!-- loopkeeper-pr-review:\1:\2 -->",
        body,
    )
    body = re.sub(
        r"<!-- codex-pr-review-no-ci:(\d+):([0-9a-f]{40}) -->",
        r"<!-- loopkeeper-pr-review-no-ci:\1:\2 -->",
        body,
    )
    body = body.replace("<!-- codex-verdict:", "<!-- loopkeeper-verdict:")
    return body


# ---------------------------------------------------------------------------
# Exit code translation
# ---------------------------------------------------------------------------

# Relay exit codes vs Loopkeeper codes (brief says translate)
# Relay: 0=success, 1=generic, 2=config, etc. Loopkeeper exit_codes: 0 success, 2 config, 3 transport, 4 trust
_EXIT_CODE_MAP: dict[int, int] = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,  # transport
    4: 4,  # trust/security
}


def translate_exit_code(relay_code: int) -> int:
    """Translate a Relay exit code to Loopkeeper's exit code."""
    if not isinstance(relay_code, int):
        raise TypeError("relay_code must be int")
    return _EXIT_CODE_MAP.get(relay_code, relay_code)


def relay_to_loopkeeper_marker(marker: str) -> str:
    """Convert a single legacy marker string to canonical, if it matches."""
    if not isinstance(marker, str):
        raise TypeError("marker must be str")
    m = re.match(r"<!-- codex-pr-review:(\d+):([0-9a-f]{40}) -->", marker)
    if m:
        return f"<!-- loopkeeper-pr-review:{m.group(1)}:{m.group(2)} -->"
    m2 = re.match(r"<!-- codex-pr-review-no-ci:(\d+):([0-9a-f]{40}) -->", marker)
    if m2:
        return f"<!-- loopkeeper-pr-review-no-ci:{m2.group(1)}:{m2.group(2)} -->"
    if marker.strip() == "<!-- codex-verdict:":
        return "<!-- loopkeeper-verdict:"
    # Also handle evidence markers? codex didn't have evidence markers, but relay compat should handle
    return marker

"""Model binding and settings for Loopkeeper.

Resolves model ids and operational settings from flag > env > default,
rejects unsupported/version-pinned shapes, and fails loud on missing binding.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass

from .errors import ConfigError
from .transport import API_STYLES, BYTES_PER_TOKEN, EFFORTS, MODEL_PATTERN

MODEL_PATTERN_RE = MODEL_PATTERN
# Reject version-pinned Claude ids: claude-<tier>-<digit>
CLAUDE_VERSIONED_RE = re.compile(r"claude-[a-z]+-[0-9]", re.IGNORECASE)
# Reject any model that looks like a version-pinned shape with date suffix e.g., -20250101 or -5
VERSION_PINNED_RE = re.compile(r".*-\d{6,}$")

DEFAULT_MAX_INPUT_BYTES = 120_000
DEFAULT_MAX_OUTPUT_TOKENS = 8_000
DEFAULT_MAX_OUTPUT_BYTES = 32_000
DEFAULT_REQUEST_TIMEOUT = 900
DEFAULT_REASONING_EFFORT = "none"
DEFAULT_API_STYLE = "responses"
DEFAULT_API_BASE_URL: str | None = None


@dataclass(frozen=True)
class Settings:
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    reasoning_effort: str = DEFAULT_REASONING_EFFORT
    api_style: str = DEFAULT_API_STYLE
    api_base_url: str | None = DEFAULT_API_BASE_URL
    # Optional model fields could be added but not required for settings precedence test
    # Keep model out of settings to avoid confusion with resolve_model per-slot

    def __post_init__(self):
        # Validate coherence immediately
        if self.max_input_bytes <= 0:
            raise ConfigError("max_input_bytes must be positive")
        if self.max_output_tokens <= 0:
            raise ConfigError("max_output_tokens must be positive")
        if self.max_output_bytes <= 0:
            raise ConfigError("max_output_bytes must be positive")
        if self.max_output_bytes > self.max_output_tokens * BYTES_PER_TOKEN:
            raise ConfigError(
                "max_output_bytes is unreachable at this max_output_tokens "
                f"(ceiling must be at most {self.max_output_tokens * BYTES_PER_TOKEN})"
            )
        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be positive")
        if self.reasoning_effort not in EFFORTS:
            raise ConfigError(f"reasoning_effort must be one of {sorted(EFFORTS)}, got {self.reasoning_effort!r}")
        if self.api_style not in API_STYLES:
            raise ConfigError(f"API style must be one of {sorted(API_STYLES)}, got {self.api_style!r}")
        if self.api_base_url is not None:
            _validate_api_base_url(self.api_base_url)


def _validate_api_base_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ConfigError(f"API base URL is not a usable URL: {url!r}")
    if parsed.query or parsed.fragment:
        raise ConfigError(f"API base URL must not carry a query or fragment: {url!r}")
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise ConfigError(
                "API base URL must use https outside loopback "
                f"(the API key travels as a bearer header): {url!r}"
            )


def _validate_model_shape(value: str, source: str) -> None:
    if not MODEL_PATTERN_RE.fullmatch(value):
        raise ConfigError(f"model bound via {source} contains unsupported characters: {value!r}")
    if CLAUDE_VERSIONED_RE.search(value):
        raise ConfigError(
            f"model bound via {source} is a version-pinned Claude id (use tier alias): {value!r}"
        )
    # Optional: reject other version-pinned vendor ids with date suffix?
    # For strictness, reject any model ending with 6+ digits (likely date pinned)
    # But allow generic model like gpt-5.3-codex which ends with not 6 digits, so fine
    if VERSION_PINNED_RE.fullmatch(value):
        # Distinguish: if it looks like claude or versioned, already caught, but generic date-pinned also rejected?
        # Only reject if it contains claude or matches vendor versioned? For now, also reject pure date-pinned as unsupported
        # Check if value contains a dash followed by 8 digits at end, likely date
        raise ConfigError(f"model bound via {source} appears version-pinned: {value!r}")


def _normalize_slot(slot: str) -> str:
    # Normalize: upper, hyphens to underscores, collapse multiple underscores
    norm = slot.strip().upper().replace("-", "_")
    # Also handle slashes or spaces? Replace non-alphanum?
    norm = re.sub(r"[^A-Z0-9_]", "_", norm)
    norm = re.sub(r"_+", "_", norm).strip("_")
    return norm


def resolve_model(slot: str, override: str | None, env: Mapping[str, str]) -> str:
    if not isinstance(slot, str) or not slot.strip():
        raise ConfigError("slot must be non-empty string")
    norm = _normalize_slot(slot)
    # Derive per-agent env var: LOOPKEEPER_AGENT_<NORM>_MODEL, but avoid duplication if norm already starts with AGENT_
    if norm.startswith("AGENT_"):
        per_agent_env = f"LOOPKEEPER_{norm}_MODEL"
    else:
        per_agent_env = f"LOOPKEEPER_AGENT_{norm}_MODEL"
    candidates: tuple[tuple[str, str | None], ...] = (
        ("--model", override),
        (per_agent_env, env.get(per_agent_env)),
        ("LOOPKEEPER_MODEL", env.get("LOOPKEEPER_MODEL")),
    )
    for source, value in candidates:
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        val = value.strip() if isinstance(value, str) else str(value)
        _validate_model_shape(val, source)
        return val
    tried = ", ".join(name for name, _ in candidates)
    raise ConfigError(
        f"no model bound for slot {slot!r}; pass --model or set one of: {tried}"
    )


def _parse_int_env(raw: str, env_key: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(f"{env_key} must be integer, got {raw!r}") from None


def resolve_settings(flags: Mapping[str, object], env: Mapping[str, str]) -> Settings:
    # Helper to get precedence: flag > env > default, with validation for env strings
    def get_int(name: str, env_key: str, default: int) -> int:
        if name in flags and flags[name] is not None:
            v = flags[name]
            if not isinstance(v, int) or isinstance(v, bool):
                raise ConfigError(f"{name} flag must be integer, got {v!r}")
            if v <= 0:
                raise ConfigError(f"{name} must be positive, got {v!r}")
            return v
        if env_key in env:
            raw = env[env_key]
            if not isinstance(raw, str):
                raise ConfigError(f"{env_key} must be string")
            v = _parse_int_env(raw, env_key)
            if v <= 0:
                raise ConfigError(f"{env_key} must be positive, got {v!r}")
            return v
        return default

    def get_str(name: str, env_key: str, default: str | None) -> str | None:
        if name in flags and flags[name] is not None:
            v = flags[name]
            if not isinstance(v, str):
                raise ConfigError(f"{name} flag must be str, got {v!r}")
            if not v.strip():
                raise ConfigError(f"{name} flag must be non-empty")
            return v.strip()
        if env_key in env:
            raw = env[env_key]
            if not isinstance(raw, str):
                raise ConfigError(f"{env_key} must be string")
            if not raw.strip():
                raise ConfigError(f"{env_key} must be non-empty")
            return raw.strip()
        return default

    # Resolve each field with precedence
    max_input_bytes = get_int("max_input_bytes", "LOOPKEEPER_MAX_INPUT_BYTES", DEFAULT_MAX_INPUT_BYTES)
    max_output_tokens = get_int("max_output_tokens", "LOOPKEEPER_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS)
    max_output_bytes = get_int("max_output_bytes", "LOOPKEEPER_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES)
    request_timeout = get_int("request_timeout", "LOOPKEEPER_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)

    reasoning_effort = get_str("reasoning_effort", "LOOPKEEPER_REASONING_EFFORT", DEFAULT_REASONING_EFFORT)
    assert reasoning_effort is not None
    if reasoning_effort not in EFFORTS:
        raise ConfigError(f"LOOPKEEPER_REASONING_EFFORT must be one of {sorted(EFFORTS)}, got {reasoning_effort!r}")

    api_style = get_str("api_style", "LOOPKEEPER_API_STYLE", DEFAULT_API_STYLE)
    assert api_style is not None
    if api_style not in API_STYLES:
        raise ConfigError(f"LOOPKEEPER_API_STYLE must be one of {sorted(API_STYLES)}, got {api_style!r}")

    api_base_url = get_str("api_base_url", "LOOPKEEPER_API_BASE_URL", DEFAULT_API_BASE_URL)
    if api_base_url is not None:
        _validate_api_base_url(api_base_url)

    # Validate coherence of output ceilings
    if max_output_bytes > max_output_tokens * BYTES_PER_TOKEN:
        raise ConfigError(
            "max_output_bytes is unreachable at this max_output_tokens "
            f"(ceiling must be at most {max_output_tokens * BYTES_PER_TOKEN})"
        )
    # Validate timeout floor
    required = (max_output_tokens * 20) // 1000  # SECONDS_PER_1K_TOKENS
    # Use 20 as constant to avoid import cycle
    if request_timeout < required:
        raise ConfigError(
            f"request_timeout {request_timeout}s is too short for max_output_tokens {max_output_tokens} (need at least {required}s)"
        )

    return Settings(
        max_input_bytes=max_input_bytes,
        max_output_tokens=max_output_tokens,
        max_output_bytes=max_output_bytes,
        request_timeout=request_timeout,
        reasoning_effort=reasoning_effort,
        api_style=api_style,
        api_base_url=api_base_url,
    )

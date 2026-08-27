import pytest

from loopkeeper.errors import ConfigError
from loopkeeper.model_binding import resolve_model, resolve_settings


def test_resolve_model_flag_precedence():
    env = {
        "LOOPKEEPER_AGENT_DOMAIN_RESEARCHER_MODEL": "env-model",
        "LOOPKEEPER_MODEL": "fallback-model",
    }
    # flag > slot-specific > generic
    assert resolve_model("domain-researcher", "flag-model", env) == "flag-model"
    assert resolve_model("domain-researcher", None, env) == "env-model"
    # slot without specific var falls back to generic
    assert resolve_model("other-agent", None, {"LOOPKEEPER_MODEL": "generic"}) == "generic"


def test_resolve_model_normalizes_slot_name():
    env = {"LOOPKEEPER_AGENT_DOMAIN_RESEARCHER_MODEL": "env-model"}
    assert resolve_model("domain-researcher", None, env) == "env-model"
    assert resolve_model("DOMAIN-RESEARCHER", None, env) == "env-model"
    assert resolve_model("domain_researcher", None, env) == "env-model"


def test_resolve_model_rejects_unsupported_shape():
    with pytest.raises(ConfigError):
        resolve_model("domain-researcher", "bad model with spaces!", {})
    with pytest.raises(ConfigError):
        resolve_model("domain-researcher", None, {"LOOPKEEPER_MODEL": "bad model"})


def test_resolve_model_rejects_version_pinned():
    # Simulate version-pinned Claude id should be rejected
    with pytest.raises(ConfigError):
        resolve_model("domain-researcher", "claude-opus-4-20250101", {})


def test_resolve_model_fails_loudly_when_unbound():
    with pytest.raises(ConfigError, match="no model bound"):
        resolve_model("domain-researcher", None, {})


def test_resolve_settings_flag_over_env_over_default():
    s = resolve_settings({"max_input_bytes": 10}, {"LOOPKEEPER_MAX_INPUT_BYTES": "20"})
    assert s.max_input_bytes == 10
    s2 = resolve_settings({}, {"LOOPKEEPER_MAX_INPUT_BYTES": "20"})
    assert s2.max_input_bytes == 20
    s3 = resolve_settings({}, {})
    assert s3.max_input_bytes > 0  # default


def test_resolve_settings_invalid_env_raises():
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_MAX_INPUT_BYTES": "not-an-integer"})
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_REASONING_EFFORT": "invalid-effort"})
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_API_STYLE": "grpc"})


def test_resolve_settings_validates_coherence():
    # max_output_bytes unreachable at token cap should fail
    with pytest.raises(ConfigError):
        resolve_settings(
            {"max_output_tokens": 100, "max_output_bytes": 10000},
            {},
        )


def test_resolve_settings_reasoning_effort_and_api_style():
    s = resolve_settings({"reasoning_effort": "high"}, {})
    assert s.reasoning_effort == "high"
    s2 = resolve_settings({}, {"LOOPKEEPER_REASONING_EFFORT": "low"})
    assert s2.reasoning_effort == "low"
    s3 = resolve_settings({}, {"LOOPKEEPER_API_STYLE": "chat"})
    assert s3.api_style == "chat"


def test_resolve_settings_api_base_url_validation():
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_API_BASE_URL": "http://api.example.com/v1"})
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_API_BASE_URL": "https://api.example.com/v1?x=1"})
    # loopback http should be allowed
    s = resolve_settings({}, {"LOOPKEEPER_API_BASE_URL": "http://127.0.0.1:8000/v1"})
    assert s.api_base_url == "http://127.0.0.1:8000/v1"

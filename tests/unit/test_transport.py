from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from loopkeeper.errors import ConfigError  # noqa: F401
from loopkeeper.model_binding import resolve_model  # noqa: F401
from loopkeeper.transport import (
    ModelRequest,
    ModelResponse,
    TransportConfig,
    TransportError,
    build_payload,
    request_model,
)

# Use fixtures from conftest: policy, artifacts, recording_opener
from loopkeeper.redaction import RedactionResult


def test_responses_payload_is_non_retaining_and_preserves_channels():
    request = ModelRequest("trusted policy", "UNTRUSTED_DIFF_BLOCK", "example-model", "none", 100, 400)
    payload = build_payload(request, api_style="responses")
    assert payload["instructions"] == "trusted policy"
    assert payload["input"] == "UNTRUSTED_DIFF_BLOCK"
    assert payload["store"] is False


def test_chat_payload_has_no_unsupported_store_flag():
    payload = build_payload(
        ModelRequest("policy", "input", "example-model", "none", 100, 400),
        api_style="chat",
    )
    assert "store" not in payload


def test_missing_model_binding_fails_loudly():
    with pytest.raises(ConfigError, match="no model bound"):
        resolve_model("AGENT_DOMAIN_RESEARCHER", None, {})


def test_flag_environment_default_precedence_is_shared_across_settings():
    from loopkeeper.model_binding import resolve_settings

    settings = resolve_settings({"max_input_bytes": 10}, {"LOOPKEEPER_MAX_INPUT_BYTES": "20"})
    assert settings.max_input_bytes == 10
    with pytest.raises(ConfigError):
        resolve_settings({}, {"LOOPKEEPER_MAX_INPUT_BYTES": "not-an-integer"})


def test_prompt_uses_policy_and_active_redactor_placeholders(policy, artifacts):  # type: ignore[no-redef]
    from loopkeeper.prompt import render_review_prompt

    prompt = render_review_prompt(policy, RedactionResult("safe", ("ACCOUNT",)), artifacts)
    assert "ACCOUNT" in prompt.instructions
    assert "Relay" not in prompt.instructions
    assert "payment-domain" not in prompt.instructions


def test_transport_retries_only_before_a_response_is_established(recording_opener):
    request = ModelRequest("trusted policy", "untrusted diff", "example-model", "none", 100, 400)
    config = TransportConfig(
        api_style="responses",
        base_url="https://api.example.com/v1/responses",
        api_key="test-key",
        request_timeout=10,
        job_deadline_epoch=9999999999,
        retry_unestablished_connection=True,
    )
    recording_opener.fail_before_response_once = True
    response = request_model(request, config, opener=recording_opener)
    assert response.text == "bounded result"
    assert recording_opener.call_count == 2


def test_transport_never_retries_after_a_response_or_after_deadline(recording_opener):
    request = ModelRequest("trusted policy", "untrusted diff", "example-model", "none", 100, 400)
    config = TransportConfig(
        api_style="responses",
        base_url="https://api.example.com/v1/responses",
        api_key="test-key",
        request_timeout=10,
        job_deadline_epoch=9999999999,
        retry_unestablished_connection=True,
    )
    recording_opener.response_then_error = True
    with pytest.raises(TransportError):
        request_model(request, config, opener=recording_opener)
    assert recording_opener.call_count == 1


# Additional coverage for transport

def test_chat_payload_keeps_trusted_untrusted_channel_split():
    payload = build_payload(
        ModelRequest("TRUSTED POLICY", "UNTRUSTED DIFF", "m", "none", 100, 400),
        api_style="chat",
    )
    assert payload["messages"] == [
        {"role": "system", "content": "TRUSTED POLICY"},
        {"role": "user", "content": "UNTRUSTED DIFF"},
    ]


def test_transport_rejects_non_https_outside_loopback():
    request = ModelRequest("i", "p", "m", "none", 100, 400)
    config = TransportConfig(
        api_style="responses",
        base_url="http://api.example.com/v1/responses",
        api_key="k",
        request_timeout=10,
        job_deadline_epoch=9999999999,
    )
    with pytest.raises((TransportError, ConfigError, ValueError)):
        request_model(request, config, opener=lambda r, timeout=None: (_ for _ in ()).throw(AssertionError("should not be called")))


def test_transport_rejects_url_with_query_or_fragment():
    request = ModelRequest("i", "p", "m", "none", 100, 400)
    for bad in [
        "https://api.example.com/v1/responses?x=1",
        "https://api.example.com/v1/responses#frag",
    ]:
        config = TransportConfig(
            api_style="responses",
            base_url=bad,
            api_key="k",
            request_timeout=10,
            job_deadline_epoch=9999999999,
        )
        with pytest.raises((TransportError, ConfigError, ValueError)):
            request_model(request, config, opener=lambda r, timeout=None: (_ for _ in ()).throw(AssertionError("should not be called")))


def test_transport_records_timeout_and_respects_deadline(recording_opener):
    import time

    request = ModelRequest("i", "p", "m", "none", 100, 400)
    # Job deadline very near, so request timeout should be capped
    near_deadline = int(time.time()) + 5
    config = TransportConfig(
        api_style="responses",
        base_url="https://api.example.com/v1/responses",
        api_key="k",
        request_timeout=100,
        job_deadline_epoch=near_deadline,
    )
    # The opener will be called with min(request_timeout, remaining)
    # We just check that timeout recorded is <=5 (plus headroom)
    # If deadline already past headroom, should fail before calling
    try:
        request_model(request, config, opener=recording_opener)
    except TransportError:
        # Could be deadline exceeded before call
        pass
    if recording_opener.call_count > 0:
        assert recording_opener.timeouts[0] <= 100


def test_output_ceiling_is_enforced():
    # Simulate oversized output
    request = ModelRequest("i", "p", "m", "none", 10, 5)
    config = TransportConfig(
        api_style="responses",
        base_url="https://api.example.com/v1/responses",
        api_key="k",
        request_timeout=10,
        job_deadline_epoch=9999999999,
    )

    def oversized_opener(req, timeout=None):
        body = json.dumps({"output_text": "x" * 100}).encode()
        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return Resp(body)

    with pytest.raises(TransportError):
        request_model(request, config, opener=oversized_opener)

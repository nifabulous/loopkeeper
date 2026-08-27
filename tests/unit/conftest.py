"""Unit-test fixtures for transport/model_binding/prompt."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from loopkeeper.policy import Policy
from loopkeeper.prompt import UntrustedArtifacts


@pytest.fixture
def policy() -> Policy:
    return Policy(
        display_name="Test Review Policy",
        categories=("functional", "security"),
        severity_guidance="P1 blocks merge, P2 should be fixed soon, P3 is low risk.",
        lifecycle_rules="NEW first appearance, OPEN still present, RESOLVED once with evidence.",
        data_handling="Do not store secrets; prefer identifiers and redacted examples.",
    )


@pytest.fixture
def artifacts() -> UntrustedArtifacts:
    # Bounded strings per brief: metadata, diff, previous_review, checks
    return UntrustedArtifacts(
        metadata="repo: owner/name pr: 1 head: abc123",
        diff="diff --git a/app.py b/app.py\n+ added line\n",
        previous_review="previous review comment with trailer",
        checks="checks: ci passed",
    )


class RecordingOpener:
    """Fake urllib opener that records timeouts and call counts.

    Supports two failure modes for retry tests:
    - fail_before_response_once: first call raises URLError before response
    - response_then_error: first call returns a response whose read() raises
    """

    def __init__(self):
        self.call_count: int = 0
        self.timeouts: list[float] = []
        self.fail_before_response_once: bool = False
        self.response_then_error: bool = False
        self._failed_once: bool = False

    def __call__(self, request: urllib.request.Request, timeout: float | None = None):
        self.call_count += 1
        if timeout is not None:
            self.timeouts.append(float(timeout))
        else:
            self.timeouts.append(0.0)

        # Mode: fail before response once
        if self.fail_before_response_once and not self._failed_once:
            self._failed_once = True
            raise urllib.error.URLError("simulated connection failure before response")

        # Mode: response then error during read
        if self.response_then_error:
            # Return a response whose read raises after establishing
            class FailingRead(io.BytesIO):
                def read(self, n=-1):  # type: ignore[override]
                    raise urllib.error.URLError("simulated failure after response established")

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            return FailingRead(b"")

        # Normal success: return bounded result JSON
        # We need to handle both wire styles; return a payload that works for both.
        # The request payload indicates api_style via URL or payload structure.
        # For simplicity, return responses-style body; chat extraction will also
        # handle fallback if we include choices.
        # Detect chat vs responses by inspecting request data
        try:
            data = request.data
            if data:
                payload = json.loads(data.decode("utf-8"))
                # If payload has messages, it's chat – return chat shape
                if "messages" in payload:
                    body = json.dumps(
                        {
                            "choices": [
                                {
                                    "message": {"content": "bounded result"},
                                    "finish_reason": "stop",
                                }
                            ]
                        }
                    ).encode("utf-8")
                else:
                    body = json.dumps({"output_text": "bounded result"}).encode("utf-8")
            else:
                body = json.dumps({"output_text": "bounded result"}).encode("utf-8")
        except Exception:
            body = json.dumps({"output_text": "bounded result"}).encode("utf-8")

        class SuccessResponse(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return SuccessResponse(body)


@pytest.fixture
def recording_opener() -> RecordingOpener:
    return RecordingOpener()

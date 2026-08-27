"""Provider-neutral HTTP transport for Loopkeeper.

Supports both Responses and Chat wire styles using only stdlib urllib.
Ported from the 488-line reference implementation.
"""

from __future__ import annotations

import json
import re
import argparse
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .errors import ConfigError, TransportError

RESPONSES_API_URL = "https://api.openai.com/v1/responses"
CHAT_COMPLETIONS_API_URL = "https://api.openai.com/v1/chat/completions"
API_STYLES = {"responses", "chat"}
EFFORTS = {"none", "low", "medium", "high", "xhigh"}
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]+$")

TRUNCATION_MARKER = "\n[TRUNCATED INPUT]"
OUTPUT_TRUNCATION_MARKER = "\n\n[TRUNCATED OUTPUT: the model hit max_output_tokens ({reason}). This review is incomplete.]"

BYTES_PER_TOKEN = 4
RESPONSE_BODY_BYTES_PER_TOKEN = 8
RESPONSE_BODY_OVERHEAD_BYTES = 64 * 1024
SECONDS_PER_1K_TOKENS = 20
DEFAULT_REQUEST_TIMEOUT = 900
POSTING_HEADROOM_SECONDS = 180

UrlOpener = Callable[[urllib.request.Request, float], IO[bytes]]


@dataclass(frozen=True)
class ModelRequest:
    instructions: str
    input_text: str
    model: str
    reasoning_effort: str
    max_output_tokens: int
    max_output_bytes: int


@dataclass(frozen=True)
class TransportConfig:
    api_style: str
    base_url: str | None
    api_key: str
    request_timeout: int
    job_deadline_epoch: int | None
    retry_unestablished_connection: bool = False


@dataclass(frozen=True)
class ModelResponse:
    text: str
    raw_bytes: bytes
    truncated: bool
    request_id: str | None


def remaining_seconds(job_deadline_epoch: int | None) -> float:
    if job_deadline_epoch is None:
        return float("inf")
    remaining = float(job_deadline_epoch) - time.time() - POSTING_HEADROOM_SECONDS
    return remaining


def resolve_api_url(api_style: str, override: str | None) -> str:
    if api_style not in API_STYLES:
        raise ConfigError(f"API style must be one of {sorted(API_STYLES)}, got {api_style!r}")
    url = override
    if url is None:
        return CHAT_COMPLETIONS_API_URL if api_style == "chat" else RESPONSES_API_URL
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise TransportError(f"API base URL is not a usable URL: {url!r}")
    if parsed.query or parsed.fragment:
        raise TransportError(f"API base URL must not carry a query or fragment: {url!r}")
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1"}:
            raise TransportError(
                "API base URL must use https outside loopback "
                f"(the API key travels as a bearer header): {url!r}"
            )
    return url


def build_chat_payload(
    model: str,
    reasoning_effort: str,
    instructions: str,
    prompt: str,
    max_output_tokens: int,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": model,
        "messages": [
            {"role": "system", "content": instructions},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_output_tokens,
    }
    if reasoning_effort != "none":
        payload["reasoning_effort"] = reasoning_effort
    return payload


def build_payload(request: ModelRequest, api_style: str) -> dict[str, object]:
    if api_style not in API_STYLES:
        raise ConfigError(f"API style must be one of {sorted(API_STYLES)}, got {api_style!r}")
    if api_style == "chat":
        return build_chat_payload(
            request.model,
            request.reasoning_effort,
            request.instructions,
            request.input_text,
            request.max_output_tokens,
        )
    payload: dict[str, object] = {
        "model": request.model,
        "instructions": request.instructions,
        "input": request.input_text,
        "store": False,
        "max_output_tokens": request.max_output_tokens,
    }
    if request.reasoning_effort != "none":
        payload["reasoning"] = {"effort": request.reasoning_effort}
    return payload


def read_bounded_body(stream: IO[bytes], max_bytes: int) -> dict[str, object]:
    raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise TransportError(f"Model API body exceeded {max_bytes} bytes")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("Model API returned an invalid response") from None
    if not isinstance(body, dict):
        raise TransportError("Model API returned an invalid response")
    return body


def response_body_limit(max_output_tokens: int, max_output_bytes: int) -> int:
    return (
        max_output_bytes
        + (max_output_tokens * RESPONSE_BODY_BYTES_PER_TOKEN)
        + RESPONSE_BODY_OVERHEAD_BYTES
    )


def enforce_output_bytes(text: str, max_bytes: int) -> str:
    size = len(text.encode("utf-8"))
    if size > max_bytes:
        raise TransportError(f"Model API output exceeded {max_bytes} bytes ({size})")
    return text


def _collect_chat_text(response: dict[str, object]) -> str:
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            text = message.get("content")
            if isinstance(text, str):
                return text
    return ""


def _chat_finish_reason(response: dict[str, object]) -> str:
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        reason = choices[0].get("finish_reason")
        if isinstance(reason, str):
            return reason
    return ""


def _collect_output_text(response: dict[str, object]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str) and direct:
        return direct
    chunks: list[str] = []
    output = response.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, dict) and part.get("type") == "output_text":
                    text = part.get("text")
                    if isinstance(text, str):
                        chunks.append(text)
    return "\n".join(chunks)


def extract_output(response: dict[str, object], api_style: str = "responses") -> str:
    if api_style == "chat":
        text = _collect_chat_text(response)
        finish_reason = _chat_finish_reason(response)
        if finish_reason == "length":
            if not text:
                raise TransportError("model API returned a length-truncated response with no text")
            return text + OUTPUT_TRUNCATION_MARKER.format(reason="max_output_tokens")
        return text
    text = _collect_output_text(response)
    if response.get("status") == "incomplete":
        details = response.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, dict) else None
        reason = reason if isinstance(reason, str) else "unknown"
        if not text:
            raise TransportError(f"Model API returned an incomplete response with no text ({reason})")
        return text + OUTPUT_TRUNCATION_MARKER.format(reason=reason)
    return text


def _open_once(
    request: ModelRequest,
    config: TransportConfig,
    opener: UrlOpener,
    timeout: float,
) -> tuple[dict[str, object], bytes]:
    if timeout <= 0:
        raise TransportError(
            f"deadline leaves no time to make request (timeout={timeout}s, deadline={config.job_deadline_epoch})"
        )
    payload = build_payload(request, config.api_style)
    url = resolve_api_url(config.api_style, config.base_url)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    # Phase 1: establish connection (opener)
    try:
        response_cm = opener(req, timeout)  # type: ignore[call-arg]
    except urllib.error.HTTPError as error:
        raise TransportError(f"Model API request failed with HTTP {error.code}") from None
    except TimeoutError:
        raise TransportError(
            f"Model API request timed out after {timeout}s "
            f"(max_output_tokens={request.max_output_tokens}); raise request_timeout or lower max_output_tokens"
        ) from None
    except urllib.error.URLError as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
            raise TransportError(
                f"Model API request timed out after {timeout}s "
                f"(max_output_tokens={request.max_output_tokens}); raise request_timeout or lower max_output_tokens"
            ) from None
        raise TransportError(f"Model API request failed to connect: {reason}") from None

    # Phase 2: read response (response already established)
    try:
        with response_cm as response:  # type: ignore[operator]
            limit = response_body_limit(request.max_output_tokens, request.max_output_bytes)
            body = read_bounded_body(response, limit)
            raw = json.dumps(body).encode("utf-8")
            return body, raw
    except TransportError:
        raise
    except TimeoutError:
        raise TransportError(
            f"Model API request timed out while reading response after {timeout}s "
            f"(max_output_tokens={request.max_output_tokens})"
        ) from None
    except urllib.error.HTTPError as error:
        raise TransportError(f"Model API request failed with HTTP {error.code}") from None
    except urllib.error.URLError as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
            raise TransportError(
                f"Model API request timed out while reading response after {timeout}s "
                f"(max_output_tokens={request.max_output_tokens})"
            ) from None
        raise TransportError(f"Model API request failed while reading response: {reason}") from None


def _parse_bounded_response(
    body: dict[str, object],
    raw_bytes: bytes,
    request: ModelRequest,
    api_style: str,
) -> ModelResponse:
    text = extract_output(body, api_style)
    if not text:
        raise TransportError("Model API returned no text")
    enforce_output_bytes(text, request.max_output_bytes)
    truncated = "TRUNCATED OUTPUT" in text
    request_id = None
    for key in ("id", "request_id", "response_id"):
        val = body.get(key)
        if isinstance(val, str):
            request_id = val
            break
    return ModelResponse(text=text, raw_bytes=raw_bytes, truncated=truncated, request_id=request_id)


def request_model(
    request: ModelRequest,
    config: TransportConfig,
    opener: UrlOpener = urllib.request.urlopen,
) -> ModelResponse:
    if config.api_style not in API_STYLES:
        raise ConfigError(f"API style must be one of {sorted(API_STYLES)}, got {config.api_style!r}")
    if not config.api_key:
        raise TransportError("API key is required")
    if config.request_timeout <= 0:
        raise TransportError("request_timeout must be positive")
    if request.max_output_tokens <= 0 or request.max_output_bytes <= 0:
        raise TransportError("max_output tokens/bytes must be positive")
    if request.max_output_bytes > request.max_output_tokens * BYTES_PER_TOKEN:
        raise TransportError(
            "max_output_bytes is unreachable at this max_output_tokens "
            f"(ceiling must be at most {request.max_output_tokens * BYTES_PER_TOKEN})"
        )
    remaining = remaining_seconds(config.job_deadline_epoch)
    if remaining != float("inf") and remaining <= 0:
        raise TransportError(
            f"job deadline leaves no time to make request (remaining={remaining}s)"
        )
    deadline = min(float(config.request_timeout), remaining) if remaining != float("inf") else float(config.request_timeout)
    required = (request.max_output_tokens * SECONDS_PER_1K_TOKENS) // 1000
    if deadline < required:
        raise TransportError(
            f"request timeout {deadline}s is too short for max_output_tokens {request.max_output_tokens} (need at least {required}s)"
        )

    try:
        body, raw = _open_once(request, config, opener, timeout=deadline)
        return _parse_bounded_response(body, raw, request, config.api_style)
    except TransportError as first_error:
        if not config.retry_unestablished_connection:
            raise
        msg = str(first_error).lower()
        # Never retry after response established
        if "while reading response" in msg or "http" in msg and "failed with http" in msg:
            raise
        # Only retry if error was before response: "failed to connect" or "timed out after" (but not while reading)
        is_before = "failed to connect" in msg or ("timed out after" in msg and "while reading" not in msg)
        if not is_before:
            raise
        # Check deadline still has room
        remaining2 = remaining_seconds(config.job_deadline_epoch)
        if remaining2 != float("inf") and remaining2 <= 0:
            raise
        deadline2 = min(float(config.request_timeout), remaining2) if remaining2 != float("inf") else float(config.request_timeout)
        if deadline2 < required:
            raise
        # One retry only
        try:
            body, raw = _open_once(request, config, opener, timeout=deadline2)
            return _parse_bounded_response(body, raw, request, config.api_style)
        except TransportError:
            # Second failure – do not retry again
            raise


def _transport_cli(argv: list[str] | None = None) -> int:
    """Small bounded CLI used by the trusted GitHub adapter.

    Keeping this entry point beside the provider-neutral transport means shell
    adapters do not need a provider-specific compatibility script.  All input
    and output files are explicitly bounded and the raw model response is
    written only to the requested output path.
    """
    parser = argparse.ArgumentParser(prog="python -m loopkeeper.transport")
    parser.add_argument("--model", required=True)
    parser.add_argument("--reasoning-effort", default="none")
    parser.add_argument("--instructions", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-input-bytes", required=True, type=int)
    parser.add_argument("--max-output-tokens", required=True, type=int)
    parser.add_argument("--max-output-bytes", required=True, type=int)
    parser.add_argument("--request-timeout", required=True, type=int)
    parser.add_argument("--job-deadline", type=int)
    parser.add_argument("--require-complete-input", action="store_true")
    args = parser.parse_args(argv)

    if args.max_input_bytes <= 0 or args.max_output_tokens <= 0 or args.max_output_bytes <= 0:
        raise ConfigError("transport limits must be positive")
    instruction_bytes = args.instructions.read_bytes()
    input_bytes = args.input.read_bytes()
    combined = len(instruction_bytes) + len(input_bytes)
    if combined > args.max_input_bytes:
        raise TransportError(
            f"model input exceeded {args.max_input_bytes} bytes ({combined})"
        )
    try:
        instructions = instruction_bytes.decode("utf-8")
        input_text = input_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransportError("model input is not valid UTF-8") from exc

    api_key = os.environ.get("LOOPKEEPER_API_KEY", "")
    if not api_key:
        raise ConfigError("LOOPKEEPER_API_KEY is required")
    config = TransportConfig(
        api_style=os.environ.get("LOOPKEEPER_API_STYLE", "responses"),
        base_url=os.environ.get("LOOPKEEPER_API_BASE_URL"),
        api_key=api_key,
        request_timeout=args.request_timeout,
        job_deadline_epoch=args.job_deadline,
        retry_unestablished_connection=True,
    )
    request = ModelRequest(
        instructions=instructions,
        input_text=input_text,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        max_output_tokens=args.max_output_tokens,
        max_output_bytes=args.max_output_bytes,
    )
    response = request_model(request, config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    temporary.write_text(response.text, encoding="utf-8")
    temporary.replace(args.output)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by shell adapters
    try:
        raise SystemExit(_transport_cli())
    except (ConfigError, TransportError) as exc:
        print(f"loopkeeper transport: {exc}", file=sys.stderr)
        raise SystemExit(2 if isinstance(exc, ConfigError) else 3) from None

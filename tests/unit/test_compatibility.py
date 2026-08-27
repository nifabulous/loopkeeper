"""Tests for Relay compatibility adapter."""

from __future__ import annotations

import pytest

try:
    from loopkeeper.adapters.relay.compat import (
        map_relay_environment,
        parse_legacy_marker,
        translate_legacy_marker_to_canonical,
    )
except ImportError:
    from adapters.relay.compat import (
        map_relay_environment,
        parse_legacy_marker,
        translate_legacy_marker_to_canonical,
    )


def test_map_relay_environment_translates_legacy_names():
    env = {
        "CODEX_MODEL": "gpt-5.3-codex",
        "CODEX_REASONING_EFFORT": "medium",
        "CODEX_MAX_INPUT_BYTES": "600000",
        "OPENAI_API_KEY": "sk-test",
        "ARBITER_SOFT_GATE": "5",
        "RELAY_AGENT_DOMAIN_RESEARCHER_MODEL": "agent-model",
        "LOOPKEEPER_MODEL": "already-set",
    }
    mapped = map_relay_environment(env)
    # Existing LOOPKEEPER_* never overridden
    assert mapped["LOOPKEEPER_MODEL"] == "already-set"
    assert mapped["LOOPKEEPER_REASONING_EFFORT"] == "medium"
    assert mapped["LOOPKEEPER_MAX_INPUT_BYTES"] == "600000"
    assert mapped["LOOPKEEPER_ARBITER_SOFT_GATE"] == "5"
    assert mapped["LOOPKEEPER_AGENT_DOMAIN_RESEARCHER_MODEL"] == "agent-model"
    # OPENAI_API_KEY mirrored
    assert mapped["LOOPKEEPER_API_KEY"] == "sk-test"
    assert mapped["OPENAI_API_KEY"] == "sk-test"

    # Legacy CODEX_TRUSTED_SHA -> LOOPKEEPER_TRUSTED_SHA
    env2 = {"CODEX_TRUSTED_SHA": "a" * 40}
    mapped2 = map_relay_environment(env2)
    assert mapped2["LOOPKEEPER_TRUSTED_SHA"] == "a" * 40

    # Per-agent normalization
    env3 = {"CODEX_AGENT_FOO_BAR_MODEL": "x"}
    mapped3 = map_relay_environment(env3)
    assert mapped3["LOOPKEEPER_AGENT_FOO_BAR_MODEL"] == "x"


def test_legacy_marker_parsing_and_translation():
    sha = "a" * 40
    body = f"hello <!-- codex-pr-review:15:{sha} --> world"
    parsed = parse_legacy_marker(body)
    assert parsed == ("pr-review", 15, sha)
    translated = translate_legacy_marker_to_canonical(body)
    assert "<!-- loopkeeper-pr-review:15:" in translated
    assert "<!-- codex-pr-review" not in translated

    body2 = "<!-- codex-verdict: {\"schema\":2} -->"
    assert parse_legacy_marker(body2) == ("verdict", 0, "")
    assert "<!-- loopkeeper-verdict:" in translate_legacy_marker_to_canonical(body2)

    # Unknown body returns None
    assert parse_legacy_marker("no marker") is None


def test_compat_keeps_package_names_loopkeeper_only():
    # Ensure new code emits only Loopkeeper names
    import pathlib
    pkg_root = pathlib.Path(__file__).resolve().parents[2] / "src" / "loopkeeper"
    # Check that no file outside compat still mentions CODEX_ (except compat and docs)
    found = []
    for p in pkg_root.rglob("*.py"):
        if p.name == "compat.py":
            continue
        text = p.read_text(encoding="utf-8")
        if "CODEX_" in text or "codex-pr-review" in text:
            # Redactor may mention codex-verdict for compatibility, allow that
            if "codex-verdict" in text and "loopkeeper-verdict" in text:
                continue
            found.append(str(p))
    # Allow failures only if we missed something — but for now we expect none outside compat
    # If there are leftover CODEX names, it suggests compat isolation broken
    assert not found, f"Found legacy CODEX names outside compat: {found}"

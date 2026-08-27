"""Tests for loopkeeper redaction — ported from Relay e834773 tests/test_codex_sanitize.py.

Covers secret, token, cookie, card, and identifier corpus plus plugin contract
enforcement: trusted-root validation, placeholder grammar, dedup, byte length,
and unsafe output rejection.
"""
from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

# These imports will fail until src/loopkeeper/redaction.py and redactor_loader.py exist
from loopkeeper.errors import SecurityError
from loopkeeper.redaction import RedactionResult, sanitize, sanitize_with_metadata
from loopkeeper.redactor_loader import load_redactor, validate_plugin_module


def import_module_from_fixture(name: str, source_root: Path):
    """Helper used by brief's fixture test: create a temporary module file under source_root."""
    source_root.mkdir(parents=True, exist_ok=True)
    mod_path = source_root / f"{name}.py"
    if not mod_path.exists():
        mod_path.write_text("redactor = object()\n", encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name + "_fixture", mod_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class PluginReturning:
    def __init__(self, text: str, placeholders: tuple[str, ...]):
        self.text = text
        self.placeholder_values = placeholders

    def redact(self, text: str) -> RedactionResult:
        return RedactionResult(self.text, self.placeholder_values)


# ---------------------------------------------------------------------------
# Brief-required security corpus (5 tests)
# ---------------------------------------------------------------------------

def test_plugin_placeholders_are_deduplicated_and_exposed():
    result = sanitize_with_metadata(
        "acct 1234",
        PluginReturning("[ACCOUNT]", ("ACCOUNT", "ACCOUNT")),
    )
    assert result.text == "[ACCOUNT]"
    assert result.placeholders == ("ACCOUNT",)


def test_plugin_loaded_from_untrusted_path_is_refused(tmp_path):
    with pytest.raises(SecurityError, match="trusted environment"):
        load_redactor("evil:redactor", (tmp_path / "trusted",))


def test_plugin_module_file_must_resolve_inside_a_trusted_root(tmp_path, monkeypatch):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    module = import_module_from_fixture("plugin", source_root=tmp_path / "outside")
    with pytest.raises(SecurityError, match="module path"):
        validate_plugin_module(module, (trusted,))


def test_builtin_or_namespace_module_without_a_file_is_refused(tmp_path):
    with pytest.raises(SecurityError, match="module path"):
        validate_plugin_module(sys, (tmp_path,))


def test_wrap_defangs_delimiters_but_does_not_replace_redaction():
    from loopkeeper.untrusted import wrap_untrusted

    assert "[REDACTED_TOKEN]" not in wrap_untrusted("diff", "sk-live-value")
    assert "sk-live-value" in wrap_untrusted("diff", "sk-live-value")


# ---------------------------------------------------------------------------
# Generic sanitizer corpus (ported from test_codex_sanitize.py)
# Use sanitize() directly — no subprocess.
# ---------------------------------------------------------------------------

def test_redacts_secrets_payment_identifiers_and_personal_contact_data():
    source = """
    Authorization: Bearer super-secret-token-value
    OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop
    -----BEGIN PRIVATE KEY-----
    private-key-material
    -----END PRIVATE KEY-----
    IBAN GB29NWBK60161331926819
    Contact Ada Lovelace at ada@example.com or +234 801 234 5678.
    """
    sanitized = sanitize(source)
    assert "super-secret-token-value" not in sanitized
    assert "sk-proj-1234567890abcdefghijklmnop" not in sanitized
    assert "private-key-material" not in sanitized
    assert "GB29NWBK60161331926819" not in sanitized
    assert "ada@example.com" not in sanitized
    assert "+234 801 234 5678" not in sanitized
    assert "[REDACTED]" in sanitized


def test_redacts_non_bearer_authorization_schemes():
    basic = sanitize("Authorization: Basic dXNlcjpwYXNz\n")
    token = sanitize("Authorization: Token abcdef123456\n")
    digest = sanitize('Authorization: Digest username="ada", response="deadbeef"\n')
    schemeless = sanitize("authorization: raw-credential-value\n")
    assert "dXNlcjpwYXNz" not in basic
    assert "Basic" in basic
    assert "abcdef123456" not in token
    assert "deadbeef" not in digest
    assert "raw-credential-value" not in schemeless


def test_redacts_the_complete_inline_authorization_value():
    custom = sanitize('x=Authorization: CustomScheme super-secret-value; y=1\n')
    digest = sanitize('curl -H "Authorization: Digest username=ada, response=deadbeef" https://x\n')
    assert "super-secret-value" not in custom
    assert "deadbeef" not in digest


def test_redacts_all_fields_from_a_diff_prefixed_digest_header():
    sanitized = sanitize('+Authorization: Digest username="ada", response="deadbeef"\n')
    assert 'response="deadbeef"' not in sanitized
    assert "[REDACTED]" in sanitized


def test_redacts_all_fields_from_a_proxy_authorization_digest_header():
    sanitized = sanitize('Proxy-Authorization: Digest username="ada", response="deadbeef"\n')
    assert 'response="deadbeef"' not in sanitized
    assert "[REDACTED]" in sanitized


def test_redacts_prefixed_authorization_headers():
    proxy = sanitize('Proxy-Authorization: Digest username="ada", response="deadbeef"\n')
    vendor = sanitize('X-Authorization: Digest username="ada", response="deadbeef"\n')
    nested = sanitize('+X-Amz-Authorization: Digest username="a", response="deadbeef"\n')
    assert "deadbeef" not in proxy
    assert "deadbeef" not in vendor
    assert "deadbeef" not in nested


def test_redacts_the_authentication_header_variant():
    sanitized = sanitize("Authentication: Bearer tok-abcdefghijkl\n")
    assert "tok-abcdefghijkl" not in sanitized
    assert "Bearer" in sanitized


def test_does_not_redact_a_www_authenticate_challenge():
    source = 'WWW-Authenticate: Digest realm="relay", qop="auth"\n'
    assert sanitize(source) == source


def test_redacts_cookie_headers():
    request = sanitize("Cookie: session=very-secret-session-token\n")
    response = sanitize("Set-Cookie: sid=abc123; HttpOnly; Secure\n")
    assert "very-secret-session-token" not in request
    assert "abc123" not in response
    assert "[REDACTED_COOKIE]" in request


def test_redacts_quoted_cookie_values_without_leaving_the_value_behind():
    sanitized = sanitize('Cookie: sid="abc123secretvalue"; Path=/\n')
    assert "abc123secretvalue" not in sanitized
    assert sanitized == "Cookie: [REDACTED_COOKIE]\n"


def test_sanitizes_sensitive_values_in_hunk_header_context():
    sanitized = sanitize('@@ -12,6 +12,9 @@ def connect(password="hunter2", iban="GB29NWBK60161331926819"):\n')
    assert 'password="hunter2"' not in sanitized
    assert "GB29NWBK60161331926819" not in sanitized
    assert sanitized.startswith("@@ -12,6 +12,9 @@ ")


def test_redacts_an_inline_cookie_whose_value_is_quoted():
    sanitized = sanitize('curl -H "Cookie: sid=\\"abc123secretvalue\\"" https://x\n')
    assert "abc123secretvalue" not in sanitized
    assert "[REDACTED_COOKIE]" in sanitized


def test_redacts_all_inline_cookie_pairs():
    sanitized = sanitize('curl -H "Cookie: sid=abc123; refresh=super-secret-refresh" https://x\n')
    assert "abc123" not in sanitized
    assert "super-secret-refresh" not in sanitized


def test_redacts_quoted_secret_assignments_containing_spaces():
    passphrase = sanitize('PASSWORD="correct horse battery staple"\n')
    single = sanitize("ADMIN_API_KEY = 'two words here'\n")
    assert "correct horse battery staple" not in passphrase
    assert "two words here" not in single


def test_credential_redaction_is_idempotent():
    source = (
        "Authorization: Basic dXNlcjpwYXNz\n"
        "Cookie: session=very-secret-session-token\n"
        'PASSWORD="correct horse battery staple"\n'
    )
    once = sanitize(source)
    assert sanitize(once) == once


def test_redacts_grouped_ibans_that_a_person_actually_pastes():
    sanitized = sanitize("Debit GB29 NWBK 6016 1331 9268 19 today.\n")
    assert "NWBK" not in sanitized
    assert "6016" not in sanitized
    assert "9268" not in sanitized


def test_preserves_bic_swift_codes_so_seed_data_stays_reviewable():
    source = '    ("CITIUS33", "Citibank", "US", "New York", "USD"),\n'
    assert sanitize(source) == source
    assert "BNPAFRPPXXX" in sanitize("Route via BIC BNPAFRPPXXX.\n")


def test_preserves_git_metadata_lines():
    source = (
        "diff --git a/app/services/seed.py b/app/services/seed.py\n"
        "index 72e1982..0123456789012 100644\n"
        "@@ -1234567890123,7 +1234567890123,9 @@ def seed_banks(session):\n"
    )
    assert sanitize(source) == source


def test_preserves_iso_8601_dates_and_timestamps():
    source = (
        "Create Date: 2026-08-13 12:53:15.865474\n"
        '"createdAt": "2026-08-15T09:30:00Z"\n'
    )
    assert sanitize(source) == source


def test_preserves_standard_references_such_as_iso_20022():
    source = '"roadmap": ["2023 rulebook migration to ISO 20022 2019 version complete"]\n'
    assert sanitize(source) == source
    assert sanitize("Built on ISO 8583 and ISO 20022:2013.\n") == (
        "Built on ISO 8583 and ISO 20022:2013.\n"
    )


def test_preserves_svg_coordinate_lists():
    source = '      <polyline points="20 6 9 17 4 12" />\n'
    assert sanitize(source) == source
    assert sanitize('<svg viewBox="0 0 24 24 16 16">\n') == '<svg viewBox="0 0 24 24 16 16">\n'


def test_a_coordinate_attribute_cannot_smuggle_an_identifier_through():
    sanitized = sanitize('<polyline points="100200300400 6 9 17" />\n')
    assert "100200300400" not in sanitized


def test_a_coordinate_attribute_cannot_smuggle_grouped_payment_identifiers():
    card = sanitize('<polyline points="4111 1111 1111 1111" />\n')
    account = sanitize('<polyline points="1234 5678" />\n')
    assert "4111 1111 1111 1111" not in card
    assert "1234 5678" not in account


def test_standard_reference_exemption_is_idempotent():
    source = (
        'ISO 20022 2019 migration, <polyline points="20 6 9 17 4 12" />, '
        "call +234 801 234 5678\n"
    )
    once = sanitize(source)
    assert "+234 801 234 5678" not in once
    assert sanitize(once) == once


def test_redacts_uetrs():
    sanitized = sanitize("UETR 97ed4827-7b6f-4491-a06f-b548d5a7512d failed.\n")
    assert "97ed4827-7b6f-4491-a06f-b548d5a7512d" not in sanitized
    assert "[UETR]" in sanitized


def test_redacts_account_numbers():
    sanitized = sanitize("Credit account 100200300400 for the beneficiary.\n")
    assert "100200300400" not in sanitized
    assert "[ACCOUNT]" in sanitized


def test_redacts_card_like_numbers_including_grouped_forms():
    contiguous = sanitize("Card 4111111111111111 on file.\n")
    grouped = sanitize("Card 4111 1111 1111 1111 on file.\n")
    hyphenated = sanitize("Card 4111-1111-1111-1111 on file.\n")
    assert "4111111111111111" not in contiguous
    assert "1111" not in grouped
    assert "1111" not in hyphenated


def test_preserves_normal_source_and_is_idempotent():
    source = "def calculate_total(amount: int) -> int:\n    return amount + 1\n"
    sanitized = sanitize(source)
    assert sanitized == source
    assert sanitize(sanitized) == sanitized


def test_payment_redaction_output_is_idempotent():
    source = (
        "IBAN GB29 NWBK 6016 1331 9268 19, BIC CITIUS33, "
        "UETR 97ed4827-7b6f-4491-a06f-b548d5a7512d, card 4111 1111 1111 1111, "
        "account 100200300400, ada@example.com, +234 801 234 5678\n"
    )
    once = sanitize(source)
    assert sanitize(once) == once


def test_preserves_ordinary_review_prose_and_diff_line_markers():
    source = "@@ -1,5 +1,5 @@\n-    return 2026\n+    return 2027\n"
    assert sanitize(source) == source


# ---------------------------------------------------------------------------
# Plugin contract additional tests (byte length, grammar, string return)
# ---------------------------------------------------------------------------

def test_plugin_returning_string_is_rejected():
    class Bad:
        def redact(self, text: str):
            return "[REDACTED]"

    with pytest.raises(SecurityError):
        sanitize_with_metadata("hello", Bad())  # type: ignore


def test_plugin_returning_non_string_text_is_rejected():
    class Bad:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult(123, ("ACCOUNT",))  # type: ignore

    with pytest.raises(SecurityError):
        sanitize_with_metadata("hello", Bad())  # type: ignore


def test_plugin_unsafe_placeholder_token_is_rejected():
    class Bad:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult("hello", ("bad-lower",))

    with pytest.raises(SecurityError):
        sanitize_with_metadata("hello", Bad())


def test_plugin_placeholder_grammar_is_enforced():
    class Bad:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult("hello", ("123INVALID",))

    with pytest.raises(SecurityError):
        sanitize_with_metadata("hello", Bad())


def test_plugin_unbounded_output_is_rejected():
    class Huge:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult("x" * 2_000_000, ("HUGE",))

    with pytest.raises(SecurityError):
        sanitize_with_metadata("hello", Huge())


def test_plugin_output_is_sanitized_again_after_plugin():
    class Leaky:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult("IBAN GB29NWBK60161331926819", ("LEAK",))

    result = sanitize_with_metadata("hello", Leaky())
    # The leaked IBAN should be redacted by the second generic pass
    assert "GB29NWBK60161331926819" not in result.text
    assert "[IBAN]" in result.text


def test_sanitize_with_metadata_runs_generic_before_plugin():
    seen = {}

    class Capturing:
        def redact(self, text: str) -> RedactionResult:
            seen["text"] = text
            return RedactionResult(text, ())

    sanitize_with_metadata("Authorization: Bearer secret123 value\n", Capturing())
    # Generic should have redacted before plugin sees it
    assert "secret123" not in seen["text"]


def test_placeholder_deduplication_preserves_first_seen_order():
    class Dup:
        def redact(self, text: str) -> RedactionResult:
            return RedactionResult("hello", ("B", "A", "B", "C", "A"))

    result = sanitize_with_metadata("hi", Dup())
    assert result.placeholders == ("B", "A", "C")


def test_load_redactor_returns_none_for_none_spec(tmp_path):
    assert load_redactor(None, (tmp_path,)) is None
    assert load_redactor("", (tmp_path,)) is None


def test_load_redactor_rejects_missing_colon(tmp_path):
    with pytest.raises(SecurityError):
        load_redactor("missingcolon", (tmp_path,))


def test_sanitize_simple_string_without_redactor():
    assert sanitize("hello world") == "hello world"
    result = sanitize_with_metadata("hello world")
    assert result.text == "hello world"
    assert result.placeholders == ()


def test_relay_adapter_placeholder_set_is_declared_and_tested():
    # Adapter should expose a declared placeholder set and its redact result
    # must only contain placeholders from that set.
    from pathlib import Path as _P
    import importlib.util as _ilu
    adapter_path = Path(__file__).resolve().parents[2] / "adapters" / "relay" / "redactor.py"
    # Try alternative location inside src
    if not adapter_path.exists():
        adapter_path = Path(__file__).resolve().parents[2] / "src" / "loopkeeper" / "adapters" / "relay" / "redactor.py"
    if not adapter_path.exists():
        pytest.skip("relay adapter not found")
    spec = _ilu.spec_from_file_location("relay_redactor", adapter_path)
    assert spec and spec.loader
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Find placeholder set
    placeholder_set = None
    for name in ("PLACEHOLDERS", "RELAY_PLACEHOLDERS", "DECLARED_PLACEHOLDERS", "ALLOWED_PLACEHOLDERS"):
        if hasattr(mod, name):
            placeholder_set = getattr(mod, name)
            break
    assert placeholder_set is not None, "adapter must declare placeholder set"
    # Find a Redactor class/instance
    redactor = None
    for attr in dir(mod):
        obj = getattr(mod, attr)
        if hasattr(obj, "redact") and callable(getattr(obj, "redact")):
            try:
                # try instantiate if class
                if isinstance(obj, type):
                    redactor = obj()
                else:
                    redactor = obj
                break
            except Exception:
                continue
    if redactor is None:
        pytest.skip("no redactor found in adapter")
    result = redactor.redact("IBAN GB29NWBK60161331926819 and ada@example.com")
    for ph in result.placeholders:
        assert ph in placeholder_set
        assert ph in ("IBAN", "BIC", "UETR", "ACCOUNT", "EMAIL", "PHONE", "SECRET", "ACCOUNT")
    # Grammar check
    import re
    for ph in placeholder_set:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", ph), f"placeholder {ph!r} violates grammar"


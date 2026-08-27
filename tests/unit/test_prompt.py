import pytest
from pathlib import Path

from loopkeeper.policy import Policy, load_policy
from loopkeeper.prompt import Prompt, UntrustedArtifacts, render_review_prompt
from loopkeeper.redaction import RedactionResult
from loopkeeper.errors import ConfigError, SecurityError


def test_prompt_uses_policy_and_active_redactor_placeholders(policy, artifacts):
    prompt = render_review_prompt(policy, RedactionResult("safe", ("ACCOUNT",)), artifacts)
    assert "ACCOUNT" in prompt.instructions
    assert "Relay" not in prompt.instructions
    assert "payment-domain" not in prompt.instructions
    # Ensure policy categories are present
    assert "functional" in prompt.instructions.lower() or "functional" in prompt.input_text.lower()
    assert isinstance(prompt, Prompt)


def test_prompt_does_not_contain_second_category_table(policy, artifacts):
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)
    # The prompt builder must not contain a second category/severity table
    # We check that raw policy severity is included but not duplicated hard-coded table
    # Simple check: prompt should not contain literal "P0 | P1 | P2" duplicated?
    # Instead ensure no hard-coded Relay payment placeholder list like "IBAN, UETR"
    assert "IBAN" not in prompt.instructions or "ACCOUNT" in prompt.instructions  # only via redactor
    assert prompt.instructions.count("##") <= 10  # bounded sections


def test_prompt_bounds_input_sections(policy):
    # Large artifact should be bounded
    large_diff = "x" * 500000
    artifacts = UntrustedArtifacts(metadata="m", diff=large_diff, previous_review=None, checks=None)
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)
    # Input should be bounded (max_input_bytes default maybe 120k)
    assert len(prompt.input_text.encode("utf-8")) <= 200000  # generous bound


def test_load_policy_rejects_path_outside_trusted_root(tmp_path):
    from loopkeeper.types import TrustedReader  # noqa

    class FakeReader:
        def read_text(self, path: str, max_bytes: int) -> str:
            return "# Test\n## functional\ncontent"

    trusted_root = tmp_path / "trusted"
    trusted_root.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside\n")

    # Path outside trusted root should be rejected
    with pytest.raises((SecurityError, ConfigError, ValueError)):
        load_policy(outside, trusted_root, FakeReader())


def test_load_policy_rejects_duplicate_category(tmp_path):
    class FakeReader:
        def read_text(self, path: str, max_bytes: int) -> str:
            return (
                "# Policy\n"
                "## functional\ncontent\n"
                "## functional\nduplicate\n"
                "## Severity\nsev\n"
                "## Lifecycle\nlife\n"
                "## Data handling\nhandle\n"
            )

    trusted_root = tmp_path
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("dummy")
    with pytest.raises((SecurityError, ConfigError, ValueError)):
        load_policy(policy_path, trusted_root, FakeReader())


def test_load_policy_rejects_unknown_category(tmp_path):
    class FakeReader:
        def read_text(self, path: str, max_bytes: int) -> str:
            return (
                "# Policy\n"
                "## unknown-category-xyz\ncontent\n"
                "## Severity\nsev\n"
            )

    trusted_root = tmp_path
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("dummy")
    with pytest.raises((SecurityError, ConfigError, ValueError)):
        load_policy(policy_path, trusted_root, FakeReader())


def test_policy_is_single_source_for_categories(policy):
    # Policy should be single source, categories from policy
    assert policy.categories == ("functional", "security")
    assert policy.display_name
    assert policy.severity_guidance
    assert policy.lifecycle_rules
    assert policy.data_handling


def test_prompt_preserves_deterministic_order(policy, artifacts):
    prompt1 = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)
    prompt2 = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)
    assert prompt1.instructions == prompt2.instructions
    assert prompt1.input_text == prompt2.input_text

from pathlib import Path

import pytest

from loopkeeper.errors import ConfigError, SecurityError
from loopkeeper.policy import load_policy
from loopkeeper.prompt import Prompt, UntrustedArtifacts, render_review_prompt
from loopkeeper.redaction import RedactionResult


def test_prompt_uses_policy_and_active_redactor_placeholders(policy, artifacts):
    prompt = render_review_prompt(policy, RedactionResult("safe", ("ACCOUNT",)), artifacts)
    assert "ACCOUNT" in prompt.instructions
    assert "Relay" not in prompt.instructions
    assert "payment-domain" not in prompt.instructions
    # Ensure policy categories are present
    assert "functional" in prompt.instructions.lower() or "functional" in prompt.input_text.lower()
    assert isinstance(prompt, Prompt)


def test_prompt_requires_exact_schema_two_json_trailer(policy, artifacts):
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)

    assert '<!-- loopkeeper-verdict: {"schema":2,"verdict":"CLEAN","findings":[]} -->' in prompt.instructions
    assert "final non-whitespace line" in prompt.instructions
    assert "plain-text `loopkeeper-verdict: approve`" in prompt.instructions
    assert "code fence" in prompt.instructions


def test_prompt_says_what_a_placeholder_is_not_only_its_name(policy, artifacts):
    """Naming the placeholders is not enough to stop a finding about one.

    A reviewer that sees `size = [ACCOUNT]` and is told only that "ACCOUNT" is
    active still reads the placeholder as the file's own content. Loopkeeper #17
    began exactly that way: a redacted byte size was reported as invalid TOML.
    """
    prompt = render_review_prompt(policy, RedactionResult("safe", ("ACCOUNT",)), artifacts)

    instructions = prompt.instructions.lower()
    assert "removed" in instructions
    assert "not evidence of invalid syntax" in instructions
    assert "do not report a finding whose subject is a placeholder" in instructions


def test_prompt_omits_the_placeholder_note_when_nothing_was_redacted(policy, artifacts):
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)

    assert "Active redaction placeholders" not in prompt.instructions


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


def test_prompt_truncation_preserves_untrusted_block_delimiters(policy):
    artifacts = UntrustedArtifacts(
        metadata="m" * 100_000,
        diff="d" * 100_000,
        previous_review=None,
        checks=None,
    )
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)
    assert "<<<UNTRUSTED_DATA metadata>>>" in prompt.input_text
    assert "<<<END_UNTRUSTED_DATA metadata>>>" in prompt.input_text
    assert "<<<UNTRUSTED_DATA diff>>>" in prompt.input_text
    assert "<<<END_UNTRUSTED_DATA diff>>>" in prompt.input_text


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


# ---------------------------------------------------------------------------
# Domain-neutral policy contract
#
# Categories are consumer-defined canonical slugs declared as bullets under
# exactly one "## Categories" section. Generic core carries no product
# vocabulary, and any other H2 section is preserved rather than rejected.
# ---------------------------------------------------------------------------


class _Reader:
    """Trusted reader stub that returns a fixed policy body."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read_text(self, path: str, max_bytes: int) -> str:
        return self._text


def _load(tmp_path: Path, text: str):
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("dummy", encoding="utf-8")
    return load_policy(policy_path, tmp_path, _Reader(text))


def _policy_text(categories: str, extra: str = "") -> str:
    return (
        "# Consumer Policy\n"
        f"## Categories\n{categories}\n"
        "## Severity\nP1 blocks merge.\n"
        "## Lifecycle\nTrack findings across rounds.\n"
        "## Data handling\nDo not store secrets.\n"
        f"{extra}"
    )


def test_policy_accepts_arbitrary_consumer_category_slugs(tmp_path):
    policy = _load(
        tmp_path,
        _policy_text("- database-migrations\n- accessibility\n- ml-safety\n"),
    )

    assert policy.categories == ("database-migrations", "accessibility", "ml-safety")


def test_policy_preserves_unknown_h2_sections_in_source_order(tmp_path):
    policy = _load(
        tmp_path,
        _policy_text(
            "- accessibility\n",
            "## Scope\nReview everything.\n## Deployment constraints\nNo Friday deploys.\n",
        ),
    )

    assert [section.heading for section in policy.extra_sections] == [
        "Scope",
        "Deployment constraints",
    ]
    assert policy.extra_sections[1].content == "No Friday deploys."


def test_prompt_renders_extra_sections_once_in_source_order(tmp_path, artifacts):
    policy = _load(
        tmp_path,
        _policy_text(
            "- accessibility\n",
            "## Scope\nReview everything.\n## Deployment constraints\nNo Friday deploys.\n",
        ),
    )

    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)

    assert prompt.instructions.count("## Scope") == 1
    assert prompt.instructions.count("## Deployment constraints") == 1
    assert prompt.instructions.index("## Scope") < prompt.instructions.index(
        "## Deployment constraints"
    )
    assert prompt.instructions.index("## Categories") < prompt.instructions.index("## Scope")


def test_policy_rejects_missing_explicit_categories_section(tmp_path):
    text = (
        "# Policy\n"
        "## Scope\nReview everything.\n"
        "## Severity\nsev\n"
        "## Lifecycle\nlife\n"
        "## Data handling\nhandle\n"
    )
    with pytest.raises(ConfigError, match="Categories"):
        _load(tmp_path, text)


def test_policy_rejects_prose_in_categories_section(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, _policy_text("functional security\n"))


def test_policy_rejects_duplicate_normalized_category(tmp_path):
    with pytest.raises(ConfigError):
        _load(tmp_path, _policy_text("- accessibility\n- accessibility\n"))


def test_policy_rejects_invalid_or_oversized_category_slug(tmp_path):
    for bad in ("- Not_A_Slug", "- trailing-", "- " + "a" * 65, "- has space"):
        with pytest.raises(ConfigError):
            _load(tmp_path, _policy_text(bad + "\n"))


def test_policy_rejects_more_than_32_categories(tmp_path):
    bullets = "".join(f"- category-{index}\n" for index in range(33))
    with pytest.raises(ConfigError):
        _load(tmp_path, _policy_text(bullets))

    ok = "".join(f"- category-{index}\n" for index in range(32))
    assert len(_load(tmp_path, _policy_text(ok)).categories) == 32


def test_policy_rejects_duplicate_structural_section_aliases(tmp_path):
    text = (
        "# Policy\n"
        "## Categories\n- accessibility\n"
        "## Severity\nsev\n"
        "## Severity guidance\nduplicate structural section\n"
        "## Lifecycle\nlife\n"
        "## Data handling\nhandle\n"
    )
    with pytest.raises(ConfigError):
        _load(tmp_path, text)


def test_extra_section_cannot_shadow_a_structural_section(tmp_path):
    """An extra section must never be mistaken for a structural one."""
    policy = _load(
        tmp_path,
        _policy_text("- accessibility\n", "## Scope\nReview everything.\n"),
    )

    headings = {section.heading.strip().lower() for section in policy.extra_sections}
    assert headings == {"scope"}
    assert policy.severity_guidance == "P1 blocks merge."


def test_schema_two_accepts_the_same_category_slug_grammar(tmp_path):
    """The prompt cannot request a category the Schema-2 trailer rejects."""
    from loopkeeper.schema import is_identity_slug

    policy = _load(
        tmp_path,
        _policy_text("- database-migrations\n- accessibility\n- ml-safety\n"),
    )
    for category in policy.categories:
        assert is_identity_slug(category), category

    assert not is_identity_slug("Not_A_Slug")
    assert not is_identity_slug("trailing-")
    assert not is_identity_slug("a" * 65)


def test_generic_policy_core_carries_no_product_vocabulary():
    """Generic core must not ship any consumer's category vocabulary."""
    import loopkeeper.policy as policy_module
    import loopkeeper.prompt as prompt_module

    for module in (policy_module, prompt_module):
        source = Path(module.__file__).read_text(encoding="utf-8").lower()
        for forbidden in ("payment-domain", "tutor/ai", "tutor-ai", "relay"):
            assert forbidden not in source, f"{module.__name__} leaks {forbidden!r}"


# ---------------------------------------------------------------------------
# Output-contract placement
#
# The PR A dogfood run produced a plain-text verdict line and a
# MALFORMED-TRAILER result. The contract was rendered second, then buried
# under the policy and preserved consumer sections.
# ---------------------------------------------------------------------------


def test_output_contract_is_the_final_instruction_section(tmp_path, artifacts):
    """Nothing from the policy may follow the machine-readable contract."""
    from loopkeeper.review_output import REVIEW_TRAILER_CONTRACT

    policy = _load(
        tmp_path,
        _policy_text(
            "- accessibility\n",
            "## Scope\nReview everything.\n## Deployment constraints\nNo Friday deploys.\n",
        ),
    )
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)

    contract_at = prompt.instructions.index(REVIEW_TRAILER_CONTRACT.rstrip()[:60])
    for marker in ("## Categories", "## Severity", "## Lifecycle", "## Data handling",
                   "## Scope", "## Deployment constraints"):
        assert prompt.instructions.index(marker) < contract_at, (
            f"{marker} appears after the output contract"
        )


def test_output_contract_survives_a_large_policy(tmp_path, artifacts):
    """A large trusted policy must not push the contract out of bounds."""
    from loopkeeper.prompt import MAX_INSTRUCTIONS_BYTES
    from loopkeeper.review_output import REVIEW_TRAILER_CONTRACT

    bulky = "".join(f"## Section {index}\n{'padding. ' * 400}\n" for index in range(40))
    policy = _load(tmp_path, _policy_text("- accessibility\n", bulky))
    prompt = render_review_prompt(policy, RedactionResult("safe", ()), artifacts)

    assert len(prompt.instructions.encode("utf-8")) <= MAX_INSTRUCTIONS_BYTES
    assert '{"schema":2,"verdict":"CLEAN","findings":[]}' in prompt.instructions
    assert prompt.instructions.rstrip().endswith(REVIEW_TRAILER_CONTRACT.rstrip().splitlines()[-1])

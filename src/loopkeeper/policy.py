"""Trusted policy loading for Loopkeeper.

The policy file is the single source for categories, severity guidance,
lifecycle instructions, data handling, and display name. The loader rejects
paths outside the validated trusted root and never opens a raw path.

Categories are consumer-defined. Generic core carries no product vocabulary:
a policy declares its own canonical category slugs as Markdown bullets under
exactly one ``## Categories`` section, and any other ``##`` section is
preserved verbatim, in source order, rather than rejected or reinterpreted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError, SecurityError
from .schema import is_identity_slug

MAX_POLICY_BYTES = 1_000_000
MAX_SECTION_BYTES = 100_000
MAX_CATEGORIES = 32

# Aliases are recognised for the four structural fields only. Every other
# heading is consumer-owned content, never a category and never a keyword.
CATEGORIES_HEADINGS = {"categories"}
SEVERITY_HEADINGS = {"severity", "severity guidance"}
LIFECYCLE_HEADINGS = {"lifecycle", "lifecycle rules", "finding lifecycle"}
DATA_HANDLING_HEADINGS = {"data handling"}

_BULLET_RE = re.compile(r"^[-*]\s+(?P<slug>\S.*)$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _norm_heading(text: str) -> str:
    return re.sub(r"[\s_]+", " ", text.strip().lower()).strip()


@dataclass(frozen=True)
class PolicySection:
    """A consumer-owned policy section preserved without interpretation."""

    heading: str
    content: str


@dataclass(frozen=True)
class Policy:
    display_name: str
    categories: tuple[str, ...]
    severity_guidance: str
    lifecycle_rules: str
    data_handling: str
    extra_sections: tuple[PolicySection, ...] = field(default=())


def _is_within(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except AttributeError:  # pragma: no cover - Python < 3.9
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False
    except (OSError, RuntimeError):
        return False


def _parse_categories(content: str) -> tuple[str, ...]:
    """Parse one canonical slug per Markdown bullet, preserving order."""
    categories: list[str] = []
    seen: set[str] = set()
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _BULLET_RE.match(line)
        if not match:
            raise ConfigError(
                "the Categories section must contain one Markdown bullet per "
                f"category (offending line: {line!r})"
            )
        slug = match.group("slug").strip()
        if not is_identity_slug(slug):
            raise ConfigError(
                f"category {slug!r} is not a canonical slug: use 1-64 characters "
                "of lowercase kebab-case, for example 'database-migrations'"
            )
        if slug in seen:
            raise ConfigError(f"duplicate category: {slug!r}")
        seen.add(slug)
        categories.append(slug)
        if len(categories) > MAX_CATEGORIES:
            raise ConfigError(f"policy declares more than {MAX_CATEGORIES} categories")
    if not categories:
        raise ConfigError("the Categories section declares no categories")
    return tuple(categories)


def load_policy(path: Path, trusted_root: Path, reader) -> Policy:
    if not isinstance(path, Path) or not isinstance(trusted_root, Path):
        raise ConfigError("path and trusted_root must be Path")
    if not _is_within(path, trusted_root):
        raise SecurityError(f"policy path {path!r} is outside trusted root {trusted_root!r}")

    # Never open the raw path; the trusted reader owns file access.
    try:
        text = reader.read_text(str(path), MAX_POLICY_BYTES)
    except FileNotFoundError as exc:
        raise ConfigError(f"policy file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"failed to read policy: {exc}") from exc

    if not isinstance(text, str):
        raise ConfigError("policy reader must return str")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ConfigError(f"policy exceeds byte ceiling {MAX_POLICY_BYTES}")
    if not text.strip():
        raise ConfigError("policy is empty")

    display_name = ""
    for line in text.splitlines():
        if line.startswith("# "):
            display_name = line[2:].strip()
            break
    if not display_name:
        raise ConfigError("policy missing display_name (first '# ' heading)")
    if len(display_name.encode("utf-8")) > MAX_SECTION_BYTES:
        raise ConfigError("display_name section exceeds byte ceiling")

    matches = list(re.finditer(r"^##\s+(.+?)\s*$", text, re.MULTILINE))
    if not matches:
        raise ConfigError("policy missing sections (no '## ' headings)")

    categories: tuple[str, ...] | None = None
    severity_guidance = ""
    lifecycle_rules = ""
    data_handling = ""
    extra_sections: list[PolicySection] = []
    seen_headings: set[str] = set()

    for index, match in enumerate(matches):
        heading_raw = match.group(1)
        heading_norm = _norm_heading(heading_raw)
        if heading_norm in seen_headings:
            raise ConfigError(f"duplicate section heading: {heading_raw!r}")
        seen_headings.add(heading_norm)

        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        content = text[start:end].strip()
        if len(content.encode("utf-8")) > MAX_SECTION_BYTES:
            raise ConfigError(f"section {heading_raw!r} exceeds byte ceiling {MAX_SECTION_BYTES}")

        if heading_norm in CATEGORIES_HEADINGS:
            if categories is not None:
                raise ConfigError("duplicate Categories section")
            categories = _parse_categories(content)
        elif heading_norm in SEVERITY_HEADINGS:
            if severity_guidance:
                raise ConfigError("duplicate severity section")
            severity_guidance = content
        elif heading_norm in LIFECYCLE_HEADINGS:
            if lifecycle_rules:
                raise ConfigError("duplicate lifecycle section")
            lifecycle_rules = content
        elif heading_norm in DATA_HANDLING_HEADINGS:
            if data_handling:
                raise ConfigError("duplicate data_handling section")
            data_handling = content
        else:
            # Consumer-owned. Preserved verbatim and in source order; it is
            # never treated as a category or as structural guidance.
            if _CONTROL_RE.search(heading_raw):
                raise ConfigError(f"section heading contains control characters: {heading_raw!r}")
            extra_sections.append(PolicySection(heading=heading_raw, content=content))

    if categories is None:
        raise ConfigError(
            "policy missing a '## Categories' section declaring one canonical "
            "category slug per Markdown bullet"
        )
    if not severity_guidance:
        raise ConfigError("policy missing severity_guidance section")
    if not lifecycle_rules:
        raise ConfigError("policy missing lifecycle_rules section")
    if not data_handling:
        raise ConfigError("policy missing data_handling section")

    return Policy(
        display_name=display_name,
        categories=categories,
        severity_guidance=severity_guidance,
        lifecycle_rules=lifecycle_rules,
        data_handling=data_handling,
        extra_sections=tuple(extra_sections),
    )

"""Trusted policy loading for Loopkeeper.

The policy file is the single source for categories, severity guidance,
lifecycle instructions, data handling, and display name. The loader
rejects paths outside the validated trusted root and never opens a raw path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError, SecurityError

MAX_POLICY_BYTES = 1_000_000
MAX_SECTION_BYTES = 100_000

# Known headings
CATEGORIES_HEADINGS = {"categories", "review completeness contract", "review completeness"}
SEVERITY_HEADINGS = {"severity", "severity guidance", "severity_guidance"}
LIFECYCLE_HEADINGS = {"lifecycle", "lifecycle rules", "lifecycle_rules", "finding lifecycle", "finding_lifecycle"}
DATA_HANDLING_HEADINGS = {"data handling", "data_handling", "data-handling"}
# Other known free-form headings that are allowed but not part of Policy
OTHER_KNOWN_HEADINGS = {
    "review order",
    "automation boundary",
    "verification quality",
    "build/release/deployment",
    "frontend/runtime behavior",
}

DISPLAY_HEADINGS = set()  # display_name comes from H1

# Machine-readable categories – the review matrix categories
ALLOWED_CATEGORIES = {
    "functional",
    "security",
    "payment-domain",
    "payment",
    "payment-domain integrity",
    "payment-domain-integrity",
    "tutor",
    "tutor/ai integrity",
    "tutor-ai-integrity",
    "frontend",
    "frontend/runtime behavior",
    "frontend-runtime-behavior",
    "build",
    "build/release/deployment",
    "build-release-deployment",
    "verification",
    "verification quality",
    "functional correctness",
    "security and privacy",
}

# Normalize category for comparison: lower, strip, collapse spaces/hyphens
def _norm_heading(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower()).strip()

def _norm_category(cat: str) -> str:
    # For category comparison, use lower, hyphens, spaces normalized
    c = cat.strip().lower()
    c = re.sub(r"[\s_]+", "-", c)
    c = re.sub(r"-+", "-", c)
    return c


@dataclass(frozen=True)
class Policy:
    display_name: str
    categories: tuple[str, ...]
    severity_guidance: str
    lifecycle_rules: str
    data_handling: str


def _is_within(path: Path, root: Path) -> bool:
    try:
        # Python 3.9+ has is_relative_to
        return path.resolve().is_relative_to(root.resolve())  # type: ignore[attr-defined]
    except AttributeError:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False
    except (OSError, RuntimeError):
        return False


def load_policy(path: Path, trusted_root: Path, reader) -> Policy:
    if not isinstance(path, Path) or not isinstance(trusted_root, Path):
        raise ConfigError("path and trusted_root must be Path")
    # Reject path outside trusted root
    # Must check before reading
    # Ensure trusted_root is absolute and exists? For tests, trusted_root may be tmp_path
    # We check is_within strictly
    if not _is_within(path, trusted_root):
        # Also handle case where path is relative and trusted_root is absolute: need to resolve
        # If path is not absolute, consider it relative to trusted_root? Check
        # For safety, if path is not within trusted_root, reject
        raise SecurityError(f"policy path {path!r} is outside trusted root {trusted_root!r}")

    # Never open raw path; use reader only
    # Reader is TrustedReader: read_text(path_str, max_bytes)
    try:
        text = reader.read_text(str(path), MAX_POLICY_BYTES)
    except FileNotFoundError as e:
        raise ConfigError(f"policy file not found: {path}") from e
    except OSError as e:
        raise ConfigError(f"failed to read policy: {e}") from e

    if not isinstance(text, str):
        raise ConfigError("policy reader must return str")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ConfigError(f"policy exceeds byte ceiling {MAX_POLICY_BYTES}")
    if not text.strip():
        raise ConfigError("policy is empty")

    # Extract display_name from first H1
    display_name = ""
    for line in text.splitlines():
        if line.startswith("# "):
            display_name = line[2:].strip()
            break
    if not display_name:
        raise ConfigError("policy missing display_name (first '# ' heading)")

    if len(display_name.encode("utf-8")) > MAX_SECTION_BYTES:
        raise ConfigError("display_name section exceeds byte ceiling")

    # Parse H2 sections: ## heading
    # Use regex to find headings
    pattern = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if not matches:
        raise ConfigError("policy missing sections (no '## ' headings)")

    seen_raw: set[str] = set()
    categories: list[str] = []
    severity_guidance = ""
    lifecycle_rules = ""
    data_handling = ""

    # Helper to get section content between headings
    # First pass: collect raw sections
    raw_sections: list[tuple[str, str, str]] = []  # (raw, norm, content)
    for idx, m in enumerate(matches):
        heading_raw = m.group(1)
        heading_norm = _norm_heading(heading_raw)
        # Check duplicate heading (case-insensitive)
        if heading_norm in seen_raw:
            raise ConfigError(f"duplicate section heading: {heading_raw!r}")
        seen_raw.add(heading_norm)

        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        content = text[start:end].strip()

        # Bound each section
        if len(content.encode("utf-8")) > MAX_SECTION_BYTES:
            raise ConfigError(f"section {heading_raw!r} exceeds byte ceiling {MAX_SECTION_BYTES}")

        raw_sections.append((heading_raw, heading_norm, content))

    # Second pass: interpret headings
    # Collect categories from per-category headings and/or categories contract section
    categories_from_headings: list[str] = []
    categories_section_content: str | None = None

    for heading_raw, heading_norm, content in raw_sections:
        if heading_norm in CATEGORIES_HEADINGS:
            categories_section_content = content
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
        elif heading_norm in OTHER_KNOWN_HEADINGS:
            # Allow but ignore for Policy
            continue
        else:
            # Treat as machine-readable category heading if it matches category pattern
            cat_slug = _norm_category(heading_raw)
            allowed_norms = {_norm_heading(c) for c in ALLOWED_CATEGORIES} | {_norm_category(c) for c in ALLOWED_CATEGORIES}
            if heading_norm in allowed_norms or cat_slug in allowed_norms:
                categories_from_headings.append(heading_norm)
            elif re.fullmatch(r"[a-z0-9][a-z0-9\-\s_/]*", heading_norm):
                # Looks machine-readable but not in allowed -> unknown category
                raise ConfigError(f"unknown category heading: {heading_raw!r}")
            else:
                # Unknown free-form heading not in known list – allow but don't treat as category?
                # For strictness, reject if not known
                # But to support real policy with headings like "Review order", we already handled via OTHER_KNOWN
                # So this branch now only triggers for truly unknown headings like "unknown-category-xyz" which is machine-readable
                # For non-machine-readable unknown, we reject as well to keep determinism
                raise ConfigError(f"unknown section heading: {heading_raw!r}")

    # Determine final categories: per-heading categories take precedence; if none, parse from categories section content
    if categories_from_headings:
        categories = categories_from_headings
    elif categories_section_content is not None:
        content_lower = categories_section_content.lower()
        # Use short canonical slugs for content parsing to avoid duplicate long forms
        SHORT_SLUGS = ["functional", "security", "payment-domain", "tutor", "frontend", "build", "verification"]
        found: list[tuple[int, str]] = []
        for slug in SHORT_SLUGS:
            # Search for slug and its long-form variants
            # For functional, also match "functional correctness"
            # For security, match "security and privacy"
            variants = [slug]
            if slug == "functional":
                variants.append("functional correctness")
            elif slug == "security":
                variants.append("security and privacy")
            elif slug == "payment-domain":
                variants.append("payment-domain integrity")
            elif slug == "tutor":
                variants.append("tutor/ai integrity")
            elif slug == "frontend":
                variants.append("frontend/runtime behavior")
            elif slug == "build":
                variants.append("build/release/deployment")
            elif slug == "verification":
                variants.append("verification quality")
            best_idx = None
            for var in variants:
                idx = content_lower.find(var)
                if idx != -1 and (best_idx is None or idx < best_idx):
                    best_idx = idx
            if best_idx is not None:
                found.append((best_idx, slug))
        found.sort()
        for _, slug in found:
            categories.append(slug)
    if not categories:
        raise ConfigError("policy missing categories (no known category headings)")
    if not severity_guidance:
        raise ConfigError("policy missing severity_guidance section")
    if not lifecycle_rules:
        raise ConfigError("policy missing lifecycle_rules section")
    if not data_handling:
        raise ConfigError("policy missing data_handling section")

    # Deduplicate categories already checked via duplicate heading, but also ensure no duplicate after normalization
    seen_cats: set[str] = set()
    for c in categories:
        if c in seen_cats:
            raise ConfigError(f"duplicate category: {c!r}")
        seen_cats.add(c)

    # Preserve deterministic order as in file (already)
    return Policy(
        display_name=display_name,
        categories=tuple(categories),
        severity_guidance=severity_guidance,
        lifecycle_rules=lifecycle_rules,
        data_handling=data_handling,
    )

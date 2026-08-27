"""Trusted agent definition loading for Loopkeeper.

The definition file is plain Markdown with YAML frontmatter for dispatch
metadata (name, description, tools, model). The body is the role prompt and
is trusted instructions, so it rides the same channel the review policy does.

All reads go through the provided TrustedReader bound to the verified root,
never a raw filesystem read. The frontmatter is dispatch metadata for
Claude Code's dispatcher and is not trusted beyond name/description.

The loader requires:
- fenced frontmatter starting with "---\\n" and closing with "\\n---"
- name and description fields in frontmatter
- bounded file and body sizes (fail-closed)

Ported from Relay's agent_runner.load_role_text with trust-boundary hardening.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import SecurityError

# Bounded sizes — oversize bodies fail closed.
# The brief's parametrized test uses 200001 bytes to trigger oversize,
# so the ceiling is 200_000.
MAX_DEFINITION_BYTES = 200_000
MAX_DEFINITION_BODY_BYTES = 200_000

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_AGENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class AgentDefinition:
    """Parsed agent definition.

    Attributes:
        name: Agent slug, e.g. "domain-researcher".
        description: Human-readable description from frontmatter.
        body: Trusted role prompt (everything after frontmatter fence).
        raw_frontmatter: Raw frontmatter text for audit.
    """

    name: str
    description: str
    body: str
    raw_frontmatter: str


def _is_within(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())  # type: ignore[attr-defined]
    except AttributeError:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except ValueError:
            return False
    except Exception:
        return False


def _validate_path_confinement(path: Path, trusted_root: Path) -> tuple[Path, str]:
    """Validate that path is inside trusted_root and return (candidate, read_path).

    Accepts both absolute and relative Paths. For relative, the read_path is
    the relative string; for absolute, it is the path relative to the root.
    """
    if not isinstance(path, Path):
        raise SecurityError("path must be Path")
    if not isinstance(trusted_root, Path):
        raise SecurityError("trusted_root must be Path")

    # Reject control characters in string form
    raw_str = str(path)
    if _CONTROL_RE.search(raw_str):
        raise SecurityError(f"path contains control characters: {raw_str!r}")
    if "\x00" in raw_str:
        raise SecurityError(f"path contains NUL: {raw_str!r}")

    if path.is_absolute():
        # Absolute: must be inside trusted_root
        try:
            root_resolved = trusted_root.resolve()
            candidate = path.resolve()
        except Exception as exc:
            raise SecurityError(f"cannot resolve path {path!r}: {exc}") from exc
        if not _is_within(candidate, trusted_root):
            raise SecurityError(f"path {path!r} escapes trusted root {trusted_root!r}")
        # Derive relative string for TrustedReader
        try:
            rel = candidate.relative_to(root_resolved)
            read_path = str(rel)
        except Exception:
            # Fallback to original string if relative fails (should not happen after _is_within)
            read_path = str(path)
        # Also ensure the relative string itself is not escaping
        if PurePosixPath(read_path).is_absolute() or ".." in PurePosixPath(read_path).parts:
            raise SecurityError(f"path {path!r} escapes trusted root")
        return candidate, read_path
    else:
        # Relative: reject absolute-like and traversal
        raw = str(path)
        # Use PurePosixPath for checks (handles both / and \)
        if raw.startswith("/") or raw.startswith("\\"):
            raise SecurityError(f"absolute path not allowed: {raw!r}")
        if PurePosixPath(raw).is_absolute():
            raise SecurityError(f"absolute path not allowed: {raw!r}")
        if re.match(r"^[A-Za-z]:[\\/]", raw):
            raise SecurityError(f"absolute path not allowed: {raw!r}")
        parts = PurePosixPath(raw).parts
        if ".." in parts:
            raise SecurityError(f"path contains '..': {raw!r}")
        if any(p == ".." for p in raw.split("/")):
            raise SecurityError(f"path contains '..': {raw!r}")
        if ".." in raw.split("\\"):
            raise SecurityError(f"path contains '..': {raw!r}")

        try:
            root_resolved = trusted_root.resolve()
            candidate = (trusted_root / path).resolve()
        except Exception as exc:
            raise SecurityError(f"cannot resolve path {raw!r} against {trusted_root!r}: {exc}") from exc

        if not _is_within(candidate, trusted_root):
            raise SecurityError(f"path {raw!r} leaves declared root {trusted_root!r}")
        return candidate, raw


def _parse_frontmatter(frontmatter: str) -> tuple[str, str]:
    """Extract name and description from frontmatter text.

    The frontmatter is a small YAML-like block. We extract name and
    description without a full YAML parser to avoid a new dependency.
    Supports folded scalar "description: >" with indented continuation lines.
    """
    # Use line-by-line parsing for folded scalars
    lines = frontmatter.splitlines()
    name: str | None = None
    description: str | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        # Skip empty or comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        # Name
        if stripped.startswith("name:"):
            val = stripped[len("name:"):].strip()
            # Strip surrounding quotes
            val = val.strip().strip('"').strip("'")
            # If val is empty, maybe representation is quoted?
            # Take first token
            if val:
                # Remove trailing comment
                val = val.split("#")[0].strip().strip('"').strip("'")
                name = val
        elif stripped.startswith("description:"):
            val = stripped[len("description:"):].strip()
            # Handle folded: ">" or "|" possibly with "-" or number
            # Examples: "description: >" then indented, or "description: >-\n  text"
            # Check if val starts with > or |
            if val.startswith(">") or val.startswith("|"):
                # Collect indented following lines
                # The current line may have ">" alone or with nothing else
                # Strip the indicator and any trailing content on same line
                # For "description: >" there is nothing after; for "description: > something" there is content
                after = val[1:].strip().lstrip("-").strip()
                collected: list[str] = []
                if after:
                    # Some writers put content on same line after ">" (unlikely but handle)
                    # If after is not empty and not a comment, treat as first line
                    # But per our files, it's always on next indented lines
                    collected.append(after.strip().strip('"').strip("'"))
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t") or lines[i].strip() == ""):
                    cont = lines[i].strip()
                    if cont:
                        # Stop if we hit next key? Indented lines are continuation, non-indented with colon is next key
                        # However folded content is indented, so if line is not indented but has content, it's next key
                        # Check if lines[i] is not indented (starts without space) and contains ":"
                        raw = lines[i]
                        if not raw.startswith(" ") and not raw.startswith("\t") and ":" in raw:
                            break
                        collected.append(cont)
                    elif cont == "" and not collected:
                        # Skip leading blank within folded? Treat as break
                        pass
                    i += 1
                description = " ".join(collected).strip()
                # Don't increment again; we already moved i to next key
                continue
            else:
                # Single line description
                # Strip quotes
                desc_val = val.strip().strip('"').strip("'")
                # Handle folded inline ">" already covered; here val is not folded, so just use it
                # If val is empty, maybe next line is folded? Already handled via > case, but also handle if val empty and next lines indented without ">"
                # For our files, description: > newline indented, so we handled.
                # For simple "description: test description", this will capture.
                if not desc_val:
                    # Next lines may be indented continuation even without ">"? Treat as folded
                    collected2: list[str] = []
                    j = i + 1
                    while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                        collected2.append(lines[j].strip())
                        j += 1
                    if collected2:
                        desc_val = " ".join(collected2).strip()
                description = desc_val
        i += 1

    # Fallback regex if not found via line parsing (e.g., compact frontmatter)
    if name is None:
        m = re.search(r"^name:\s*([^\n#]+)", frontmatter, re.MULTILINE)
        if m:
            name = m.group(1).strip().strip('"').strip("'").split()[0]
    if description is None:
        # Look for description presence even if parsing failed
        if "description:" in frontmatter:
            # Extract via regex as last resort: everything after description: up to next key or end
            m2 = re.search(r"^description:\s*([^\n]*(?:\n[ \t]+[^\n]*)*)", frontmatter, re.MULTILINE)
            if m2:
                raw_desc = m2.group(1).strip()
                # Clean folded indicator
                raw_desc = raw_desc.lstrip(">").lstrip("|").strip()
                # Take first line of collected? For "x" case, raw_desc will be ""?
                description = raw_desc if raw_desc else None

    return name or "", description or ""


def parse_definition_text(text: str) -> AgentDefinition:
    """Parse raw definition text into AgentDefinition.

    Requires fenced YAML frontmatter with name and description.
    Bounds file and body sizes.

    Args:
        text: Raw file content (UTF-8).

    Raises:
        ValueError: Missing fence, missing name/description, empty.
        SecurityError: Oversize body or file.
    """
    if not isinstance(text, str):
        raise TypeError("definition text must be str")
    # Bound whole file
    if len(text.encode("utf-8")) > MAX_DEFINITION_BYTES:
        raise SecurityError(f"agent definition exceeds byte ceiling {MAX_DEFINITION_BYTES} (size {len(text.encode('utf-8'))})")
    if not text:
        raise ValueError("agent definition is empty")
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter fence: file must start with '---\\n'")
    # Find closing fence: "\n---" after offset 4
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("unterminated YAML frontmatter fence: missing closing '---'")
    # Extract frontmatter and body
    frontmatter = text[4:end]
    # The text after closing fence: should be "\n---" plus optional newline
    # end points to the "\n" before "---", so the fence is text[end:end+4] == "\n---"
    # Body starts after that.
    body_start = end + 4
    # If there's a newline immediately after, skip it (but preserve body content correctly)
    # The definition body is everything after the fence, stripped of a single leading newline sequence
    if body_start < len(text) and text[body_start] == "\n":
        body = text[body_start + 1 :]
    elif body_start < len(text) and text[body_start:body_start+2] == "\r\n":
        body = text[body_start+2:]
    else:
        body = text[body_start:]
        # Also handle case where body starts with "\n" due to "\n---\n"
        if body.startswith("\n"):
            body = body.lstrip("\n")
        # Preserve body as is (don't lstrip all, but original agent_runner does lstrip("\n"))
        # For consistency with original, we do lstrip("\n") once
        # Actually original did text[end+4:].lstrip("\n")
        # So we mimic that for body
        # But we already handled single newline; for safety also lstrip
        # However we want deterministic.
        pass
    # For original behavior, body = text[end+4:].lstrip("\n")
    # Let's ensure we match that if we haven't already:
    # Re-derive correctly for safety?
    # Recompute using original method to avoid divergence
    # This ensures body is exactly as original loader would produce
    try:
        alt_body = text[end + 4 :].lstrip("\n")
        # Use alt_body as canonical if it differs from our computed body
        # They are same for "\n---\n" case, but for "\n---" without newline, alt_body is same as body
        body = alt_body
    except Exception:
        pass

    # Validate frontmatter contains name and description
    name, description = _parse_frontmatter(frontmatter)
    if not name:
        raise ValueError("agent definition frontmatter missing required 'name'")
    if not description:
        raise ValueError("agent definition frontmatter missing required 'description'")
    # Validate name shape
    if not _AGENT_NAME_RE.fullmatch(name):
        raise ValueError(f"agent name {name!r} must match {_AGENT_NAME_RE.pattern}")

    # Bound body
    if len(body.encode("utf-8")) > MAX_DEFINITION_BODY_BYTES:
        raise SecurityError(f"agent definition body exceeds byte ceiling {MAX_DEFINITION_BODY_BYTES} (size {len(body.encode('utf-8'))})")

    return AgentDefinition(name=name, description=description, body=body, raw_frontmatter=frontmatter)


def load_definition(path: Path, trusted_root: Path, reader) -> AgentDefinition:
    """Load and parse an agent definition via TrustedReader.

    Args:
        path: Path to the definition file (relative or absolute).
        trusted_root: The declared trusted root for this read.
        reader: A TrustedReader bound to the verified trust root.

    Returns:
        Parsed AgentDefinition.

    Raises:
        SecurityError: Path escapes root or oversize.
        ValueError: Missing fence, missing name/description, empty.
        TrustError: Reader fails in a way that maps to trust (unlikely here).
    """
    if not isinstance(trusted_root, Path):
        raise TypeError("trusted_root must be Path")
    if not hasattr(reader, "read_text"):
        raise TypeError("reader must have read_text method")

    # Validate path confinement and derive read path
    _, read_path = _validate_path_confinement(path, trusted_root)

    # Read via TrustedReader with byte ceiling
    text = reader.read_text(read_path, MAX_DEFINITION_BYTES)
    if not isinstance(text, str):
        raise ValueError("TrustedReader must return str")
    if len(text.encode("utf-8")) > MAX_DEFINITION_BYTES:
        raise SecurityError(f"agent definition exceeds byte ceiling {MAX_DEFINITION_BYTES}")

    return parse_definition_text(text)

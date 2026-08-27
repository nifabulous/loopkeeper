"""Path confinement helper for Loopkeeper manifests."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from .errors import ManifestError

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def resolve_bounded_path(raw: str, root: Path, max_bytes: int) -> Path:
    """Resolve ``raw`` against ``root`` without allowing escape.

    Validation is performed before any filesystem read beyond stat:

    - ``raw`` must be a non-empty relative POSIX path with no ``..`` component,
      no absolute prefix, and no control characters.
    - The resolved absolute path must remain inside the resolved ``root``
      (symlink-aware via :meth:`Path.resolve`).
    - If the target exists and is a file, its size must not exceed ``max_bytes``.

    Args:
        raw: The untrusted relative path string from the manifest.
        root: The declared trusted or untrusted root.
        max_bytes: Maximum allowed file size in bytes.

    Returns:
        The resolved absolute :class:`Path` inside ``root``.

    Raises:
        ManifestError: If the path is malformed, escapes the root, or exceeds
            the byte cap. This maps to exit 2.
    """
    if not isinstance(raw, str):
        raise ManifestError("path must be str")
    if not isinstance(root, Path):
        raise ManifestError("root must be Path")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise ManifestError("max_bytes must be int")
    if max_bytes <= 0:
        raise ManifestError("max_bytes must be positive")

    if raw == "":
        raise ManifestError("path must be non-empty")
    if _CONTROL_RE.search(raw):
        raise ManifestError(f"path contains control characters: {raw!r}")
    # Reject absolute paths (POSIX and Windows style)
    if raw.startswith("/") or raw.startswith("\\"):
        raise ManifestError(f"absolute path not allowed: {raw!r}")
    # Also catch via PurePosixPath
    if PurePosixPath(raw).is_absolute():
        raise ManifestError(f"absolute path not allowed: {raw!r}")
    # Reject Windows drive letter absolute like C:\ or C:/
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        raise ManifestError(f"absolute path not allowed: {raw!r}")
    # Reject control via newline etc already handled, but also check for NUL explicitly
    if "\x00" in raw:
        raise ManifestError(f"path contains NUL: {raw!r}")
    # Reject '..' as a path component
    parts = PurePosixPath(raw).parts
    if ".." in parts:
        raise ManifestError(f"path contains '..': {raw!r}")
    # Also reject any segment that after cleaning is '..' (e.g., 'a/../b' already caught)
    # Explicitly split on '/' to catch edge cases like '..' with trailing slash
    if any(p == ".." for p in raw.split("/")):
        raise ManifestError(f"path contains '..': {raw!r}")
    # Also reject if raw contains backslash traversal
    if ".." in raw.split("\\"):
        raise ManifestError(f"path contains '..': {raw!r}")

    # Join and resolve
    try:
        root_resolved = root.resolve()
    except Exception as exc:
        raise ManifestError(f"cannot resolve root {root!r}: {exc}") from exc

    candidate = root / raw
    try:
        candidate_resolved = candidate.resolve()
    except Exception as exc:
        raise ManifestError(f"cannot resolve path {raw!r} against {root!r}: {exc}") from exc

    # Symlink-aware confinement: candidate must be inside root
    try:
        # Python 3.9+ is_relative_to, fallback otherwise
        is_inside = candidate_resolved.is_relative_to(root_resolved)  # type: ignore[attr-defined]
    except AttributeError:
        try:
            candidate_resolved.relative_to(root_resolved)
            is_inside = True
        except ValueError:
            is_inside = False
    except Exception:
        is_inside = False

    if not is_inside:
        raise ManifestError(f"path {raw!r} leaves declared root {root!r}")

    # Byte cap check if file exists
    try:
        if candidate_resolved.exists() and candidate_resolved.is_file():
            size = candidate_resolved.stat().st_size
            if size > max_bytes:
                raise ManifestError(f"file {raw!r} exceeds byte cap {max_bytes} (size {size})")
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"cannot stat file {raw!r}: {exc}") from exc

    return candidate_resolved

"""Exit code mapping for Loopkeeper.

Business dispositions and retained invalid trailers exit 0; config/manifest 2;
transport 3; trust/security 4.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_TRANSPORT = 3
EXIT_TRUST = 4

# Aliases per brief
EXIT_MANIFEST = EXIT_CONFIG
EXIT_SECURITY = EXIT_TRUST

_EXCEPTION_EXIT_MAP: dict[type[BaseException], int] = {}


def exit_code_for_exception(exc: BaseException) -> int:
    """Map an exception to its CLI exit code."""
    # Lazy import to avoid cycle
    from .errors import ManifestError, TrustError, ConfigError, SecurityError, TransportError

    if isinstance(exc, TrustError):
        return EXIT_TRUST
    if isinstance(exc, SecurityError):
        return EXIT_TRUST
    if isinstance(exc, PermissionError):
        return EXIT_TRUST
    if isinstance(exc, ManifestError):
        return EXIT_CONFIG
    if isinstance(exc, ConfigError):
        return EXIT_CONFIG
    if isinstance(exc, TransportError):
        return EXIT_TRANSPORT
    # Default for unknown
    return 1

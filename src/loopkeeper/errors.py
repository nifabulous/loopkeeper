"""Loopkeeper errors."""


class SecurityError(ValueError):
    """Raised for trust-boundary violations: untrusted plugin, unsafe placeholder, or unbounded output."""


class SchemaError(ValueError):
    """Raised for schema validation failures.

    Covers unknown versions, malformed fields, duplicate trailers,
    invalid identity, and invalid lifecycle transitions.
    """


class ConfigError(ValueError):
    """Raised for invalid configuration, missing model binding, or malformed settings."""


class TransportError(RuntimeError):
    """Raised for model transport failures, timeouts, or envelope violations."""


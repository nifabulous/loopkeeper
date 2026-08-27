"""Loopkeeper errors."""


class SecurityError(ValueError):
    """Raised for trust-boundary violations: untrusted plugin, unsafe placeholder, or unbounded output."""


class SchemaError(ValueError):
    """Raised for schema validation failures.

    Covers unknown versions, malformed fields, duplicate trailers,
    invalid identity, and invalid lifecycle transitions.
    """


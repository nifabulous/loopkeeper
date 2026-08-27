"""Loopkeeper schema errors."""


class SchemaError(ValueError):
    """Raised for schema validation failures.

    Covers unknown versions, malformed fields, duplicate trailers,
    invalid identity, and invalid lifecycle transitions.
    """


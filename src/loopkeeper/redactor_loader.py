"""Trusted redactor plugin loading.

Only ``module:object`` specs whose ``module.__file__`` resolves inside a
declared trusted root are accepted.  Builtin or namespace packages without a
file are refused.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import SecurityError

if TYPE_CHECKING:
    from .redaction import Redactor


def validate_plugin_module(module, trusted_roots: tuple[Path, ...]) -> None:
    file = getattr(module, "__file__", None)
    if not file:
        raise SecurityError("module path is not inside trusted environment: module has no file")
    try:
        module_path = Path(file).resolve()
    except Exception as exc:
        raise SecurityError(f"module path is not inside trusted environment: {exc}") from exc
    for root in trusted_roots:
        try:
            trusted = Path(root).resolve()
        except Exception:
            continue
        try:
            module_path.relative_to(trusted)
            return
        except ValueError:
            continue
    raise SecurityError(f"module path {module_path} is not inside trusted environment")


def load_redactor(spec: str | None, trusted_roots: tuple[Path, ...]) -> Redactor | None:
    if spec is None or spec == "":
        return None
    if ":" not in spec:
        raise SecurityError("redactor spec must be 'module:object'")
    module_name, attr = spec.split(":", 1)
    if not module_name or not attr:
        raise SecurityError("redactor spec must be 'module:object'")
    if ":" in attr:
        raise SecurityError("redactor spec must be 'module:object' with single colon")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise SecurityError(f"redactor module not in trusted environment: {exc}") from exc
    # Validate file location before exposing the attribute
    validate_plugin_module(module, trusted_roots)
    try:
        obj = getattr(module, attr)
    except AttributeError as exc:
        raise SecurityError(f"redactor object not found: {attr}") from exc
    if not hasattr(obj, "redact") or not callable(getattr(obj, "redact")):
        raise SecurityError("redactor must have callable redact method")
    return obj


__all__ = ["load_redactor", "validate_plugin_module"]

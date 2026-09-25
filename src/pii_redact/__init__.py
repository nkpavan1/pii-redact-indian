"""pii-redact: local PII redaction and pseudonymization.

The string-level API is importable from the package root:

    from pii_redact import MappingStore, RedactResult, redact_text, reverse_text

Those names are loaded on first use rather than at import time, so importing
the package (or a light submodule such as the key tool) doesn't pull in
Presidio and spaCy.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

__version__ = "0.2.0"

_LAZY_EXPORTS = {
    "MappingStore": "pii_redact.anonymize.mapping_store",
    "RedactResult": "pii_redact.api",
    "TextTooLongError": "pii_redact.api",
    "redact_text": "pii_redact.api",
    "redact_texts": "pii_redact.api",
    "reverse_text": "pii_redact.api",
    "reverse_texts": "pii_redact.api",
}

__all__ = ["__version__", *_LAZY_EXPORTS]

if TYPE_CHECKING:
    from pii_redact.anonymize.mapping_store import MappingStore
    from pii_redact.api import (
        RedactResult,
        TextTooLongError,
        redact_text,
        redact_texts,
        reverse_text,
        reverse_texts,
    )


def __getattr__(name: str):
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value
    return value

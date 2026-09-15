"""JSON extraction.

Recursively walks arbitrary nesting (objects and arrays in any combination)
and emits one TextBlock per string leaf, with an exact path back to that
leaf's position so the render stage can write a replacement to precisely
that location without re-walking the structure itself.

Path format is this project's own (not a JSONPath library dependency, to
keep the footprint small - see project instructions, environment section):
root is "$", each step is `["key"]` (JSON-quoted, so keys containing dots,
quotes, or unicode are unambiguous) or `[N]` for array indices, e.g.
`$["accounts"][0]["ifsc"]`. Only render/json_.py is expected to parse it.

Known limitation, intentional and documented rather than silently missed:
only string leaf values are treated as PII candidates. A PAN or phone
number stored as a JSON number (unusual, but not impossible in a hand-built
export) will not be extracted - NER-scanning numeric leaves as text would
produce far more false positives (any numeric field) than it would ever
catch.

Field-name-driven fast-pathing (per the project instructions' explicit
tradeoff: allow/deny by key, falling back to NER only for unrecognized
fields) is deliberately NOT done here. This extractor's job is only to
surface every string leaf with its path; deciding which fields get
detected via a fast key-name match vs. full NER is the detect stage's
concern; and there is no per-field-name allow-list config surface for it
yet (config/allowlists.py is entity-type-scoped, not key-name-scoped). Flag
this as a follow-up if JSON detection performance on large files becomes
an actual problem, not before.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pii_redact.extract.base import Extractor
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock


class JsonExtractionError(ValueError):
    pass


def _path_with_key(parent_path: str, key: str) -> str:
    return f"{parent_path}[{json.dumps(key)}]"


def _path_with_index(parent_path: str, index: int) -> str:
    return f"{parent_path}[{index}]"


def _walk(value: Any, path: str, blocks: list[TextBlock]) -> None:
    if isinstance(value, dict):
        for key, sub_value in value.items():
            _walk(sub_value, _path_with_key(path, key), blocks)
    elif isinstance(value, list):
        for index, sub_value in enumerate(value):
            _walk(sub_value, _path_with_index(path, index), blocks)
    elif isinstance(value, str):
        if value.strip():
            blocks.append(TextBlock(text=value, location=Location(json_path=path)))
    # int/float/bool/None leaves: intentionally skipped, see module docstring.


def _detect_indent(text: str) -> int | None:
    """Best-effort: returns the leading-space count of the first indented
    line, or None for compact/single-line JSON. Used so the renderer can
    match the source file's formatting style rather than always
    re-serializing compact or with a fixed indent."""
    for line in text.splitlines()[1:]:
        stripped = line.lstrip(" ")
        leading = len(line) - len(stripped)
        if leading > 0 and stripped:
            return leading
    return None


class JsonExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        text = path.read_text(encoding="utf-8-sig")
        try:
            root = json.loads(text)
        except json.JSONDecodeError as exc:
            raise JsonExtractionError(f"{path}: invalid JSON ({exc})") from exc

        blocks: list[TextBlock] = []
        _walk(root, "$", blocks)

        return ExtractedDocument(
            doc_format=DocFormat.JSON,
            source_path=path,
            blocks=blocks,
            format_metadata={"indent": _detect_indent(text)},
        )

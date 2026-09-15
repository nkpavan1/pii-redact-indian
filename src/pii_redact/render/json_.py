"""JSON re-rendering.

Re-parses source_path fresh (same philosophy as render/csv_.py: the
renderer re-reads the source rather than trusting extracted state to be
the full document) and writes replacements back at the exact path recorded
by extract/json_.py, leaving every other value untouched. Rejects a
replacement whose path no longer resolves to a string leaf rather than
guessing - see JsonRenderError uses below.

Known limitations, documented rather than silently missed:
- Non-ASCII output uses raw UTF-8 (ensure_ascii=False) regardless of
  whether the source file used \\uXXXX escapes - semantically identical,
  not necessarily byte-identical.
- Only "pretty with N-space indent" vs "compact" is reproduced (via
  format_metadata["indent"]); exact separator/whitespace style (e.g.
  maximally compact `,`/`:` with no spaces vs json.dump's default
  `', '`/`': '`) is not preserved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument


class JsonRenderError(ValueError):
    pass


def _parse_path(path: str) -> list[str | int]:
    if not path.startswith("$"):
        raise JsonRenderError(f"invalid json_path (must start with '$'): {path!r}")

    tokens: list[str | int] = []
    i, n = 1, len(path)
    while i < n:
        if path[i] != "[":
            raise JsonRenderError(f"invalid json_path syntax at position {i}: {path!r}")
        i += 1
        if i < n and path[i] == '"':
            start = i
            i += 1
            while i < n and path[i] != '"':
                i += 2 if path[i] == "\\" else 1
            if i >= n:
                raise JsonRenderError(f"unterminated string in json_path: {path!r}")
            i += 1  # include closing quote
            tokens.append(json.loads(path[start:i]))
        else:
            start = i
            while i < n and path[i].isdigit():
                i += 1
            if start == i:
                raise JsonRenderError(f"invalid json_path segment at position {start}: {path!r}")
            tokens.append(int(path[start:i]))
        if i >= n or path[i] != "]":
            raise JsonRenderError(f"expected ']' at position {i} in json_path: {path!r}")
        i += 1
    return tokens


def _navigate_to_parent(root: Any, tokens: list[str | int], path: str) -> tuple[Any, str | int]:
    node = root
    for token in tokens[:-1]:
        try:
            node = node[token]
        except (KeyError, IndexError, TypeError) as exc:
            raise JsonRenderError(
                f"json_path {path!r} no longer resolves in the re-read source "
                f"(failed at step {token!r}) - refusing to write a mismatched output"
            ) from exc
    return node, tokens[-1]


class JsonRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        text = source_path.read_text(encoding="utf-8-sig")
        try:
            root = json.loads(text)
        except json.JSONDecodeError as exc:
            raise JsonRenderError(f"{source_path}: invalid JSON on re-read ({exc})") from exc

        for block_index, new_text in replacements.items():
            block = extracted.blocks[block_index]
            path = block.location.json_path
            tokens = _parse_path(path)
            container, last_key = _navigate_to_parent(root, tokens, path)

            try:
                current = container[last_key]
            except (KeyError, IndexError, TypeError) as exc:
                raise JsonRenderError(
                    f"json_path {path!r} no longer resolves in the re-read source - "
                    "refusing to write a mismatched output"
                ) from exc
            if not isinstance(current, str):
                raise JsonRenderError(
                    f"json_path {path!r} now points at a {type(current).__name__}, "
                    "not the string it was when detected - refusing to overwrite it"
                )
            container[last_key] = new_text

        output_path.parent.mkdir(parents=True, exist_ok=True)
        indent = extracted.format_metadata.get("indent")
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(root, f, indent=indent, ensure_ascii=False)
            f.write("\n")

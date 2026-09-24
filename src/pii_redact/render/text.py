"""Plain-text / markdown re-rendering.

Re-reads the source with the encoding extract/text.py recorded and splices
each replaced block back into its recorded (start, end) span, so everything
outside a replaced span is written back byte-for-byte - line endings
included (the file is decoded and re-encoded without newline translation).

Fails closed if the source changed between extract and render: a block's
recorded span must still hold exactly that block's text, otherwise the
replacement would land in the wrong place.
"""

from __future__ import annotations

from pathlib import Path

from pii_redact.extract.csv_ import _read_text
from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument


class TextRenderError(ValueError):
    pass


class TextRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        encoding = extracted.format_metadata["encoding"]
        text, _ = _read_text(source_path)

        # Splice from the end backwards so earlier spans' offsets stay valid.
        for block_index in sorted(replacements, key=lambda i: extracted.blocks[i].source_ref[0], reverse=True):
            block = extracted.blocks[block_index]
            start, end = block.source_ref
            if text[start:end] != block.text:
                raise TextRenderError(
                    f"{source_path}: block {block_index} no longer matches the "
                    "source text - refusing to write a mismatched output"
                )
            text = text[:start] + replacements[block_index] + text[end:]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(text.encode(encoding))

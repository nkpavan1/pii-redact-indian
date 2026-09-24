"""CSV re-rendering.

Re-reads source_path using the exact encoding/delimiter/quotechar/header
state that extract/csv_.py recorded in ExtractedDocument.format_metadata,
rather than trusting extracted.blocks to reconstruct the full grid - the
extractor only keeps blocks for non-empty cells (that's all detection
needs), so blocks alone can't round-trip empty cells or ones beyond the
header's width. Only cells named in `replacements` are overwritten;
everything else is written back cell-for-cell as read.

Known limitation: csv.Sniffer never actually detects the line terminator
(it always reports '\\r\\n', regardless of the source file's real line
endings - a CPython Sniffer quirk, not something we're choosing not to
sniff), so a source file using bare '\\n' will come back out as '\\r\\n'.
Cell content and structure round-trip exactly; the raw bytes of untouched
lines do not. Fine for RFC 4180 consumers; worth knowing if a byte-diff
against the original is ever expected to be empty.
"""

from __future__ import annotations

import csv
from pathlib import Path

from pii_redact.extract.csv_ import HEADER_ROW, column_name_for
from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument


class CsvRenderError(ValueError):
    pass


def redacted_rows(
    source_path: Path, extracted: ExtractedDocument, replacements: dict[int, str]
) -> tuple[list[str] | None, list[list[str]]]:
    """(header_row or None, data_rows) of the re-read source with every
    replacement applied."""
    meta = extracted.format_metadata
    with source_path.open("r", encoding=meta["encoding"], newline="") as f:
        rows = list(csv.reader(f, delimiter=meta["delimiter"], quotechar=meta["quotechar"]))
    if not rows:
        raise CsvRenderError(f"{source_path}: no rows found on re-read")

    header = meta["header"]
    header_row: list[str] | None = None
    if meta["has_header"]:
        header_row = list(rows[0])
        data_rows = [list(r) for r in rows[1:]]
    else:
        data_rows = [list(r) for r in rows]

    # (row_index, column_name) -> target row list + col_index, built with
    # the exact same naming rule the extractor used, so a block's location
    # always resolves to the right cell. Header cells use HEADER_ROW and
    # positional names, mirroring extract/csv_.py.
    position_by_location: dict[tuple[int, str], tuple[list[str], int]] = {}
    if header_row is not None:
        for col_index in range(len(header_row)):
            position_by_location[(HEADER_ROW, column_name_for(col_index, None))] = (
                header_row, col_index,
            )
    for row_index, row in enumerate(data_rows):
        for col_index in range(len(row)):
            column_name = column_name_for(col_index, header or header_row)
            position_by_location[(row_index, column_name)] = (row, col_index)

    for block_index, new_text in replacements.items():
        block = extracted.blocks[block_index]
        key = (block.location.row, block.location.column)
        if key not in position_by_location:
            raise CsvRenderError(
                f"{source_path}: replacement for block {block_index} "
                f"targets {key}, which no longer exists in the "
                "re-read source - refusing to write a mismatched output"
            )
        target_row, col_index = position_by_location[key]
        target_row[col_index] = new_text

    return header_row, data_rows


class CsvRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        meta = extracted.format_metadata
        header_row, data_rows = redacted_rows(source_path, extracted, replacements)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding=meta["encoding"], newline="") as f:
            writer = csv.writer(
                f,
                delimiter=meta["delimiter"],
                quotechar=meta["quotechar"],
                lineterminator=meta["lineterminator"],
            )
            if header_row is not None:
                writer.writerow(header_row)
            writer.writerows(data_rows)

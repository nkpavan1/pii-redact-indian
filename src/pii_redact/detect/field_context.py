"""Field names as detection context for structured data (CSV, XLSX, JSON).

A cell or a JSON value is extracted on its own, so the analyzer never saw
the column header or key that tells a human what it is: an account number
alone in a cell scores 0.15 and is never masked, although its header says
"Account No". Here each value gets a label, and the pipeline analyzes
"<label>: <value>" - the same trick that makes frontmatter lines work - so
the label's words act as context words for the value.

Labels:
- CSV: the column header (when the file has one) and the cell to the left
  in the same row (label-beside-value exports: "Account No,123...").
- XLSX: the nearest label-like cell above in the same column (tables often
  start below a preamble) and the label-like cell to the left in the same
  row. openpyxl has no notion of a header row, and both layouts are
  common in bank and tax spreadsheets.

A label must look like one (letters, no digits), so an amount or a date
next to a value is never used as its label.
- JSON: the value's key, or for an array item the nearest enclosing key.

Labels are turned into words before use: `account_number` and
`accountNumber` become "account number" (spaCy keeps `account_number` as
one token, whose lemma matches no context word), and the bank-statement
abbreviations "A/C" and "Acct" become "account" (spaCy splits "A/C" into
"A", "/", "C").
"""

from __future__ import annotations

import re

from openpyxl.utils.cell import column_index_from_string, coordinate_from_string

from pii_redact.extract.csv_ import HEADER_ROW
from pii_redact.types import DocFormat, ExtractedDocument

_ABBREVIATIONS = [
    (re.compile(r"(?i)\ba\s*/\s*c\b"), "account"),
    (re.compile(r"(?i)\bacct\b"), "account"),
]
_MAX_LABEL_CHARS = 80
# Kept out of regex reach: see pipeline._context_window's " | " rationale.
_LABEL_SEPARATOR = " | "


def label_words(name: str) -> str:
    """`account_number` / `accountNumber` / `A/C No.` -> words a context
    matcher can use: "account number", "account No."."""
    text = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name)  # camelCase
    text = re.sub(r"[_\-.]+", " ", text)
    for pattern, replacement in _ABBREVIATIONS:
        text = pattern.sub(replacement, text)
    return " ".join(text.split())[:_MAX_LABEL_CHARS]


def _join(*labels: str | None) -> str | None:
    words = [label_words(label) for label in labels if label and label.strip()]
    words = [w for w in words if w]
    return _LABEL_SEPARATOR.join(words) if words else None


def looks_like_a_label(text: str | None) -> bool:
    """A header or field label has letters and no digits ("Account No",
    "Customer Id"). A value next to it - an amount, a date, another
    account number - does not, so it is never used as a label."""
    return (
        text is not None
        and len(text) <= _MAX_LABEL_CHARS
        and any(c.isalpha() for c in text)
        and not any(c.isdigit() for c in text)
    )


def _csv_labels(extracted: ExtractedDocument) -> dict[int, str]:
    header = extracted.format_metadata.get("header")
    columns = {name: i for i, name in reversed(list(enumerate(header or [])))}
    cell_text: dict[tuple[int, int], str] = {}
    positions: dict[int, tuple[int, int]] = {}
    for index, block in enumerate(extracted.blocks):
        if block.location.row == HEADER_ROW:
            continue
        column = block.location.column
        if header is not None and column in columns:
            col_index = columns[column]
        elif column.startswith("col_") and column[4:].isdigit():
            col_index = int(column[4:])
        else:
            continue
        positions[index] = (block.location.row, col_index)
        cell_text[(block.location.row, col_index)] = block.text

    labels = {}
    for index, (row, col_index) in positions.items():
        column_header = header[col_index] if header is not None and col_index < len(header) else None
        left = cell_text.get((row, col_index - 1)) if col_index > 0 else None
        label = _join(column_header, left if looks_like_a_label(left) else None)
        if label:
            labels[index] = label
    return labels


def _xlsx_labels(extracted: ExtractedDocument) -> dict[int, str]:
    """A sheet's table often starts below a preamble (bank name, account
    summary), so a column's header is not assumed to be in row 1: a cell's
    column label is the nearest label-like cell above it in the same
    column. Values with digits (account numbers, amounts) are never labels,
    so a column of account numbers keeps its header however long it is."""
    cells: dict[tuple[str, int, int], str] = {}
    targets: dict[int, tuple[str, int, int]] = {}
    for index, block in enumerate(extracted.blocks):
        kind, sheet, ref = block.source_ref
        if kind not in ("value", "formula_result"):
            continue
        column_letter, row = coordinate_from_string(ref)
        position = (sheet, column_index_from_string(column_letter), row)
        cells[position] = block.text
        targets[index] = position

    # Walk each column top to bottom once, remembering the last label seen.
    label_above: dict[tuple[str, int, int], str] = {}
    current: dict[tuple[str, int], str] = {}
    for sheet, column, row in sorted(cells):
        if (sheet, column) in current:
            label_above[(sheet, column, row)] = current[(sheet, column)]
        if looks_like_a_label(cells[(sheet, column, row)]):
            current[(sheet, column)] = cells[(sheet, column, row)]

    labels = {}
    for index, (sheet, column, row) in targets.items():
        left = cells.get((sheet, column - 1, row))
        label = _join(label_above.get((sheet, column, row)), left if looks_like_a_label(left) else None)
        if label:
            labels[index] = label
    return labels


def _json_labels(extracted: ExtractedDocument) -> dict[int, str]:
    from pii_redact.render.json_ import _parse_path

    labels = {}
    for index, block in enumerate(extracted.blocks):
        keys = [token for token in _parse_path(block.location.json_path) if isinstance(token, str)]
        label = _join(keys[-1]) if keys else None
        if label:
            labels[index] = label
    return labels


_BY_FORMAT = {
    DocFormat.CSV: _csv_labels,
    DocFormat.XLSX: _xlsx_labels,
    DocFormat.JSON: _json_labels,
}

FIELD_CONTEXT_FORMATS = frozenset(_BY_FORMAT)


def field_labels(extracted: ExtractedDocument) -> dict[int, str]:
    """Block index -> label words, for blocks that have a field label."""
    build = _BY_FORMAT.get(extracted.doc_format)
    return build(extracted) if build else {}

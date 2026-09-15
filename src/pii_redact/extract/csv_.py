"""CSV extraction.

Sniffs encoding and delimiter rather than assuming UTF-8/comma - Indian
bank/tax exports commonly use UTF-8-with-BOM or a legacy Windows codepage.
Auto-detects whether the first row is a header so field-name-based
allow-lists have something to key off; the detected dialect/header state is
stashed in ExtractedDocument.format_metadata so render/csv_.py can round-trip
it on write instead of re-guessing.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from pii_redact.extract.base import Extractor
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock

# No chardet/charset-normalizer dependency - this project deliberately keeps
# the dependency footprint small (see project instructions, environment
# section). Instead we try a short, ordered list of encodings that covers
# the realistic cases rather than doing statistical detection: cp1252/
# latin-1 cover the legacy Windows codepages most likely to show up in
# older Indian bank/tax CSV exports. UTF-8-with-BOM is handled separately
# below (see _read_text) rather than via "utf-8-sig" in this list - that
# codec decodes a no-BOM file just as happily as a with-BOM one, which
# would make every plain-UTF-8 file's *recorded* encoding "utf-8-sig" and
# then, on write, silently gain a BOM it never had.
_ENCODING_CANDIDATES = ["utf-8", "cp1252", "latin-1"]
_UTF8_BOM = b"\xef\xbb\xbf"

_SNIFF_SAMPLE_CHARS = 8192


class CsvExtractionError(ValueError):
    pass


def column_name_for(col_index: int, header: list[str] | None) -> str:
    """Shared with render/csv_.py so the two sides can never disagree on
    how a TextBlock.location.column maps back to a cell position - it's
    the join key between "what was detected" and "what to overwrite"."""
    if header is not None and col_index < len(header):
        return header[col_index]
    return f"col_{col_index}"


def _read_text(path: Path) -> tuple[str, str]:
    """Returns (text, encoding_used)."""
    raw = path.read_bytes()
    if raw.startswith(_UTF8_BOM):
        return raw.decode("utf-8-sig"), "utf-8-sig"
    for encoding in _ENCODING_CANDIDATES:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise CsvExtractionError(
        f"{path}: could not decode with any of {_ENCODING_CANDIDATES}"
    )


def _sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel  # comma-delimited fallback


def _sniff_has_header(sample: str) -> bool:
    try:
        return csv.Sniffer().has_header(sample)
    except csv.Error:
        # Sniffer couldn't decide (e.g. a single-row file). Assume a header
        # is present: treating a real header row as data just means it also
        # gets scanned for PII (harmless), whereas treating real data as a
        # header would silently exclude that row from field-name matching
        # and from anonymization entirely.
        return True


class CsvExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        text, encoding = _read_text(path)
        sample = text[:_SNIFF_SAMPLE_CHARS]
        dialect = _sniff_dialect(sample)
        has_header = _sniff_has_header(sample)

        rows = list(csv.reader(io.StringIO(text), dialect=dialect))
        if not rows:
            raise CsvExtractionError(f"{path}: no rows found")

        header: list[str] | None = None
        data_rows = rows
        if has_header:
            header = rows[0]
            data_rows = rows[1:]

        blocks: list[TextBlock] = []
        for row_index, row in enumerate(data_rows):
            for col_index, cell in enumerate(row):
                if not cell.strip():
                    continue
                column_name = column_name_for(col_index, header)
                blocks.append(
                    TextBlock(
                        text=cell,
                        location=Location(row=row_index, column=column_name),
                    )
                )

        return ExtractedDocument(
            doc_format=DocFormat.CSV,
            source_path=path,
            blocks=blocks,
            format_metadata={
                "encoding": encoding,
                "delimiter": dialect.delimiter,
                "quotechar": dialect.quotechar,
                "lineterminator": dialect.lineterminator,
                "has_header": has_header,
                "header": header,
                "row_count": len(data_rows),
            },
        )

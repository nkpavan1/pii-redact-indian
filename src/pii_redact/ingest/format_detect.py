"""Format detection by magic bytes, not just file extension - a renamed or
mislabeled file should still route to the correct extractor, and a file
whose extension lies about its content should be rejected rather than fed
to the wrong parser.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from pii_redact.types import DocFormat

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class UnsupportedFormatError(ValueError):
    pass


def detect_format(path: Path) -> DocFormat:
    if not path.is_file():
        raise UnsupportedFormatError(f"Not a file: {path}")

    head = path.read_bytes()[:16]

    if head.startswith(_PDF_MAGIC):
        return DocFormat.PDF
    if head.startswith(_JPEG_MAGIC) or head.startswith(_PNG_MAGIC):
        return DocFormat.IMAGE
    if head.startswith(_ZIP_MAGIC):
        if _is_xlsx(path):
            return DocFormat.XLSX
        raise UnsupportedFormatError(
            f"{path}: zip-based file but not a recognized XLSX workbook "
            "(e.g. docx/pptx are not in scope)"
        )
    return _detect_text_format(path)


def _is_xlsx(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            return any(name.startswith("xl/") for name in names)
    except zipfile.BadZipFile:
        return False


def _detect_text_format(path: Path) -> DocFormat:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UnsupportedFormatError(
            f"{path}: not PDF/XLSX/image and not valid UTF-8 text"
        ) from exc

    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(text)
            return DocFormat.JSON
        except json.JSONDecodeError:
            pass  # falls through to CSV - e.g. a CSV cell starting with '['

    if path.suffix.lower() == ".json":
        raise UnsupportedFormatError(f"{path}: .json extension but invalid JSON")

    return DocFormat.CSV

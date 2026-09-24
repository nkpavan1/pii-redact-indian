import json
import zipfile

import pytest

from pii_redact.ingest.format_detect import UnsupportedFormatError, detect_format
from pii_redact.types import DocFormat


def test_detects_pdf(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(b"%PDF-1.7\n...")
    assert detect_format(p) == DocFormat.PDF


def test_detects_jpeg_by_magic_bytes_even_with_wrong_extension(tmp_path):
    p = tmp_path / "scan.pdf"  # deliberately mislabeled
    p.write_bytes(b"\xff\xd8\xff\xe0rest-of-jpeg")
    assert detect_format(p) == DocFormat.IMAGE


def test_detects_png(tmp_path):
    p = tmp_path / "scan.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\nrest")
    assert detect_format(p) == DocFormat.IMAGE


def test_detects_xlsx(tmp_path):
    p = tmp_path / "book.xlsx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("xl/workbook.xml", "<workbook/>")
        zf.writestr("[Content_Types].xml", "<Types/>")
    assert detect_format(p) == DocFormat.XLSX


def test_rejects_docx_masquerading_as_zip(tmp_path):
    p = tmp_path / "resume.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("word/document.xml", "<document/>")
    with pytest.raises(UnsupportedFormatError):
        detect_format(p)


def test_detects_json(tmp_path):
    p = tmp_path / "data.json"
    p.write_text(json.dumps({"pan": "ABCDE1234F"}))
    assert detect_format(p) == DocFormat.JSON


def test_detects_csv(tmp_path):
    p = tmp_path / "data.csv"
    p.write_text("name,pan\nJohn,ABCDE1234F\n")
    assert detect_format(p) == DocFormat.CSV


def test_detects_csv_with_utf8_bom(tmp_path):
    p = tmp_path / "data.csv"
    p.write_bytes(b"\xef\xbb\xbfname,pan\nJohn,ABCDE1234F\n")
    assert detect_format(p) == DocFormat.CSV


@pytest.mark.parametrize("name", ["note.md", "note.txt", "note.markdown", "NOTE.MD"])
def test_prose_extensions_route_to_text_not_csv(tmp_path, name):
    # B1: a note used to fall through to the CSV path, whose header sniffer
    # dropped its first line from detection.
    p = tmp_path / name
    p.write_text("Ravi Kumar, PAN ABCPE1234F\n\nSecond paragraph, with commas.\n")
    assert detect_format(p) == DocFormat.TEXT


def test_markdown_starting_with_a_link_is_text_not_json(tmp_path):
    p = tmp_path / "links.md"
    p.write_text("[home](index.md)\n")
    assert detect_format(p) == DocFormat.TEXT


def test_magic_bytes_still_win_over_a_text_extension(tmp_path):
    p = tmp_path / "actually_a_pdf.txt"
    p.write_bytes(b"%PDF-1.7\n...")
    assert detect_format(p) == DocFormat.PDF


def test_rejects_invalid_json_extension(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not valid json")
    with pytest.raises(UnsupportedFormatError):
        detect_format(p)

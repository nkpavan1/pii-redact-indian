import pytest

from pii_redact.extract.csv_ import CsvExtractionError, CsvExtractor
from pii_redact.types import DocFormat


def _cells(extracted):
    return {(b.location.row, b.location.column): b.text for b in extracted.blocks}


def test_header_detected_with_numeric_column_signal(tmp_path):
    p = tmp_path / "accounts.csv"
    p.write_text(
        "name,pan,account_number\n"
        "Rahul Kumar,ABCDEF1234F,123456789012\n"
        "Priya Singh,PQRSX5678G,987654321098\n",
        encoding="utf-8",
    )
    extracted = CsvExtractor().extract(p)

    assert extracted.doc_format == DocFormat.CSV
    assert extracted.format_metadata["has_header"] is True
    assert extracted.format_metadata["header"] == ["name", "pan", "account_number"]
    assert extracted.format_metadata["delimiter"] == ","

    cells = _cells(extracted)
    assert cells[(0, "name")] == "Rahul Kumar"
    assert cells[(0, "pan")] == "ABCDEF1234F"
    assert cells[(1, "account_number")] == "987654321098"


def test_headerless_file_falls_back_to_column_index_names(tmp_path):
    p = tmp_path / "raw.csv"
    p.write_text("123456789012,ABCDE1234F\n987654321098,PQRSX5678G\n", encoding="utf-8")
    extracted = CsvExtractor().extract(p)

    assert extracted.format_metadata["has_header"] is False
    assert extracted.format_metadata["header"] is None

    cells = _cells(extracted)
    assert cells[(0, "col_0")] == "123456789012"
    assert cells[(1, "col_1")] == "PQRSX5678G"


def test_semicolon_delimiter_is_sniffed(tmp_path):
    p = tmp_path / "eu_style.csv"
    p.write_text(
        "name;account_number\nRahul Kumar;123456789012\nPriya Singh;987654321098\n",
        encoding="utf-8",
    )
    extracted = CsvExtractor().extract(p)

    assert extracted.format_metadata["delimiter"] == ";"
    cells = _cells(extracted)
    assert cells[(0, "name")] == "Rahul Kumar"


def test_utf8_bom_is_stripped(tmp_path):
    p = tmp_path / "bom.csv"
    p.write_bytes(
        b"\xef\xbb\xbfname,pan\nRahul Kumar,ABCDE1234F\n"
    )
    extracted = CsvExtractor().extract(p)

    assert extracted.format_metadata["encoding"] == "utf-8-sig"
    cells = _cells(extracted)
    # The BOM must not leak into the first header name.
    assert extracted.format_metadata["header"][0] == "name"
    assert cells[(0, "pan")] == "ABCDE1234F"


def test_falls_back_to_cp1252_when_utf8_is_invalid(tmp_path):
    p = tmp_path / "legacy.csv"
    # 0x92 is an invalid standalone UTF-8 byte but is a valid cp1252
    # character (right single quotation mark).
    p.write_bytes(b"name,note\nRahul,Can\x92t verify\n")
    extracted = CsvExtractor().extract(p)

    assert extracted.format_metadata["encoding"] == "cp1252"
    cells = _cells(extracted)
    assert cells[(0, "note")] == "Can’t verify"


def test_empty_cells_are_skipped(tmp_path):
    p = tmp_path / "sparse.csv"
    p.write_text("name,pan,note\nRahul Kumar,ABCDE1234F,\n", encoding="utf-8")
    extracted = CsvExtractor().extract(p)

    cells = _cells(extracted)
    assert (0, "note") not in cells


def test_no_rows_raises(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    with pytest.raises(CsvExtractionError):
        CsvExtractor().extract(p)

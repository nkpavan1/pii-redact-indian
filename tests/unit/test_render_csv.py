import csv

import pytest

from pii_redact.extract.csv_ import CsvExtractor
from pii_redact.render.csv_ import CsvRenderError, CsvRenderer
from pii_redact.types import ExtractedDocument, Location, TextBlock


def _read_grid(path, encoding="utf-8"):
    with path.open("r", encoding=encoding, newline="") as f:
        return list(csv.reader(f))


def test_round_trip_with_header_only_replaces_targeted_cell(tmp_path):
    src = tmp_path / "accounts.csv"
    src.write_text(
        "name,pan,account_number\n"
        "Rahul Kumar,ABCDEF1234F,123456789012\n"
        "Priya Singh,PQRSX5678G,987654321098\n",
        encoding="utf-8",
    )
    extracted = CsvExtractor().extract(src)

    pan_block_index = next(
        i for i, b in enumerate(extracted.blocks)
        if b.location.row == 0 and b.location.column == "pan"
    )

    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {pan_block_index: "IN_PAN_A"}, out)

    grid = _read_grid(out)
    assert grid[0] == ["name", "pan", "account_number"]
    assert grid[1] == ["Rahul Kumar", "IN_PAN_A", "123456789012"]
    assert grid[2] == ["Priya Singh", "PQRSX5678G", "987654321098"]


def test_no_replacements_leaves_all_cells_unchanged(tmp_path):
    src = tmp_path / "accounts.csv"
    src.write_text("name,pan\nRahul Kumar,ABCDEF1234F\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)

    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {}, out)

    assert _read_grid(out) == [["name", "pan"], ["Rahul Kumar", "ABCDEF1234F"]]


def test_empty_cells_preserved_through_round_trip(tmp_path):
    src = tmp_path / "sparse.csv"
    src.write_text("name,pan,note\nRahul Kumar,ABCDE1234F,\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)

    name_block_index = next(
        i for i, b in enumerate(extracted.blocks) if b.location.column == "name"
    )
    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {name_block_index: "PERSON_A"}, out)

    grid = _read_grid(out)
    assert grid == [["name", "pan", "note"], ["PERSON_A", "ABCDE1234F", ""]]


def test_headerless_round_trip(tmp_path):
    src = tmp_path / "raw.csv"
    src.write_text("123456789012,ABCDE1234F\n987654321098,PQRSX5678G\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)

    col1_row1 = next(
        i for i, b in enumerate(extracted.blocks)
        if b.location.row == 1 and b.location.column == "col_1"
    )
    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {col1_row1: "IN_PAN_B"}, out)

    grid = _read_grid(out)
    assert grid == [["123456789012", "ABCDE1234F"], ["987654321098", "IN_PAN_B"]]


def test_semicolon_delimiter_round_trip(tmp_path):
    src = tmp_path / "eu.csv"
    src.write_text("name;account_number\nRahul Kumar;123456789012\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)

    acct_index = next(
        i for i, b in enumerate(extracted.blocks) if b.location.column == "account_number"
    )
    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {acct_index: "ACCT_A"}, out)

    assert out.read_text(encoding="utf-8").splitlines()[1] == "Rahul Kumar;ACCT_A"


def test_legacy_encoding_round_trip(tmp_path):
    src = tmp_path / "legacy.csv"
    src.write_bytes(b"name,note\nRahul,Can\x92t verify\n")
    extracted = CsvExtractor().extract(src)

    note_index = next(
        i for i, b in enumerate(extracted.blocks) if b.location.column == "note"
    )
    out = tmp_path / "out.csv"
    CsvRenderer().render(src, extracted, {note_index: "REDACTED"}, out)

    grid = _read_grid(out, encoding="cp1252")
    assert grid == [["name", "note"], ["Rahul", "REDACTED"]]


def test_stale_location_raises_instead_of_silently_writing_wrong_cell(tmp_path):
    src = tmp_path / "accounts.csv"
    src.write_text("name,pan\nRahul Kumar,ABCDEF1234F\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)

    # Fabricate a block whose location doesn't exist in the re-read grid.
    extracted.blocks.append(
        TextBlock(text="ghost", location=Location(row=99, column="nonexistent"))
    )
    ghost_index = len(extracted.blocks) - 1

    out = tmp_path / "out.csv"
    with pytest.raises(CsvRenderError):
        CsvRenderer().render(src, extracted, {ghost_index: "X"}, out)

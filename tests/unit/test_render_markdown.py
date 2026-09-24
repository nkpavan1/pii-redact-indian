"""Markdown output for every input format (render/markdown.py), plus the
pipeline's --format markdown path end to end. Synthetic data only."""

import json
import zipfile

import openpyxl
import pymupdf
import pytest
import yaml
from cryptography.fernet import Fernet
from openpyxl.comments import Comment

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.audit.logger import AuditLogger
from pii_redact.extract.csv_ import CsvExtractor
from pii_redact.extract.json_ import JsonExtractor
from pii_redact.extract.text import TextExtractor
from pii_redact.extract.xlsx import XlsxExtractor
from pii_redact.pipeline import markdown_output_name, run_pipeline
from pii_redact.render.markdown import to_markdown
from pii_redact.types import DocFormat, ExtractedDocument, Location, Mode, OutputFormat, TextBlock


def _index(extracted, text):
    return next(i for i, b in enumerate(extracted.blocks) if b.text == text)


# --- per format


def test_text_markdown_is_the_source_with_replacements_in_place(tmp_path):
    src = tmp_path / "note.md"
    src.write_bytes(b"---\nauthor: Ravi Kumar\n---\n# Notes\n\n```\nPAN ABCPE1234F\n```\n")
    extracted = TextExtractor().extract(src)
    replacements = {_index(extracted, "author: Ravi Kumar"): "author: PERSON_A"}
    code_block = next(i for i, b in enumerate(extracted.blocks) if "ABCPE1234F" in b.text)
    replacements[code_block] = extracted.blocks[code_block].text.replace("ABCPE1234F", "IN_PAN_A")

    out = to_markdown(src, extracted, replacements)

    assert out == "---\nauthor: PERSON_A\n---\n# Notes\n\n```\nPAN IN_PAN_A\n```\n"


def test_csv_becomes_a_table_with_its_header(tmp_path):
    # A numeric column makes the sniffer's header guess reliable; with all
    # text columns it may (legitimately) decide there is no header.
    src = tmp_path / "accounts.csv"
    src.write_bytes(b"name,amount,note\nRavi Kumar,1250,has a | pipe\nAsha Rao,300,ok\n")
    extracted = CsvExtractor().extract(src)
    assert extracted.format_metadata["has_header"] is True

    out = to_markdown(src, extracted, {_index(extracted, "Ravi Kumar"): "PERSON_A"})

    assert out == (
        "| name | amount | note |\n"
        "|---|---|---|\n"
        "| PERSON_A | 1250 | has a \\| pipe |\n"
        "| Asha Rao | 300 | ok |\n"
    )


def test_headerless_csv_gets_column_letters(tmp_path):
    src = tmp_path / "one_row.csv"
    src.write_text("Ravi Kumar,ABCPE1234F\n", encoding="utf-8")
    extracted = CsvExtractor().extract(src)
    # The sniffer treats a lone row as a header; it is still redacted.
    out = to_markdown(src, extracted, {_index(extracted, "Ravi Kumar"): "PERSON_A"})
    assert out.splitlines()[0] == "| PERSON_A | ABCPE1234F |"


def test_json_is_a_fenced_block_that_parses_back(tmp_path):
    src = tmp_path / "data.json"
    src.write_text(json.dumps({"name": "Ravi Kumar", "notes": "uses ``` fences", "amount": 12}), encoding="utf-8")
    extracted = JsonExtractor().extract(src)

    out = to_markdown(src, extracted, {_index(extracted, "Ravi Kumar"): "PERSON_A"})

    lines = out.splitlines()
    assert lines[0] == "````json" and lines[-1] == "````"  # fence longer than any run inside
    assert json.loads("\n".join(lines[1:-1])) == {"name": "PERSON_A", "notes": "uses ``` fences", "amount": 12}


def _patch_cached_formula_value(path):
    with zipfile.ZipFile(path) as zin:
        contents = {n: zin.read(n) for n in zin.namelist()}
    xml = contents["xl/worksheets/sheet1.xml"].decode("utf-8")
    old = '<c r="A3"><f>A2</f><v /></c>'
    assert old in xml
    contents["xl/worksheets/sheet1.xml"] = xml.replace(
        old, '<c r="A3" t="str"><f>A2</f><v>Ravi Kumar</v></c>'
    ).encode("utf-8")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in contents.items():
            zout.writestr(name, data)


def test_xlsx_sheets_become_tables_and_formula_results_are_redacted(tmp_path):
    src = tmp_path / "book.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Ravi Kumar salary"  # a sheet name is never rendered
    ws["A1"], ws["B1"] = "Name", "Amount"
    ws["A2"], ws["B2"] = "Ravi Kumar", 1250.5
    ws["A3"] = "=A2"
    ws["A2"].comment = Comment("Checked by Asha Rao", "reviewer")
    wb.create_sheet("Empty")
    wb.save(src)
    _patch_cached_formula_value(src)
    extracted = XlsxExtractor().extract(src)
    replacements = {
        i: {"Ravi Kumar": "PERSON_A", "Checked by Asha Rao": "Checked by PERSON_B"}[b.text]
        for i, b in enumerate(extracted.blocks)
        if b.text in ("Ravi Kumar", "Checked by Asha Rao")
    }
    assert any(extracted.blocks[i].read_only for i in replacements)  # the formula result

    out = to_markdown(src, extracted, replacements)

    assert "Ravi" not in out and "Asha" not in out
    assert out == (
        "## Sheet 1\n\n"
        "| A | B |\n"
        "|---|---|\n"
        "| Name | Amount |\n"
        "| PERSON_A | 1250.5 |\n"
        "| PERSON_A |  |\n\n"
        "Comments:\n\n"
        "- A2: Checked by PERSON_B\n\n"
        "## Sheet 2\n\n"
        "_(empty sheet)_\n"
    )


def test_positioned_blocks_are_in_reading_order_with_rows_joined(tmp_path):
    blocks = [
        TextBlock("10023456", Location(page=0, bbox=(200, 100, 260, 112))),
        TextBlock("Customer Id", Location(page=0, bbox=(70, 101, 130, 113))),
        TextBlock("Statement", Location(page=0, bbox=(70, 60, 160, 75))),
        TextBlock("Page two line", Location(page=1, bbox=(70, 60, 160, 75))),
    ]
    extracted = ExtractedDocument(DocFormat.PDF, tmp_path / "x.pdf", blocks)

    out = to_markdown(extracted.source_path, extracted, {0: "CUSTOMER_ID_A"})

    assert out == (
        "## Page 1\n\n"
        "Statement\n"
        "Customer Id | CUSTOMER_ID_A\n\n"
        "## Page 2\n\n"
        "Page two line\n"
    )


def test_image_ocr_lines_have_no_page_heading(tmp_path):
    blocks = [TextBlock("Name Ravi Kumar", Location(bbox=(10, 10, 200, 30)))]
    extracted = ExtractedDocument(DocFormat.IMAGE, tmp_path / "scan.png", blocks)
    assert to_markdown(extracted.source_path, extracted, {0: "Name PERSON_A"}) == "Name PERSON_A\n"


# --- pipeline --format markdown, end to end


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "state" / "mapping.enc", key=Fernet.generate_key())


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "state" / "audit.log.jsonl")


def _markdown(path, tmp_path, store, audit):
    result = run_pipeline(
        path, tmp_path / "out", Mode.PSEUDONYMIZE, None, store, audit,
        non_interactive=True, output_format=OutputFormat.MARKDOWN,
    )
    assert result.written, result.failure_reason
    return result


def test_markdown_note_with_frontmatter_values_redacted_and_yaml_still_valid(tmp_path, store, audit):
    src = tmp_path / "note.md"
    src.write_text(
        "---\nauthor: Ravi Kumar\ndob: 15/08/1990\ntitle: Loan notes\n---\n"
        "Ravi Kumar, PAN ABCPE1234F, asked about the loan.\n",
        encoding="utf-8",
    )

    result = _markdown(src, tmp_path, store, audit)

    assert result.output_path.name == "note.md"
    out = result.output_path.read_text(encoding="utf-8")
    assert "Ravi" not in out and "ABCPE1234F" not in out and "1990" not in out
    frontmatter = yaml.safe_load(out.split("---\n")[1])
    assert frontmatter == {"author": "PERSON_A", "dob": "IN_DATE_OF_BIRTH_A", "title": "Loan notes"}
    assert out.endswith("PERSON_A, PAN IN_PAN_A, asked about the loan.\n")


def test_pdf_to_markdown_end_to_end(tmp_path, store, audit):
    src = tmp_path / "letter.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Dear Ravi Kumar,", fontsize=11)
    page.insert_text((72, 92), "Your PAN ABCPE1234F is on file.", fontsize=11)
    doc.save(src)
    doc.close()

    result = _markdown(src, tmp_path, store, audit)

    assert result.output_path.name == "letter.pdf.md"
    assert result.output_path.read_text(encoding="utf-8") == (
        "## Page 1\n\nDear PERSON_A,\nYour PAN IN_PAN_A is on file.\n"
    )


def test_markdown_output_makes_formula_results_redactable(tmp_path, store, audit):
    # Native XLSX output can't overwrite a formula's cached result, so --yes
    # refuses it; markdown output has no such limit and proceeds.
    src = tmp_path / "book.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"], ws["A2"], ws["A3"] = "Customer", "Ravi Kumar", "=A2"
    wb.save(src)
    _patch_cached_formula_value(src)

    native = run_pipeline(src, tmp_path / "native", Mode.PSEUDONYMIZE, None, store, audit, non_interactive=True)
    assert not native.written
    assert native.preview.has_unredactable

    result = _markdown(src, tmp_path, store, audit)
    out = result.output_path.read_text(encoding="utf-8")
    assert "Ravi" not in out
    assert "| PERSON_A |" in out
    assert not result.preview.has_unredactable


def test_markdown_output_names():
    from pathlib import Path

    assert markdown_output_name(Path("note.md")) == "note.md"
    assert markdown_output_name(Path("NOTE.MARKDOWN")) == "NOTE.MARKDOWN"
    assert markdown_output_name(Path("statement.pdf")) == "statement.pdf.md"
    assert markdown_output_name(Path("notes.txt")) == "notes.txt.md"

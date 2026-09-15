import pymupdf
import pytest

import pii_redact.extract.pdf as pdf_module
from pii_redact.extract.ocr import OcrLine
from pii_redact.extract.pdf import PdfExtractionError, PdfExtractor, _normalize_text
from pii_redact.types import DocFormat


# --- _normalize_text: real AIS PDF bug - some PDF generators encode word
# separators as Unicode control characters instead of spaces, confirmed
# directly (0x08 backspace, 0x05 ENQ), which silently makes spaCy treat an
# entire label/name as one unrecognizable token (see module docstring).


def test_normalize_replaces_control_characters_with_space():
    assert _normalize_text("Date\x08of\x08Birth") == "Date of Birth"


def test_normalize_handles_different_control_character():
    assert _normalize_text("RAHUL\x05KUMAR\x05SHARMA") == "RAHUL KUMAR SHARMA"


def test_normalize_collapses_whitespace_runs():
    assert _normalize_text("Mobile\x08\x08Number") == "Mobile Number"


def test_normalize_strips_leading_and_trailing_whitespace():
    assert _normalize_text("\x08Name\x08") == "Name"


def test_normalize_leaves_ordinary_text_unchanged():
    assert _normalize_text("Rahul Kumar Sharma") == "Rahul Kumar Sharma"


def test_normalize_empty_or_all_control_becomes_empty_string():
    assert _normalize_text("\x08\x05") == ""


def test_extraction_normalizes_control_characters_in_real_pdf(tmp_path):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Date\x08of\x08Birth", fontsize=11)
    doc.save(p)

    extracted = PdfExtractor().extract(p)
    assert extracted.blocks[0].text == "Date of Birth"


def test_native_text_single_line(tmp_path):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    doc.save(p)

    extracted = PdfExtractor().extract(p)
    assert extracted.doc_format == DocFormat.PDF
    assert extracted.needs_ocr_pages == []
    assert len(extracted.blocks) == 1
    block = extracted.blocks[0]
    assert block.text == "Name: Rahul Kumar"
    assert block.location.page == 0
    assert block.location.bbox is not None
    assert block.source_ref[:2] == ("line", 0)  # [2] is the font size


def test_native_text_multiple_lines_and_pages(tmp_path):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page1 = doc.new_page()
    page1.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    page1.insert_text((72, 92), "PAN: ABCDE1234F", fontsize=11)
    page2 = doc.new_page()
    page2.insert_text((72, 72), "Account: 123456789012", fontsize=11)
    doc.save(p)

    extracted = PdfExtractor().extract(p)
    texts_by_page = {}
    for b in extracted.blocks:
        texts_by_page.setdefault(b.location.page, []).append(b.text)

    assert texts_by_page[0] == ["Name: Rahul Kumar", "PAN: ABCDE1234F"]
    assert texts_by_page[1] == ["Account: 123456789012"]


def test_form_field_value_extracted_once_not_duplicated(tmp_path):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Please fill the field below:", fontsize=11)
    w = pymupdf.Widget()
    w.field_name = "customer_name"
    w.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    w.field_value = "Priya Singh"
    w.rect = pymupdf.Rect(72, 150, 300, 170)
    page.add_widget(w)
    doc.save(p)

    extracted = PdfExtractor().extract(p)
    matching = [b for b in extracted.blocks if "Priya Singh" in b.text]
    assert len(matching) == 1
    assert matching[0].source_ref == ("form_field", 0, "customer_name")

    # The unrelated line of text must still come through normally.
    assert any(b.text == "Please fill the field below:" for b in extracted.blocks)


def test_scanned_page_is_flagged_and_routed_to_ocr(tmp_path, monkeypatch):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page()  # blank page - near-zero native text -> OCR routing
    doc.save(p)

    monkeypatch.setattr(
        pdf_module, "ocr_lines",
        lambda image: [OcrLine(text="Scanned PAN ABCDE1234F", bbox=(100, 100, 400, 130))],
    )

    extracted = PdfExtractor().extract(p)
    assert extracted.needs_ocr_pages == [0]
    assert len(extracted.blocks) == 1
    block = extracted.blocks[0]
    assert block.text == "Scanned PAN ABCDE1234F"
    assert block.source_ref[:2] == ("ocr_line", 0)  # [2] is the estimated font size


def test_ocr_bbox_is_scaled_from_render_dpi_to_pdf_points(tmp_path, monkeypatch):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(p)

    # At 300 DPI, 300 pixels == 1 inch == 72 PDF points.
    monkeypatch.setattr(
        pdf_module, "ocr_lines",
        lambda image: [OcrLine(text="x", bbox=(300, 300, 600, 330))],
    )

    extracted = PdfExtractor().extract(p)
    bbox = extracted.blocks[0].location.bbox
    assert bbox == pytest.approx((72.0, 72.0, 144.0, 79.2))


def test_mixed_native_and_scanned_pages(tmp_path, monkeypatch):
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    native_page = doc.new_page()
    native_page.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    doc.new_page()  # blank - needs OCR
    doc.save(p)

    monkeypatch.setattr(
        pdf_module, "ocr_lines",
        lambda image: [OcrLine(text="Scanned content", bbox=(0, 0, 10, 10))],
    )

    extracted = PdfExtractor().extract(p)
    assert extracted.needs_ocr_pages == [1]
    assert {b.location.page for b in extracted.blocks} == {0, 1}


def test_scanned_page_without_tesseract_raises_fail_closed(tmp_path):
    # No mocking here - Tesseract genuinely isn't installed on this
    # machine, so this exercises the real fail-closed path end to end.
    p = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page()
    doc.save(p)

    with pytest.raises(PdfExtractionError):
        PdfExtractor().extract(p)


def test_invalid_pdf_raises(tmp_path):
    p = tmp_path / "not_really.pdf"
    p.write_bytes(b"this is not a pdf file")
    with pytest.raises(PdfExtractionError):
        PdfExtractor().extract(p)

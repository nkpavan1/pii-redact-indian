import io

import pymupdf
import pytest
from PIL import Image

from pii_redact.extract.pdf import PdfExtractor
from pii_redact.render.pdf import PdfRenderError, PdfRenderer, _safe_replacement_text
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock


def _block_index(extracted, predicate):
    return next(i for i, b in enumerate(extracted.blocks) if predicate(b))


# --- _safe_replacement_text: PyMuPDF silently drops/garbles replacement
# text wider than the original's box - real bug on an AIS document where a
# 10-char date was replaced with the 18-char "<IN_DATE_OF_BIRTH>" marker
# and rendered as the single stray character "1". A same-or-shorter
# replacement at the original font size is the only thing this project can
# guarantee fits, since the original text's presence proves its own length
# fits that box.


def test_short_replacement_passes_through_unchanged():
    assert _safe_replacement_text("ABCDE1234F", "<IN_PAN>") == "<IN_PAN>"


def test_long_replacement_falls_back_to_shorter_generic_marker():
    # "<IN_DATE_OF_BIRTH>" (18 chars) is longer than "23/07/1991" (10 chars)
    # - the real failing case.
    result = _safe_replacement_text("23/07/1991", "<IN_DATE_OF_BIRTH>")
    assert len(result) <= len("23/07/1991")
    assert result in ("[REDACTED]", "***", "X")


def test_falls_back_to_shortest_marker_for_very_short_original():
    result = _safe_replacement_text("AB", "<SOME_VERY_LONG_ENTITY_TYPE_NAME>")
    assert result == "X"


def test_exact_length_boundary_is_not_truncated():
    original = "1234567890"  # 10 chars
    replacement = "0123456789"  # also 10 chars - exactly at the boundary
    assert _safe_replacement_text(original, replacement) == replacement


def test_narrow_real_world_field_renders_fallback_legibly_not_garbled(tmp_path):
    # Reproduces the exact real bug: a date in a narrow bbox at small font,
    # replaced with a long custom entity marker that doesn't fit. Before
    # the fix, PyMuPDF rendered this as the single stray character "1".
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((8.88, 150.47), "23/07/1991", fontsize=6.84)
    doc.save(src)

    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: b.text == "23/07/1991")

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {idx: "<IN_DATE_OF_BIRTH>"}, out)

    result_text = pymupdf.open(out)[0].get_text("text").strip()
    assert "23/07/1991" not in result_text  # original PII still gone either way
    assert result_text != "1"  # the actual garbled failure observed before the fix
    assert result_text in ("<IN_DATE_OF_BIRTH>", "[REDACTED]", "***", "X")


def test_native_line_true_redaction_not_cosmetic_overlay(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    doc.save(src)

    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: b.text == "Name: Rahul Kumar")

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {idx: "Name: <PERSON>"}, out)

    result_text = pymupdf.open(out)[0].get_text("text")
    assert "Rahul Kumar" not in result_text  # true redaction: gone from content stream
    assert "<PERSON>" in result_text


def test_only_targeted_line_is_redacted(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    page.insert_text((72, 92), "Amount: Rs. 50,000", fontsize=11)
    doc.save(src)

    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: "Rahul Kumar" in b.text)

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {idx: "Name: <PERSON>"}, out)

    result_text = pymupdf.open(out)[0].get_text("text")
    assert "Rahul Kumar" not in result_text
    assert "Amount: Rs. 50,000" in result_text  # untouched


def test_no_replacements_leaves_text_unchanged(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    doc.save(src)
    extracted = PdfExtractor().extract(src)

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {}, out)

    assert "Rahul Kumar" in pymupdf.open(out)[0].get_text("text")


def test_form_field_round_trip(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    w = pymupdf.Widget()
    w.field_name = "customer_name"
    w.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    w.field_value = "Priya Singh"
    w.rect = pymupdf.Rect(72, 150, 300, 170)
    page.add_widget(w)
    doc.save(src)

    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: b.source_ref[0] == "form_field")

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {idx: "PERSON_A"}, out)

    result_page = pymupdf.open(out)[0]
    result_widget = next(result_page.widgets())
    assert result_widget.field_value == "PERSON_A"
    assert "Priya Singh" not in result_page.get_text("text")


def test_ocr_line_redaction_obscures_image_pixels(tmp_path):
    src = tmp_path / "doc.pdf"
    img = Image.new("RGB", (200, 100), color="white")
    for x in range(50, 150):
        for y in range(20, 60):
            img.putpixel((x, y), (255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    doc = pymupdf.open()
    page = doc.new_page(width=200, height=100)
    page.insert_image(pymupdf.Rect(0, 0, 200, 100), stream=buf.getvalue())
    doc.save(src)

    extracted = ExtractedDocument(
        doc_format=DocFormat.PDF,
        source_path=src,
        blocks=[
            TextBlock(
                text="scanned PII",
                location=Location(page=0, bbox=(50, 20, 150, 60)),
                source_ref=("ocr_line", 0),
            )
        ],
    )

    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {0: "REDACTED"}, out)

    result_page = pymupdf.open(out)[0]
    pix = result_page.get_pixmap(dpi=72)
    assert pix.pixel(100, 40) == (0, 0, 0)  # formerly red, now blacked out


def test_metadata_scrubbed_even_with_no_replacements(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "hello world of pdf", fontsize=11)
    doc.set_metadata({"author": "Rahul Kumar", "title": "Personal Tax Statement"})
    doc.save(src)

    extracted = PdfExtractor().extract(src)
    out = tmp_path / "out.pdf"
    PdfRenderer().render(src, extracted, {}, out)

    meta = pymupdf.open(out).metadata
    assert meta["author"] == ""
    assert meta["title"] == ""


def test_stale_page_raises(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "page zero content", fontsize=11)
    page1 = doc.new_page()
    page1.insert_text((72, 72), "Name: Rahul Kumar", fontsize=11)
    doc.save(src)
    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: "Rahul Kumar" in b.text)
    assert extracted.blocks[idx].source_ref[1] == 1  # sanity: detected on page 1

    # Simulate the source changing between extract and render (page 1
    # removed, so the block's recorded page_number is now out of range).
    # PyMuPDF refuses to save a document back over the file it was opened
    # from unless incremental - so save to a scratch path and replace.
    doc2 = pymupdf.open(src)
    doc2.delete_page(1)
    scratch = tmp_path / "scratch.pdf"
    doc2.save(scratch)
    doc2.close()
    scratch.replace(src)

    out = tmp_path / "out.pdf"
    with pytest.raises(PdfRenderError):
        PdfRenderer().render(src, extracted, {idx: "X"}, out)


def test_stale_form_field_raises(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    w = pymupdf.Widget()
    w.field_name = "customer_name"
    w.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    w.field_value = "Priya Singh"
    w.rect = pymupdf.Rect(72, 150, 300, 170)
    page.add_widget(w)
    doc.save(src)
    extracted = PdfExtractor().extract(src)
    idx = _block_index(extracted, lambda b: b.source_ref[0] == "form_field")

    fabricated = TextBlock(
        text="ghost",
        location=Location(page=0, bbox=None),
        source_ref=("form_field", 0, "nonexistent_field"),
    )
    extracted.blocks.append(fabricated)
    ghost_index = len(extracted.blocks) - 1

    out = tmp_path / "out.pdf"
    with pytest.raises(PdfRenderError):
        PdfRenderer().render(src, extracted, {ghost_index: "X"}, out)


def test_invalid_pdf_on_reread_raises(tmp_path):
    src = tmp_path / "doc.pdf"
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "hello world of pdf", fontsize=11)
    doc.save(src)
    extracted = PdfExtractor().extract(src)

    src.write_bytes(b"not a valid pdf anymore")

    out = tmp_path / "out.pdf"
    with pytest.raises(PdfRenderError):
        PdfRenderer().render(src, extracted, {}, out)

"""PDF extraction via PyMuPDF.

Per-page routing: a page with near-zero extractable native text is treated
as scanned/image content and routed through OCR (extract/ocr.py) instead -
checked per page, not per document, since a single PDF can mix native text
pages with a scanned/signed page (see project instructions).

Extraction granularity is LINE, not word/span or whole-paragraph:
- Word/span granularity would fragment multi-word entities (e.g. "Rahul
  Kumar" as two separate one-word detections) and lose surrounding context
  some recognizers rely on (e.g. a DOB recognizer needing a nearby context
  word in the same string).
- Whole-paragraph granularity risks bundling PII together with unrelated
  computation-relevant text (a name and a transaction amount in the same
  paragraph) into one block, which would then get the WHOLE paragraph's
  bbox redacted even though the amount itself is not PII.
Line granularity is the practical middle ground, and it pairs directly with
the render stage's strategy (see render/pdf.py): redact-and-replace each
affected line's bbox as one unit via PyMuPDF's own redaction API, which
removes the original content and draws the (mostly-unchanged, only
PII-substituted) replacement text back into the same box - so non-PII text
sharing a line with PII is not lost, only possibly reflowed within that
line's bounding box.

AcroForm text field values are extracted separately via page.widgets().
Verified directly (not assumed): a filled form field's value ALSO appears
as ordinary page text via get_text("dict") - PyMuPDF renders the field's
appearance stream as page content - so extracting both naively would
double-detect the same value. Any native-text line whose bbox mostly
overlaps a widget's rect is skipped; the widget path is the single source
of truth for that value.

Scanned pages are OCR'd via extract/ocr.py, which raises OcrError (wrapped
here as PdfExtractionError) if the Tesseract binary isn't installed - see
environment/OS requirements. This is a deliberate fail-closed choice: a
scanned page's PII must never be silently skipped just because OCR isn't
available on a given machine.

Not specially handled (documented gap, not a bug): a page that is mostly a
scanned image but also carries an overlaid fillable widget would be routed
through OCR only, missing the precise widget value - a rare hybrid case in
practice for bank/tax documents, which tend to be either fully native or
fully scanned per page.

TEXT NORMALIZATION, added after a real user's AIS PDF confirmed this is a
real, reproducible problem, not a theoretical one: some PDF generation
tools encode what should be a space between words as a Unicode CONTROL
character instead - confirmed directly on that document as exactly 0x08
(backspace) and 0x05 (ENQ), almost certainly a font/cmap substitution bug
in whatever tool produced the PDF (`"Date\x08of\x08Birth"`,
`"RAHUL\x05KUMAR\x05SHARMA"`). Left uncleaned, this corrupts every
downstream consumer, confirmed directly against a real spaCy pipeline, not
assumed: spaCy tokenizes `"Date\x08of\x08Birth"` as ONE token (lemma
`"date\x08of\x08birth"`), which can never match this project's
`context=["dob","birth","bear"]` list no matter how good the surrounding-
context mechanism is, and `"RAHUL\x05KUMAR\x05SHARMA"` similarly
becomes one unrecognizable token instead of a normal three-word name NER
can identify - so a value can fail detection for a reason that has
NOTHING to do with context windows, scoring thresholds, or any of this
project's other detection-tuning mechanisms. `_normalize_text` replaces
every Unicode control character (category "Cc") with a space and collapses
whitespace runs, applied once at extraction time so every downstream
consumer - detection, anonymization, AND rendering - sees the same clean
`TextBlock.text` consistently; a control character has no legitimate
place in normal extracted document text regardless of what a particular
PDF's font mapping intended it as.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

import pymupdf
from PIL import Image

from pii_redact.extract.base import Extractor
from pii_redact.extract.ocr import OcrError, ocr_lines
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock

_MIN_NATIVE_TEXT_CHARS = 10
_WIDGET_OVERLAP_THRESHOLD = 0.5
_OCR_DPI = 300


class PdfExtractionError(ValueError):
    pass


def _normalize_text(text: str) -> str:
    cleaned = "".join(" " if unicodedata.category(c) == "Cc" else c for c in text)
    return re.sub(r"[ \t]+", " ", cleaned).strip()


def _rect_overlap_fraction(inner: pymupdf.Rect, outer: pymupdf.Rect) -> float:
    inner_area = inner.get_area()
    if inner_area <= 0:
        return 0.0
    return (inner & outer).get_area() / inner_area


def _extract_widgets(page, page_number: int) -> tuple[list[TextBlock], list[pymupdf.Rect]]:
    blocks: list[TextBlock] = []
    rects: list[pymupdf.Rect] = []
    for widget in page.widgets() or []:
        rects.append(widget.rect)
        value = widget.field_value
        if isinstance(value, str) and _normalize_text(value):
            blocks.append(
                TextBlock(
                    text=_normalize_text(value),
                    location=Location(page=page_number, bbox=tuple(widget.rect)),
                    source_ref=("form_field", page_number, widget.field_name),
                )
            )
    return blocks, rects


def _extract_native_lines(
    page, page_number: int, widget_rects: list[pymupdf.Rect]
) -> list[TextBlock]:
    blocks: list[TextBlock] = []
    for block in page.get_text("dict")["blocks"]:
        if block.get("type") != 0:  # 0 = text, 1 = image
            continue
        for line in block["lines"]:
            text = _normalize_text("".join(span["text"] for span in line["spans"]))
            if not text:
                continue
            line_rect = pymupdf.Rect(line["bbox"])
            if any(
                _rect_overlap_fraction(line_rect, w) > _WIDGET_OVERLAP_THRESHOLD
                for w in widget_rects
            ):
                continue  # this is a form field's rendered appearance - see module docstring
            # Font size the ORIGINAL text was drawn at - render/pdf.py needs
            # this to size a replacement, since PyMuPDF's own redaction
            # text-insertion silently fails (renders nothing or garbles the
            # text) rather than auto-fitting when a replacement doesn't fit
            # the box - confirmed directly on a real narrow date field, see
            # render/pdf.py's module docstring.
            font_size = line["spans"][0]["size"] if line["spans"] else 11.0
            blocks.append(
                TextBlock(
                    text=text,
                    location=Location(page=page_number, bbox=tuple(line_rect)),
                    source_ref=("line", page_number, font_size),
                )
            )
    return blocks


def _extract_ocr_page(page, page_number: int) -> list[TextBlock]:
    pix = page.get_pixmap(dpi=_OCR_DPI)
    image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    try:
        lines = ocr_lines(image)
    except OcrError as exc:
        raise PdfExtractionError(f"page {page_number}: {exc}") from exc

    scale = 72.0 / _OCR_DPI  # Tesseract's bbox is in render-dpi pixels; PDF space is points
    blocks: list[TextBlock] = []
    for line in lines:
        text = _normalize_text(line.text)
        if not text:
            continue
        x0, y0, x1, y1 = line.bbox
        pdf_bbox = (x0 * scale, y0 * scale, x1 * scale, y1 * scale)
        # No real font size for OCR'd text - approximate from the scaled
        # box height (a commonly-used rough point-size-from-height ratio).
        # Same rationale as the native-line font_size above: render/pdf.py
        # needs SOME size hint to avoid PyMuPDF's default (11pt) being
        # wildly wrong for small print.
        font_size = max((pdf_bbox[3] - pdf_bbox[1]) * 0.75, 4.0)
        blocks.append(
            TextBlock(
                text=text,
                location=Location(page=page_number, bbox=pdf_bbox),
                source_ref=("ocr_line", page_number, font_size),
            )
        )
    return blocks


class PdfExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        try:
            doc = pymupdf.open(path)
        except Exception as exc:
            raise PdfExtractionError(f"{path}: could not open PDF ({exc})") from exc

        blocks: list[TextBlock] = []
        needs_ocr_pages: list[int] = []
        for page_number, page in enumerate(doc):
            native_text = page.get_text("text")
            if len(native_text.strip()) < _MIN_NATIVE_TEXT_CHARS:
                needs_ocr_pages.append(page_number)
                blocks.extend(_extract_ocr_page(page, page_number))
                continue

            widget_blocks, widget_rects = _extract_widgets(page, page_number)
            blocks.extend(_extract_native_lines(page, page_number, widget_rects))
            blocks.extend(widget_blocks)

        return ExtractedDocument(
            doc_format=DocFormat.PDF,
            source_path=path,
            blocks=blocks,
            needs_ocr_pages=needs_ocr_pages,
        )

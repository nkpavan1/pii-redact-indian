"""Standalone image extraction (JPEG/PNG) via extract/ocr.py's Tesseract
wrapper - the same OCR primitive extract/pdf.py uses for scanned pages.

Unlike the PDF path, there's no DPI-vs-PDF-points conversion here: the
image's own pixel grid IS the coordinate system, so OCR bboxes are used
as-is.

KNOWN, UNMITIGATED GAP - read before trusting this on an ID card scan:
OCR only ever catches text. It does not detect faces/photos and does not
decode QR codes or barcodes. An Aadhaar card scan's QR code encodes the
same demographic data as the printed text, in machine-readable form, and
neither it nor the photo is touched by anything in this module - see
project instructions and the original extract/image.py TODO this replaces.
Closing this requires either (a) a policy of full-image blackout for a
defined "this whole image is sensitive" document type (e.g. id_card_scan),
which needs render/image.py to know the document's doc_type - it currently
doesn't; Renderer.render()'s signature doesn't carry it, and extending it
would touch three other already-working renderers for a policy question
("blackout always, or only when text PII is actually detected?") that
deserves its own design pass, not a rushed bolt-on here - or (b) adding
face detection and QR-region decoding as their own detection stages. Ship
neither of these as "handled" - this module only ever does per-region
text redaction, same as extract/pdf.py's OCR path.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, UnidentifiedImageError

from pii_redact.extract.base import Extractor
from pii_redact.extract.ocr import OcrError, ocr_lines
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock


class ImageExtractionError(ValueError):
    pass


class ImageExtractor(Extractor):
    def extract(self, path: Path) -> ExtractedDocument:
        try:
            image = Image.open(path)
            image.load()
        except (UnidentifiedImageError, OSError) as exc:
            raise ImageExtractionError(f"{path}: could not open image ({exc})") from exc

        try:
            lines = ocr_lines(image.convert("RGB"))
        except OcrError as exc:
            raise ImageExtractionError(f"{path}: {exc}") from exc

        blocks: list[TextBlock] = [
            TextBlock(
                text=line.text,
                location=Location(bbox=line.bbox),
                source_ref=("ocr_line",),
            )
            for line in lines
            if line.text.strip()
        ]

        return ExtractedDocument(doc_format=DocFormat.IMAGE, source_path=path, blocks=blocks)

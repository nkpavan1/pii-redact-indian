"""PDF re-rendering via PyMuPDF's real redaction annotations.

Verified directly (not assumed): add_redact_annot's fill genuinely
obscures pixel/image content underneath the rect, not just vector text
objects - so the same mechanism redacts both native-text lines and
OCR'd/scanned regions (source_ref kinds "line" and "ocr_line" both use
it). Text inserted via add_redact_annot(..., text=replacement) becomes a
real, newly machine-readable text object at that location - so a
scanned/OCR'd region that was never extractable text before *becomes*
extractable after redaction (a small but real upside for the eventual
LLM-consumer use case, not just a black box with nothing left behind).

This is true redaction, not the cosmetic-overlay bug described in the
project instructions: apply_redactions() actually removes the underlying
content in the annotated region before drawing the fill/replacement text,
it doesn't just draw a rectangle on top of text that's still there.

AcroForm fields (source_ref "form_field") are NOT redacted via annotation
- the field's own field_value is updated directly (widget.update()),
matching how the value was extracted (see extract/pdf.py's widget/
duplicate-appearance note) - annotating the field's rendered appearance
as well would be redundant with the widget update and was deliberately
excluded at extraction time.

Metadata scrub (project instructions: "Strip or sanitize [metadata] on
every processed PDF"): doc.set_metadata({}) unconditionally clears title/
author/subject/keywords/creator/producer - verified this is a full
replace, not a merge, so passing {} blanks everything, not just fields
explicitly set to "".

Known gap, not attempted here: XMP metadata (a separate, richer metadata
stream from the classic docinfo dict scrubbed above) and embedded document
thumbnails are not scrubbed - PyMuPDF exposes xref-level XML metadata
access for this but it hasn't been wired up. Don't tell a user metadata is
fully scrubbed without mentioning this, especially for Adobe-authored PDFs
(which commonly carry XMP).

REPLACEMENT TEXT FITTING - found on a real user's AIS document, not
hypothetical: PyMuPDF's redaction text-insertion does NOT auto-fit or
overflow-and-still-render when the replacement text is wider than the
original text's box - it silently renders NOTHING, or truncates into
garbage (confirmed directly: a 10-character date replaced with the
18-character marker "<IN_DATE_OF_BIRTH>" came out as the single stray
character "1"). This happened even after matching the original font size
exactly and even at font sizes small enough that a plain width
calculation (`pymupdf.get_text_length`) predicted it should fit - PyMuPDF's
internal fitting logic is stricter than that measurement in ways this
project could not reverse-engineer reliably. The only thing confirmed
SAFE by construction: a replacement no longer than the original text, at
the original font size - since the original text's own presence is proof
its own length fits that box. `_safe_replacement_text` enforces this,
falling back through progressively shorter generic markers
(`"[REDACTED]"`, `"***"`, `"X"`) when the real replacement doesn't fit
that budget.

KNOWN, REAL CONSEQUENCE for `pseudonymize` mode specifically: if a coded
identifier (e.g. `IN_DATE_OF_BIRTH_A`) doesn't fit a narrow original
field's character budget, this renders a generic fallback marker instead -
which means that specific occurrence is no longer parseable by
`reverse()`. The mapping store itself is unaffected (the code was still
generated and stored), only this one rendered occurrence in the PDF loses
its visible, reversible code. Not silently hidden: this is the tradeoff of
"always render something legible" over "always render the exact code,
even if PyMuPDF drops it entirely."
"""

from __future__ import annotations

from pathlib import Path

import pymupdf

from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument

_FALLBACK_MARKERS = ("[REDACTED]", "***", "X")


class PdfRenderError(ValueError):
    pass


def _safe_replacement_text(original_text: str, new_text: str) -> str:
    if len(new_text) <= len(original_text):
        return new_text
    for fallback in _FALLBACK_MARKERS:
        if len(fallback) <= len(original_text):
            return fallback
    return "X"


def _find_widget(page, field_name: str):
    for widget in page.widgets() or []:
        if widget.field_name == field_name:
            return widget
    return None


class PdfRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        try:
            doc = pymupdf.open(source_path)
        except Exception as exc:
            raise PdfRenderError(f"{source_path}: could not open PDF ({exc})") from exc

        for block_index, new_text in replacements.items():
            block = extracted.blocks[block_index]
            kind, page_number, *rest = block.source_ref

            if page_number is None or page_number >= doc.page_count:
                raise PdfRenderError(
                    f"block {block_index}: page {page_number} no longer exists in "
                    "the re-read source - refusing to write a mismatched output"
                )
            page = doc[page_number]

            if kind in ("line", "ocr_line"):
                bbox = block.location.bbox
                if bbox is None:
                    raise PdfRenderError(
                        f"block {block_index}: missing bbox for a {kind!r} block"
                    )
                font_size = rest[0] if rest else 11.0
                safe_text = _safe_replacement_text(block.text, new_text)
                page.add_redact_annot(
                    pymupdf.Rect(bbox), text=safe_text, fontsize=font_size, fill=(0, 0, 0)
                )
            elif kind == "form_field":
                field_name = rest[0]
                widget = _find_widget(page, field_name)
                if widget is None:
                    raise PdfRenderError(
                        f"block {block_index}: form field {field_name!r} no longer "
                        f"exists on page {page_number} in the re-read source"
                    )
                widget.field_value = new_text
                widget.update()
            else:
                raise PdfRenderError(
                    f"block {block_index}: unrecognized source_ref kind {kind!r}"
                )

        for page in doc:
            page.apply_redactions()

        doc.set_metadata({})

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(output_path)

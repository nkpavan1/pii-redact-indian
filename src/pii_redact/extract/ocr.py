"""Shared OCR primitive: reconstructs line-level text + bounding boxes from
Tesseract's word-level output. Used by both extract/pdf.py (scanned/image
pages) and extract/image.py (standalone JPEG/PNG scans) so the two share
one tested implementation instead of two drifting copies.

Calls pytesseract directly rather than depending on presidio-image-redactor
- see pyproject.toml's dependency comment for why. This module only
extracts OCR'd text + bboxes; detection/anonymization go through this
project's own Presidio pipeline exactly like every other format, so the
review gate and entity allow-lists apply uniformly to OCR'd content too.

Verified on this machine, not assumed: with no Tesseract binary installed
(it's a separate native install, not a pip package - see environment/OS
requirements), pytesseract.image_to_data raises TesseractNotFoundError.
That's wrapped here as OcrError and is meant to propagate as an extraction
failure (fail-closed) rather than silently skipping the page/image.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytesseract
from PIL import Image


class OcrError(RuntimeError):
    pass


@dataclass(frozen=True)
class OcrLine:
    text: str
    bbox: tuple[float, float, float, float]  # pixel coordinates, (x0, y0, x1, y1)


def ocr_lines(image: Image.Image) -> list[OcrLine]:
    """Groups Tesseract's word-level results into lines (via Tesseract's
    own block/paragraph/line numbering), giving each line one concatenated
    text string and a bounding box covering all its words - same "line
    granularity" tradeoff as extract/pdf.py's native-text path, and for
    the same reason: it gives Presidio's NER enough surrounding context to
    work with, and pairs with the render stage redacting a whole bbox
    region as one unit."""
    try:
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    except pytesseract.TesseractNotFoundError as exc:
        raise OcrError(
            "Tesseract OCR binary not found - it's a separate native install, "
            "not a pip package (see README/environment setup)"
        ) from exc

    line_word_indices: dict[tuple[int, int, int], list[int]] = {}
    for i in range(len(data["text"])):
        word = data["text"][i]
        if not word or not word.strip():
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        line_word_indices.setdefault(key, []).append(i)

    lines: list[OcrLine] = []
    for key in sorted(line_word_indices):
        indices = line_word_indices[key]
        text = " ".join(data["text"][i] for i in indices)
        lefts = [data["left"][i] for i in indices]
        tops = [data["top"][i] for i in indices]
        rights = [data["left"][i] + data["width"][i] for i in indices]
        bottoms = [data["top"][i] + data["height"][i] for i in indices]
        lines.append(OcrLine(text=text, bbox=(min(lefts), min(tops), max(rights), max(bottoms))))
    return lines

import pytesseract
import pytest
from PIL import Image

from pii_redact.extract.ocr import OcrError, ocr_lines


def test_missing_tesseract_binary_raises_ocr_error():
    # No Tesseract binary is installed in this dev environment (verified -
    # see the project instructions' environment section) - this exercises
    # the real failure path, not a simulation of it.
    image = Image.new("RGB", (100, 30), color="white")
    with pytest.raises(OcrError):
        ocr_lines(image)


def _fake_image_to_data(words_by_line, **kwargs):
    """Builds a pytesseract.image_to_data-shaped dict from a simple
    [(block, par, line, [(text, left, top, width, height), ...]), ...]
    spec, so line-grouping logic can be tested without a real OCR engine."""
    data = {
        "text": [], "block_num": [], "par_num": [], "line_num": [],
        "left": [], "top": [], "width": [], "height": [], "conf": [],
    }
    for block, par, line, words in words_by_line:
        for text, left, top, width, height in words:
            data["text"].append(text)
            data["block_num"].append(block)
            data["par_num"].append(par)
            data["line_num"].append(line)
            data["left"].append(left)
            data["top"].append(top)
            data["width"].append(width)
            data["height"].append(height)
            data["conf"].append(95)
    return data


def test_words_are_grouped_into_lines_with_union_bbox(monkeypatch):
    spec = [
        (1, 1, 1, [("Name:", 10, 10, 40, 15), ("Rahul", 55, 10, 50, 15), ("Kumar", 110, 10, 50, 15)]),
        (1, 1, 2, [("PAN:", 10, 30, 35, 15), ("ABCDE1234F", 50, 30, 80, 15)]),
    ]

    monkeypatch.setattr(
        pytesseract, "image_to_data",
        lambda image, output_type=None: _fake_image_to_data(spec),
    )

    lines = ocr_lines(Image.new("RGB", (1, 1)))
    assert len(lines) == 2
    assert lines[0].text == "Name: Rahul Kumar"
    assert lines[0].bbox == (10, 10, 160, 25)
    assert lines[1].text == "PAN: ABCDE1234F"
    assert lines[1].bbox == (10, 30, 130, 45)


def test_empty_words_are_skipped(monkeypatch):
    spec = [(1, 1, 1, [("Rahul", 10, 10, 40, 15), ("", 55, 10, 10, 15), ("   ", 70, 10, 10, 15)])]
    monkeypatch.setattr(
        pytesseract, "image_to_data",
        lambda image, output_type=None: _fake_image_to_data(spec),
    )

    lines = ocr_lines(Image.new("RGB", (1, 1)))
    assert len(lines) == 1
    assert lines[0].text == "Rahul"


def test_no_words_returns_no_lines(monkeypatch):
    monkeypatch.setattr(
        pytesseract, "image_to_data",
        lambda image, output_type=None: _fake_image_to_data([]),
    )
    assert ocr_lines(Image.new("RGB", (1, 1))) == []

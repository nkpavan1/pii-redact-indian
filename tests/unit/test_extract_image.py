import pytest
from PIL import Image

import pii_redact.extract.image as image_module
from pii_redact.extract.image import ImageExtractionError, ImageExtractor
from pii_redact.extract.ocr import OcrLine
from pii_redact.types import DocFormat


def test_missing_tesseract_raises_fail_closed(tmp_path):
    # No Tesseract binary is installed in this dev environment - this is
    # a real failure path, not a simulation of one.
    p = tmp_path / "scan.png"
    Image.new("RGB", (100, 30), color="white").save(p)

    with pytest.raises(ImageExtractionError):
        ImageExtractor().extract(p)


def test_ocr_lines_become_blocks(tmp_path, monkeypatch):
    p = tmp_path / "scan.png"
    Image.new("RGB", (400, 200), color="white").save(p)

    monkeypatch.setattr(
        image_module, "ocr_lines",
        lambda image: [
            OcrLine(text="Name: Rahul Kumar", bbox=(10, 10, 200, 30)),
            OcrLine(text="PAN: ABCDE1234F", bbox=(10, 40, 180, 60)),
        ],
    )

    extracted = ImageExtractor().extract(p)
    assert extracted.doc_format == DocFormat.IMAGE
    assert [b.text for b in extracted.blocks] == ["Name: Rahul Kumar", "PAN: ABCDE1234F"]
    assert extracted.blocks[0].location.bbox == (10, 10, 200, 30)
    assert extracted.blocks[0].source_ref == ("ocr_line",)


def test_empty_ocr_lines_are_filtered(tmp_path, monkeypatch):
    p = tmp_path / "scan.png"
    Image.new("RGB", (100, 30), color="white").save(p)

    monkeypatch.setattr(
        image_module, "ocr_lines",
        lambda image: [OcrLine(text="   ", bbox=(0, 0, 1, 1)), OcrLine(text="Rahul", bbox=(1, 1, 2, 2))],
    )

    extracted = ImageExtractor().extract(p)
    assert len(extracted.blocks) == 1
    assert extracted.blocks[0].text == "Rahul"


def test_invalid_image_raises(tmp_path):
    p = tmp_path / "not_an_image.png"
    p.write_bytes(b"this is not image data")
    with pytest.raises(ImageExtractionError):
        ImageExtractor().extract(p)

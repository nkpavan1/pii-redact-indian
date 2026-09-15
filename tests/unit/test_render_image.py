import pytest
from PIL import Image

from pii_redact.render.image import ImageRenderError, ImageRenderer
from pii_redact.types import DocFormat, ExtractedDocument, Location, TextBlock


def _doc(blocks):
    return ExtractedDocument(doc_format=DocFormat.IMAGE, source_path=None, blocks=blocks)


def test_redacted_region_is_blackened(tmp_path):
    src = tmp_path / "scan.png"
    img = Image.new("RGB", (200, 100), color="white")
    img.save(src)

    blocks = [TextBlock(text="Rahul Kumar", location=Location(bbox=(10, 10, 150, 40)), source_ref=("ocr_line",))]
    extracted = _doc(blocks)

    out = tmp_path / "out.png"
    ImageRenderer().render(src, extracted, {0: "PERSON_A"}, out)

    result = Image.open(out).convert("RGB")
    assert result.getpixel((80, 25)) == (0, 0, 0)  # inside the redacted region
    assert result.getpixel((5, 5)) == (255, 255, 255)  # outside, untouched


def test_no_replacements_leaves_image_unchanged(tmp_path):
    src = tmp_path / "scan.png"
    img = Image.new("RGB", (200, 100), color="white")
    img.save(src)
    blocks = [TextBlock(text="Rahul Kumar", location=Location(bbox=(10, 10, 150, 40)), source_ref=("ocr_line",))]
    extracted = _doc(blocks)

    out = tmp_path / "out.png"
    ImageRenderer().render(src, extracted, {}, out)

    result = Image.open(out).convert("RGB")
    assert result.getpixel((80, 25)) == (255, 255, 255)


def test_only_targeted_region_is_redacted(tmp_path):
    src = tmp_path / "scan.png"
    Image.new("RGB", (200, 100), color="white").save(src)
    blocks = [
        TextBlock(text="Rahul Kumar", location=Location(bbox=(10, 10, 100, 30)), source_ref=("ocr_line",)),
        TextBlock(text="unrelated text", location=Location(bbox=(10, 50, 100, 70)), source_ref=("ocr_line",)),
    ]
    extracted = _doc(blocks)

    out = tmp_path / "out.png"
    ImageRenderer().render(src, extracted, {0: "PERSON_A"}, out)

    result = Image.open(out).convert("RGB")
    assert result.getpixel((50, 20)) == (0, 0, 0)  # block 0 region - redacted
    assert result.getpixel((50, 60)) == (255, 255, 255)  # block 1 region - untouched


def test_missing_bbox_raises(tmp_path):
    src = tmp_path / "scan.png"
    Image.new("RGB", (100, 30), color="white").save(src)
    blocks = [TextBlock(text="x", location=Location(bbox=None), source_ref=("ocr_line",))]
    extracted = _doc(blocks)

    out = tmp_path / "out.png"
    with pytest.raises(ImageRenderError):
        ImageRenderer().render(src, extracted, {0: "X"}, out)


def test_out_of_range_block_index_raises(tmp_path):
    src = tmp_path / "scan.png"
    Image.new("RGB", (100, 30), color="white").save(src)
    extracted = _doc([])

    out = tmp_path / "out.png"
    with pytest.raises(ImageRenderError):
        ImageRenderer().render(src, extracted, {0: "X"}, out)


def test_invalid_image_raises(tmp_path):
    src = tmp_path / "not_an_image.png"
    src.write_bytes(b"not image data")
    extracted = _doc([])

    out = tmp_path / "out.png"
    with pytest.raises(ImageRenderError):
        ImageRenderer().render(src, extracted, {}, out)

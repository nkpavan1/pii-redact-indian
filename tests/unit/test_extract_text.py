import pytest

from pii_redact.extract.text import TextExtractor
from pii_redact.render.text import TextRenderError, TextRenderer
from pii_redact.types import DocFormat


def _extract(tmp_path, content: bytes, name="note.md"):
    p = tmp_path / name
    p.write_bytes(content)
    return p, TextExtractor().extract(p)


def test_first_line_is_a_block(tmp_path):
    # B1: the CSV path treated line 1 as a header and never scanned it.
    _, extracted = _extract(tmp_path, b"Ravi Kumar, PAN ABCPE1234F\nmore of the same paragraph\n")
    assert extracted.doc_format == DocFormat.TEXT
    assert extracted.blocks[0].text == "Ravi Kumar, PAN ABCPE1234F\nmore of the same paragraph"
    assert extracted.blocks[0].location.row == 0


def test_blank_lines_split_paragraphs(tmp_path):
    _, extracted = _extract(tmp_path, b"# Title\n\nFirst para.\n   \nSecond para\nline two\n")
    assert [b.text for b in extracted.blocks] == ["# Title", "First para.", "Second para\nline two"]
    assert [b.location.row for b in extracted.blocks] == [0, 2, 4]


def test_frontmatter_lines_are_scanned_like_any_paragraph(tmp_path):
    _, extracted = _extract(tmp_path, b"---\nauthor: Ravi Kumar\n---\n\nBody.\n")
    assert extracted.blocks[0].text == "---\nauthor: Ravi Kumar\n---"


def test_crlf_paragraph_has_no_trailing_carriage_return(tmp_path):
    # Line breaks inside a paragraph are kept as-is (so render can splice
    # the span back exactly); only the paragraph's own trailing "\r" is
    # excluded.
    _, extracted = _extract(tmp_path, b"line one\r\nline two\r\n\r\nnext\r\n")
    assert [b.text for b in extracted.blocks] == ["line one\r\nline two", "next"]


def test_empty_file_has_no_blocks(tmp_path):
    _, extracted = _extract(tmp_path, b"")
    assert extracted.blocks == []


def _render(tmp_path, source, extracted, replacements):
    out = tmp_path / "out" / source.name
    TextRenderer().render(source, extracted, replacements, out)
    return out.read_bytes()


def test_render_replaces_only_the_replaced_block_byte_for_byte(tmp_path):
    source, extracted = _extract(tmp_path, b"Ravi Kumar wrote this.\r\n\r\n# Heading\r\nUntouched.\r\n")
    out = _render(tmp_path, source, extracted, {0: "PERSON_A wrote this."})
    assert out == b"PERSON_A wrote this.\r\n\r\n# Heading\r\nUntouched.\r\n"


def test_render_multiple_blocks_keeps_offsets_valid(tmp_path):
    source, extracted = _extract(tmp_path, b"aaa\n\nbbb\n\nccc\n")
    out = _render(tmp_path, source, extracted, {0: "A-LONGER-ONE", 2: "C"})
    assert out == b"A-LONGER-ONE\n\nbbb\n\nC\n"


def test_render_preserves_utf8_bom(tmp_path):
    source, extracted = _extract(tmp_path, b"\xef\xbb\xbfRavi Kumar\n")
    out = _render(tmp_path, source, extracted, {0: "PERSON_A"})
    assert out == b"\xef\xbb\xbfPERSON_A\n"


def test_render_refuses_if_source_changed_since_extract(tmp_path):
    source, extracted = _extract(tmp_path, b"Ravi Kumar\n")
    source.write_bytes(b"Someone else\n")
    with pytest.raises(TextRenderError):
        TextRenderer().render(source, extracted, {0: "PERSON_A"}, tmp_path / "out.md")

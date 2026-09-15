from pathlib import Path

from pii_redact.pipeline import _anonymize_blocks
from pii_redact.types import DocFormat, ExtractedDocument, Detection, Location, Mode, TextBlock
from tests.unit.test_anonymize_operators import InMemoryMappingStore


def _doc(blocks: list[TextBlock]) -> ExtractedDocument:
    return ExtractedDocument(doc_format=DocFormat.CSV, source_path=Path("x.csv"), blocks=blocks)


def test_redact_mode_replaces_single_detection(tmp_path):
    blocks = [TextBlock(text="Rahul Kumar", location=Location(row=0, column="name"))]
    extracted = _doc(blocks)
    detections = [
        Detection(entity_type="PERSON", start=0, end=11, score=0.85, block_index=0, location=blocks[0].location)
    ]

    result = _anonymize_blocks(extracted, detections, Mode.REDACT, InMemoryMappingStore())
    assert result == {0: "<PERSON>"}


def test_redact_mode_handles_multiple_detections_in_one_block():
    text = "Name Rahul Kumar, PAN ABCDE1234F"
    blocks = [TextBlock(text=text, location=Location(row=0, column="note"))]
    extracted = _doc(blocks)
    name_start, name_end = text.index("Rahul Kumar"), text.index("Rahul Kumar") + len("Rahul Kumar")
    pan_start, pan_end = text.index("ABCDE1234F"), text.index("ABCDE1234F") + len("ABCDE1234F")
    detections = [
        Detection(entity_type="PERSON", start=name_start, end=name_end, score=0.85, block_index=0, location=blocks[0].location),
        Detection(entity_type="IN_PAN", start=pan_start, end=pan_end, score=0.9, block_index=0, location=blocks[0].location),
    ]

    result = _anonymize_blocks(extracted, detections, Mode.REDACT, InMemoryMappingStore())
    assert result[0] == "Name <PERSON>, PAN <IN_PAN>"


def test_pseudonymize_mode_gives_same_code_for_same_value_across_blocks():
    blocks = [
        TextBlock(text="Rahul Kumar", location=Location(row=0, column="name")),
        TextBlock(text="Signed: Rahul Kumar", location=Location(row=1, column="signature")),
    ]
    extracted = _doc(blocks)
    detections = [
        Detection(entity_type="PERSON", start=0, end=11, score=0.85, block_index=0, location=blocks[0].location),
        Detection(entity_type="PERSON", start=8, end=19, score=0.85, block_index=1, location=blocks[1].location),
    ]

    store = InMemoryMappingStore()
    result = _anonymize_blocks(extracted, detections, Mode.PSEUDONYMIZE, store)
    code_in_block0 = result[0]
    code_in_block1 = result[1].replace("Signed: ", "")
    assert code_in_block0 == code_in_block1


def test_read_only_block_is_excluded_from_replacements():
    blocks = [
        TextBlock(
            text="Rahul Kumar",
            location=Location(sheet="Sheet", cell="A2"),
            source_ref=("formula_result", "Sheet", "A2"),
            read_only=True,
        )
    ]
    extracted = _doc(blocks)
    detections = [
        Detection(entity_type="PERSON", start=0, end=11, score=0.85, block_index=0, location=blocks[0].location)
    ]

    result = _anonymize_blocks(extracted, detections, Mode.REDACT, InMemoryMappingStore())
    assert result == {}


def test_read_only_block_does_not_block_other_blocks_in_same_document():
    blocks = [
        TextBlock(
            text="Rahul Kumar",
            location=Location(sheet="Sheet", cell="A2"),
            source_ref=("formula_result", "Sheet", "A2"),
            read_only=True,
        ),
        TextBlock(text="ABCDE1234F", location=Location(sheet="Sheet", cell="B1")),
    ]
    extracted = _doc(blocks)
    detections = [
        Detection(entity_type="PERSON", start=0, end=11, score=0.85, block_index=0, location=blocks[0].location),
        Detection(entity_type="IN_PAN", start=0, end=10, score=0.9, block_index=1, location=blocks[1].location),
    ]

    result = _anonymize_blocks(extracted, detections, Mode.REDACT, InMemoryMappingStore())
    assert result == {1: "<IN_PAN>"}


def test_no_detections_returns_empty_dict():
    extracted = _doc([TextBlock(text="nothing sensitive", location=Location(row=0, column="note"))])
    result = _anonymize_blocks(extracted, [], Mode.REDACT, InMemoryMappingStore())
    assert result == {}

import json

import pytest

from pii_redact.extract.json_ import JsonExtractionError, JsonExtractor
from pii_redact.types import DocFormat


def _paths_to_text(extracted):
    return {b.location.json_path: b.text for b in extracted.blocks}


def test_flat_object(tmp_path):
    p = tmp_path / "flat.json"
    p.write_text(json.dumps({"name": "Rahul Kumar", "pan": "ABCDE1234F"}))
    extracted = JsonExtractor().extract(p)

    assert extracted.doc_format == DocFormat.JSON
    assert _paths_to_text(extracted) == {
        '$["name"]': "Rahul Kumar",
        '$["pan"]': "ABCDE1234F",
    }


def test_nested_object(tmp_path):
    p = tmp_path / "nested.json"
    p.write_text(json.dumps({"customer": {"name": "Rahul Kumar", "pan": "ABCDE1234F"}}))
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {
        '$["customer"]["name"]': "Rahul Kumar",
        '$["customer"]["pan"]': "ABCDE1234F",
    }


def test_array_of_objects_indexes_each_element(tmp_path):
    p = tmp_path / "accounts.json"
    p.write_text(
        json.dumps({"accounts": [{"ifsc": "HDFC0001234"}, {"ifsc": "SBIN0005678"}]})
    )
    extracted = JsonExtractor().extract(p)

    paths = _paths_to_text(extracted)
    assert paths['$["accounts"][0]["ifsc"]'] == "HDFC0001234"
    assert paths['$["accounts"][1]["ifsc"]'] == "SBIN0005678"


def test_root_level_array(tmp_path):
    p = tmp_path / "list.json"
    p.write_text(json.dumps(["ABCDE1234F", "PQRSX5678G"]))
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {
        '$[0]': "ABCDE1234F",
        '$[1]': "PQRSX5678G",
    }


def test_deeply_mixed_nesting(tmp_path):
    p = tmp_path / "mixed.json"
    p.write_text(
        json.dumps({"a": [{"b": {"c": ["deep pan: ABCDE1234F"]}}]})
    )
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {
        '$["a"][0]["b"]["c"][0]': "deep pan: ABCDE1234F",
    }


def test_key_with_dot_and_quote_is_unambiguous(tmp_path):
    p = tmp_path / "odd_keys.json"
    p.write_text(json.dumps({'weird.key "with" quotes': "ABCDE1234F"}))
    extracted = JsonExtractor().extract(p)

    expected_path = '$[' + json.dumps('weird.key "with" quotes') + ']'
    assert _paths_to_text(extracted) == {expected_path: "ABCDE1234F"}


def test_non_string_leaves_are_skipped(tmp_path):
    p = tmp_path / "typed.json"
    p.write_text(json.dumps({"age": 30, "active": True, "note": None, "name": "Rahul"}))
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {'$["name"]': "Rahul"}


def test_empty_string_leaf_is_skipped(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"name": "Rahul", "note": ""}))
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {'$["name"]': "Rahul"}


def test_utf8_bom_is_stripped(tmp_path):
    p = tmp_path / "bom.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"name": "Rahul"}).encode("utf-8"))
    extracted = JsonExtractor().extract(p)

    assert _paths_to_text(extracted) == {'$["name"]': "Rahul"}


def test_invalid_json_raises(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not valid json")
    with pytest.raises(JsonExtractionError):
        JsonExtractor().extract(p)


def test_indent_detected_for_pretty_printed_file(tmp_path):
    p = tmp_path / "pretty.json"
    p.write_text(json.dumps({"name": "Rahul", "pan": "ABCDE1234F"}, indent=4))
    extracted = JsonExtractor().extract(p)
    assert extracted.format_metadata["indent"] == 4


def test_indent_is_none_for_compact_file(tmp_path):
    p = tmp_path / "compact.json"
    p.write_text(json.dumps({"name": "Rahul"}, separators=(",", ":")))
    extracted = JsonExtractor().extract(p)
    assert extracted.format_metadata["indent"] is None

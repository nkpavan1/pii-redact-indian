import json

import pytest

from pii_redact.extract.json_ import JsonExtractor
from pii_redact.render.json_ import JsonRenderError, JsonRenderer
from pii_redact.types import ExtractedDocument, Location, TextBlock


def _block_index(extracted, path):
    return next(i for i, b in enumerate(extracted.blocks) if b.location.json_path == path)


def test_flat_object_round_trip_replaces_only_targeted_leaf(tmp_path):
    src = tmp_path / "flat.json"
    src.write_text(json.dumps({"name": "Rahul Kumar", "pan": "ABCDE1234F"}))
    extracted = JsonExtractor().extract(src)
    pan_index = _block_index(extracted, '$["pan"]')

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {pan_index: "IN_PAN_A"}, out)

    result = json.loads(out.read_text())
    assert result == {"name": "Rahul Kumar", "pan": "IN_PAN_A"}


def test_nested_object_replacement(tmp_path):
    src = tmp_path / "nested.json"
    src.write_text(json.dumps({"customer": {"name": "Rahul Kumar", "pan": "ABCDE1234F"}}))
    extracted = JsonExtractor().extract(src)
    pan_index = _block_index(extracted, '$["customer"]["pan"]')

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {pan_index: "IN_PAN_A"}, out)

    result = json.loads(out.read_text())
    assert result == {"customer": {"name": "Rahul Kumar", "pan": "IN_PAN_A"}}


def test_array_of_objects_replaces_only_one_element(tmp_path):
    src = tmp_path / "accounts.json"
    src.write_text(
        json.dumps({"accounts": [{"ifsc": "HDFC0001234"}, {"ifsc": "SBIN0005678"}]})
    )
    extracted = JsonExtractor().extract(src)
    idx0 = _block_index(extracted, '$["accounts"][0]["ifsc"]')

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {idx0: "IFSC_A"}, out)

    result = json.loads(out.read_text())
    assert result["accounts"][0]["ifsc"] == "IFSC_A"
    assert result["accounts"][1]["ifsc"] == "SBIN0005678"  # untouched


def test_root_level_array_replacement(tmp_path):
    src = tmp_path / "list.json"
    src.write_text(json.dumps(["ABCDE1234F", "PQRSX5678G"]))
    extracted = JsonExtractor().extract(src)
    idx1 = _block_index(extracted, "$[1]")

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {idx1: "IN_PAN_B"}, out)

    assert json.loads(out.read_text()) == ["ABCDE1234F", "IN_PAN_B"]


def test_no_replacements_leaves_document_unchanged(tmp_path):
    src = tmp_path / "flat.json"
    original = {"name": "Rahul Kumar", "pan": "ABCDE1234F"}
    src.write_text(json.dumps(original))
    extracted = JsonExtractor().extract(src)

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {}, out)

    assert json.loads(out.read_text()) == original


def test_key_with_dot_and_quote_round_trips(tmp_path):
    src = tmp_path / "odd_keys.json"
    src.write_text(json.dumps({'weird.key "with" quotes': "ABCDE1234F"}))
    extracted = JsonExtractor().extract(src)
    idx = _block_index(
        extracted, '$[' + json.dumps('weird.key "with" quotes') + ']'
    )

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {idx: "REDACTED"}, out)

    assert json.loads(out.read_text()) == {'weird.key "with" quotes': "REDACTED"}


def test_indent_style_is_preserved(tmp_path):
    src = tmp_path / "pretty.json"
    src.write_text(json.dumps({"name": "Rahul"}, indent=4))
    extracted = JsonExtractor().extract(src)
    idx = _block_index(extracted, '$["name"]')

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {idx: "PERSON_A"}, out)

    out_text = out.read_text()
    assert '\n    "name"' in out_text  # 4-space indent preserved


def test_non_ascii_value_written_as_readable_utf8(tmp_path):
    src = tmp_path / "unicode.json"
    src.write_text(
        json.dumps({"city": "Bengaluru", "note": "मुंबई"}, ensure_ascii=False),
        encoding="utf-8",
    )
    extracted = JsonExtractor().extract(src)
    idx = _block_index(extracted, '$["city"]')

    out = tmp_path / "out.json"
    JsonRenderer().render(src, extracted, {idx: "CITY_A"}, out)

    out_text = out.read_text(encoding="utf-8")
    assert "मुंबई" in out_text  # untouched value stays raw UTF-8, not \uXXXX-escaped
    assert "\\u" not in out_text


def test_stale_path_raises_instead_of_silently_writing_wrong_value(tmp_path):
    src = tmp_path / "flat.json"
    src.write_text(json.dumps({"name": "Rahul Kumar"}))
    extracted = JsonExtractor().extract(src)

    extracted.blocks.append(
        TextBlock(text="ghost", location=Location(json_path='$["nonexistent"]["nested"]'))
    )
    ghost_index = len(extracted.blocks) - 1

    out = tmp_path / "out.json"
    with pytest.raises(JsonRenderError):
        JsonRenderer().render(src, extracted, {ghost_index: "X"}, out)


def test_path_pointing_at_non_string_raises(tmp_path):
    src = tmp_path / "typed.json"
    src.write_text(json.dumps({"name": "Rahul", "age": 30}))
    extracted = JsonExtractor().extract(src)

    # "age" was never extracted (non-string leaf) - fabricate a block that
    # incorrectly targets it, simulating a structure mismatch.
    extracted.blocks.append(TextBlock(text="30", location=Location(json_path='$["age"]')))
    fake_index = len(extracted.blocks) - 1

    out = tmp_path / "out.json"
    with pytest.raises(JsonRenderError):
        JsonRenderer().render(src, extracted, {fake_index: "X"}, out)


def test_invalid_json_on_reread_raises(tmp_path):
    src = tmp_path / "flat.json"
    src.write_text(json.dumps({"name": "Rahul"}))
    extracted = JsonExtractor().extract(src)

    src.write_text("{not valid json anymore")  # simulate source changing mid-pipeline

    out = tmp_path / "out.json"
    with pytest.raises(JsonRenderError):
        JsonRenderer().render(src, extracted, {}, out)

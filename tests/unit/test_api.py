"""Tests for the public string API (pii_redact.api). Real detection, a real
encrypted MappingStore with an explicit key, synthetic data only.

The synthetic PAN is ABCPE1234F: a PAN's 4th character is the holder type,
and ABCDE1234F ('D' is not a holder type) is not detected at all - see
tests/unit/test_pipeline_run.py.
"""

import json
import re

import pytest
from cryptography.fernet import Fernet

import pii_redact
from pii_redact import api
from pii_redact.anonymize.mapping_store import MappingStore, MappingStoreError
from pii_redact.api import (
    MAX_TEXT_CHARS,
    RedactResult,
    TextTooLongError,
    redact_text,
    redact_texts,
    reverse_text,
    reverse_texts,
)
from pii_redact.audit.logger import AuditLogger
from pii_redact.pipeline import run_pipeline
from pii_redact.types import Detection, Mode

TEXT = "Ravi Kumar, PAN ABCPE1234F, called about the loan."
REDACTED = "PERSON_A, PAN IN_PAN_A, called about the loan."


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


def _explode(*_args, **_kwargs):
    raise RuntimeError("analyzer down")


# --- public surface


def test_public_names_are_importable_from_the_package_root():
    from pii_redact import MappingStore as M
    from pii_redact import RedactResult as R
    from pii_redact import redact_text as rt
    from pii_redact import redact_texts as rts
    from pii_redact import reverse_text as vt
    from pii_redact import reverse_texts as vts

    assert (M, R, rt, rts, vt, vts) == (
        MappingStore, RedactResult, redact_text, redact_texts, reverse_text, reverse_texts,
    )
    assert {"redact_text", "redact_texts", "reverse_text", "reverse_texts", "RedactResult", "MappingStore"} <= set(
        pii_redact.__all__
    )


def test_unknown_package_attribute_still_raises():
    with pytest.raises(AttributeError):
        pii_redact.not_a_real_name  # noqa: B018


# --- redact_text


def test_redact_text_pseudonymizes_and_counts_by_type(store):
    res = redact_text(TEXT, store)
    assert res.text == REDACTED
    assert res.entities == {"PERSON": 1, "IN_PAN": 1}


def test_spans_are_offsets_of_the_codes_in_the_output(store):
    res = redact_text(TEXT, store)
    assert res.spans == [(0, 8, "PERSON", "PERSON_A"), (14, 22, "IN_PAN", "IN_PAN_A")]
    for start, end, entity_type, code in res.spans:
        assert res.text[start:end] == code
        assert code.startswith(entity_type + "_")


def test_round_trip_restores_the_original_text(store):
    assert reverse_text(redact_text(TEXT, store).text, store) == TEXT


def test_codes_are_plain_ascii_and_need_no_json_escaping(store):
    text = 'Ravi Kumar <ravi.kumar@example.com>, "PAN" ABCPE1234F'
    res = redact_text(text, store)
    assert res.entities == {"PERSON": 1, "EMAIL_ADDRESS": 1, "IN_PAN": 1}
    for *_, code in res.spans:
        assert re.fullmatch(r"[A-Z0-9_]+", code)
        assert json.dumps(code) == f'"{code}"'
    # And the codes survive a JSON string round trip inside a message.
    wire = json.dumps({"content": res.text})
    assert reverse_text(json.loads(wire)["content"], store) == text


def test_redacting_an_already_redacted_text_changes_nothing(store):
    once = redact_text(TEXT, store)
    codes_before = store.all_codes()

    twice = redact_text(once.text, store)

    assert twice.text == once.text
    assert twice.entities == {}
    assert twice.spans == []
    assert store.all_codes() == codes_before  # no new codes, no PERSON_PERSON_A


def test_existing_codes_pass_through_while_new_pii_is_still_redacted(store):
    first = redact_text(TEXT, store).text
    res = redact_text(first + " Asha Rao will call back.", store)
    assert res.text == first + " PERSON_B will call back."
    assert res.entities == {"PERSON": 1}


def test_detection_running_across_a_code_keeps_the_code_and_redacts_the_rest(store, monkeypatch):
    # NER can read an existing code plus a neighboring name as one PERSON
    # ("PERSON_A Kumar"). The code must survive and "Kumar" must not leak.
    store.get_or_create_code("PERSON", "RAVI", display="Ravi")
    monkeypatch.setattr(
        api,
        "detect_in_block",
        lambda block, *_a, **_k: [Detection("PERSON", 0, len(block.text), 0.85, 0, block.location)],
    )

    res = redact_text("PERSON_A, Kumar", store)

    assert res.text == "PERSON_A, PERSON_B"
    assert res.spans == [(10, 18, "PERSON", "PERSON_B")]
    assert reverse_text(res.text, store) == "Ravi, Kumar"


def test_real_detector_span_across_a_code_leaves_the_code_intact(store):
    # Found by probe, no stub: with "Address" nearby, the address
    # recognizer's pattern runs straight across an existing code. Without
    # code protection the code would be folded into a new address value
    # ("IN_ADDRESS_B" = "IN_ADDRESS_A, near the ...") and never reverse.
    store.get_or_create_code(
        "IN_ADDRESS", "B204,SUNRISEAPARTMENTS,RAMPUR", display="B-204, Sunrise Apartments, Rampur"
    )

    res = redact_text("Address: IN_ADDRESS_A, near the old temple road in the town centre", store)

    assert res.text == "Address: IN_ADDRESS_A, IN_ADDRESS_B"
    assert reverse_text(res.text, store) == (
        "Address: B-204, Sunrise Apartments, Rampur, near the old temple road in the town centre"
    )


def test_detection_entirely_inside_a_code_is_dropped(store, monkeypatch):
    store.get_or_create_code("IN_PAN", "ABCPE1234F", display="ABCPE1234F")
    monkeypatch.setattr(
        api,
        "detect_in_block",
        lambda block, *_a, **_k: [Detection("PERSON", 0, 8, 0.85, 0, block.location)],
    )

    res = redact_text("IN_PAN_A is on file", store)

    assert res.text == "IN_PAN_A is on file"
    assert res.entities == {}


def test_unknown_code_shaped_token_is_not_treated_as_a_code(store):
    # Only codes the store issued are protected; PERSON_Z was never issued,
    # so it is just text (scanned like any other).
    assert api.find_codes("PERSON_Z met PERSON_A", {"PERSON_A"}) == [(13, 21)]


def test_same_person_gets_the_same_code_in_documents_and_strings(tmp_path, store):
    audit = AuditLogger(tmp_path / "audit.log.jsonl")
    out_dir = tmp_path / "out"
    docs = {
        "a.md": "Ravi Kumar approved the transfer.\n",
        "b.txt": "RAVI KUMAR\n\nStatement for the quarter.\n",
    }
    for name, content in docs.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        result = run_pipeline(path, out_dir, Mode.PSEUDONYMIZE, None, store, audit, non_interactive=True)
        assert result.written, result.failure_reason

    assert (out_dir / "a.md").read_text(encoding="utf-8") == "PERSON_A approved the transfer.\n"
    assert (out_dir / "b.txt").read_text(encoding="utf-8").startswith("PERSON_A\n")

    res = redact_text("Please remind Ravi Kumar about the loan.", store)
    assert res.text == "Please remind PERSON_A about the loan."
    # The all-caps sighting never replaces the mixed-case display form.
    assert reverse_text(res.text, store) == "Please remind Ravi Kumar about the loan."


# --- redact_texts / reverse_texts


def test_redact_texts_is_one_to_one_and_order_preserving(store):
    texts = [
        "Ravi Kumar called.",
        "",
        "   ",
        "No personal data here.",
        "Asha Rao and Ravi Kumar met.",
    ]
    results = redact_texts(texts, store)
    assert [r.text for r in results] == [
        "PERSON_A called.",
        "",
        "   ",
        "No personal data here.",
        "PERSON_B and PERSON_A met.",
    ]
    assert [r.entities for r in results] == [{"PERSON": 1}, {}, {}, {}, {"PERSON": 2}]


def test_code_issued_earlier_in_a_batch_is_protected_later_in_it(store, monkeypatch):
    # Text 1 issues PERSON_A; text 2 already contains "PERSON_A" and the
    # detector (stubbed) flags it. It must be treated as the known code.
    def fake_detect(block, *_a, **_k):
        return [Detection("PERSON", 0, 8, 0.85, 0, block.location)]

    monkeypatch.setattr(api, "detect_in_block", fake_detect)
    results = redact_texts(["Somebody", "PERSON_A said hi"], store)

    assert [r.text for r in results] == ["PERSON_A", "PERSON_A said hi"]
    assert results[1].entities == {}


def test_reverse_texts_is_one_to_one_and_leaves_unknown_codes(store):
    results = redact_texts(["Ravi Kumar called.", "Asha Rao replied."], store)
    replies = [r.text for r in results] + ["PERSON_Z is unknown.", ""]
    assert reverse_texts(replies, store) == [
        "Ravi Kumar called.",
        "Asha Rao replied.",
        "PERSON_Z is unknown.",
        "",
    ]


# --- options


def test_threshold_above_every_score_redacts_nothing(store):
    res = redact_text(TEXT, store, threshold=0.99)
    assert res.text == TEXT
    assert res.entities == {}


@pytest.mark.parametrize("bad", [-0.1, 1.5])
def test_threshold_out_of_range_is_rejected(store, bad):
    with pytest.raises(ValueError, match="threshold"):
        redact_text(TEXT, store, threshold=bad)


def test_entities_limits_what_is_redacted(store):
    res = redact_text(TEXT, store, entities=["IN_PAN"])
    assert res.text == "Ravi Kumar, PAN IN_PAN_A, called about the loan."


def test_unknown_entity_name_is_rejected_not_silently_ignored(store):
    # "PAN" is not an entity type ("IN_PAN" is); Presidio would just skip
    # it and redact nothing.
    with pytest.raises(ValueError, match="PAN"):
        redact_text(TEXT, store, entities=["PAN"])


def test_empty_entities_is_rejected(store):
    with pytest.raises(ValueError):
        redact_text(TEXT, store, entities=[])


# --- input validation and fail-closed behavior


def test_text_without_letters_or_digits_skips_detection(store, monkeypatch):
    monkeypatch.setattr(api, "detect_in_block", _explode)
    assert redact_text("  \n\t -- ", store).text == "  \n\t -- "


def test_too_long_text_is_rejected_before_any_work(store, monkeypatch):
    monkeypatch.setattr(api, "detect_in_block", _explode)
    with pytest.raises(TextTooLongError):
        redact_texts(["Ravi Kumar", "x" * (MAX_TEXT_CHARS + 1)], store)
    assert store.all_codes() == {}


def test_non_string_input_is_rejected(store):
    with pytest.raises(TypeError):
        redact_texts(["fine", None], store)
    with pytest.raises(TypeError):
        reverse_texts(["fine", 42], store)


def test_detection_failure_raises_instead_of_passing_text_through(store, monkeypatch):
    monkeypatch.setattr(api, "detect_in_block", _explode)
    with pytest.raises(RuntimeError, match="analyzer down"):
        redact_text(TEXT, store)


def test_unreadable_store_raises(tmp_path):
    path = tmp_path / "mapping.enc"
    path.write_bytes(b"not a fernet token")
    store = MappingStore(path, key=Fernet.generate_key())
    with pytest.raises(MappingStoreError):
        redact_text(TEXT, store)
    with pytest.raises(MappingStoreError):
        reverse_text("PERSON_A", store)


def test_find_pii_reports_what_is_still_in_the_clear_in_order(store):
    store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    text = "PERSON_A met Asha Rao; PAN ABCPE1234F; email asha@example.com"
    findings = api.find_pii(text, store)
    assert [(f.entity_type, text[f.start : f.end]) for f in findings] == [
        ("PERSON", "Asha Rao"),
        ("IN_PAN", "ABCPE1234F"),
        ("EMAIL_ADDRESS", "asha@example.com"),
    ]
    assert store.all_codes() == {"PERSON_A": "Ravi Kumar"}  # read-only: nothing issued


def test_result_repr_shows_counts_only(store):
    res = redact_text(TEXT, store)
    shown = repr(res)
    assert "PERSON_A" not in shown
    assert "loan" not in shown
    assert "'PERSON': 1" in shown

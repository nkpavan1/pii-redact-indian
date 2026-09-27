"""The known-value sweep (detect/known_values.py): values the mapping store
already knows - and values found elsewhere in the same call or document -
are masked wherever they appear, even where NER misses them. Reported by
the stack's black-box test of the 0.3.0 service. Synthetic data only."""

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import find_pii, redact_texts, reverse_text
from pii_redact.config.allowlists import DOC_TYPE_ALLOWLISTS
from pii_redact.detect.known_values import (
    ID_TYPES,
    KnownMatch,
    KnownValues,
    find_known,
    merge_known,
    store_index,
    swept_types,
)
from pii_redact.pipeline import analyze_document
from pii_redact.types import Detection, Location

# NER finds no name in either sentence (probed): only the sweep masks them.
UNSEEN_BY_NER = "Ask Periwinkle Zanzibar about it."
ALL_CAPS_UNSEEN = "PRIYA SHARMA PAID THE BILL."


@pytest.fixture
def key():
    return Fernet.generate_key()


@pytest.fixture
def store(tmp_path, key):
    return MappingStore(tmp_path / "mapping.enc", key=key)


def _index(*values):
    index = KnownValues()
    for entity_type, surface in values:
        index.add(entity_type, surface)
    return index


def _found(text, index, types=("PERSON", *ID_TYPES)):
    return [(text[m.start : m.end], m.entity_type) for m in find_known(text, [index], set(types))]


def _det(entity_type, start, end):
    return Detection(entity_type, start, end, 0.85, 0, Location())


def _make(start, end, entity_type):
    return Detection(entity_type, start, end, 1.0, 0, Location())


# --- names


@pytest.mark.parametrize(
    "text, found",
    [
        (UNSEEN_BY_NER, "Periwinkle Zanzibar"),
        ("ask periwinkle zanzibar", "periwinkle zanzibar"),
        ("PERIWINKLE ZANZIBAR PAID", "PERIWINKLE ZANZIBAR"),
        ("Periwinkle   Zanzibar's notes", "Periwinkle   Zanzibar"),
        ("(Periwinkle Zanzibar)", "Periwinkle Zanzibar"),
    ],
)
def test_a_known_name_is_found_in_any_case_as_whole_words(text, found):
    assert _found(text, _index(("PERSON", "Periwinkle Zanzibar"))) == [(found, "PERSON")]


@pytest.mark.parametrize(
    "text",
    [
        "Periwinkle Zanzibaria",  # not a whole word
        "XPeriwinkle Zanzibar",
        "Periwinkle, Zanzibar",  # punctuation between the words
        "Periwinkle_Zanzibar",
    ],
)
def test_a_known_name_is_not_found_inside_other_words(text):
    assert _found(text, _index(("PERSON", "Periwinkle Zanzibar"))) == []


def test_the_longest_known_name_wins():
    index = _index(("PERSON", "Ravi Kumar"), ("PERSON", "Ravi Kumar Sharma"))
    assert _found("Met Ravi Kumar Sharma and Ravi Kumar.", index) == [
        ("Ravi Kumar Sharma", "PERSON"),
        ("Ravi Kumar", "PERSON"),
    ]


def test_initials_must_be_written_the_same_way():
    index = _index(("PERSON", "R. Rajesh Kumar"))
    assert _found("Cheque from R. Rajesh Kumar.", index) == [("R. Rajesh Kumar", "PERSON")]
    assert _found("Cheque from R Rajesh Kumar.", index) == []


@pytest.mark.parametrize(
    "value",
    [
        "Asha",  # one word: never swept
        "Kumar",
        "Om Ra",  # too short
        "Ping Ravi Kumar",  # starts with a word that is never a name (a pre-0.4.0 NER span)
        "Ravi Kumar Sir",  # ends with one
        "The Kumar",  # a stop word
        "Ravi 2 Kumar",  # a digit
    ],
)
def test_names_that_would_over_mask_are_never_swept(value):
    index = _index(("PERSON", value))
    assert len(index) == 0
    assert _found(f"x {value} y", index) == []


def test_a_known_value_inside_a_code_is_left_alone():
    index = _index(("PERSON", "Asha Rao"))
    text = "PERSON_A Asha Rao"
    assert find_known(text, [index], {"PERSON"}, exclude=[(0, 8)]) == [KnownMatch(9, 17, "PERSON")]
    assert find_known(text, [index], {"PERSON"}, exclude=[(9, 13)]) == []


# --- identifiers


@pytest.mark.parametrize(
    "text, found",
    [
        ("transfer to 50100123456789 today", "50100123456789"),
        ("A/c 50100123456789.", "50100123456789"),
        ("UPI/50100123456789/Payment", "50100123456789"),
        ("ref (5010-0123-4567-89)", "5010-0123-4567-89"),
    ],
)
def test_a_known_account_number_is_found_as_a_whole_token(text, found):
    index = _index(("BANK_ACCOUNT_NUMBER", "50100123456789"))
    assert _found(text, index) == [(found, "BANK_ACCOUNT_NUMBER")]


@pytest.mark.parametrize("text", ["TXN50100123456789", "501001234567890", "50100123456789X"])
def test_a_known_identifier_is_not_found_inside_a_longer_token(text):
    assert _found(text, _index(("BANK_ACCOUNT_NUMBER", "50100123456789"))) == []


def test_phone_numbers_match_in_any_indian_mobile_format():
    index = _index(("PHONE_NUMBER", "9876501234"))
    for text in ("call 9876501234", "call +91-9876501234", "call 09876501234"):
        assert [t for _, t in _found(text, index)] == ["PHONE_NUMBER"], text


def test_email_addresses_match_without_trailing_punctuation():
    index = _index(("EMAIL_ADDRESS", "periwinkle.test@example.com"))
    assert _found("Mail periwinkle.test@example.com.", index) == [
        ("periwinkle.test@example.com", "EMAIL_ADDRESS")
    ]


def test_short_identifiers_are_never_swept():
    assert len(_index(("BANK_ACCOUNT_NUMBER", "1234567"), ("IN_PAN", "ABCDEFGH"))) == 0


def test_only_requested_types_are_swept():
    index = _index(("PERSON", "Asha Rao"), ("IN_PAN", "ABCPE1234F"))
    text = "Asha Rao, ABCPE1234F"
    assert _found(text, index, types={"IN_PAN"}) == [("ABCPE1234F", "IN_PAN")]
    assert _found(text, index, types={"PERSON"}) == [("Asha Rao", "PERSON")]


def test_swept_types():
    assert swept_types(["PERSON", "IN_MOBILE", "IN_ADDRESS", "IN_DATE_OF_BIRTH"]) == {"PERSON", "PHONE_NUMBER"}
    every_allowlisted_type = {t for types in DOC_TYPE_ALLOWLISTS.values() for t in types}
    assert ID_TYPES <= every_allowlisted_type


# --- merging with detections


def test_merge_adds_a_match_nothing_else_covers():
    merged = merge_known([], [KnownMatch(4, 12, "PERSON")], _make)
    assert [(d.start, d.end, d.entity_type) for d in merged] == [(4, 12, "PERSON")]


def test_merge_widens_a_detection_the_match_contains():
    # NER's "NARAYANAN" inside a known "LAKSHMI NARAYANAN"
    merged = merge_known([_det("PERSON", 8, 17)], [KnownMatch(0, 17, "PERSON")], _make)
    assert [(d.start, d.end) for d in merged] == [(0, 17)]


def test_merge_keeps_a_longer_detection_that_contains_the_match():
    # NER's "Ravi Kumar Sharma" around a known "Ravi Kumar": a different,
    # longer name keeps its own span rather than leaking "Sharma".
    detections = [_det("PERSON", 0, 17)]
    assert merge_known(detections, [KnownMatch(0, 10, "PERSON")], _make) == detections


def test_merge_unions_partial_overlaps_of_the_same_type():
    merged = merge_known([_det("PERSON", 5, 17)], [KnownMatch(0, 10, "PERSON")], _make)
    assert [(d.start, d.end) for d in merged] == [(0, 17)]


def test_merge_gives_an_exact_span_the_known_type():
    merged = merge_known([_det("BANK_ACCOUNT_NUMBER", 3, 13)], [KnownMatch(3, 13, "PHONE_NUMBER")], _make)
    assert [(d.start, d.end, d.entity_type) for d in merged] == [(3, 13, "PHONE_NUMBER")]


def test_merge_leaves_a_partly_overlapping_other_type_alone():
    detections = [_det("IN_ADDRESS", 0, 30)]
    assert merge_known(detections, [KnownMatch(20, 40, "PERSON")], _make) == detections


# --- the store's index


class _Counting:
    def __init__(self):
        self.builds = 0

    def build(self, entries):
        self.builds += 1
        return KnownValues.from_entries(entries)


def test_store_index_is_built_once_and_kept_up_to_date(store):
    store.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao")
    counter = _Counting()
    first = store.derived("probe", counter.build)
    assert store.derived("probe", counter.build) is first
    store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")  # this instance: updated in place
    again = store.derived("probe", counter.build)
    assert again is first and counter.builds == 1
    assert [t for _, t in _found("Ravi Kumar and Asha Rao", again)] == ["PERSON", "PERSON"]


def test_store_index_is_rebuilt_when_another_process_writes(tmp_path, key):
    path = tmp_path / "shared.enc"
    service_view = MappingStore(path, key=key, cache=True)
    counter = _Counting()
    service_view.derived("probe", counter.build)
    MappingStore(path, key=key).get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao")  # "Tool 1"
    index = service_view.derived("probe", counter.build)
    assert counter.builds == 2
    assert _found("Asha Rao", index) == [("Asha Rao", "PERSON")]


def test_a_derived_value_without_add_entry_is_dropped_on_write(store):
    store.derived("plain", lambda entries: len(entries))
    store.get_or_create_code("PERSON", "ASHA RAO")
    assert store.derived("plain", lambda entries: len(entries)) == 1


# --- end to end: chat


def test_a_stored_name_is_masked_where_ner_misses_it(store):
    stored = redact_texts(["Periwinkle Zanzibar called."], store)[0].text
    assert stored == "PERSON_A called."
    [result] = redact_texts([UNSEEN_BY_NER], store)
    assert result.text == "Ask PERSON_A about it."
    assert result.entities == {"PERSON": 1}


@pytest.mark.parametrize("order", ["found first", "missed first"])
def test_a_name_found_anywhere_in_a_request_is_masked_everywhere_in_it(store, order):
    texts = ["Priya Sharma called.", ALL_CAPS_UNSEEN]
    if order == "missed first":
        texts.reverse()
    out = {r.text for r in redact_texts(texts, store)}
    assert out == {"PERSON_A called.", "PERSON_A PAID THE BILL."}
    assert reverse_text("PERSON_A", store) == "Priya Sharma"


def test_a_stored_account_number_is_masked_in_chat_without_context(store):
    code = store.get_or_create_code("BANK_ACCOUNT_NUMBER", "50100123456789", display="50100123456789")
    [result] = redact_texts(["Please send it to 50100123456789 today."], store)
    assert result.text == f"Please send it to {code} today."


def test_a_known_name_is_not_swept_when_people_are_not_requested(store):
    redact_texts(["Periwinkle Zanzibar called."], store)
    [result] = redact_texts([UNSEEN_BY_NER + " PAN ABCPE1234F"], store, entities=["IN_PAN"])
    assert result.text == UNSEEN_BY_NER + " PAN IN_PAN_A"


def test_a_longer_new_name_around_a_known_one_does_not_leak(store):
    redact_texts(["Ravi Kumar called."], store)
    [result] = redact_texts(["Ravi Kumar Sharma called."], store)
    assert "Sharma" not in result.text and "Kumar" not in result.text


def test_redacting_twice_changes_nothing(store):
    first = [r.text for r in redact_texts(["Periwinkle Zanzibar called.", UNSEEN_BY_NER], store)]
    codes_before = store.all_codes()
    assert [r.text for r in redact_texts(first, store)] == first
    assert store.all_codes() == codes_before


def test_the_residual_check_flags_a_known_name_left_in_the_clear(store):
    redact_texts(["Periwinkle Zanzibar called."], store)
    findings = find_pii(UNSEEN_BY_NER, store)
    assert [(f.entity_type, f.start, f.end) for f in findings] == [("PERSON", 4, 23)]
    assert find_pii("Ask PERSON_A about it.", store) == []


# --- end to end: documents


def _masked_values(path, store=None, doc_type=None):
    extracted, detections = analyze_document(path, doc_type, store)
    return sorted({(extracted.blocks[d.block_index].text[d.start : d.end], d.entity_type) for d in detections})


def test_a_name_found_on_one_line_of_a_document_is_masked_on_every_line(tmp_path):
    note = tmp_path / "note.txt"
    note.write_text(f"Priya Sharma called.\n\n{ALL_CAPS_UNSEEN}\n", encoding="utf-8")
    assert _masked_values(note) == [("PRIYA SHARMA", "PERSON"), ("Priya Sharma", "PERSON")]


def test_a_document_is_swept_for_what_the_store_knows(tmp_path, store):
    redact_texts(["Periwinkle Zanzibar called."], store)
    note = tmp_path / "note.txt"
    note.write_text(UNSEEN_BY_NER + "\n", encoding="utf-8")
    assert _masked_values(note) == []  # without the store: missed
    assert _masked_values(note, store) == [("Periwinkle Zanzibar", "PERSON")]


def test_analyzing_a_document_writes_nothing_to_the_store(tmp_path, store):
    note = tmp_path / "note.txt"
    note.write_text("Priya Sharma called.\n", encoding="utf-8")
    analyze_document(note, None, store)
    assert store.all_codes() == {}
    assert len(store_index(store)) == 0

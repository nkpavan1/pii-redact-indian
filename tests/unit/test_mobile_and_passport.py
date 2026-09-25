"""Indian mobile numbers without context (chat only) and passport numbers
(context-scoped), both approved after the 0.2.0 masking-table review.
Synthetic numbers only."""

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore, normalize_value
from pii_redact.api import redact_text
from pii_redact.config.allowlists import allowlist_for
from pii_redact.detect.analyzer import detect_in_block, get_analyzer
from pii_redact.types import Location, TextBlock


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


DOCUMENT = allowlist_for("bank_statement")


# --- mobiles in chat


@pytest.mark.parametrize(
    "text, expected",
    [
        ("9876543210", "PHONE_NUMBER_A"),
        ("98765 43210", "PHONE_NUMBER_A"),
        ("98765-43210", "PHONE_NUMBER_A"),
        ("+91 98765 43210", "PHONE_NUMBER_A"),
        ("+91-9876543210", "PHONE_NUMBER_A"),
        ("919876543210", "PHONE_NUMBER_A"),
        ("09876543210", "PHONE_NUMBER_A"),
        ("call me on 9876543210", "call me on PHONE_NUMBER_A"),
        ("whatsapp 9876543210", "whatsapp PHONE_NUMBER_A"),
        ("reach me at +91 98765 43210.", "reach me at PHONE_NUMBER_A."),
    ],
)
def test_chat_masks_mobiles_without_context_in_every_common_format(store, text, expected):
    res = redact_text(text, store)
    assert res.text == expected
    assert res.entities == {"PHONE_NUMBER": 1}


def test_every_format_of_one_number_gets_one_code(store):
    variants = ["9876543210", "+91 98765 43210", "098765 43210", "91-98765-43210", "mobile 9876543210"]
    codes = {redact_text(v, store).spans[0][3] for v in variants}
    assert codes == {"PHONE_NUMBER_A"}


def test_a_number_found_by_both_phone_recognizers_is_counted_once(store):
    # Presidio's PhoneRecognizer (context "mobile") and the chat mobile
    # recognizer both fire on this span.
    res = redact_text("mobile 9876543210", store)
    assert res.entities == {"PHONE_NUMBER": 1}
    block = TextBlock("mobile 9876543210", Location())
    assert len(detect_in_block(block, 0, allowlist_for("chat"))) == 1


def test_internal_entity_name_never_reaches_callers(store):
    res = redact_text("call 9876543210 or 8765432109", store)
    assert set(res.entities) == {"PHONE_NUMBER"}
    assert all(code.startswith("PHONE_NUMBER_") for *_, code in res.spans)
    assert "IN_MOBILE" not in "".join(store.all_codes())


@pytest.mark.parametrize(
    "text",
    [
        "salary 12,50,000",
        "Amount 9,876,543,210",
        "Rs 9876543210.50",
        "1234567890",  # not a mobile: starts 1-5
        "5876543210",
        "98765432101234",  # inside a longer digit run
        "TXN9876543210",  # inside an alphanumeric reference
        "UPI/9876543210/ref",  # inside a slash-separated reference
        "ref 123-456-7890",
    ],
)
def test_things_that_only_look_like_mobiles_are_left_alone(store, text):
    assert redact_text(text, store).text == text


@pytest.mark.parametrize("text", ["call me on 9876543210", "9876543210", "+91 98765 43210", "whatsapp 9876543210"])
def test_documents_keep_context_scoped_phone_detection(store, text):
    assert redact_text(text, store, entities=DOCUMENT).text == text


def test_documents_still_mask_phones_next_to_a_context_word(store):
    assert redact_text("mobile 9876543210", store, entities=DOCUMENT).text == "mobile PHONE_NUMBER_A"


def test_known_false_positive_account_number_is_labeled_phone_in_chat(store):
    # Recorded, safe direction: masked either way, just under a phone label.
    assert redact_text("account 9876543210", store).text == "account PHONE_NUMBER_A"


@pytest.mark.parametrize(
    "raw, key",
    [
        ("9876543210", "9876543210"),
        ("+91 98765 43210", "9876543210"),
        ("91-98765-43210", "9876543210"),
        ("098765 43210", "9876543210"),
        ("+1 (555) 010-0199", "+1(555)0100199"),  # other numbers keep their old key
        ("12345", "12345"),
    ],
)
def test_phone_keys_collapse_indian_mobile_prefixes(raw, key):
    assert normalize_value("PHONE_NUMBER", raw) == key


# --- passports


@pytest.mark.parametrize(
    "text, expected",
    [
        ("passport M1234567", "passport IN_PASSPORT_A"),
        ("Passport No: M12 34567", "Passport No: IN_PASSPORT_A"),
        ("passport number is J8369850", "passport number is IN_PASSPORT_A"),  # ends in 0: Presidio's pattern missed it
    ],
)
def test_passport_number_next_to_passport_is_masked(store, text, expected):
    assert redact_text(text, store).text == expected


@pytest.mark.parametrize("text", ["M1234567", "my ID M1234567", "invoice M1234567"])
def test_passport_shaped_value_without_context_is_left_alone(store, text):
    assert redact_text(text, store).text == text


def test_only_one_recognizer_handles_passports_so_nothing_fires_twice():
    analyzer = get_analyzer()
    handlers = [r.name for r in analyzer.registry.recognizers if "IN_PASSPORT" in r.supported_entities]
    assert handlers == ["PassportNumberRecognizer"]
    results = analyzer.analyze(text="passport M1234567", entities=["IN_PASSPORT"], language="en", score_threshold=0.0)
    assert len(results) == 1

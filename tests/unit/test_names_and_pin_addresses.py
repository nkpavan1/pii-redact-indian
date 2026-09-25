"""The two approved detection improvements: names after a title (spaCy
misses all-caps names with initials entirely) and addresses anchored on a
PIN code (no "address" label needed). End to end through redact_text,
synthetic data only - every name, address and PIN here is made up."""

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import redact_text, reverse_text
from pii_redact.detect.recognizers.address import PinCodeAddressRecognizer
from pii_redact.detect.recognizers.salutation_names import SalutationNameRecognizer


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


def _names(text):
    return [text[r.start : r.end] for r in SalutationNameRecognizer().analyze(text, ["PERSON"])]


def _addresses(text):
    return [text[r.start : r.end] for r in PinCodeAddressRecognizer().analyze(text, ["IN_ADDRESS"])]


# --- names after a title


@pytest.mark.parametrize(
    "text, name",
    [
        ("MR. R RAJESH KUMAR", "R RAJESH KUMAR"),
        ("Mr. R. K. Narayan", "R. K. Narayan"),
        ("SMT. K LAKSHMI", "K LAKSHMI"),
        ("Shri A P J Abdul Kalam", "A P J Abdul Kalam"),
        ("DR. S RADHAKRISHNAN", "S RADHAKRISHNAN"),
        ("MR RAJESH K", "RAJESH K"),
        ("Dear Mrs. Asha Rao,", "Asha Rao"),
        ("KUMARI MEERA NAIR", "MEERA NAIR"),
    ],
)
def test_name_after_a_title_is_found_without_the_title(text, name):
    assert _names(text) == [name]


@pytest.mark.parametrize(
    "text",
    [
        "DR NEFT TRANSFER 5000",  # bare DR is the debit marker on statements
        "DR 5,000.00",
        "MS Excel sheet",  # bare MS is not a title here
        "mr ravi",  # a name word must start with a capital
        "MRS 12345",
    ],
)
def test_non_names_after_title_like_words_are_ignored(text):
    assert _names(text) == []


def test_a_statement_header_word_ends_the_name():
    assert _names("MR RAJESH KUMAR SAVINGS ACCOUNT") == ["RAJESH KUMAR"]


def test_relation_markers_are_not_read_as_initials():
    assert _names("MRS. PRIYA SHARMA W/O MR. RAJESH SHARMA") == ["PRIYA SHARMA", "RAJESH SHARMA"]


def test_all_caps_titled_name_is_redacted_end_to_end(store):
    # spaCy alone finds no PERSON here at all.
    res = redact_text("MR. R RAJESH KUMAR, customer since 2019", store)
    assert res.text == "MR. PERSON_A, customer since 2019"
    assert reverse_text(res.text, store) == "MR. R RAJESH KUMAR, customer since 2019"


# --- addresses anchored on a PIN code


@pytest.mark.parametrize(
    "text, address",
    [
        ("12 MG Road, Indiranagar, Bengaluru 560038", "12 MG Road, Indiranagar, Bengaluru 560038"),
        ("Flat 3, Lake View, Pune - 411001", "Flat 3, Lake View, Pune - 411001"),
        (
            "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH",
            "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH",
        ),
        ("4th Floor, Tower B, Cyber City, Gurugram 122002, Haryana", "4th Floor, Tower B, Cyber City, Gurugram 122002, Haryana"),
        ("BHOPAL - 462001", "BHOPAL - 462001"),
        ("my pincode is 560038", "560038"),
        ("PIN: 462 001", "462 001"),
    ],
)
def test_address_ending_in_a_pin_code_is_found(text, address):
    assert address in _addresses(text)


@pytest.mark.parametrize(
    "text",
    [
        "NEFT-123456 credited",
        "IMPS - 560038",
        "Invoice total 560038",
        "Amount 5,60,038.00",
        "Ref no 1234567",
        "The meeting is at 10, and the fee is 450000",
        "Balance, closing 1250000",  # 7 digits: not a PIN
    ],
)
def test_other_numbers_are_not_addresses(text):
    assert _addresses(text) == []


def test_unlabeled_address_is_redacted_end_to_end(store):
    text = "Please courier it to 12 MG Road, Indiranagar, Bengaluru 560038 by Friday."
    res = redact_text(text, store)
    assert "560038" not in res.text and "Indiranagar" not in res.text
    assert "IN_ADDRESS_A" in res.text
    assert reverse_text(res.text, store) == text

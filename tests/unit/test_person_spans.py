"""PERSON span refinement (detect/person_spans.py): words glued to a name
are trimmed off, and a name NER cut short is extended over the rest of it,
so one person gets one code. Reported by the stack's black-box test of the
0.3.0 service. Synthetic names only."""

import re

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import redact_texts, reverse_text
from pii_redact.detect.analyzer import get_analyzer
from pii_redact.detect.person_spans import NOT_NAME_WORDS, TITLES, extend_span, name_part, trim_span

CODE = re.compile(r"\bPERSON_[A-Z]+\b")


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


def _trimmed(text):
    span = trim_span(text, 0, len(text))
    return None if span is None else text[span[0] : span[1]]


# --- trimming (no NLP involved)


@pytest.mark.parametrize(
    "span, name",
    [
        ("Ping Ravi Kumar", "Ravi Kumar"),
        ("Customer Periwinkle Zanzibar", "Periwinkle Zanzibar"),
        ("Email Ravi Kumar", "Ravi Kumar"),
        ("Remind Asha Rao", "Asha Rao"),
        ("Call Periwinkle Zanzibar", "Periwinkle Zanzibar"),
        ("Dear Ram Kumar", "Ram Kumar"),
        ("Hi Priya Sharma", "Priya Sharma"),
        ("Please call Ravi Kumar", "Ravi Kumar"),
        ("Ravi Kumar's", "Ravi Kumar"),
        ("Ravi Kumar ji", "Ravi Kumar"),
        ("Asha Rao madam", "Asha Rao"),
        ("Mr. Ravi Kumar", "Ravi Kumar"),
        ("Smt Lakshmi Narayanan", "Lakshmi Narayanan"),
        ("RAVI KUMAR SAVINGS", "RAVI KUMAR"),
        ("Ravi Kumar Monday", "Ravi Kumar"),
        ("S/O RAVI KUMAR", "RAVI KUMAR"),
    ],
)
def test_words_glued_to_a_name_are_trimmed(span, name):
    assert _trimmed(span) == name


@pytest.mark.parametrize(
    "span",
    [
        # Given names that are also English words or month names: trimming
        # them would leak a real name part, so none of them is on the list.
        "Ram Kumar",
        "Bill Mathew",
        "Will Thomas",
        "Mark Dsouza",
        "Rose Mary",
        "Sunny Deol",
        "May Thomas",
        "June Pereira",
        "Jan Mathew",
        # A title after a name is part of it.
        "Priya Kumari",
        "Lakshmi Sri",
    ],
)
def test_names_that_are_also_words_are_kept_whole(span):
    assert _trimmed(span) == span


def test_word_lists_never_contain_common_given_names():
    names = {"ram", "bill", "will", "mark", "rose", "sunny", "may", "june", "april", "august", "jan", "mar"}
    assert not names & NOT_NAME_WORDS
    assert not names & TITLES
    assert not {"kumari", "sri"} & NOT_NAME_WORDS  # titles only in front of a name


@pytest.mark.parametrize("span", ["Dear Sir", "Thanks", "Customer", "Mr.", "Hi team"])
def test_a_span_with_no_name_left_is_dropped(span):
    assert _trimmed(span) is None


def _name_part(text):
    span = name_part(text, 0, len(text))
    return None if span is None else text[span[0] : span[1]]


@pytest.mark.parametrize(
    "span, name",
    [
        ("Ravi Kumar", "Ravi Kumar"),
        # spaCy runs a name on into the identifier after it.
        ("Ravi Kumar PAN ABCPE1234F", "Ravi Kumar"),
        ("Ravi Kumar UPI 9876543210", "Ravi Kumar"),
        ("Ravi PAN ABCPE1234F", "Ravi"),  # one word, but a label was trimmed off
        ("Ravi Kumar 9876543210", "Ravi Kumar"),
        # Not names: a label with a number in it.
        ("Q4(Jan-Mar)", None),
        ("Form 16", None),
        ("9876543210", None),
    ],
)
def test_a_span_is_cut_at_its_first_word_with_a_digit(span, name):
    assert _name_part(span) == name


def _extended(text, name):
    start = text.index(name)
    doc = get_analyzer().nlp_engine.process_text(text, "en").tokens
    s, e = extend_span(text, start, start + len(name), doc)
    return text[s:e]


@pytest.mark.parametrize(
    "text, name, extended",
    [
        ("Please call Periwinkle Zanzibar today.", "Periwinkle", "Periwinkle Zanzibar"),
        ("LAKSHMI NARAYANAN PAID THE BILL.", "NARAYANAN", "LAKSHMI NARAYANAN"),
        # An all-caps acronym never joins a Title-case name, nor a date,
        # a statement word, or anything across punctuation.
        ("Customer Ravi Kumar PAN ABCPE1234F", "Ravi Kumar", "Ravi Kumar"),
        ("Meet Ravi Kumar Monday at noon", "Ravi Kumar", "Ravi Kumar"),
        ("MR RAVI KUMAR SAVINGS ACCOUNT", "RAVI KUMAR", "RAVI KUMAR"),
        ("Ravi Kumar, Zanzibar", "Ravi Kumar", "Ravi Kumar"),
        ("ravi kumar Zanzibar", "ravi kumar", "ravi kumar"),
    ],
)
def test_extension_joins_only_what_looks_like_more_of_the_name(text, name, extended):
    assert _extended(text, name) == extended


# --- end to end: one person, one code


@pytest.mark.parametrize("name", ["Ravi Kumar", "Lakshmi Narayanan"])
def test_one_person_gets_one_code_across_sentence_frames(store, name):
    frames = [
        "{N} called.",
        "Ping {N} on Monday.",
        "Customer {N}, PAN ABCPE1234F.",
        "Email {N} the report.",
        "Remind {N} tomorrow.",
        "Call {N}.",
        "Dear {N}, thanks.",
        "Ping {N} on 9876501234.",
    ]
    out = [r.text for r in redact_texts([f.format(N=name) for f in frames], store)]
    codes = {code for text in out for code in CODE.findall(text)}
    assert len(codes) == 1, out
    assert reverse_text(codes.pop(), store) == name
    for part in name.split():
        assert not any(part in text for text in out), out
    assert out[1] == "Ping PERSON_A on Monday."
    assert out[2] == "Customer PERSON_A, PAN IN_PAN_A."


@pytest.mark.parametrize(
    "text, expected, name",
    [
        # NER: "Ping Periwinkle" - trimmed, then extended over "Zanzibar".
        ("Ping Periwinkle Zanzibar on 9876501234.", "Ping PERSON_A on PHONE_NUMBER_A.", "Periwinkle Zanzibar"),
        # NER: "Periwinkle" alone - extended.
        ("Please call Periwinkle Zanzibar today.", "Please call PERSON_A today.", "Periwinkle Zanzibar"),
        # NER: "NARAYANAN" alone - extended left, and not over "PAID" (a verb).
        ("LAKSHMI NARAYANAN PAID THE BILL.", "PERSON_A PAID THE BILL.", "LAKSHMI NARAYANAN"),
        ("RAM KUMAR PAID THE BILL.", "PERSON_A PAID THE BILL.", "RAM KUMAR"),
    ],
)
def test_a_name_cut_short_is_extended_over_the_rest_of_it(store, text, expected, name):
    [result] = redact_texts([text], store)
    assert result.text == expected
    assert reverse_text("PERSON_A", store) == name


@pytest.mark.parametrize(
    "text, expected",
    [
        # NER's span is "Ravi Kumar PAN ABCPE1234F"; 0.3.0 dropped all of it.
        ("Ravi Kumar PAN ABCPE1234F", "PERSON_A PAN IN_PAN_A"),
        ("Pay Ravi Kumar UPI 9876543210", "Pay PERSON_A UPI PHONE_NUMBER_A"),
    ],
)
def test_a_name_run_on_into_an_identifier_is_still_masked(store, text, expected):
    [result] = redact_texts([text], store)
    assert result.text == expected
    assert reverse_text("PERSON_A", store) == "Ravi Kumar"

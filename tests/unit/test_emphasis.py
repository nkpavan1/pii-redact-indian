"""Names in markdown emphasis (0.4.3): spaCy reads a copy of the text with
the emphasis marks blanked. Synthetic names and prompts only."""

import re

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import redact_text, redact_texts, reverse_text
from pii_redact.detect.emphasis import blank_emphasis
from pii_redact.detect.person_spans import NOT_NAME_WORDS


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


# --- blanking (no NLP involved)


@pytest.mark.parametrize(
    "text, blanked",
    [
        ("**Ravi** called", "  Ravi   called"),
        ("Thanks, *Asha*!", "Thanks,  Asha !"),
        ("Ask __Priya__ now", "Ask   Priya   now"),
        ("***Meera***", "   Meera   "),
        ("~~old rule~~ gone", "  old rule   gone"),
        ("**_Suresh_**", "  _Suresh_  ".replace("_", " ")),
        ("- **Name:** Ravi Kumar", "-   Name:   Ravi Kumar"),
    ],
)
def test_emphasis_marks_become_spaces(text, blanked):
    assert blank_emphasis(text) == blanked
    assert len(blank_emphasis(text)) == len(text)


@pytest.mark.parametrize(
    "text",
    [
        "user_name and first_name",  # inside a word
        "2*3*4 = 24",
        "* item one\n* item two",  # list bullets
        "a * b and a _ b",  # a lone mark
        r"a \*literal\* star",  # escaped
        "`code` stays",
        "no marks at all",
    ],
)
def test_other_marks_are_left_alone(text):
    assert blank_emphasis(text) == text


def test_marks_inside_a_code_span_are_blanked_too():
    # Only the backticks are kept; spaCy reads code spans as it did before.
    assert blank_emphasis("`**code**` stays") == "`  code  ` stays"


# --- names in emphasis are masked


@pytest.mark.parametrize(
    "text, expected",
    [
        ("**Ravi** called me yesterday.", "**PERSON_A** called me yesterday."),
        ("I spoke to **Asha** about the loan.", "I spoke to **PERSON_A** about the loan."),
        ("Thanks, **Meera**!", "Thanks, **PERSON_A**!"),
        ("*Suresh* will send the documents.", "*PERSON_A* will send the documents."),
        ("You are **Tara**, a personal assistant.", "You are **PERSON_A**, a personal assistant."),
        ("**Ravi Kumar** will call tomorrow.", "**PERSON_A** will call tomorrow."),
    ],
)
def test_a_name_in_emphasis_is_masked(store, text, expected):
    res = redact_text(text, store)
    assert res.text == expected
    assert reverse_text(res.text, store) == text


def test_a_bold_name_from_a_reversed_reply_is_masked_again(store):
    # The leak this closes: the model bolds a code, the reply is reversed
    # for the user, and the client sends that reply back in the history.
    first = redact_text("Ravi called me yesterday.", store)
    assert first.text == "PERSON_A called me yesterday."
    reply = reverse_text("Sure, **PERSON_A**, here is the summary.", store)
    assert reply == "Sure, **Ravi**, here is the summary."
    assert redact_text(reply, store).text == "Sure, **PERSON_A**, here is the summary."


# --- instruction text in emphasis is not


def test_heading_and_label_words_are_never_names():
    assert {"goal", "pros", "cons", "summary", "tone", "kannada", "hindi", "english"} <= NOT_NAME_WORDS
    assert not {"grace", "joy", "hope", "frank", "bill", "mark", "rose"} & NOT_NAME_WORDS


BOLD_PROMPT = """# Household assistant

You are **Tara**, the household assistant for Ravi Kumar.

## Core truths
- **Be genuinely helpful, not performatively helpful.**
- **Have opinions.** Disagree when it matters.
- **Earn trust through competence.** Private things stay private.

**Goal:** keep the household running smoothly.
**Tone:** warm, short, *never* preachy.
**Language:** Kannada or English, as the user writes.
**Pros** and **Cons** go in a table, with a **Summary** at the end.
_Note_: ~~old rule~~ replaced by the one above.
Reply in **Markdown** only when asked; run **Docker** commands only when asked."""


def test_a_bold_system_prompt_keeps_its_instructions(store):
    [res] = redact_texts([BOLD_PROMPT], store)
    codes = {reverse_text(code, store): code for code in re.findall(r"\bPERSON_[A-Z]+\b", res.text)}
    assert set(codes) == {"Tara", "Ravi Kumar"}
    assert res.text == BOLD_PROMPT.replace("Tara", codes["Tara"]).replace("Ravi Kumar", codes["Ravi Kumar"])
    assert reverse_text(res.text, store) == BOLD_PROMPT

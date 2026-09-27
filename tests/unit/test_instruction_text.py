"""False positives on ordinary instruction text (stack issue 5): found in a
real assistant system prompt, where they garbled every cloud turn. The verb
"address" must never start an address, software names are not people, and
the owner's name in the same prompt must still be masked. Synthetic data
only."""

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import redact_text, redact_texts, reverse_text
from pii_redact.detect.analyzer import get_analyzer
from pii_redact.detect.recognizers.address import AddressRecognizer


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


def _addresses(text):
    return [text[r.start : r.end] for r in AddressRecognizer().analyze(text, ["IN_ADDRESS"])]


# --- "address" the verb


@pytest.mark.parametrize(
    "text",
    [
        "Please address this issue today.",
        "Address envelopes neatly.",
        "## Addressing the user\n- Greet the person by their **first name** when they say hi/hello or open a conversation.",
        "We will address your concerns, one by one, in the next release 2.1.",
        "How should I address him, and what title do I use?",
        "The complaint was addressed on 12 March, 2024.",
        "Update the address-book entries for 2024, today.",
    ],
)
def test_the_verb_address_never_masks_anything(store, text):
    assert redact_text(text, store).text == text


@pytest.mark.parametrize(
    "text",
    [
        "email address: ravi.test@example.com, 2024",
        "IP address: 192.168.1.10",
        "Web address - www.example.com/contact, page 2",
        "Wallet address: 0x12ab34cd56ef7890",
        "My address is the same as before.",  # no house number, no comma
    ],
)
def test_non_postal_or_non_address_values_are_not_addresses(text):
    assert _addresses(text) == []


# --- "address" the label: still masked


@pytest.mark.parametrize(
    "text, value",
    [
        ("Address: B-204, Sunrise Apartments, Main Road, Rampur", "B-204, Sunrise Apartments, Main Road, Rampur"),
        ("My address is 12 MG Road, Indiranagar, near the lake. Call me later.",
         "12 MG Road, Indiranagar, near the lake"),
        ("Address of the assessee: B-204, SUNRISE APARTMENTS,MAIN ROAD", "B-204, SUNRISE APARTMENTS,MAIN ROAD"),
        ("Residential Address - Flat 5, Lotus Towers, Sector 12", "Flat 5, Lotus Towers, Sector 12"),
        ("address was 7 Park Street, Kolkata", "7 Park Street, Kolkata"),
        # Abbreviations don't end the value.
        ("Address: No. 12, St. Mary's Road, Opp. Bus Stand, Dist. Sehore. Thanks.",
         "No. 12, St. Mary's Road, Opp. Bus Stand, Dist. Sehore"),
        # A trailing comma continues onto the next line.
        ("Address: Flat 5, Lotus Towers,\nSector 12, Noida\nThanks", "Flat 5, Lotus Towers,\nSector 12, Noida"),
        # A label on its own line: the lines under it, up to a blank line.
        ("Permanent Address\nFlat 5, Lotus Towers\nSector 12\nNoida\n\nNext section", "Flat 5, Lotus Towers\nSector 12\nNoida"),
        ("## Address:\n- 12 MG Road, Indiranagar\n", "12 MG Road, Indiranagar"),
        # PDF context windows: the label block next to the value, or one
        # unrelated block in between.
        ("Address | B-204, SUNRISE APARTMENTS,RAMPUR H.O", "B-204, SUNRISE APARTMENTS,RAMPUR H.O"),
        ("Address | Customer Id | 12 MG Road, Indiranagar", "12 MG Road, Indiranagar"),
    ],
)
def test_an_address_after_its_label_is_found(text, value):
    assert value in _addresses(text)


def test_a_labeled_address_is_masked_and_the_label_kept(store):
    res = redact_text("My address is 12 MG Road, Indiranagar, near the lake. Call me later.", store)
    assert res.text == "My address is IN_ADDRESS_A. Call me later."
    assert reverse_text(res.text, store) == "My address is 12 MG Road, Indiranagar, near the lake. Call me later."


# --- software names are not people


@pytest.mark.parametrize(
    "text",
    [
        "You are in a plain terminal (CLI). Markdown does NOT render.",
        "Use Python and JSON. Open GitHub, run Docker, check YAML in VS Code.",
        "Kubernetes restarts the pod; Redis keeps the cache.",
    ],
)
def test_software_names_are_not_masked_as_people(store, text):
    assert redact_text(text, store).text == text


# --- a system prompt: only the owner's name changes

SYSTEM_PROMPT = """# Household assistant

You are the household assistant for Ravi Kumar.

## Addressing the user
- Greet the person by their **first name** when they say hi/hello or open a conversation.
- Please address this issue today if it is urgent.
- Address envelopes neatly when asked to draft letters.

## Output
You are in a plain terminal (CLI). Markdown does NOT render. Use plain text, and run Docker commands only when asked.

Ravi Kumar prefers short answers."""


def test_a_system_prompt_keeps_its_instructions_and_loses_the_owners_name(store):
    [res] = redact_texts([SYSTEM_PROMPT], store)
    assert res.entities == {"PERSON": 2}
    assert res.text == SYSTEM_PROMPT.replace("Ravi Kumar", "PERSON_A")
    assert reverse_text(res.text, store) == SYSTEM_PROMPT


def test_the_old_context_scoped_pattern_is_gone():
    names = {type(r).__name__ for r in get_analyzer().registry.recognizers}
    assert "AddressRecognizer" in names
    address = next(r for r in get_analyzer().registry.recognizers if type(r).__name__ == "AddressRecognizer")
    assert not getattr(address, "context", None)  # the label is the context now

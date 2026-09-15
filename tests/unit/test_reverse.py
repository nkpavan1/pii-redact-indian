from pathlib import Path

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.reverse.reverse import reverse


class FakeMappingStore(MappingStore):
    """Test double: real MappingStore.all_codes() is NotImplementedError
    until the persistence backend is built."""

    def __init__(self, codes_to_values: dict[str, str]):
        super().__init__(store_path=Path("unused"))
        self._codes_to_values = codes_to_values

    def all_codes(self) -> dict[str, str]:
        return self._codes_to_values


def test_reverses_exact_match_codes():
    store = FakeMappingStore({"PERSON_A": "Rahul Kumar", "PAN_A": "ABCDE1234F"})
    text = "PERSON_A's PAN is PAN_A."
    assert reverse(text, store) == "Rahul Kumar's PAN is ABCDE1234F."


def test_does_not_reverse_paraphrased_code():
    # Deliberate v1 behavior: exact-match only, no fuzzy matching.
    store = FakeMappingStore({"PERSON_A": "Rahul Kumar"})
    text = "The person referred to as Person A confirmed the amount."
    assert reverse(text, store) == text


def test_empty_mapping_store_is_a_no_op():
    store = FakeMappingStore({})
    assert reverse("nothing to reverse here", store) == "nothing to reverse here"


def test_longest_code_wins_when_one_code_prefixes_another():
    store = FakeMappingStore({"PAN_A": "AAAA0000A", "PAN_A1": "BBBB1111B"})
    assert reverse("value: PAN_A1", store) == "value: BBBB1111B"

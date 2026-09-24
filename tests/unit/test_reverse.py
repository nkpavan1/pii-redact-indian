from pathlib import Path

from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.reverse.reverse import find_codes, reverse, reverse_many


class FakeMappingStore(MappingStore):
    """Test double with a fixed code -> value table. Passes an explicit key
    so constructing it never touches the OS credential store (see
    tests/conftest.py's keyring guard)."""

    def __init__(self, codes_to_values: dict[str, str]):
        super().__init__(store_path=Path("unused"), key=Fernet.generate_key())
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


def test_code_never_matches_inside_a_longer_unknown_token():
    # PERSON_AB isn't in the store, so it must stay exactly as written -
    # not become "Ravi KumarB".
    store = FakeMappingStore({"PERSON_A": "Ravi Kumar"})
    assert reverse("PERSON_AB and XPERSON_A and PERSON_A_1", store) == (
        "PERSON_AB and XPERSON_A and PERSON_A_1"
    )


def test_unknown_code_shaped_token_is_left_untouched():
    # Models sometimes invent codes that were never issued.
    store = FakeMappingStore({"PERSON_A": "Ravi Kumar"})
    assert reverse("PERSON_A met PERSON_Z.", store) == "Ravi Kumar met PERSON_Z."


def test_code_next_to_punctuation_still_reverses():
    store = FakeMappingStore({"PERSON_A": "Ravi Kumar", "IN_PAN_A": "ABCPE1234F"})
    text = "PERSON_A's PAN (IN_PAN_A), \"PERSON_A\"; PERSON_A."
    assert reverse(text, store) == (
        "Ravi Kumar's PAN (ABCPE1234F), \"Ravi Kumar\"; Ravi Kumar."
    )


def test_find_codes_returns_whole_token_spans_of_known_codes_only():
    text = "PERSON_A, PERSON_AB, IN_PAN_A. PERSON_Z"
    assert find_codes(text, {"PERSON_A", "IN_PAN_A"}) == [(0, 8), (21, 29)]
    assert find_codes(text, set()) == []


def test_reverse_many_reads_the_store_once():
    class CountingStore(FakeMappingStore):
        reads = 0

        def all_codes(self):
            CountingStore.reads += 1
            return super().all_codes()

    store = CountingStore({"PERSON_A": "Ravi Kumar"})
    assert reverse_many(["PERSON_A", "hi PERSON_A", ""], store) == ["Ravi Kumar", "hi Ravi Kumar", ""]
    assert CountingStore.reads == 1


def test_code_inside_a_json_string_reverses():
    import json

    store = FakeMappingStore({"PERSON_A": "Ravi Kumar"})
    payload = json.dumps({"reply": "Hello PERSON_A"})
    assert json.loads(reverse(payload, store)) == {"reply": "Hello Ravi Kumar"}

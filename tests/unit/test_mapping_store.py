import json

import keyring
import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import (
    MappingStore,
    MappingStoreError,
    _keyring_username_for,
    _KEYRING_SERVICE,
    _letter_suffix,
    _make_code,
)


@pytest.fixture
def store(tmp_path):
    # Explicit key bypasses keyring/OS Credential Manager entirely - fast,
    # and doesn't leave test junk behind in a real credential store.
    return MappingStore(tmp_path / "mapping.enc", key=Fernet.generate_key())


def test_same_value_returns_same_code(store):
    code1 = store.get_or_create_code("PERSON", "RAHUL KUMAR")
    code2 = store.get_or_create_code("PERSON", "RAHUL KUMAR")
    assert code1 == code2 == "PERSON_A"


def test_different_values_get_different_codes(store):
    code1 = store.get_or_create_code("PERSON", "RAHUL KUMAR")
    code2 = store.get_or_create_code("PERSON", "PRIYA SINGH")
    assert code1 == "PERSON_A"
    assert code2 == "PERSON_B"


def test_same_value_different_entity_types_get_independent_codes(store):
    # Same normalized string could coincidentally collide across entity
    # types - counters and codes must stay per-entity-type.
    code1 = store.get_or_create_code("PERSON", "ABCDE1234F")
    code2 = store.get_or_create_code("IN_PAN", "ABCDE1234F")
    assert code1 == "PERSON_A"
    assert code2 == "IN_PAN_A"


def test_letter_suffix_sequence():
    assert _letter_suffix(1) == "A"
    assert _letter_suffix(26) == "Z"
    assert _letter_suffix(27) == "AA"
    assert _letter_suffix(28) == "AB"
    assert _letter_suffix(52) == "AZ"
    assert _letter_suffix(53) == "BA"


def test_make_code():
    assert _make_code("PERSON", 1) == "PERSON_A"
    assert _make_code("IN_PAN", 27) == "IN_PAN_AA"


def test_reverse_lookup_returns_original_value(store):
    code = store.get_or_create_code("PERSON", "RAHUL KUMAR")
    assert store.reverse_lookup(code) == "RAHUL KUMAR"


def test_reverse_lookup_unknown_code_returns_none(store):
    assert store.reverse_lookup("PERSON_Z") is None


def test_all_codes_returns_full_mapping(store):
    c1 = store.get_or_create_code("PERSON", "RAHUL KUMAR")
    c2 = store.get_or_create_code("IN_PAN", "ABCDE1234F")
    assert store.all_codes() == {c1: "RAHUL KUMAR", c2: "ABCDE1234F"}


def test_persists_across_separate_instances(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "mapping.enc"

    store1 = MappingStore(path, key=key)
    code = store1.get_or_create_code("PERSON", "RAHUL KUMAR")

    # A second instance - simulating a separate process run - must see the
    # same persisted entry, not start fresh.
    store2 = MappingStore(path, key=key)
    assert store2.get_or_create_code("PERSON", "RAHUL KUMAR") == code
    assert store2.reverse_lookup(code) == "RAHUL KUMAR"


def test_encrypted_file_never_contains_plaintext_value(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "mapping.enc"
    store = MappingStore(path, key=key)
    store.get_or_create_code("PERSON", "RAHUL KUMAR")

    raw = path.read_bytes()
    assert b"RAHUL KUMAR" not in raw
    assert b"PERSON" not in raw


def test_wrong_key_raises_mapping_store_error(tmp_path):
    path = tmp_path / "mapping.enc"
    MappingStore(path, key=Fernet.generate_key()).get_or_create_code("PERSON", "RAHUL KUMAR")

    wrong_key_store = MappingStore(path, key=Fernet.generate_key())
    with pytest.raises(MappingStoreError):
        wrong_key_store.get_or_create_code("PERSON", "ANYONE")


def test_corrupted_file_raises_mapping_store_error(tmp_path):
    path = tmp_path / "mapping.enc"
    path.write_bytes(b"not a valid fernet token")
    store = MappingStore(path, key=Fernet.generate_key())
    with pytest.raises(MappingStoreError):
        store.all_codes()


# --- display form (B3): keyed on the normalized value, reversed to the
# surface form actually seen in a document.


def test_reverses_to_display_form_not_normalized_key(store):
    code = store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    assert store.reverse_lookup(code) == "Ravi Kumar"
    assert store.all_codes() == {code: "Ravi Kumar"}


def test_address_display_keeps_its_spaces(store):
    # normalize_value strips spaces from non-PERSON keys; that must never
    # leak into what reversal gives back.
    code = store.get_or_create_code(
        "IN_ADDRESS", "B204,SUNRISEAPARTMENTS,RAMPUR", display="B-204, Sunrise Apartments, Rampur"
    )
    assert store.reverse_lookup(code) == "B-204, Sunrise Apartments, Rampur"


def test_display_whitespace_is_collapsed(store):
    code = store.get_or_create_code("PERSON", "RAVI KUMAR", display="  Ravi\n Kumar ")
    assert store.reverse_lookup(code) == "Ravi Kumar"


def test_same_key_different_display_keeps_one_code(store):
    c1 = store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    c2 = store.get_or_create_code("PERSON", "RAVI KUMAR", display="RAVI KUMAR")
    assert c1 == c2


def test_all_caps_display_upgrades_to_later_mixed_case_sighting(store):
    # Bank statements print names in capitals; a later "Ravi Kumar" is the
    # better form to show a human.
    code = store.get_or_create_code("PERSON", "RAVI KUMAR", display="RAVI KUMAR")
    assert store.reverse_lookup(code) == "RAVI KUMAR"
    store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    assert store.reverse_lookup(code) == "Ravi Kumar"


def test_mixed_case_display_is_never_downgraded(store):
    code = store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    store.get_or_create_code("PERSON", "RAVI KUMAR", display="RAVI KUMAR")
    store.get_or_create_code("PERSON", "RAVI KUMAR", display="ravi kumar")
    assert store.reverse_lookup(code) == "Ravi Kumar"


def test_display_upgrade_is_persisted(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "mapping.enc"
    code = MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR", display="RAVI KUMAR")
    MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    assert MappingStore(path, key=key).reverse_lookup(code) == "Ravi Kumar"


def _write_legacy_store(path, key, entries, counters):
    # A store written before `display` existed: entries carry only
    # entity_type / value / code.
    plaintext = json.dumps({"entries": entries, "counters": counters}).encode("utf-8")
    path.write_bytes(Fernet(key).encrypt(plaintext))


def test_legacy_store_without_display_still_reverses_and_keeps_its_codes(tmp_path):
    key = Fernet.generate_key()
    path = tmp_path / "legacy.enc"
    _write_legacy_store(
        path, key,
        [{"entity_type": "PERSON", "value": "RAVI KUMAR", "code": "PERSON_A"}],
        {"PERSON": 1},
    )
    store = MappingStore(path, key=key)

    assert store.all_codes() == {"PERSON_A": "RAVI KUMAR"}
    # Same normalized key -> same existing code, no new entry...
    assert store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar") == "PERSON_A"
    # ...and that sighting lazily upgrades the legacy all-caps value.
    assert store.reverse_lookup("PERSON_A") == "Ravi Kumar"
    assert store.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao") == "PERSON_B"


def test_different_store_paths_get_different_keyring_usernames(tmp_path):
    u1 = _keyring_username_for(tmp_path / "a.enc")
    u2 = _keyring_username_for(tmp_path / "b.enc")
    assert u1 != u2


@pytest.mark.keyring
def test_keyring_backed_key_is_created_once_and_reused(tmp_path):
    # Writes (then deletes) a real OS Credential Manager entry, so it's
    # opt-in only: set PII_REDACT_KEYRING_TESTS=1 to run it (see conftest.py).
    path = tmp_path / "mapping.enc"
    username = _keyring_username_for(path)
    try:
        store1 = MappingStore(path)  # no explicit key -> goes through keyring
        code = store1.get_or_create_code("PERSON", "RAHUL KUMAR")

        store2 = MappingStore(path)  # separate instance, same path -> same keyring key
        assert store2.get_or_create_code("PERSON", "RAHUL KUMAR") == code
    finally:
        keyring.delete_password(_KEYRING_SERVICE, username)

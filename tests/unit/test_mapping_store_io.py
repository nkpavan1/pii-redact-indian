"""MappingStore file handling: atomic writes, crash safety, the in-memory
cache, transactions, locking, and the no-silent-create mode."""

import os
import threading

import pytest
from cryptography.fernet import Fernet

from pii_redact.anonymize import mapping_store as ms
from pii_redact.anonymize.mapping_store import (
    MappingStore,
    MappingStoreError,
    _KEYRING_SERVICE,
    _keyring_username_for,
    encrypt_empty_store,
)


@pytest.fixture
def key():
    return Fernet.generate_key()


@pytest.fixture
def path(tmp_path):
    return tmp_path / "store" / "mapping.enc"


class _Counter:
    def __init__(self):
        self.calls = 0

    def wrap(self, func):
        def counted(*args, **kwargs):
            self.calls += 1
            return func(*args, **kwargs)

        return counted


# --- atomic writes and crash safety


def test_save_leaves_no_temp_file_behind(path, key):
    MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR")
    assert sorted(p.name for p in path.parent.iterdir() if p.name != "mapping.enc.lock") == ["mapping.enc"]


def test_crash_before_the_rename_leaves_the_previous_store_intact(path, key, monkeypatch):
    store = MappingStore(path, key=key)
    first = store.get_or_create_code("PERSON", "RAVI KUMAR", display="Ravi Kumar")
    before = path.read_bytes()
    real_replace = os.replace

    def crash(*_args, **_kwargs):
        raise OSError("simulated crash between temp write and rename")

    monkeypatch.setattr(ms.os, "replace", crash)
    with pytest.raises(OSError):
        store.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao")
    monkeypatch.setattr(ms.os, "replace", real_replace)

    assert path.read_bytes() == before
    assert MappingStore(path, key=key).all_codes() == {first: "Ravi Kumar"}
    # The instance that failed dropped its unsaved change, and both it and a
    # fresh one keep working - the never-saved ordinal is simply reissued.
    assert store.all_codes() == {first: "Ravi Kumar"}
    assert store.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao") == "PERSON_B"
    assert MappingStore(path, key=key).reverse_lookup("PERSON_B") == "Asha Rao"


def test_crash_while_writing_the_temp_file_leaves_the_store_intact(path, key, monkeypatch):
    store = MappingStore(path, key=key)
    store.get_or_create_code("PERSON", "RAVI KUMAR")
    before = path.read_bytes()

    def crash(_fd):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(ms.os, "fsync", crash)
    with pytest.raises(OSError):
        store.get_or_create_code("PERSON", "ASHA RAO")

    assert path.read_bytes() == before


def test_rename_is_retried_while_another_process_holds_the_file(path, key, monkeypatch):
    real_replace = os.replace
    attempts = []

    def busy_twice(src, dst):
        attempts.append(1)
        if len(attempts) <= 2:
            raise PermissionError("sharing violation")
        real_replace(src, dst)

    monkeypatch.setattr(ms, "_REPLACE_BACKOFF_S", 0)
    monkeypatch.setattr(ms.os, "replace", busy_twice)

    code = MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR")

    assert len(attempts) == 3
    assert MappingStore(path, key=key).all_codes() == {code: "RAVI KUMAR"}


def test_rename_that_never_succeeds_fails_closed(path, key, monkeypatch):
    def always_busy(*_args, **_kwargs):
        raise PermissionError("sharing violation")

    monkeypatch.setattr(ms, "_REPLACE_BACKOFF_S", 0)
    monkeypatch.setattr(ms, "_REPLACE_ATTEMPTS", 3)
    monkeypatch.setattr(ms.os, "replace", always_busy)

    with pytest.raises(MappingStoreError, match="still in use"):
        MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR")


# --- in-memory cache


def test_cached_store_reads_the_file_once_while_it_is_unchanged(path, key):
    MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR")
    store = MappingStore(path, key=key, cache=True)
    reads = _Counter()
    store._read_locked = reads.wrap(store._read_locked)

    for _ in range(5):
        assert store.get_or_create_code("PERSON", "RAVI KUMAR") == "PERSON_A"
        assert store.reverse_lookup("PERSON_A") == "RAVI KUMAR"
        store.all_codes()

    assert reads.calls == 1


def test_uncached_store_reads_every_time_but_decrypts_only_on_change(path, key):
    MappingStore(path, key=key).get_or_create_code("PERSON", "RAVI KUMAR")
    store = MappingStore(path, key=key)
    reads = _Counter()
    decrypts = _Counter()
    store._read_locked = reads.wrap(store._read_locked)
    store._fernet.decrypt = decrypts.wrap(store._fernet.decrypt)

    for _ in range(3):
        store.all_codes()

    assert reads.calls == 3
    assert decrypts.calls == 1


def test_cached_store_sees_codes_written_by_another_instance(path, key):
    service = MappingStore(path, key=key, cache=True)
    tool = MappingStore(path, key=key)
    assert service.all_codes() == {}

    code = tool.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao")

    assert service.all_codes() == {code: "Asha Rao"}
    assert service.get_or_create_code("PERSON", "ASHA RAO") == code
    assert service.get_or_create_code("PERSON", "RAVI KUMAR") == "PERSON_B"


def test_writes_never_trust_a_stale_signature(path, key, monkeypatch):
    # If the stat signature ever failed to change (a file system with coarse
    # timestamps), cached READS could be briefly stale - but a WRITE re-reads
    # the actual bytes under the lock, so it never reissues a code another
    # process already handed out, and never duplicates a value.
    service = MappingStore(path, key=key, cache=True)
    monkeypatch.setattr(service, "_signature", lambda: ("frozen",))
    service.all_codes()

    MappingStore(path, key=key).get_or_create_code("PERSON", "ASHA RAO")

    assert service.all_codes() == {}  # the documented read staleness
    assert service.get_or_create_code("PERSON", "ASHA RAO") == "PERSON_A"
    assert service.get_or_create_code("PERSON", "RAVI KUMAR") == "PERSON_B"
    assert MappingStore(path, key=key).all_codes() == {"PERSON_A": "ASHA RAO", "PERSON_B": "RAVI KUMAR"}


def test_load_reports_the_number_of_codes_and_rejects_a_wrong_key(path, key):
    store = MappingStore(path, key=key)
    store.get_or_create_code("PERSON", "RAVI KUMAR")
    store.get_or_create_code("IN_PAN", "ABCPE1234F")

    assert MappingStore(path, key=key, cache=True).load() == 2
    with pytest.raises(MappingStoreError):
        MappingStore(path, key=Fernet.generate_key()).load()


# --- transactions


def test_transaction_issues_many_codes_with_one_save(path, key):
    store = MappingStore(path, key=key)
    saves = _Counter()
    store._save_locked = saves.wrap(store._save_locked)

    with store.transaction():
        codes = [store.get_or_create_code("PERSON", f"PERSON NUMBER {i}") for i in range(20)]

    assert saves.calls == 1
    assert len(set(codes)) == 20
    assert len(MappingStore(path, key=key).all_codes()) == 20


def test_transaction_with_nothing_new_does_not_write(path, key):
    store = MappingStore(path, key=key)
    store.get_or_create_code("PERSON", "RAVI KUMAR")
    before = os.stat(path).st_mtime_ns

    with store.transaction():
        store.get_or_create_code("PERSON", "RAVI KUMAR")

    assert os.stat(path).st_mtime_ns == before


def test_reads_inside_a_transaction_see_its_own_new_codes(path, key):
    store = MappingStore(path, key=key)
    with store.transaction():
        code = store.get_or_create_code("PERSON", "ASHA RAO", display="Asha Rao")
        assert store.reverse_lookup(code) == "Asha Rao"
        assert store.all_codes() == {code: "Asha Rao"}


def test_transaction_that_raises_saves_nothing(path, key):
    store = MappingStore(path, key=key)
    store.get_or_create_code("PERSON", "RAVI KUMAR")
    before = path.read_bytes()

    with pytest.raises(RuntimeError):
        with store.transaction():
            store.get_or_create_code("PERSON", "ASHA RAO")
            raise RuntimeError("boom")

    assert path.read_bytes() == before
    assert store.all_codes() == {"PERSON_A": "RAVI KUMAR"}
    assert store.get_or_create_code("PERSON", "ASHA RAO") == "PERSON_B"


def test_nested_transactions_join_the_outer_one(path, key):
    store = MappingStore(path, key=key)
    saves = _Counter()
    store._save_locked = saves.wrap(store._save_locked)

    with store.transaction():
        store.get_or_create_code("PERSON", "RAVI KUMAR")
        with store.transaction():
            store.get_or_create_code("PERSON", "ASHA RAO")

    assert saves.calls == 1
    assert len(MappingStore(path, key=key).all_codes()) == 2


def test_a_writer_waits_for_another_instances_transaction(path, key):
    holder = MappingStore(path, key=key)
    impatient = MappingStore(path, key=key, lock_timeout=0.2)
    inside = threading.Event()
    release = threading.Event()

    def hold_the_lock():
        with holder.transaction():
            holder.get_or_create_code("PERSON", "RAVI KUMAR")
            inside.set()
            release.wait(10)

    thread = threading.Thread(target=hold_the_lock)
    thread.start()
    try:
        assert inside.wait(10)
        with pytest.raises(MappingStoreError, match="timed out"):
            impatient.get_or_create_code("PERSON", "ASHA RAO")
    finally:
        release.set()
        thread.join(10)

    # Once the holder is done, the waiting writer gets the next ordinal.
    assert impatient.get_or_create_code("PERSON", "ASHA RAO") == "PERSON_B"


# --- keys and the no-silent-create mode (fake credential store)


def test_default_mode_still_creates_a_key_on_first_use(path, fake_keyring):
    MappingStore(path).get_or_create_code("PERSON", "RAVI KUMAR")
    assert (_KEYRING_SERVICE, _keyring_username_for(path)) in fake_keyring


def test_no_create_mode_refuses_when_the_key_is_missing(path, fake_keyring):
    with pytest.raises(MappingStoreError, match="no key"):
        MappingStore(path, create=False)
    assert fake_keyring == {}


def test_no_create_mode_refuses_when_the_store_file_is_missing(path, key, fake_keyring):
    fake_keyring[(_KEYRING_SERVICE, _keyring_username_for(path))] = key.decode()
    with pytest.raises(MappingStoreError, match="not found"):
        MappingStore(path, create=False)


def test_no_create_mode_opens_an_initialized_store(path, key, fake_keyring):
    fake_keyring[(_KEYRING_SERVICE, _keyring_username_for(path))] = key.decode()
    path.parent.mkdir(parents=True)
    path.write_bytes(encrypt_empty_store(key))

    store = MappingStore(path, create=False, cache=True)

    assert store.load() == 0
    assert store.get_or_create_code("PERSON", "RAVI KUMAR") == "PERSON_A"


def test_invalid_key_in_the_credential_store_is_a_store_error(path, fake_keyring):
    fake_keyring[(_KEYRING_SERVICE, _keyring_username_for(path))] = "not-a-fernet-key"
    with pytest.raises(MappingStoreError, match="not a valid"):
        MappingStore(path)

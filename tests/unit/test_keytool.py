"""redact-key, against an in-memory stand-in for the OS credential store
(the `fake_keyring` fixture) - these tests never touch Credential Manager.

Every test also checks the one rule that matters most here: the key never
appears in any output except `export`'s stdout."""

import io
import subprocess
import sys

import pytest
from cryptography.fernet import Fernet

from pii_redact import keytool
from pii_redact.anonymize.mapping_store import (
    _KEYRING_SERVICE,
    MappingStore,
    _keyring_username_for,
    encrypt_empty_store,
)


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "redaction" / "mapping_store.enc"


def _stored(fake_keyring, store_path):
    return fake_keyring.get((_KEYRING_SERVICE, _keyring_username_for(store_path)))


def _put_key(fake_keyring, store_path, key: bytes):
    fake_keyring[(_KEYRING_SERVICE, _keyring_username_for(store_path))] = key.decode()


def _initialized(fake_keyring, store_path) -> str:
    assert keytool.main(["init", "--store", str(store_path)]) == 0
    return _stored(fake_keyring, store_path)


def _run(argv, capsys):
    code = keytool.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


# --- init / check


def test_init_creates_an_empty_decryptable_store_and_its_key(store_path, fake_keyring, capsys):
    code, out, err = _run(["init", "--store", str(store_path)], capsys)

    assert code == 0
    key = _stored(fake_keyring, store_path)
    assert key is not None
    assert MappingStore(store_path, key=key.encode(), create=False).load() == 0
    assert out == ""
    assert key not in err


def test_init_twice_is_a_no_op(store_path, fake_keyring, capsys):
    key = _initialized(fake_keyring, store_path)
    code, _, err = _run(["init", "--store", str(store_path)], capsys)
    assert code == 0
    assert "already set up" in err
    assert _stored(fake_keyring, store_path) == key


def test_init_refuses_a_store_file_without_a_key(store_path, fake_keyring, capsys):
    store_path.parent.mkdir(parents=True)
    store_path.write_bytes(encrypt_empty_store(Fernet.generate_key()))
    code, _, err = _run(["init", "--store", str(store_path)], capsys)
    assert code == 1
    assert "redact-key import" in err
    assert fake_keyring == {}


def test_init_refuses_a_key_without_a_store_file(store_path, fake_keyring, capsys):
    _put_key(fake_keyring, store_path, Fernet.generate_key())
    code, _, err = _run(["init", "--store", str(store_path)], capsys)
    assert code == 1
    assert "backup" in err
    assert not store_path.exists()


def test_init_removes_its_store_file_if_saving_the_key_fails(store_path, fake_keyring, monkeypatch):
    def broken_set_password(*_args):
        raise RuntimeError("credential store unavailable")

    monkeypatch.setattr(keytool.keyring, "set_password", broken_set_password)
    with pytest.raises(RuntimeError):
        keytool.main(["init", "--store", str(store_path)])
    assert not store_path.exists()


def test_check_reports_a_missing_key(store_path, fake_keyring, capsys):
    code, out, err = _run(["check", "--store", str(store_path)], capsys)
    assert code == 1
    assert "MISSING" in err
    assert out == ""


def test_check_confirms_a_working_setup_without_showing_the_key(store_path, fake_keyring, capsys):
    key = _initialized(fake_keyring, store_path)
    MappingStore(store_path, key=key.encode()).get_or_create_code("PERSON", "RAVI KUMAR")
    capsys.readouterr()

    code, out, err = _run(["check", "--store", str(store_path)], capsys)

    assert code == 0
    assert "decrypts with this key (1 codes)" in err
    assert key not in out + err
    assert "length" not in err.lower()  # not even its length


def test_check_detects_a_key_that_does_not_match_the_store(store_path, fake_keyring, capsys):
    _initialized(fake_keyring, store_path)
    _put_key(fake_keyring, store_path, Fernet.generate_key())
    code, _, err = _run(["check", "--store", str(store_path)], capsys)
    assert code == 1
    assert "does NOT decrypt" in err


def test_store_defaults_to_the_redaction_home(monkeypatch, tmp_path, fake_keyring, capsys):
    monkeypatch.setenv("PII_REDACT_HOME", str(tmp_path / "home"))
    code, _, err = _run(["check"], capsys)
    assert code == 1
    assert str(tmp_path / "home" / "mapping_store.enc") in err


# --- export


def test_export_requires_explicit_confirmation(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)
    code, out, err = _run(["export", "--store", str(store_path)], capsys)
    assert code == 1
    assert "--i-understand" in err
    assert key not in out + err


def test_export_refuses_when_not_on_an_interactive_terminal(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: False)
    for extra in ([], ["--clip"]):
        code, out, err = _run(["export", "--store", str(store_path), "--i-understand", *extra], capsys)
        assert code == 1
        assert "interactive terminal" in err
        assert key not in out + err


def test_export_prints_only_the_key_on_stdout(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    capsys.readouterr()
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)

    code, out, err = _run(["export", "--store", str(store_path), "--i-understand"], capsys)

    assert code == 0
    assert out == key + "\n"
    assert key not in err


def test_export_refuses_a_key_that_does_not_decrypt_the_store(store_path, fake_keyring, capsys, monkeypatch):
    _initialized(fake_keyring, store_path)
    wrong = Fernet.generate_key()
    _put_key(fake_keyring, store_path, wrong)
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)

    code, out, err = _run(["export", "--store", str(store_path), "--i-understand"], capsys)

    assert code == 1
    assert wrong.decode() not in out + err


def test_export_clip_copies_prints_nothing_and_clears_afterwards(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    capsys.readouterr()
    copied, cleared = [], []
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)
    monkeypatch.setattr(keytool.clipboard, "copy_secret", lambda text: copied.append(text) or 41)
    monkeypatch.setattr(keytool.clipboard, "clear_if_unchanged", lambda seq: cleared.append(seq) or True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")

    code, out, err = _run(["export", "--store", str(store_path), "--i-understand", "--clip"], capsys)

    assert code == 0
    assert copied == [key]
    assert cleared == [41]
    assert key not in out + err
    assert "cleared" in err


def test_export_clip_still_clears_on_ctrl_c(store_path, fake_keyring, capsys, monkeypatch):
    _initialized(fake_keyring, store_path)
    cleared = []
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)
    monkeypatch.setattr(keytool.clipboard, "copy_secret", lambda text: 7)
    monkeypatch.setattr(keytool.clipboard, "clear_if_unchanged", lambda seq: cleared.append(seq) or True)

    def interrupted(_prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    assert keytool.main(["export", "--store", str(store_path), "--i-understand", "--clip"]) == 0
    assert cleared == [7]


def test_export_clip_reports_a_clipboard_failure_cleanly(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)

    def unavailable(_text):
        raise OSError("clipboard busy")

    monkeypatch.setattr(keytool.clipboard, "copy_secret", unavailable)
    code, out, err = _run(["export", "--store", str(store_path), "--i-understand", "--clip"], capsys)
    assert code == 1
    assert "Nothing was copied" in err
    assert key not in out + err


# --- import


def _stdin(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))  # not a TTY: read as a line


def test_import_restores_a_backed_up_key(store_path, fake_keyring, capsys, monkeypatch):
    key = _initialized(fake_keyring, store_path)
    fake_keyring.clear()  # e.g. a new Windows profile
    _stdin(monkeypatch, key + "\n")

    code, out, err = _run(["import", "--store", str(store_path)], capsys)

    assert code == 0
    assert _stored(fake_keyring, store_path) == key
    assert key not in out + err


def test_import_refuses_a_key_that_does_not_decrypt_the_store(store_path, fake_keyring, capsys, monkeypatch):
    _initialized(fake_keyring, store_path)
    fake_keyring.clear()
    _stdin(monkeypatch, Fernet.generate_key().decode() + "\n")

    code, _, err = _run(["import", "--store", str(store_path)], capsys)

    assert code == 1
    assert "does NOT decrypt" in err
    assert fake_keyring == {}


def test_import_never_silently_replaces_a_different_key(store_path, fake_keyring, capsys, monkeypatch):
    # No store file yet, so any valid key "decrypts" - the existing key must
    # still not be overwritten without --replace.
    original = Fernet.generate_key()
    _put_key(fake_keyring, store_path, original)
    other = Fernet.generate_key().decode()

    _stdin(monkeypatch, other + "\n")
    code, _, err = _run(["import", "--store", str(store_path)], capsys)
    assert code == 1
    assert "--replace" in err
    assert _stored(fake_keyring, store_path) == original.decode()

    _stdin(monkeypatch, other + "\n")
    code, _, _ = _run(["import", "--store", str(store_path), "--replace"], capsys)
    assert code == 0
    assert _stored(fake_keyring, store_path) == other


def test_import_rejects_garbage(store_path, fake_keyring, capsys, monkeypatch):
    _stdin(monkeypatch, "definitely not a key\n")
    code, _, err = _run(["import", "--store", str(store_path)], capsys)
    assert code == 1
    assert "not a valid key" in err
    assert fake_keyring == {}


# --- startup cost


def test_keytool_does_not_load_presidio():
    # redact-key must start instantly and pull in as little as possible.
    probe = "import sys, pii_redact.keytool; print('presidio_analyzer' in sys.modules, 'spacy' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "False False"


# --- forget


def _with_entries(fake_keyring, store_path):
    key = _initialized(fake_keyring, store_path)
    store = MappingStore(store_path, key=key.encode(), create=False)
    with store.transaction():
        for value in ("Ping Ravi Kumar", "Asha Rao", "Periwinkle"):
            store.get_or_create_code("PERSON", value.upper(), display=value)
    return key, store


def test_forget_removes_entries_after_showing_them(store_path, fake_keyring, capsys, monkeypatch):
    key, store = _with_entries(fake_keyring, store_path)
    capsys.readouterr()
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    code, out, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A", "--code", "PERSON_C"], capsys)

    assert code == 0
    assert "Ping Ravi Kumar" in err and "Periwinkle" in err  # shown before asking
    assert out == ""
    assert key not in out + err
    fresh = MappingStore(store_path, key=key.encode(), create=False)
    assert fresh.all_codes() == {"PERSON_B": "Asha Rao"}
    # A removed code is never issued again.
    assert fresh.get_or_create_code("PERSON", "NEW PERSON") == "PERSON_D"


def test_forget_does_nothing_unless_confirmed(store_path, fake_keyring, capsys, monkeypatch):
    key, store = _with_entries(fake_keyring, store_path)
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    code, _, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A"], capsys)
    assert code == 1 and "Nothing was removed" in err
    assert len(MappingStore(store_path, key=key.encode(), create=False).all_codes()) == 3


def test_forget_refuses_unknown_codes_and_removes_nothing(store_path, fake_keyring, capsys, monkeypatch):
    key, store = _with_entries(fake_keyring, store_path)
    code, _, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A", "--code", "PERSON_Z", "--yes"], capsys)
    assert code == 1 and "PERSON_Z" in err
    assert len(MappingStore(store_path, key=key.encode(), create=False).all_codes()) == 3


def test_forget_needs_a_terminal_or_yes_and_yes_prints_no_values(store_path, fake_keyring, capsys, monkeypatch):
    key, store = _with_entries(fake_keyring, store_path)
    capsys.readouterr()
    monkeypatch.setattr(keytool, "_is_interactive", lambda **_: False)
    code, _, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A"], capsys)
    assert code == 1 and "--yes" in err

    code, out, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A", "--yes"], capsys)
    assert code == 0
    assert "PERSON_A" in err and "Ravi" not in out + err
    assert "PERSON_A" not in MappingStore(store_path, key=key.encode(), create=False).all_codes()


def test_forget_needs_an_existing_store(store_path, fake_keyring, capsys):
    code, _, err = _run(["forget", "--store", str(store_path), "--code", "PERSON_A", "--yes"], capsys)
    assert code == 1
    assert "redact-key init" in err

"""redact-key: set up, check, back up and restore the mapping store's key.

The key lives in the OS credential store (Windows Credential Manager),
bound to the store file's resolved path. Without it, every code in the
store is permanently irreversible - so back it up once, to a password
manager, and back up the (encrypted) store file itself as well.

    redact-key check  [--store PATH]
    redact-key init   [--store PATH]
    redact-key export [--store PATH] --i-understand [--clip]
    redact-key import [--store PATH] [--replace]

Meant to be run by a person, at a terminal - never by an agent or a script.
No command prints the key except `export` without `--clip`, and `export`
only runs on an interactive terminal with --i-understand. `import` reads
the key without echoing it, and refuses a key that can't decrypt the
existing store, so a wrong paste can't replace a working key.

Imports nothing heavy (no Presidio/spaCy), so it starts instantly.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

import keyring
from cryptography.fernet import Fernet

from pii_redact import clipboard
from pii_redact.anonymize.mapping_store import (
    _KEYRING_SERVICE,
    MappingStore,
    MappingStoreError,
    _keyring_username_for,
    encrypt_empty_store,
)
from pii_redact.config.paths import HOME_ENV, default_store_path

EXIT_OK = 0
EXIT_PROBLEM = 1


def _stored_key(store_path: Path) -> str | None:
    return keyring.get_password(_KEYRING_SERVICE, _keyring_username_for(store_path))


def _is_valid_fernet_key(key: str) -> bool:
    try:
        Fernet(key.encode("utf-8"))
    except (ValueError, TypeError):
        return False
    return True


def _decrypts_store(store_path: Path, key: str) -> int | None:
    """Number of codes if `key` decrypts the store file, else None."""
    try:
        return MappingStore(store_path, key=key.encode("utf-8"), create=False).load()
    except MappingStoreError:
        return None


def _say(message: str) -> None:
    # Everything except the exported key itself goes to stderr, so stdout
    # carries the key and nothing else.
    print(message, file=sys.stderr)


def _check(store_path: Path) -> int:
    _say(f"store: {store_path}")
    _say(f"  resolved to: {store_path.resolve()}  (the key is bound to this path)")
    key = _stored_key(store_path)
    if key is None:
        _say("  key:  MISSING from the OS credential store")
        return EXIT_PROBLEM
    if not _is_valid_fernet_key(key):
        _say("  key:  present, but NOT a valid key")
        return EXIT_PROBLEM
    _say("  key:  present")
    if not store_path.is_file():
        _say("  file: MISSING")
        return EXIT_PROBLEM
    codes = _decrypts_store(store_path, key)
    if codes is None:
        _say("  file: present, but does NOT decrypt with this key")
        return EXIT_PROBLEM
    _say(f"  file: present, decrypts with this key ({codes} codes)")
    return EXIT_OK


def _init(store_path: Path) -> int:
    key = _stored_key(store_path)
    exists = store_path.exists()
    if key is not None and exists:
        if _decrypts_store(store_path, key) is not None:
            _say(f"{store_path}: already set up (key present, store decrypts). Nothing to do.")
            return EXIT_OK
        _say(f"{store_path}: a key and a store file exist, but the key does not decrypt the store.")
        return EXIT_PROBLEM
    if exists:
        _say(
            f"{store_path}: a store file exists but there is no key for it. "
            "Restore the key with `redact-key import`."
        )
        return EXIT_PROBLEM
    if key is not None:
        _say(
            f"{store_path}: a key exists but there is no store file. Restore the store file "
            "from your backup instead of creating a new, empty one."
        )
        return EXIT_PROBLEM

    new_key = Fernet.generate_key()
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with open(store_path, "xb") as f:  # "x": never overwrite a store that appeared meanwhile
        f.write(encrypt_empty_store(new_key))
    try:
        keyring.set_password(_KEYRING_SERVICE, _keyring_username_for(store_path), new_key.decode("utf-8"))
    except BaseException:
        # Don't leave behind a store file nobody holds the key to - the next
        # `init` would refuse to touch it.
        store_path.unlink(missing_ok=True)
        raise
    _say(f"{store_path}: created an empty store and saved its key in the OS credential store.")
    _say("Next: back the key up to your password manager with `redact-key export --clip --i-understand`.")
    return EXIT_OK


def _is_interactive(*, needs_stdout: bool) -> bool:
    return sys.stdin.isatty() and (not needs_stdout or sys.stdout.isatty())


def _export(store_path: Path, *, confirmed: bool, to_clipboard: bool) -> int:
    if not confirmed:
        _say("Refusing: export writes out the store's secret key. Re-run with --i-understand.")
        return EXIT_PROBLEM
    if not _is_interactive(needs_stdout=not to_clipboard):
        _say("Refusing: export only runs on an interactive terminal (not piped or redirected).")
        return EXIT_PROBLEM
    key = _stored_key(store_path)
    if key is None:
        _say(f"{store_path}: no key in the OS credential store - nothing to export.")
        return EXIT_PROBLEM
    if store_path.is_file() and _decrypts_store(store_path, key) is None:
        _say(f"{store_path}: the stored key does NOT decrypt this store - refusing to export it.")
        return EXIT_PROBLEM

    if not to_clipboard:
        print(key)
        _say("Save this in your password manager, then clear this terminal's scrollback.")
        return EXIT_OK

    try:
        sequence_number = clipboard.copy_secret(key)
    except (OSError, RuntimeError) as exc:
        _say(f"Could not copy to the clipboard ({exc}). Nothing was copied.")
        return EXIT_PROBLEM
    _say("Key copied to the clipboard (kept out of clipboard history and cloud sync).")
    try:
        input("Paste it into your password manager, then press Enter to clear the clipboard... ")
    except (EOFError, KeyboardInterrupt):
        _say("")
    finally:
        if clipboard.clear_if_unchanged(sequence_number):
            _say("Clipboard cleared.")
        else:
            _say("Something else was copied since - the clipboard was left as it is.")
    return EXIT_OK


def _read_key_from_user() -> str:
    if sys.stdin.isatty():
        return getpass.getpass("Paste the key (input is hidden): ").strip()
    return sys.stdin.readline().strip()


def _import(store_path: Path, *, replace: bool) -> int:
    new_key = _read_key_from_user()
    if not _is_valid_fernet_key(new_key):
        _say("That is not a valid key. Nothing was changed.")
        return EXIT_PROBLEM
    if store_path.is_file() and _decrypts_store(store_path, new_key) is None:
        _say(f"{store_path}: that key does NOT decrypt this store. Nothing was changed.")
        return EXIT_PROBLEM

    current = _stored_key(store_path)
    if current == new_key:
        _say(f"{store_path}: that key is already in the OS credential store. Nothing to do.")
        return EXIT_OK
    if current is not None and not replace:
        _say(
            f"{store_path}: a different key is already stored for this store. "
            "Re-run with --replace to overwrite it."
        )
        return EXIT_PROBLEM

    keyring.set_password(_KEYRING_SERVICE, _keyring_username_for(store_path), new_key)
    _say(f"{store_path}: key saved in the OS credential store.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact-key",
        description="Set up, check, back up and restore the mapping store's encryption key.",
    )
    store_help = (
        f"Mapping store file (default: $env:{HOME_ENV}\\mapping_store.enc, else "
        f"{default_store_path()})"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="Is the key present, and does it decrypt the store?")
    init = commands.add_parser("init", help="Create a new, empty store and its key.")
    export = commands.add_parser("export", help="Back up the key (prints it, or copies it with --clip).")
    export.add_argument("--i-understand", dest="confirmed", action="store_true",
                        help="Confirm that you are about to handle the store's secret key.")
    export.add_argument("--clip", action="store_true",
                        help="Copy to the clipboard instead of printing; cleared after you press Enter.")
    restore = commands.add_parser("import", help="Restore the key from a backup (read from stdin).")
    restore.add_argument("--replace", action="store_true",
                         help="Overwrite a different key already stored for this store.")
    for command in (check, init, export, restore):
        command.add_argument("--store", type=Path, default=None, help=store_help)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store_path = args.store if args.store is not None else default_store_path()
    if args.command == "check":
        return _check(store_path)
    if args.command == "init":
        return _init(store_path)
    if args.command == "export":
        return _export(store_path, confirmed=args.confirmed, to_clipboard=args.clip)
    return _import(store_path, replace=args.replace)


if __name__ == "__main__":
    sys.exit(main())

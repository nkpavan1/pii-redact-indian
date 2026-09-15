"""The real-value <-> coded-identifier mapping store.

This is the single most sensitive artifact in the system (see project
instructions, security requirements) - encrypted at rest, key never
logged/committed/transmitted, and it's what lets a human reverse a coded
identifier back to a real value at the end of a workflow. The LLM/agent side
never has access to this file.

Storage format: a single Fernet-encrypted file at store_path. Decrypted
plaintext is JSON: {"entries": [{"entity_type", "value", "code"}, ...],
"counters": {entity_type: int}}. Entries are a flat list rather than a
{value: code} dict so entity_type is never reconstructed by parsing the
code string (see _make_code) - keeps lookup unambiguous even if two entity
types ever produced visually similar codes.

Key management: one Fernet key per store_path (not one global key), stored
in the OS credential manager via `keyring` - on Windows this lands in
Credential Manager via WinVaultKeyring, confirmed by direct probe (see
environment/OS requirements section). Keying by store_path means two
independent mapping stores (e.g. different clients/projects) never share a
key. Key loss is permanent and by design (see project instructions): there
is deliberately no built-in backup/export path here.

Concurrency: every mutating or reading call takes an OS-level file lock
(via `filelock`) for the duration of its own read-modify-write cycle - not
held for the lifetime of the MappingStore object - so two `redact`
processes touching the same store file don't race and silently drop each
other's entries.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import keyring
from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock

_KEYRING_SERVICE = "pii-redact-mapping-store"


def normalize_value(entity_type: str, raw_value: str) -> str:
    """Canonicalize a detected value before using it as a mapping-store key,
    so formatting variation (case, whitespace, separators) doesn't produce
    multiple codes for the same real-world value.

    Deliberately entity-type-aware: stripping spaces is right for a PAN
    (`ABCDE 1234F` -> `ABCDE1234F`) but wrong for a PERSON name where
    internal spaces are meaningful (`Rahul Kumar` must not become
    `RahulKumar`).
    """
    collapsed_whitespace = re.sub(r"\s+", " ", raw_value.strip())
    if entity_type in {"PERSON"}:
        return collapsed_whitespace.upper()
    # IDs/numbers: strip internal separators as well as surrounding whitespace.
    return re.sub(r"[\s-]", "", collapsed_whitespace).upper()


def _letter_suffix(n: int) -> str:
    """1 -> "A", 26 -> "Z", 27 -> "AA", 28 -> "AB", ... (spreadsheet-column
    style), so codes stay human-readable past the 26th value of a given
    entity type instead of falling back to raw numbers."""
    letters = []
    while n > 0:
        n, remainder = divmod(n - 1, 26)
        letters.append(chr(ord("A") + remainder))
    return "".join(reversed(letters))


def _make_code(entity_type: str, ordinal: int) -> str:
    return f"{entity_type}_{_letter_suffix(ordinal)}"


def _keyring_username_for(store_path: Path) -> str:
    # Hash the resolved path rather than using it verbatim as the keyring
    # username - keeps it a fixed, predictable shape regardless of path
    # length/characters, while still giving each distinct store file its
    # own independent key.
    resolved = str(store_path.resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


def _get_or_create_key(store_path: Path) -> bytes:
    username = _keyring_username_for(store_path)
    existing = keyring.get_password(_KEYRING_SERVICE, username)
    if existing is not None:
        return existing.encode("utf-8")
    key = Fernet.generate_key()
    keyring.set_password(_KEYRING_SERVICE, username, key.decode("utf-8"))
    return key


class MappingStoreError(ValueError):
    pass


class MappingStore:
    def __init__(self, store_path: Path, key: bytes | None = None):
        self.store_path = store_path
        self._fernet = Fernet(key or _get_or_create_key(store_path))
        self._lock_path = store_path.with_name(store_path.name + ".lock")

    def _load(self) -> dict:
        if not self.store_path.exists():
            return {"entries": [], "counters": {}}
        encrypted = self.store_path.read_bytes()
        if not encrypted:
            return {"entries": [], "counters": {}}
        try:
            plaintext = self._fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise MappingStoreError(
                f"{self.store_path}: could not decrypt with the configured key - "
                "wrong key, corrupted file, or a store from a different install"
            ) from exc
        return json.loads(plaintext.decode("utf-8"))

    def _save(self, data: dict) -> None:
        plaintext = json.dumps(data).encode("utf-8")
        encrypted = self._fernet.encrypt(plaintext)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_bytes(encrypted)

    def get_or_create_code(self, entity_type: str, raw_value: str) -> str:
        with FileLock(str(self._lock_path)):
            data = self._load()
            for entry in data["entries"]:
                if entry["entity_type"] == entity_type and entry["value"] == raw_value:
                    return entry["code"]

            ordinal = data["counters"].get(entity_type, 0) + 1
            code = _make_code(entity_type, ordinal)
            data["counters"][entity_type] = ordinal
            data["entries"].append({"entity_type": entity_type, "value": raw_value, "code": code})
            self._save(data)
            return code

    def reverse_lookup(self, code: str) -> str | None:
        with FileLock(str(self._lock_path)):
            data = self._load()
            for entry in data["entries"]:
                if entry["code"] == code:
                    return entry["value"]
            return None

    def all_codes(self) -> dict[str, str]:
        """code -> real value, for building the reverse() substitution pass."""
        with FileLock(str(self._lock_path)):
            data = self._load()
            return {entry["code"]: entry["value"] for entry in data["entries"]}

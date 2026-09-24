"""The real-value <-> coded-identifier mapping store.

This is the single most sensitive artifact in the system (see project
instructions, security requirements) - encrypted at rest, key never
logged/committed/transmitted, and it's what lets a human reverse a coded
identifier back to a real value at the end of a workflow. The LLM/agent side
never has access to this file.

Storage format: a single Fernet-encrypted file at store_path. Decrypted
plaintext is JSON: {"entries": [{"entity_type", "value", "display",
"code"}, ...], "counters": {entity_type: int}}. Entries are a flat list
rather than a {value: code} dict so entity_type is never reconstructed by
parsing the code string (see _make_code) - keeps lookup unambiguous even if
two entity types ever produced visually similar codes.

`value` is the normalized lookup key (see normalize_value) - upper-cased,
and for IDs stripped of spaces/hyphens - which is right for matching but
wrong for showing a human: reversing to it turned "Ravi Kumar" into "RAVI
KUMAR" and an address into one run-together word. `display` is the surface
form actually seen in a document, and it's what reversal returns. Entries
written before `display` existed have none; they reverse to `value` until
their next sighting records one (lazy migration - nothing is rewritten up
front).

Key management: one Fernet key per store_path (not one global key), stored
in the OS credential manager via `keyring` - on Windows this lands in
Credential Manager via WinVaultKeyring, confirmed by direct probe (see
environment/OS requirements section). Keying by store_path means two
independent mapping stores (e.g. different clients/projects) never share a
key. Losing the key makes every code in the store permanently
irreversible; this module never exposes it - backing it up is a separate,
user-run step (`redact-key export`, see keytool.py).

Writes are atomic: the new version is written to a temporary file next to
the store, flushed to disk, and renamed over the store in one step. A crash
at any point leaves either the old store or the new one, never a torn
file (the old in-place write could leave a half-written file behind, and a
half-written store can't be decrypted at all).

Concurrency: several processes (the redact CLI, redact-publish,
redact-service) can share one store. Every write happens inside a
transaction that holds an OS-level file lock (via `filelock`), starts from
the current file contents, and saves once at the end - so two writers can
never hand out the same code or drop each other's entries. Reads take the
same lock when they touch the file, which also keeps a reader from holding
the file open while a writer renames over it (a sharing violation on
Windows).

Caching (`cache=True`, for the long-running service): the decrypted store
is kept in memory and only re-read when the file's stat signature (mtime,
size, file ID) changes, so an unchanged store costs one stat() per lookup
instead of a lock, a read and a decrypt. That signature is reliable on
NTFS; a write always re-reads and compares the actual file bytes under the
lock, so correctness never depends on it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import keyring
from cryptography.fernet import Fernet, InvalidToken
from filelock import FileLock, Timeout

_KEYRING_SERVICE = "pii-redact-mapping-store"

# os.replace on Windows fails with a sharing violation while another process
# (antivirus, a search indexer, a backup tool) briefly has the store open.
# Retrying for up to ~2s rides that out.
_REPLACE_ATTEMPTS = 40
_REPLACE_BACKOFF_S = 0.05


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


def _clean_display(display: str) -> str:
    # A span can wrap across a line break inside a paragraph; the display
    # form is meant to be dropped back into running text, so collapse it.
    return re.sub(r"\s+", " ", display.strip())


def _has_mixed_case(text: str) -> bool:
    return any(c.isupper() for c in text) and any(c.islower() for c in text)


def _should_upgrade_display(current: str, candidate: str) -> bool:
    """Bank statements and tax forms print names in ALL CAPS, so the first
    sighting of a person is often the all-caps form. A later mixed-case
    sighting ("Ravi Kumar" after "RAVI KUMAR") is the better form to show
    back to a human, so it replaces an all-caps display - but only that
    way round, so the display settles instead of flip-flopping between
    sightings."""
    return current.isupper() and _has_mixed_case(candidate)


def _display_of(entry: dict) -> str:
    return entry.get("display") or entry["value"]


def _needs_display_upgrade(entry: dict, display: str | None) -> bool:
    return bool(display) and _should_upgrade_display(_display_of(entry), display)


def _keyring_username_for(store_path: Path) -> str:
    # Hash the resolved path rather than using it verbatim as the keyring
    # username - keeps it a fixed, predictable shape regardless of path
    # length/characters, while still giving each distinct store file its
    # own independent key.
    resolved = str(store_path.resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


def _existing_key(store_path: Path) -> bytes | None:
    existing = keyring.get_password(_KEYRING_SERVICE, _keyring_username_for(store_path))
    return existing.encode("utf-8") if existing is not None else None


def _get_or_create_key(store_path: Path) -> bytes:
    existing = _existing_key(store_path)
    if existing is not None:
        return existing
    key = Fernet.generate_key()
    keyring.set_password(_KEYRING_SERVICE, _keyring_username_for(store_path), key.decode("utf-8"))
    return key


class MappingStoreError(ValueError):
    pass


_EMPTY_STORE = {"entries": [], "counters": {}}


@dataclass
class _Snapshot:
    """One decrypted version of the store file, with lookup indexes.

    `raw` is the encrypted bytes it was decrypted from, so a later read can
    tell "file unchanged" by comparing bytes instead of decrypting again.
    """

    raw: bytes
    signature: tuple | None
    data: dict
    by_key: dict[tuple[str, str], dict]
    by_code: dict[str, dict]

    @classmethod
    def build(cls, raw: bytes, signature: tuple | None, data: dict) -> _Snapshot:
        by_key: dict[tuple[str, str], dict] = {}
        by_code: dict[str, dict] = {}
        for entry in data["entries"]:
            by_key.setdefault((entry["entity_type"], entry["value"]), entry)
            by_code.setdefault(entry["code"], entry)
        return cls(raw, signature, data, by_key, by_code)


def encrypt_empty_store(key: bytes) -> bytes:
    """Encrypted bytes of a store with no entries - what `redact-key init`
    writes, so a freshly created store is a real, decryptable file."""
    return Fernet(key).encrypt(json.dumps(_EMPTY_STORE).encode("utf-8"))


class MappingStore:
    """Thread-safe within a process; safe across processes via the file lock.

    `create=True` (the default, and the legacy `redact` behavior) generates
    and saves a new key the first time a path is used. The Phase 7 tools
    pass `create=False`: they refuse to start unless the key and the store
    file already exist, so a wrong or mistyped path fails loudly instead of
    silently starting a second store that hands out the same codes for
    different people.
    """

    def __init__(
        self,
        store_path: Path,
        key: bytes | None = None,
        *,
        cache: bool = False,
        create: bool = True,
        lock_timeout: float = -1,
    ):
        self.store_path = Path(store_path)
        if key is None:
            key = _get_or_create_key(self.store_path) if create else _existing_key(self.store_path)
            if key is None:
                raise MappingStoreError(
                    f"{self.store_path}: no key for this store in the OS credential store "
                    "(set one up with `redact-key init`, or restore it with `redact-key import`)"
                )
        if not create and not self.store_path.is_file():
            raise MappingStoreError(f"{self.store_path}: store file not found")
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise MappingStoreError(f"{self.store_path}: the key is not a valid Fernet key") from exc
        # Separate from the encryption key (derived, never the key itself),
        # used only for keyed_digest().
        self._digest_key = hashlib.sha256(b"pii-redact/keyed-digest/v1\0" + key).digest()

        self._lock_path = self.store_path.with_name(self.store_path.name + ".lock")
        self._tmp_path = self.store_path.with_name(self.store_path.name + ".tmp")
        self._file_lock = FileLock(str(self._lock_path), timeout=lock_timeout)
        self._cache = cache
        self._mutex = threading.RLock()
        self._snapshot: _Snapshot | None = None
        self._txn: _Snapshot | None = None
        self._txn_dirty = False

    # --- file access (callers hold self._mutex)

    def _signature(self) -> tuple | None:
        try:
            st = os.stat(self.store_path)
        except FileNotFoundError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self._file_lock.acquire()
        except Timeout as exc:
            raise MappingStoreError(f"{self.store_path}: timed out waiting for the store lock") from exc
        try:
            yield
        finally:
            self._file_lock.release()

    def _read_locked(self) -> _Snapshot:
        """Current file contents, read while holding the file lock. Reuses
        the cached snapshot without decrypting when the bytes are
        identical."""
        signature = self._signature()
        try:
            raw = self.store_path.read_bytes()
        except FileNotFoundError:
            raw = b""
        cached = self._snapshot
        if cached is not None and cached.raw == raw:
            cached.signature = signature
            return cached
        if not raw:
            return _Snapshot.build(raw, signature, {"entries": [], "counters": {}})
        try:
            data = json.loads(self._fernet.decrypt(raw).decode("utf-8"))
        except InvalidToken as exc:
            raise MappingStoreError(
                f"{self.store_path}: could not decrypt with the configured key - "
                "wrong key, corrupted file, or a store from a different install"
            ) from exc
        except ValueError as exc:  # decrypted, but not the JSON this module writes
            raise MappingStoreError(f"{self.store_path}: store contents are not valid") from exc
        return _Snapshot.build(raw, signature, data)

    def _save_locked(self, snapshot: _Snapshot) -> None:
        raw = self._fernet.encrypt(json.dumps(snapshot.data).encode("utf-8"))
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._tmp_path, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(self._tmp_path, self.store_path)
                break
            except PermissionError as exc:
                if attempt == _REPLACE_ATTEMPTS - 1:
                    raise MappingStoreError(
                        f"{self.store_path}: could not replace the store file (still in use)"
                    ) from exc
                time.sleep(_REPLACE_BACKOFF_S)
        snapshot.raw = raw
        snapshot.signature = self._signature()

    def _snapshot_for_read(self) -> _Snapshot:
        with self._mutex:
            if self._txn is not None:
                return self._txn
            cached = self._snapshot
            if self._cache and cached is not None and cached.signature == self._signature():
                return cached
            with self._locked():
                self._snapshot = self._read_locked()
            return self._snapshot

    # --- public API

    def keyed_digest(self, text: str) -> str:
        """HMAC-SHA256 of `text` under a key derived from this store's key.
        For identifiers that must not reveal what they identify - e.g. a
        document's path, which often carries a name. A plain hash of a short,
        guessable string ("Ravi Kumar PAN.pdf") can be reversed by trying
        candidates; this one can't without the key."""
        return hmac.new(self._digest_key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def load(self) -> int:
        """Reads the store now (whatever the cache says) and returns how many
        codes it holds. Raises MappingStoreError if it can't be read - which
        is how a long-running service checks its store at startup."""
        with self._mutex:
            with self._locked():
                self._snapshot = self._read_locked()
            return len(self._snapshot.by_code)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Holds the cross-process lock for the whole block, starting from
        the latest file contents, and saves at most once - at the end, in
        one atomic write. Every code issued inside the block is part of
        that one write. If the block raises, nothing from it is saved.

        Nested use joins the outer transaction."""
        with self._mutex:
            if self._txn is not None:
                yield
                return
            with self._locked():
                snapshot = self._read_locked()
                # Until this transaction finishes cleanly, the cached
                # snapshot may hold changes that were never saved.
                self._snapshot = None
                self._txn, self._txn_dirty = snapshot, False
                try:
                    yield
                    if self._txn_dirty:
                        self._save_locked(snapshot)
                finally:
                    self._txn, self._txn_dirty = None, False
                self._snapshot = snapshot

    def get_or_create_code(
        self, entity_type: str, raw_value: str, display: str | None = None
    ) -> str:
        """`raw_value` is the normalized lookup key; `display` is the surface
        form as it appeared in the document (defaults to `raw_value`)."""
        display = _clean_display(display) if display is not None else None
        key = (entity_type, raw_value)
        with self._mutex:
            if self._txn is None:
                # Fast path: a known value needs no lock and no write.
                entry = self._snapshot_for_read().by_key.get(key)
                if entry is not None and not _needs_display_upgrade(entry, display):
                    return entry["code"]
            with self.transaction():
                return self._get_or_create_in_txn(entity_type, raw_value, display)

    def _get_or_create_in_txn(self, entity_type: str, raw_value: str, display: str | None) -> str:
        snapshot = self._txn
        entry = snapshot.by_key.get((entity_type, raw_value))
        if entry is not None:
            if _needs_display_upgrade(entry, display):
                entry["display"] = display
                self._txn_dirty = True
            return entry["code"]

        ordinal = snapshot.data["counters"].get(entity_type, 0) + 1
        code = _make_code(entity_type, ordinal)
        while code in snapshot.by_code:  # defensive: counters out of step with entries
            ordinal += 1
            code = _make_code(entity_type, ordinal)
        snapshot.data["counters"][entity_type] = ordinal
        entry = {
            "entity_type": entity_type,
            "value": raw_value,
            "display": display or raw_value,
            "code": code,
        }
        snapshot.data["entries"].append(entry)
        snapshot.by_key[(entity_type, raw_value)] = entry
        snapshot.by_code[code] = entry
        self._txn_dirty = True
        return code

    def reverse_lookup(self, code: str) -> str | None:
        with self._mutex:
            entry = self._snapshot_for_read().by_code.get(code)
            return _display_of(entry) if entry is not None else None

    def all_codes(self) -> dict[str, str]:
        """code -> display form, for building the reverse() substitution
        pass."""
        with self._mutex:
            snapshot = self._snapshot_for_read()
            return {code: _display_of(entry) for code, entry in snapshot.by_code.items()}

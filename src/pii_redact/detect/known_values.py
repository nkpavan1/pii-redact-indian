"""Finds values the mapping store already knows, wherever they appear.

NER misses names it has seen before, depending on the sentence around them.
Measured on the 0.3.0 service with synthetic names: after "Periwinkle
Zanzibar" was stored, "Ask Periwinkle Zanzibar about it." came back
unchanged, and "PRIYA SHARMA PAID THE BILL." was missed although "Priya
Sharma" had been stored earlier in the same request. So after analysis,
every text is also swept for values that are already known: the store's
entries, plus whatever this call's own detections found (so a name found
once in a request, or in a document, is masked everywhere in it). A match
reuses the existing code, because the matched text normalizes to the
stored key.

What the sweep covers, and why:
- PERSON values of two or more words, matched case-insensitively as whole
  words, longest first. Single-word values are never swept ("Asha" is
  also a word, "Kumar" is half of India). Neither are values that contain
  a stop word, a digit, or start or end with a word that is never a name
  (person_spans.py), which keeps out stored NER mistakes such as
  "Ping Ravi Kumar" from before 0.4.0.
- Identifiers (ID_TYPES: PAN, Aadhaar, account numbers, e-mail, phone,
  ...), matched as a whole token of at least MIN_ID_CHARS characters with
  a digit or an "@" in it. Context-scoped ones gain the most: an account
  number stored from a statement is masked in chat without "account" next
  to it.
- Not covered: IN_ADDRESS (free-form, and the PIN-code recognizer finds
  repeats anyway) and IN_DATE_OF_BIRTH (a date recurs legitimately as a
  transaction date).

Only the entity types the caller asked for are swept, and never text
inside a code.

Cost: the store's index is built once per version of the store and then
kept up to date as codes are issued (MappingStore.derived). A sweep is one
pass over the words of a text with dictionary lookups, so it does not
grow with the size of the store.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass

from spacy.lang.en.stop_words import STOP_WORDS

from pii_redact.anonymize.mapping_store import MappingStore, normalize_value
from pii_redact.detect.person_spans import is_not_a_name_word
from pii_redact.types import Detection

NAME_TYPE = "PERSON"
ID_TYPES = frozenset(
    {
        "IN_PAN",
        "IN_AADHAAR",
        "IN_PASSPORT",
        "IN_VOTER",
        "IN_VEHICLE_REGISTRATION",
        "IN_GSTIN",
        "IFSC",
        "UPI_ID",
        "BANK_ACCOUNT_NUMBER",
        "DRIVING_LICENSE",
        "EPF_UAN",
        "DEMAT_DP_ID",
        "TAN",
        "CIN",
        "ITR_ACK_NUMBER",
        "CKYC_NUMBER",
        "MF_FOLIO_NUMBER",
        "RATION_CARD_NUMBER",
        "CREDIT_CARD",
        "AIS_DOWNLOAD_ID",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
    }
)
SWEPT_TYPES = ID_TYPES | {NAME_TYPE}
MIN_ID_CHARS = 8
MIN_NAME_LETTERS = 5

# Detections reported under another name (analyzer._REPORTED_AS): asking
# for IN_MOBILE means the phone numbers it finds are swept too.
_REQUESTED_AS = {"IN_MOBILE": "PHONE_NUMBER"}

_STORE_INDEX = "known_values"
_NAME_WORD = re.compile(r"[^\W_]+")
# An identifier-shaped run: no whitespace and none of the characters that
# separate fields in running text or statement narrations ("UPI/9876.../").
_ID_RUN = re.compile(r"[^\s,;:()\[\]{}<>\"'|/\\=?!]+")
_ID_RUN_EDGES = "._-+*#"
_GENERIC_ID_TYPE = "IN_PAN"  # any type normalized the plain way (not PERSON, not PHONE_NUMBER)


@dataclass(frozen=True)
class KnownMatch:
    start: int
    end: int
    entity_type: str


def swept_types(entities: Iterable[str]) -> frozenset[str]:
    """The entity types to sweep for, given the ones a caller asked for."""
    return frozenset(_REQUESTED_AS.get(e, e) for e in entities) & SWEPT_TYPES


def _sweepable_name(key: str, words: tuple[str, ...]) -> bool:
    return (
        not any(c.isdigit() for c in key)
        and sum(len(w) >= 2 for w in words) >= 2
        and sum(len(w) for w in words) >= MIN_NAME_LETTERS
        and not is_not_a_name_word(words[0], leading=True)
        and not is_not_a_name_word(words[-1], leading=False)
        and not any(w in STOP_WORDS for w in words)
    )


def _sweepable_id(key: str) -> bool:
    return len(key) >= MIN_ID_CHARS and (any(c.isdigit() for c in key) or "@" in key)


def _is_whole_token(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return not (before.isalnum() or before == "_" or after.isalnum() or after == "_")


class KnownValues:
    """An index of values to find in text: (entity type, normalized key)
    pairs, the same keys the mapping store uses."""

    def __init__(self) -> None:
        # first word -> [(all words, key)], longest first
        self._names: dict[str, list[tuple[tuple[str, ...], str]]] = {}
        self._name_keys: set[str] = set()
        # normalized key -> entity types it is known as
        self._ids: dict[str, set[str]] = {}

    @classmethod
    def from_entries(cls, entries: Sequence[dict]) -> KnownValues:
        index = cls()
        for entry in entries:
            index.add_entry(entry)
        return index

    def __len__(self) -> int:
        return len(self._name_keys) + sum(len(types) for types in self._ids.values())

    def add_entry(self, entry: dict) -> None:
        """Adds a mapping-store entry (also MappingStore.derived's update hook)."""
        self.add_key(entry["entity_type"], entry["value"])

    def add(self, entity_type: str, surface: str) -> None:
        """Adds a value as it appeared in a text."""
        self.add_key(entity_type, normalize_value(entity_type, surface))

    def add_key(self, entity_type: str, key: str) -> None:
        if entity_type == NAME_TYPE:
            words = tuple(w.casefold() for w in _NAME_WORD.findall(key))
            if key in self._name_keys or not words or not _sweepable_name(key, words):
                return
            self._name_keys.add(key)
            bucket = self._names.setdefault(words[0], [])
            bucket.append((words, key))
            bucket.sort(key=lambda candidate: -len(candidate[0]))
        elif entity_type in ID_TYPES and _sweepable_id(key):
            self._ids.setdefault(key, set()).add(entity_type)

    def find(self, text: str, types: Collection[str]) -> list[KnownMatch]:
        matches = []
        if NAME_TYPE in types and self._names:
            matches.extend(self._find_names(text))
        if self._ids and not ID_TYPES.isdisjoint(types):
            matches.extend(self._find_ids(text, types))
        return matches

    def _find_names(self, text: str) -> list[KnownMatch]:
        words = [(m.group().casefold(), m.start(), m.end()) for m in _NAME_WORD.finditer(text)]
        matches = []
        i = 0
        while i < len(words):
            for candidate, key in self._names.get(words[i][0], ()):
                n = len(candidate)
                if i + n > len(words) or any(words[i + j][0] != candidate[j] for j in range(1, n)):
                    continue
                start, end = words[i][1], words[i + n - 1][2]
                # The words match; the text between them must too (spaces,
                # and "R." style initials), which is what the key checks.
                if _is_whole_token(text, start, end) and normalize_value(NAME_TYPE, text[start:end]) == key:
                    matches.append(KnownMatch(start, end, NAME_TYPE))
                    i += n
                    break
            else:
                i += 1
        return matches

    def _find_ids(self, text: str, types: Collection[str]) -> list[KnownMatch]:
        matches = []
        for m in _ID_RUN.finditer(text):
            start, end = m.span()
            while start < end and text[start] in _ID_RUN_EDGES:
                start += 1
            while end > start and text[end - 1] in _ID_RUN_EDGES:
                end -= 1
            if end - start < MIN_ID_CHARS:
                continue
            run = text[start:end]
            found = {
                t for t in self._ids.get(normalize_value(_GENERIC_ID_TYPE, run), ()) if t != "PHONE_NUMBER"
            }
            if "PHONE_NUMBER" in self._ids.get(normalize_value("PHONE_NUMBER", run), ()):
                found.add("PHONE_NUMBER")
            found &= set(types)
            if found:
                matches.append(KnownMatch(start, end, min(found)))
        return matches


def store_index(store: MappingStore) -> KnownValues:
    """The index of everything `store` knows, kept with the store."""
    return store.derived(_STORE_INDEX, KnownValues.from_entries)


def find_known(
    text: str,
    indexes: Iterable[KnownValues],
    types: Collection[str],
    exclude: Collection[tuple[int, int]] = (),
) -> list[KnownMatch]:
    """Known values in `text` from any of `indexes`, not overlapping each
    other (longer first) or any `exclude` span (codes already in the text)."""
    candidates = [m for index in indexes for m in index.find(text, types)]
    candidates.sort(key=lambda m: (m.start, -(m.end - m.start)))
    kept: list[KnownMatch] = []
    for m in candidates:
        if any(s < m.end and m.start < e for s, e in exclude):
            continue
        if kept and m.start < kept[-1].end:
            continue
        kept.append(m)
    return kept


def merge_known(
    detections: list[Detection],
    matches: Iterable[KnownMatch],
    make: Callable[[int, int, str], Detection],
) -> list[Detection]:
    """Adds known-value matches to a text's detections.

    - Nothing overlaps: the match is added.
    - A detection of the same type already covers it: nothing changes (a
      new, longer name keeps its own span and code - "Ravi Kumar Sharma"
      is not "Ravi Kumar" plus a leaked "Sharma").
    - It covers detections of the same type, or overlaps them partly: they
      are replaced by one span over all of them ("LAKSHMI NARAYANAN" over
      NER's "NARAYANAN").
    - A detection of another type has exactly the same span: the known
      type wins, so the value keeps the code it already has.
    - A detection of another type overlaps it partly: the detection stays
      and the match is dropped."""
    result = list(detections)
    for m in matches:
        overlapping = [d for d in result if d.start < m.end and m.start < d.end]
        if any(d.entity_type != m.entity_type and (d.start, d.end) != (m.start, m.end) for d in overlapping):
            continue
        if any(d.entity_type == m.entity_type and d.start <= m.start and m.end <= d.end for d in overlapping):
            continue
        start = min([m.start, *(d.start for d in overlapping)])
        end = max([m.end, *(d.end for d in overlapping)])
        result = [d for d in result if d not in overlapping]
        result.append(make(start, end, m.entity_type))
    return result


def local_index(values: Iterable[tuple[str, str]], types: Collection[str]) -> KnownValues:
    """An index of (entity type, surface text) pairs found by this call's
    own detections."""
    index = KnownValues()
    for entity_type, surface in values:
        if entity_type in types:
            index.add(entity_type, surface)
    return index

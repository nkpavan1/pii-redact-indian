"""Public string-level API - the shared core of redact-publish (documents)
and redact-service (chat):

    from pii_redact import MappingStore, RedactResult, redact_text, reverse_text

`redact_text` pseudonymizes a string with the same detection (Presidio plus
this project's recognizers) and the same mapping store as the document
pipeline, so a person gets the same code (`PERSON_A`) whether they were
first seen in a published document or in a chat message. `reverse_text`
puts the stored surface forms back.

Guarantees:
- Same (entity type, normalized value) -> same code, across calls,
  processes and both tools, as long as they share one mapping store.
- Codes are ASCII `[A-Z0-9_]` tokens: nothing in them needs escaping inside
  a JSON string, and reversal only ever matches them as whole tokens.
- Codes already in the text (from a redacted document, or a model reply
  that echoed them) are passed through unchanged, so redacting an already
  redacted text changes nothing. The text around them is still scanned,
  which can only ever add a redaction, never undo one.
- Fail closed: an error in detection or in the mapping store raises. No
  code path returns the input unredacted after a failure.

Not thread-safe: the analyzer and anonymizer are process-wide singletons,
so a caller serving concurrent requests (redact-service) must serialize
calls.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace

from presidio_analyzer import RecognizerResult

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.anonymize.operators import get_anonymizer_engine, pseudonym_operators
from pii_redact.config.allowlists import allowlist_for
from pii_redact.detect.analyzer import SCORE_THRESHOLD, detect_in_block, get_analyzer
from pii_redact.reverse.reverse import find_codes, reverse, reverse_many
from pii_redact.types import Detection, Location, TextBlock

# Entity allow-list used when the caller doesn't pass `entities`.
DEFAULT_DOC_TYPE = "chat"

# spaCy's default nlp.max_length. Longer texts make spaCy raise mid-call;
# checking up front gives callers a distinct error (the service maps it to
# "too large" instead of a generic failure) before any store write happens.
MAX_TEXT_CHARS = 1_000_000


class TextTooLongError(ValueError):
    pass


@dataclass(frozen=True)
class RedactResult:
    """`text` is the pseudonymized text. `entities` counts what was redacted
    in this call, by entity type (never values). `spans` lists
    (start, end, entity_type, code) with offsets into `text`, for review
    UIs.

    `text` and `spans` are excluded from repr(), so logging a result can
    only ever show counts."""

    text: str = field(repr=False)
    entities: dict[str, int] = field(default_factory=dict)
    spans: list[tuple[int, int, str, str]] = field(default_factory=list, repr=False)


def _resolve_threshold(threshold: float | None) -> float:
    if threshold is None:
        return SCORE_THRESHOLD
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    return float(threshold)


def _resolve_entities(entities: Iterable[str] | None) -> list[str]:
    """Rejects rather than ignores unknown names: Presidio silently skips an
    entity type it has no recognizer for, so a typo (`PAN` for `IN_PAN`)
    would otherwise quietly turn redaction off for that type."""
    if entities is None:
        return allowlist_for(DEFAULT_DOC_TYPE)
    requested = list(entities)
    if not requested:
        raise ValueError("entities must not be empty")
    unknown = sorted(set(requested) - set(get_analyzer().get_supported_entities()))
    if unknown:
        raise ValueError(f"unsupported entity types: {unknown}")
    return requested


def _check_texts(texts: Sequence[str]) -> None:
    # All inputs are validated before any is processed, so a bad item late
    # in a batch fails the call before anything is written to the store.
    for text in texts:
        if not isinstance(text, str):
            raise TypeError("texts must be strings")
        if len(text) > MAX_TEXT_CHARS:
            raise TextTooLongError(f"text longer than {MAX_TEXT_CHARS} characters")


def _pieces_outside(start: int, end: int, code_spans: list[tuple[int, int]], text: str) -> list[tuple[int, int]]:
    """Parts of text[start:end] not covered by a code, each trimmed to its
    first and last letter or digit. Pieces with no letter or digit (the ", "
    between a code and a name) are dropped."""
    pieces = []
    cursor = start
    for code_start, code_end in code_spans:
        if code_end <= cursor or code_start >= end:
            continue
        if code_start > cursor:
            pieces.append((cursor, code_start))
        cursor = max(cursor, code_end)
    if cursor < end:
        pieces.append((cursor, end))

    trimmed = []
    for piece_start, piece_end in pieces:
        while piece_start < piece_end and not text[piece_start].isalnum():
            piece_start += 1
        while piece_end > piece_start and not text[piece_end - 1].isalnum():
            piece_end -= 1
        if piece_start < piece_end:
            trimmed.append((piece_start, piece_end))
    return trimmed


def _outside_codes(
    detections: list[Detection], code_spans: list[tuple[int, int]], text: str
) -> list[Detection]:
    """Keeps codes already in the text out of every detection. A detection
    entirely inside a code is dropped; one that runs across a code (NER
    reading "PERSON_A Kumar" as one name) is cut down to the parts outside
    it, so "Kumar" is still redacted and the code is left alone."""
    if not code_spans:
        return detections
    kept = []
    for d in detections:
        if not any(code_start < d.end and d.start < code_end for code_start, code_end in code_spans):
            kept.append(d)
            continue
        for piece_start, piece_end in _pieces_outside(d.start, d.end, code_spans, text):
            kept.append(replace(d, start=piece_start, end=piece_end))
    return kept


def _detect(text: str, entities: list[str], threshold: float) -> list[Detection]:
    if not any(ch.isalnum() for ch in text):
        return []
    return detect_in_block(
        TextBlock(text=text, location=Location()), 0, entities, score_threshold=threshold
    )


def _pseudonymize(
    text: str,
    detections: list[Detection],
    store: MappingStore,
    known_codes: set[str],
) -> RedactResult:
    detections = _outside_codes(detections, find_codes(text, known_codes), text)
    if not detections:
        return RedactResult(text=text)

    result = get_anonymizer_engine().anonymize(
        text=text,
        analyzer_results=[
            RecognizerResult(entity_type=d.entity_type, start=d.start, end=d.end, score=d.score)
            for d in detections
        ],
        operators=pseudonym_operators(store),
    )
    spans = sorted((item.start, item.end, item.entity_type, item.text) for item in result.items)
    return RedactResult(
        text=result.text,
        entities=dict(Counter(entity_type for _, _, entity_type, _ in spans)),
        spans=spans,
    )


def redact_texts(
    texts: Sequence[str],
    store: MappingStore,
    *,
    threshold: float | None = None,
    entities: Iterable[str] | None = None,
) -> list[RedactResult]:
    """Pseudonymizes each text; results are 1:1 with `texts`, in order.

    `threshold` is the minimum detection score (default: the project-wide
    SCORE_THRESHOLD). `entities` limits which entity types are redacted
    (default: the "chat" allow-list, see config/allowlists.py).

    Detection runs first, with no store lock held - it's the slow part.
    Then every code the call needs is issued inside one store transaction:
    one lock, and at most one save, however many texts and entities."""
    texts = list(texts)
    _check_texts(texts)
    resolved_threshold = _resolve_threshold(threshold)
    resolved_entities = _resolve_entities(entities)

    found = [_detect(text, resolved_entities, resolved_threshold) for text in texts]
    if not any(found):
        return [RedactResult(text=text) for text in texts]

    results = []
    with store.transaction():
        known_codes = set(store.all_codes())
        for text, detections in zip(texts, found):
            result = _pseudonymize(text, detections, store, known_codes)
            # A code issued for an earlier text counts as known for later ones.
            known_codes.update(code for *_, code in result.spans)
            results.append(result)
    return results


def redact_text(
    text: str,
    store: MappingStore,
    *,
    threshold: float | None = None,
    entities: Iterable[str] | None = None,
) -> RedactResult:
    return redact_texts([text], store, threshold=threshold, entities=entities)[0]


@dataclass(frozen=True)
class Finding:
    """One detection that is still in the clear: an entity type, where it
    is, and how confident the detector was. Never the value itself."""

    entity_type: str
    start: int
    end: int
    score: float


def find_pii(
    text: str,
    store: MappingStore,
    *,
    threshold: float | None = None,
    entities: Iterable[str] | None = None,
) -> list[Finding]:
    """Detections in `text` that are not codes the store issued - PII still
    in the clear. Changes nothing, issues no codes. Used as the residual
    check on already-redacted output: anything found here should have
    been redacted and wasn't."""
    _check_texts([text])
    detections = _detect(text, _resolve_entities(entities), _resolve_threshold(threshold))
    if not detections:
        return []
    detections = _outside_codes(detections, find_codes(text, set(store.all_codes())), text)
    return sorted(
        (Finding(d.entity_type, d.start, d.end, d.score) for d in detections),
        key=lambda f: (f.start, f.end, f.entity_type),
    )


def reverse_texts(texts: Sequence[str], store: MappingStore) -> list[str]:
    """Replaces every code the store knows with its stored surface form;
    1:1 with `texts`, in order. Code-shaped tokens the store never issued
    are left as written."""
    texts = list(texts)
    for text in texts:
        if not isinstance(text, str):
            raise TypeError("texts must be strings")
    return reverse_many(texts, store)


def reverse_text(text: str, store: MappingStore) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return reverse(text, store)

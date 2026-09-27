"""Builds the Presidio AnalyzerEngine used by the detect stage.

Wires in the custom recognizers on top of Presidio's built-ins, and swaps
the built-in IN_AADHAAR recognizer for the Verhoeff-checksummed one (see
detect/recognizers/aadhaar_checksum.py) rather than stacking both, which
would double-detect every match under the same entity type.

VERIFIED, NOT ASSUMED: registry.load_predefined_recognizers() does NOT
actually load ANY of Presidio's country-specific recognizers by default -
every single one, India's included (InPanRecognizer, InAadhaarRecognizer,
InGstinRecognizer, InPassportRecognizer, InVoterRecognizer,
InVehicleRegistrationRecognizer), ships with `enabled: false` in this
presidio-analyzer release's own default conf YAML. Passing
`countries=["in"]` to load_predefined_recognizers() does NOT override this
- it only filters among recognizers already enabled, confirmed by direct
probe (only locale-agnostic ones came back, zero India-specific ones).
This means the "Built-in Indian recognizers already available in Presidio"
premise in the project instructions was WRONG as stated for this release
- they exist in the library but are inert unless explicitly instantiated
and added, exactly like a custom recognizer. Found only because an
end-to-end smoke test showed IN_PAN never firing on realistic input;
no unit test caught it, because every recognizer-level test in this
project instantiates the recognizer class directly rather than going
through the registry-loading path where this gate lives. _INDIA_BUILTINS
below is how they're actually activated.


SCORE_THRESHOLD exists because analyze() otherwise returns everything,
unfiltered - discovered via an end-to-end smoke test whose preview showed
five low-confidence entity types firing on plain digit strings with zero
surrounding context. This project's several context-scoped custom
recognizers (see detect/recognizers/banking.py etc.) are deliberately given
a LOW base score (0.15-0.3) specifically so they stay silent without a
context-word boost - that design only works if something actually filters
scores below the boosted range, which nothing did until this threshold was
added. 0.5 was chosen empirically (not just theoretically): it sits above
every unboosted low-confidence recognizer's base score, and below what a
genuine single-word context match boosts a 0.15-base recognizer to
(confirmed by direct probe: 0.15 -> 0.5 with one matching context word
nearby) as well as below the higher-confidence format-only recognizers
(TAN 0.6, CIN/IFSC 0.7) that should fire even without context.

KNOWN, DOCUMENTED GAP this does NOT fix: structured per-cell extraction
(CSV/XLSX/JSON - see those extract/ modules) hands each cell's bare value
to the analyzer with NO surrounding sentence, so context-word boosting has
nothing to boost from - a bank account number sitting in its own cell will
almost always score below this threshold and go undetected, even though a
human reading the column header "account_number" would recognize it
instantly. The real fix is a field-name-driven fast path (redact by known
key/column name), which extract/json_.py's docstring already flags as a
deferred, NOT-yet-implemented follow-up - it is not solved by this
threshold and this threshold does not pretend to solve it.
"""

from __future__ import annotations

from functools import lru_cache

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult
from presidio_analyzer.predefined_recognizers import (
    InGstinRecognizer,
    InVehicleRegistrationRecognizer,
    InVoterRecognizer,
)

from pii_redact.detect.emphasis import blank_emphasis
from pii_redact.detect.person_spans import refine_person_results
from pii_redact.detect.recognizers import AADHAAR_REPLACEMENT_ENTITY, get_custom_recognizers
from pii_redact.types import Detection, TextBlock

SCORE_THRESHOLD = 0.5

# MEASURED, NOT ASSUMED: one analyze() call is quadratic in text length.
# Presidio's LemmaContextAwareEnhancer walks every token of the whole
# document for every candidate result (_find_index_of_match_token), and
# a long text has thousands of low-score candidates before thresholding -
# profiled at ~84M token visits for a ~200K-character text. spaCy itself is
# linear (1.4s at 48K chars, 5.8s at 200K), but analyze() took 2.2s and
# 16s. Long texts are therefore analyzed in chunks of about _CHUNK_CHARS,
# cut at a paragraph, line, sentence or word boundary, each analyzed
# together with _CHUNK_OVERLAP_CHARS of its neighbors so that a name, a
# context word or a long match (an address) near a cut is still seen whole.
# A result belongs to the chunk it starts in, so none is counted twice.
_CHUNK_CHARS = 10_000
_CHUNK_OVERLAP_CHARS = 1_000
_CHUNK_BREAKS = ("\n\n", "\n", ". ", " ")

# Presidio's India-specific built-ins that ship disabled (see module
# docstring) - activated explicitly here, the same way a custom recognizer
# is. InAadhaarRecognizer, InPassportRecognizer and InPanRecognizer are
# deliberately left out: this project's AadhaarChecksumRecognizer,
# PassportNumberRecognizer and PanRecognizer replace them (see
# recognizers/aadhaar_checksum.py, recognizers/other_documents.py and
# recognizers/pan.py for why).
_INDIA_BUILTINS = [
    InVoterRecognizer,
    InVehicleRegistrationRecognizer,
    InGstinRecognizer,
]

# Entity types whose built-in recognizer is replaced, not stacked with a
# custom one - two recognizers on one type would report the same span twice.
_REPLACED_BUILTIN_ENTITIES = {AADHAAR_REPLACEMENT_ENTITY, "IN_PASSPORT", "IN_PAN"}

# Entity types emitted by a recognizer but reported under another name.
# IN_MOBILE exists only so that the `chat` allow-list alone can request the
# context-free mobile recognizer (see recognizers/phone.py); to callers it
# is a PHONE_NUMBER, so one number gets one code whichever recognizer found
# it.
_REPORTED_AS = {"IN_MOBILE": "PHONE_NUMBER"}


def _build_registry() -> RecognizerRegistry:
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    for recognizer_cls in _INDIA_BUILTINS:
        registry.add_recognizer(recognizer_cls())

    # Defensive, not currently load-bearing: neither replaced built-in is
    # loaded by load_predefined_recognizers() today (see module docstring) -
    # this guards against double-registration if a future presidio-analyzer
    # release changes that default.
    for recognizer in list(registry.recognizers):
        if _REPLACED_BUILTIN_ENTITIES & set(recognizer.supported_entities):
            registry.remove_recognizer(recognizer.name)

    for custom_recognizer in get_custom_recognizers():
        registry.add_recognizer(custom_recognizer)

    return registry


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Process-wide singleton - building the registry and loading the spaCy
    model is too expensive to redo per document in a batch run."""
    return AnalyzerEngine(registry=_build_registry())


def _chunk_bounds(text: str) -> list[tuple[int, int]]:
    bounds = []
    start, n = 0, len(text)
    while start < n:
        end = min(n, start + _CHUNK_CHARS)
        if end < n:
            earliest = start + int(_CHUNK_CHARS * 0.8)
            for separator in _CHUNK_BREAKS:
                cut = text.rfind(separator, earliest, end)
                if cut != -1:
                    end = cut + len(separator)
                    break
        bounds.append((start, end))
        start = end
    return bounds


def _analyze_one(text: str, entities: list[str], language: str, score_threshold: float) -> list[RecognizerResult]:
    """One analyze() call, with PERSON spans refined against the same spaCy
    Doc the analyzer used (see person_spans.py) - computed once here and
    handed to analyze(), so refining costs no second NLP pass.

    spaCy reads the text with its markdown emphasis marks blanked
    (emphasis.py); the copy has the same length, so its offsets hold for
    `text`, which everything else reads."""
    analyzer = get_analyzer()
    artifacts = analyzer.nlp_engine.process_text(blank_emphasis(text), language)
    results = analyzer.analyze(
        text=text, entities=entities, language=language, score_threshold=score_threshold, nlp_artifacts=artifacts
    )
    return refine_person_results(text, results, artifacts.tokens)


def _analyze(text: str, entities: list[str], language: str, score_threshold: float) -> list[RecognizerResult]:
    if len(text) <= _CHUNK_CHARS:
        return _analyze_one(text, entities, language, score_threshold)
    results = []
    for start, end in _chunk_bounds(text):
        window_start = max(0, start - _CHUNK_OVERLAP_CHARS)
        window_end = min(len(text), end + _CHUNK_OVERLAP_CHARS)
        for r in _analyze_one(text[window_start:window_end], entities, language, score_threshold):
            if start <= window_start + r.start < end:
                results.append(
                    RecognizerResult(r.entity_type, window_start + r.start, window_start + r.end, r.score)
                )
    return results


def detect_in_block(
    block: TextBlock,
    block_index: int,
    entities: list[str],
    language: str = "en",
    context_text: str | None = None,
    context_offset: int = 0,
    score_threshold: float = SCORE_THRESHOLD,
) -> list[Detection]:
    """Runs the analyzer over `block.text` by default. When `context_text`
    is given (a wider window built by the caller, e.g. pipeline.py's
    `_context_window` for PDF/image line blocks - see its docstring for
    why), that wider text is analyzed instead, so a field label on one
    line and its value on the next can share the context-word boost
    neither would get analyzed alone - but every returned Detection's
    offsets are still relative to `block.text`, exactly as if
    `context_text` had never been involved.

    A result that starts or ends outside `block.text`'s own span (i.e. it
    spilled into neighboring context, most commonly a spaCy NER span
    bleeding a token or two past a line boundary) is CLIPPED to the
    block's own range, not discarded outright - clipping is safe here
    specifically because the block boundary is a real separator inserted
    by the caller, not an arbitrary cut through the block's own content,
    so the clipped-off portion was never actually part of this block's
    text to begin with. A clip that leaves nothing inside the block's
    range is dropped.
    """
    text = block.text if context_text is None else context_text
    results = _analyze(text, entities, language, score_threshold)

    block_start = context_offset
    block_end = context_offset + len(block.text)

    # (entity_type, start, end) -> Detection; one per span and type, the
    # highest score winning - two recognizers reporting the same span under
    # the same (reported) type must not be counted twice.
    detections: dict[tuple[str, int, int], Detection] = {}
    for r in results:
        start = max(r.start, block_start)
        end = min(r.end, block_end)
        if start >= end:
            continue  # no overlap with this block at all
        entity_type = _REPORTED_AS.get(r.entity_type, r.entity_type)
        key = (entity_type, start - context_offset, end - context_offset)
        if key in detections and detections[key].score >= r.score:
            continue
        detections[key] = Detection(
            entity_type=entity_type,
            start=key[1],
            end=key[2],
            score=r.score,
            block_index=block_index,
            location=block.location,
        )
    return list(detections.values())

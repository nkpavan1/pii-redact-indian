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

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.predefined_recognizers import (
    InGstinRecognizer,
    InPanRecognizer,
    InPassportRecognizer,
    InVehicleRegistrationRecognizer,
    InVoterRecognizer,
)

from pii_redact.detect.recognizers import AADHAAR_REPLACEMENT_ENTITY, get_custom_recognizers
from pii_redact.types import Detection, TextBlock

SCORE_THRESHOLD = 0.5

# Presidio's India-specific built-ins that ship disabled (see module
# docstring) - activated explicitly here, the same way a custom recognizer
# is. InAadhaarRecognizer is deliberately excluded from this list: this
# project's own AadhaarChecksumRecognizer replaces it (see below).
_INDIA_BUILTINS = [
    InPanRecognizer,
    InPassportRecognizer,
    InVoterRecognizer,
    InVehicleRegistrationRecognizer,
    InGstinRecognizer,
]


def _build_registry() -> RecognizerRegistry:
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    for recognizer_cls in _INDIA_BUILTINS:
        registry.add_recognizer(recognizer_cls())

    # Defensive, not currently load-bearing: InAadhaarRecognizer isn't
    # actually loaded by load_predefined_recognizers() today (see module
    # docstring) - this guards against double-registration if a future
    # presidio-analyzer release changes that default.
    for recognizer in list(registry.recognizers):
        if AADHAAR_REPLACEMENT_ENTITY in recognizer.supported_entities:
            registry.remove_recognizer(recognizer.name)

    for custom_recognizer in get_custom_recognizers():
        registry.add_recognizer(custom_recognizer)

    return registry


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Process-wide singleton - building the registry and loading the spaCy
    model is too expensive to redo per document in a batch run."""
    return AnalyzerEngine(registry=_build_registry())


def _looks_like_a_person_name(text: str) -> bool:
    """Plausibility filter on spaCy's PERSON entity, same spirit as this
    project's other validate_result-style checksum/format checks: a real
    person's name never contains a digit.

    Found via a real end-to-end test, not a unit test in isolation:
    spaCy's NER misclassifies short, decontextualized, non-sentence-like
    strings as PERSON with high confidence - confirmed directly on a
    quarter label from an AIS document, "Q4(Jan-Mar)", tagged PERSON at
    0.85 both with and without surrounding context (so this is not a
    context-window side effect - it happens on the bare block-alone pass
    too, and would have existed even before context windowing was added,
    just never surfaced by a document that happened to trigger it)."""
    return not any(c.isdigit() for c in text)


def detect_in_block(
    block: TextBlock,
    block_index: int,
    entities: list[str],
    language: str = "en",
    context_text: str | None = None,
    context_offset: int = 0,
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
    analyzer = get_analyzer()
    text = block.text if context_text is None else context_text
    results = analyzer.analyze(
        text=text,
        entities=entities,
        language=language,
        score_threshold=SCORE_THRESHOLD,
    )

    block_start = context_offset
    block_end = context_offset + len(block.text)

    detections = []
    for r in results:
        if r.entity_type == "PERSON" and not _looks_like_a_person_name(text[r.start : r.end]):
            continue
        start = max(r.start, block_start)
        end = min(r.end, block_end)
        if start >= end:
            continue  # no overlap with this block at all
        detections.append(
            Detection(
                entity_type=r.entity_type,
                start=start - context_offset,
                end=end - context_offset,
                score=r.score,
                block_index=block_index,
                location=block.location,
            )
        )
    return detections

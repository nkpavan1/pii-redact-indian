"""Exercises the real, fully-wired AnalyzerEngine end to end - registry
construction, the India-builtins-are-disabled-by-default gotcha, the
custom-recognizer/Presidio-builtin class-name collision class of bug, and
score-threshold filtering.

None of this was covered anywhere else: every other recognizer test
instantiates a recognizer class directly, bypassing the exact
registry-loading path where both bugs this file guards against were found
(via an end-to-end CLI smoke test, not a unit test - see detect/analyzer.py
and detect/recognizers/__init__.py for the full story). Skips cleanly if
the spaCy model isn't installed (a separate, one-time setup step - see
README) rather than treating "model missing" and "code broken" as the same
outcome: the model-load probe is separate from, and never swallows, a
failure in get_analyzer() itself.
"""

from __future__ import annotations

import pytest

pytest.importorskip("presidio_analyzer")

try:
    import spacy

    spacy.load("en_core_web_lg")
    _SPACY_MODEL_AVAILABLE = True
except (ImportError, OSError):
    _SPACY_MODEL_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _SPACY_MODEL_AVAILABLE,
    reason="requires `python -m spacy download en_core_web_lg` (see README)",
)


@pytest.fixture(scope="module")
def analyzer():
    # Regression guard for the custom-recognizer/Presidio-builtin
    # class-name collision (was: CreditCardRecognizer TypeError crash) -
    # simply not raising here is itself a real assertion.
    from pii_redact.detect.analyzer import get_analyzer

    get_analyzer.cache_clear()
    return get_analyzer()


def test_india_builtin_recognizers_are_actually_active(analyzer):
    # Regression guard for Presidio's country-specific recognizers
    # shipping with enabled: false by default - load_predefined_recognizers()
    # alone does NOT activate them; _build_registry() must add them
    # explicitly (see detect/analyzer.py's module docstring).
    names = {type(r).__name__ for r in analyzer.registry.recognizers}
    for expected in ("InPanRecognizer", "InPassportRecognizer", "InVoterRecognizer",
                      "InVehicleRegistrationRecognizer", "InGstinRecognizer"):
        assert expected in names, f"{expected} missing from the built registry"
    # The built-in Aadhaar recognizer must be replaced, not stacked.
    assert "InAadhaarRecognizer" not in names
    assert "AadhaarChecksumRecognizer" in names


def test_realistic_pan_is_detected_above_threshold(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    # Valid PAN 4th-character holder-type code ('P' = individual) - an
    # earlier smoke test used an invalid one and IN_PAN silently never
    # fired, which looked like a bug but was actually bad test data.
    results = analyzer.analyze(
        text="PAN: ABCPK1234F", language="en", score_threshold=SCORE_THRESHOLD
    )
    assert any(r.entity_type == "IN_PAN" for r in results)


def test_unboosted_low_confidence_custom_recognizer_is_filtered_out(analyzer):
    # Regression guard for the missing score_threshold bug: a bare 12-digit
    # run with zero surrounding context must NOT surface any of this
    # project's deliberately-low-base-score custom recognizers.
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="123456789012", language="en", score_threshold=SCORE_THRESHOLD
    )
    custom_low_confidence_entities = {
        "BANK_ACCOUNT_NUMBER", "EPF_UAN", "MF_FOLIO_NUMBER",
        "ITR_ACK_NUMBER", "RATION_CARD_NUMBER", "CKYC_NUMBER",
    }
    assert not any(r.entity_type in custom_low_confidence_entities for r in results)


def test_context_word_boosts_low_confidence_recognizer_above_threshold(analyzer):
    # Regression guard for the multi-word-context-phrase bug: single-word
    # context entries must actually boost the score.
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="UAN: 123456789012", language="en", score_threshold=SCORE_THRESHOLD
    )
    assert any(r.entity_type == "EPF_UAN" for r in results)


def test_bare_date_is_not_flagged_as_date_of_birth(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="Transaction date: 15/08/1990", language="en", score_threshold=SCORE_THRESHOLD
    )
    assert not any(r.entity_type == "IN_DATE_OF_BIRTH" for r in results)


@pytest.mark.parametrize(
    "text",
    [
        "DOB: 15/08/1990",
        "Date of Birth: 15-Aug-1990",
        "Born on 1990-08-15",
        "born 15 August 1990",
    ],
)
def test_dob_context_words_correctly_lemma_matched(analyzer, text):
    # Regression guard for the lemma-vs-surface-form bug: "born" must be
    # listed as its lemma "bear" (spaCy lemmatizes "born" -> "bear") or the
    # context boost silently never fires - confirmed to fail before the fix.
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(text=text, language="en", score_threshold=SCORE_THRESHOLD)
    assert any(r.entity_type == "IN_DATE_OF_BIRTH" for r in results), (
        f"IN_DATE_OF_BIRTH did not fire on {text!r} - check CONTEXT lemmas in "
        "detect/recognizers/dates.py"
    )


def test_driving_license_context_lemma_is_correct(analyzer):
    # "driving" lemmatizes to "drive" - same class of bug as the DOB one,
    # found in the same audit. Context list must contain "drive".
    with_context = analyzer.analyze(
        text="Driving Licence No: AB1220110012345", language="en", score_threshold=0.0
    )
    without_context = analyzer.analyze(
        text="AB1220110012345", language="en", score_threshold=0.0
    )
    score_with = next((r.score for r in with_context if r.entity_type == "DRIVING_LICENSE"), 0)
    score_without = next((r.score for r in without_context if r.entity_type == "DRIVING_LICENSE"), 0)
    assert score_with > score_without


def test_itr_ack_context_lemma_is_correct(analyzer):
    # "filing" lemmatizes to "file" - same class of bug, found in the same
    # audit. Context list must contain "file".
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="ITR e-filing acknowledgement number 123456789012345",
        language="en",
        score_threshold=SCORE_THRESHOLD,
    )
    assert any(r.entity_type == "ITR_ACK_NUMBER" for r in results)


# --- Real AIS bug report: label and value on separate lines/blocks ---
# (see pipeline.py's _context_window and detect_in_block's context_text
# param, added specifically because a real user's AIS PDF has "Date of
# Birth" as one line and the actual date as the next line - neither could
# see the other's context in isolation.)


def test_dob_value_alone_has_no_context_and_is_not_detected(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="15/08/1990", language="en", score_threshold=SCORE_THRESHOLD
    )
    assert not any(r.entity_type == "IN_DATE_OF_BIRTH" for r in results)


def test_dob_value_detected_via_detect_in_block_context_window(analyzer):
    from pii_redact.detect.analyzer import detect_in_block
    from pii_redact.types import Location, TextBlock

    label = TextBlock(text="Date of Birth", location=Location(page=0))
    value = TextBlock(text="15/08/1990", location=Location(page=0))
    window_text = f"{label.text} | {value.text}"
    offset = len(label.text) + len(" | ")

    detections = detect_in_block(
        value, 1, ["IN_DATE_OF_BIRTH"], context_text=window_text, context_offset=offset
    )
    assert len(detections) == 1
    d = detections[0]
    assert d.entity_type == "IN_DATE_OF_BIRTH"
    # Offsets must be relative to value.text, not the window.
    assert value.text[d.start : d.end] == "15/08/1990"


def test_detection_spilling_into_neighbor_text_is_clipped_not_dropped(analyzer):
    # Regression guard for the PERSON-span-bleeds-across-lines finding: a
    # NER span that overruns into neighboring context must be clipped to
    # the target block's own range, not rejected outright.
    from pii_redact.detect.analyzer import detect_in_block
    from pii_redact.types import Location, TextBlock

    name_block = TextBlock(text="RAHUL KUMAR SHARMA", location=Location(page=0))
    label_block = TextBlock(text="Name of Assessee", location=Location(page=0))
    window_text = f"{name_block.text} | {label_block.text}"

    detections = detect_in_block(
        name_block, 0, ["PERSON"], context_text=window_text, context_offset=0
    )
    assert any(
        d.entity_type == "PERSON" and name_block.text[d.start : d.end] == "RAHUL KUMAR SHARMA"
        for d in detections
    )
    # No detection should ever reference an offset beyond the block's own text.
    assert all(d.end <= len(name_block.text) for d in detections)


# --- Real AIS bug report: quarter labels and the Download ID field ---


def test_quarter_label_is_not_flagged_as_date_of_birth_even_with_context(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    # Deliberately hostile: DOB context words present nearby, and the
    # quarter still must not be flagged as a date of birth.
    results = analyzer.analyze(
        text="Date of Birth field | Q4(Jan-Mar) TDS Summary",
        language="en",
        score_threshold=SCORE_THRESHOLD,
    )
    assert not any(r.entity_type == "IN_DATE_OF_BIRTH" for r in results)


def test_ais_download_id_detected_end_to_end(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="Download ID: ABCDE1234F202501151030",
        language="en",
        score_threshold=SCORE_THRESHOLD,
    )
    matches = [r for r in results if r.entity_type == "AIS_DOWNLOAD_ID"]
    assert len(matches) == 1
    assert matches[0].score == 1.0  # validate_result forces MAX on a plausible date/time


def test_quarter_label_is_not_misdetected_as_person(analyzer):
    # Real user report: spaCy's NER tags "Q4(Jan-Mar)" as PERSON at 0.85
    # confidence, both with and without surrounding context - a
    # decontextualized-short-string NER quirk, not a context-window
    # side effect. detect_in_block's digit-plausibility filter on PERSON
    # must reject it.
    from pii_redact.detect.analyzer import detect_in_block
    from pii_redact.types import Location, TextBlock

    block = TextBlock(text="Q4(Jan-Mar)", location=Location(page=0))
    detections = detect_in_block(block, 0, ["PERSON"])
    assert not any(d.entity_type == "PERSON" for d in detections)


def test_full_name_is_still_detected_after_person_plausibility_filter(analyzer):
    from pii_redact.detect.analyzer import detect_in_block
    from pii_redact.types import Location, TextBlock

    block = TextBlock(text="RAHUL KUMAR SHARMA", location=Location(page=0))
    detections = detect_in_block(block, 0, ["PERSON"])
    assert any(
        d.entity_type == "PERSON" and block.text[d.start : d.end] == "RAHUL KUMAR SHARMA"
        for d in detections
    )


def test_ais_download_id_does_not_also_fire_as_in_pan(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    results = analyzer.analyze(
        text="Download ID: ABCDE1234F202501151030",
        language="en",
        score_threshold=SCORE_THRESHOLD,
    )
    assert not any(r.entity_type == "IN_PAN" for r in results)


# --- Real AIS bug report: the free-text Address field wasn't redacted at
# all - neither Presidio's built-ins nor any of this project's other
# recognizers target unstructured postal addresses.


def test_bare_address_has_no_context_and_is_not_detected(analyzer):
    from pii_redact.detect.analyzer import SCORE_THRESHOLD

    address = "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH"
    results = analyzer.analyze(text=address, language="en", score_threshold=SCORE_THRESHOLD)
    assert not any(r.entity_type == "IN_ADDRESS" for r in results)


def test_address_detected_via_context_window(analyzer):
    from pii_redact.detect.analyzer import detect_in_block
    from pii_redact.types import Location, TextBlock

    address_text = (
        "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR H.O,"
        "RAMPUR,BHOPAL,462001,MADHYA PRADESH"
    )
    label = TextBlock(text="Address", location=Location(page=0))
    value = TextBlock(text=address_text, location=Location(page=0))
    window_text = f"{label.text} | {value.text}"
    offset = len(label.text) + len(" | ")

    detections = detect_in_block(
        value, 1, ["IN_ADDRESS"], context_text=window_text, context_offset=offset
    )
    assert len(detections) == 1
    d = detections[0]
    assert d.entity_type == "IN_ADDRESS"
    assert value.text[d.start : d.end] == address_text


def test_address_recognizer_has_a_known_false_positive_risk_on_long_prose(analyzer):
    # Documents, not hides, a real accepted tradeoff (same class as
    # MutualFundFolioRecognizer/RationCardNumberRecognizer's own "HIGH FP
    # risk, intentionally broad" notes): AddressRecognizer's pattern is
    # any 20+ character run of typical address punctuation, so ordinary
    # long prose sitting near an incidental "address" mention CAN be
    # swept up too - confirmed directly, not a hypothetical. This is the
    # accepted cost of catching free-text addresses at all, since no
    # fixed format exists to pattern-match more precisely.
    text = "Address | Part B1 - Information relating to tax deducted or collected at source"
    results = analyzer.analyze(text=text, language="en", score_threshold=0.5)
    assert any(
        r.entity_type == "IN_ADDRESS" and "tax deducted" in text[r.start : r.end]
        for r in results
    )

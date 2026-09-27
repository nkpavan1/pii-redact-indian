"""PanRecognizer (detect/recognizers/pan.py): Presidio's PAN recognizer
with its quadratic "PAN (Low)" pattern bounded to the token. Same
detections, linear time. Synthetic values only."""

import time

import pytest
import regex
from presidio_analyzer.predefined_recognizers import InPanRecognizer

from pii_redact.detect.analyzer import SCORE_THRESHOLD, get_analyzer
from pii_redact.detect.recognizers.pan import PanRecognizer

PRESIDIO_FLAGS = regex.DOTALL | regex.MULTILINE | regex.IGNORECASE


def _pattern(recognizer_cls, name):
    return next(p for p in recognizer_cls.PATTERNS if p.name == name)


def test_only_the_low_pattern_changes():
    ours = {p.name: (p.regex, p.score) for p in PanRecognizer.PATTERNS}
    theirs = {p.name: (p.regex, p.score) for p in InPanRecognizer.PATTERNS}
    assert ours.keys() == theirs.keys()
    for name in ("PAN (High)", "PAN (Medium)"):
        assert ours[name] == theirs[name]
    assert ours["PAN (Low)"][1] == theirs["PAN (Low)"][1]
    assert ".*" not in ours["PAN (Low)"][0]
    assert PanRecognizer().context == InPanRecognizer().context


@pytest.mark.parametrize(
    "token",
    ["ABCPE1234F", "AB1234CDEF", "A1234BCDEF", "ABCDEF1234", "1234ABCDEF", "X-12345678", "ABCDEFGHIJ",
     "1234567890", "AB12CD34EF", "abcpe1234f"],
)
def test_the_bounded_low_pattern_matches_what_presidio_matches_within_a_token(token):
    theirs = regex.compile(_pattern(InPanRecognizer, "PAN (Low)").regex, flags=PRESIDIO_FLAGS)
    ours = regex.compile(_pattern(PanRecognizer, "PAN (Low)").regex, flags=PRESIDIO_FLAGS)
    assert bool(ours.fullmatch(token)) == bool(theirs.fullmatch(token))


def test_the_low_pattern_is_linear():
    text = " ".join(f"Line {i}: the shipment of widgets number {i} left the warehouse on time." for i in range(700))
    ours = regex.compile(_pattern(PanRecognizer, "PAN (Low)").regex, flags=PRESIDIO_FLAGS)
    started = time.perf_counter()
    list(ours.finditer(text))
    # Presidio's took about 1.3 s on this text (287 ms per 11K characters).
    assert time.perf_counter() - started < 0.1


@pytest.mark.parametrize(
    "text, found",
    [
        ("PAN: ABCPE1234F", True),
        ("my pan is ABCPE1234F.", True),
        ("ABCPE1234F", True),
        ("ABCDE1234F", False),  # 'D' is not a PAN holder type
        ("PAN: AB12CD34EF", False),  # the low pattern alone can't pass the threshold
    ],
)
def test_detection_is_unchanged(text, found):
    results = get_analyzer().analyze(text=text, language="en", entities=["IN_PAN"], score_threshold=SCORE_THRESHOLD)
    assert any(r.entity_type == "IN_PAN" for r in results) is found

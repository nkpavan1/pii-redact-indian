"""PAN numbers: Presidio's InPanRecognizer without its quadratic pattern.

MEASURED, NOT ASSUMED: Presidio's "PAN (Low)" pattern,

    \\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\\w@#$%^?~-]{10})\\b

checks its two lookaheads with `.*?`, and Presidio compiles patterns with
DOTALL, so from every word boundary they may scan to the end of the text:
quadratic in text length. On an 11K-character window of ordinary numbered
text it took 287 ms, and every analyzed window pays it. It can never
produce a result either: its score is 0.01, and a context word lifts it to
at most 0.4, below SCORE_THRESHOLD (0.5). (So can't "PAN (Medium)", 0.1 ->
0.45, but that one costs nothing and is kept as it is.)

PanRecognizer keeps Presidio's patterns, scores and context words, with the
Low pattern's lookaheads bounded to the 10-character token itself - which
is what they were meant to check: 0.8 ms on the same window. Presidio's
version also matched a token that merely had four digits somewhere later
in the text; that difference only ever affected a score-0.01 result.

Named PanRecognizer, not InPanRecognizer: Presidio resolves recognizer
classes by global class name (see recognizers/__init__.py).
"""

from __future__ import annotations

from presidio_analyzer import Pattern
from presidio_analyzer.predefined_recognizers import InPanRecognizer

_TOKEN_CHAR = r"[\w@#$%^?~-]"
_LOW = rf"\b((?={_TOKEN_CHAR}{{0,9}}[a-zA-Z])(?={_TOKEN_CHAR}{{0,6}}[0-9]{{4}}){_TOKEN_CHAR}{{10}})\b"
_LOW_NAME = "PAN (Low)"


class PanRecognizer(InPanRecognizer):
    PATTERNS = [
        *(p for p in InPanRecognizer.PATTERNS if p.name != _LOW_NAME),
        Pattern(_LOW_NAME, _LOW, next(p.score for p in InPanRecognizer.PATTERNS if p.name == _LOW_NAME)),
    ]

    def __init__(self):
        super().__init__(patterns=self.PATTERNS, name="PanRecognizer")

"""Postal address - free-text with no fixed structure, unlike every other
recognizer in this project. Presidio has no built-in for this (checked
`presidio_analyzer.predefined_recognizers` directly - only
`MacAddressRecognizer` exists, an unrelated network identifier). spaCy's
own NER only catches fragments of a real address (confirmed directly: on
a real AIS document's address line, it tagged just the trailing state
name "PRADESH" as LOCATION at 0.85 - and LOCATION is deliberately excluded
from every allow-list in this project anyway, since a city/place name can
be computation-relevant elsewhere). Neither covers the address as a whole,
which is what actually needs to disappear.

Found via a real user report on an AIS document: the "Address" field's
value (house number, street, locality, city, state, PIN code all run
together, e.g. "B-204, SUNRISE APARTMENTS,MAIN ROAD,RAMPUR
H.O,RAMPUR,BHOPAL,462001,MADHYA PRADESH") was not being redacted at
all, because nothing in Presidio's built-ins or this project's other
recognizers targets free-text address blocks.

Two recognizers:
- AddressRecognizer: a value after an address *label* ("Address:",
  "my address is", "Address of the assessee:", a label block next to the
  value in a PDF). Below.
- PinCodeAddressRecognizer: anything ending in a PIN code, no label needed.
"""

from __future__ import annotations

import regex
from presidio_analyzer import LocalRecognizer, Pattern, PatternRecognizer, RecognizerResult

# --- labeled addresses
#
# Until 0.4.0 this was a context-scoped pattern: any run of 20+ address-ish
# characters, masked when any form of "address" was nearby. On instruction
# text that garbled whole sentences - found in a real system prompt by the
# stack session: "Please address this issue today." became "IN_ADDRESS_E.",
# and the heading "## Addressing the user" took the phrase after it along.
# Presidio's context words match any form of a word (and as substrings), so
# the verb counted as much as the noun; and the old pattern ran through
# sentences, since "." and newlines were address characters.
#
# Now the value must follow the noun used as a label, and look like an
# address:
# - A label is "address" or "addresses" as a word, not in "e-mail address",
#   "IP address", "web address" and the like, followed by a separator:
#   ":" or a dash, "is"/"was" ("my address is"), "of ...:" ("Address of the
#   assessee:"), the " | " between a PDF label block and its value
#   (pipeline._context_window), or the end of a line the label has to
#   itself ("Address" as a heading or table label).
# - The value runs to the end of the line (on to the next line after a
#   trailing comma), or, after a label on its own line, over the next few
#   short lines. It stops at a sentence end ("... Indiranagar. Call me").
# - It must be at least 10 characters and contain a digit or a comma - real
#   addresses have a house number or a comma, "the same as before" has
#   neither.
_NOT_POSTAL = (
    r"(?i:e-?mail|mail|ip|mac|web|website|url|wallet|memory|server|ethernet|network|bitcoin|crypto|contract|"
    r"hardware|broadcast|gateway|host|return)"
)
_LABEL = rf"(?<![\w@.\-])(?<!{_NOT_POSTAL}[ \t_\-]?)(?i:address(?:es)?)(?![\w@\-])"
_INLINE_SEPARATOR = (
    r"(?:"
    r"[ \t]*[:–—][ \t]*"                     # "Address: ...", "Address – ..."
    r"|[ \t]+-[ \t]*|[ \t]*-[ \t]+"          # "Address - ...", but not "address-book"
    r"|[ \t]*\|[ \t]*"                        # a PDF label block next to its value ("Address | ...")
    r"|[ \t]+(?i:is|was)[ \t]+(?:(?i:at)[ \t]+)?"                                     # "my address is ..."
    r"|[ \t]+(?i:of)[ \t]+[^\n:|]{1,40}?(?:[ \t]*[:–—|][ \t]*|[ \t]+(?i:is|was)[ \t]+)"  # "Address of X: ..."
    r")"
)
_INLINE_LABEL = regex.compile(_LABEL + _INLINE_SEPARATOR)
# A label with its line to itself: "Address", "Address:", "## Address",
# "Permanent Address", then the value on the following lines.
_LINE_LABEL = regex.compile(
    rf"(?m)^[ \t#*>\-]*(?:[A-Za-z]+[ \t]+){{0,2}}{_LABEL}[ \t]*:?[ \t]*\r?\n"
)
_VALUE_CHAR = r"[\w \t,./\-#()'&]"
_INLINE_VALUE = regex.compile(rf"[\w#]{_VALUE_CHAR}*(?:(?<=,[ \t]*)\r?\n[ \t]*[\w#]{_VALUE_CHAR}*)*")
_VALUE_LINE = regex.compile(rf"[ \t>*\-]*([\w#]{_VALUE_CHAR}{{0,79}})[ \t]*(?:\r?\n|$)")
# A period ends the value when a sentence starts after it ("... near the
# lake. Call me") - unless it ends an abbreviation: a word of up to three
# letters ("No. 12", "St. Mary's Road", "Opp. Bus Stand") or a longer one
# from the list ("Dist. Bhopal").
_ABBREVIATIONS = r"(?i:dist|bldg|blvd|sect|apts|extn|taluk|tehsil)"
_SENTENCE_END = regex.compile(rf"(?<=\b[A-Za-z]{{4,}})(?<!\b{_ABBREVIATIONS})\.(?=[ \t]+[A-Z][a-z])")
_MAX_VALUE_LINES = 5
_MIN_VALUE_CHARS = 10
_TRAILING = " \t,./-(&'"


def _looks_like_an_address(value: str) -> bool:
    return len(value) >= _MIN_VALUE_CHARS and any(c.isdigit() or c == "," for c in value)


def _trimmed(text: str, start: int, end: int) -> tuple[int, int] | None:
    stop = _SENTENCE_END.search(text, start, end)
    if stop:
        end = stop.start()
    while end > start and text[end - 1] in _TRAILING:
        end -= 1
    return (start, end) if _looks_like_an_address(text[start:end]) else None


def _inline_value(text: str, pos: int) -> tuple[int, int] | None:
    match = _INLINE_VALUE.match(text, pos)
    return _trimmed(text, pos, match.end()) if match else None


def _value_lines(text: str, pos: int) -> tuple[int, int] | None:
    start = end = None
    for _ in range(_MAX_VALUE_LINES):
        match = _VALUE_LINE.match(text, pos)
        if not match:
            break
        if start is None:
            start = match.start(1)
        end = match.end(1)
        pos = match.end()
    return _trimmed(text, start, end) if start is not None else None


class AddressRecognizer(LocalRecognizer):
    """IN_ADDRESS: the value after an address label (see above). Score 0.6,
    no context step - the label is the context."""

    SCORE = 0.6

    def __init__(self):
        super().__init__(supported_entities=["IN_ADDRESS"], name="AddressRecognizer", supported_language="en")

    def load(self) -> None:
        pass

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None) -> list[RecognizerResult]:
        spans = set()
        for label in _INLINE_LABEL.finditer(text):
            starts = [label.end()]
            if "|" in label.group():
                # A PDF label can sit two blocks before its value, with an
                # unrelated neighbor block in between.
                next_pipe = text.find("|", label.end(), label.end() + 80)
                if next_pipe != -1:
                    after = next_pipe + 1
                    while after < len(text) and text[after] in " \t":
                        after += 1
                    starts.append(after)
            for start in starts:
                span = _inline_value(text, start)
                if span:
                    spans.add(span)
        for label in _LINE_LABEL.finditer(text):
            span = _value_lines(text, label.end())
            if span:
                spans.add(span)
        return [RecognizerResult("IN_ADDRESS", start, end, self.SCORE) for start, end in sorted(spans)]


# --- PIN-code-anchored addresses (no "address" label needed)
#
# An Indian address almost always ends in a 6-digit PIN code (first digit
# 1-9, sometimes written "560 038"). Anchoring on it finds addresses that
# have no "address" label nearby - the common case in chat ("send it to 12
# MG Road, Indiranagar, Bengaluru 560038") and in letterheads.
#
# Pieces:
# - a word is an address token: "B-204", "No.12", "#12", "H.O", "3rd".
# - a segment is 1-6 such words ending in a comma: "12 MG Road,".
# - the place is 1-4 words right before the PIN (city/state).
# - an optional trailing state or country in capitals after the PIN.
# Case matters for that last part, so these patterns are compiled without
# Presidio's default IGNORECASE.
#
# The place right before the PIN must start with a capital letter (a city
# or state), which keeps ordinary sentences ending in a 6-digit number
# ("..., and the fee is 450000") out.
#
# Known behavior, accepted (the safe direction): a leading phrase can be
# swept into the first segment ("Send it to 12 MG Road, ..." takes "Send it
# to" too - up to six words), and "Word - 123456" matches for capitalized
# words not on the banking list below.
_PIN = r"(?<!\d)(?<!\d[.,])[1-9]\d{2}[ \t]?\d{3}(?![\d,]?\d)"
_ADDRESS_WORD = r"[\w#/.'&()\-]+"
_SEGMENT = rf"{_ADDRESS_WORD}(?:[ \t]+{_ADDRESS_WORD}){{0,5}}[ \t]*,[ \t]*"
_PLACE = rf"[A-Z][\w.'\-]*(?:[ \t]+{_ADDRESS_WORD}){{0,3}}"
_TRAILING_REGION = r"(?:[ \t]*,[ \t]*[A-Z][A-Za-z]+(?:[ \t]+[A-Z][A-Za-z]+){0,2}(?![A-Za-z]))?"
# Transaction prefixes that are followed by a dash and 6 digits on bank
# statements, and must not be read as "City - PIN".
_NOT_PLACES = r"(?i:neft|imps|rtgs|upi|atm|pos|chq|cheque|ref|txn|inv|invoice|order|id|no|emi|otp)"


class PinCodeAddressRecognizer(PatternRecognizer):
    """IN_ADDRESS anchored on a PIN code.

    - "12 MG Road, Indiranagar, Bengaluru 560038" (segments + place + PIN):
      0.6, masked with no context word.
    - "BHOPAL - 462001" (a place, a dash, a PIN - one line of a letterhead):
      0.5, masked; banking prefixes (NEFT-..., IMPS-...) excluded.
    - "PIN 560038" / "pincode is 560038": 0.5, the number only.
    The existing AddressRecognizer still handles labeled addresses."""

    PATTERNS = [
        Pattern(
            "Address ending in a PIN code",
            rf"(?<![\w#/.'&()\-])(?:{_SEGMENT}){{1,6}}{_PLACE}[ \t]*[-,]?[ \t]*{_PIN}{_TRAILING_REGION}",
            0.6,
        ),
        Pattern(
            "Place - PIN code",
            rf"(?<![\w#/.'&()\-])(?!{_NOT_PLACES}\b)[A-Za-z]{{3,}}(?:[ \t]+[A-Za-z]{{3,}}){{0,2}}[ \t]*-[ \t]*{_PIN}",
            0.5,
        ),
        Pattern(
            "PIN code",
            # The keyword stays in the text ("pincode is IN_ADDRESS_A");
            # only the number is matched.
            rf"(?<=(?i:\bpin[ \t]*(?:code)?(?:[ \t]+(?:is|no\.?|number))?)[ \t]*[:.\-]?[ \t]*){_PIN}",
            0.5,
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IN_ADDRESS",
            patterns=self.PATTERNS,
            name="PinCodeAddressRecognizer",
            global_regex_flags=regex.MULTILINE,
        )

"""Markdown emphasis marks, blanked for the NER pass (0.4.3).

spaCy misses a single name in emphasis: "**Ravi** called me yesterday.",
"Thanks, **Meera**!" and "*Suresh* will send the documents." get no
PERSON at all, though the same sentences without the marks do. Models bold
names often, so a reply's "**PERSON_A**" came back reversed as "**Ravi**"
in the next turn's history, and went out in the clear. A single-word name
isn't swept either (known_values.py), so nothing else caught it.

So spaCy reads a copy of the text with the emphasis marks replaced by
spaces. The copy has the same length, so every offset spaCy reports holds
for the original, and everything else - the pattern recognizers, the
output - works on the original text.

A run of marks counts when it opens emphasis (after the start, a space or
punctuation, before a non-space) or closes it (after a non-space, before
the end, a space or punctuation) - roughly CommonMark's flanking rules.
Marks inside a word (snake_case, 2*3*4), list bullets ("* item") and
escaped marks (\\*) are left alone, and so are code spans: a backtick
usually quotes code, not a name.
"""

from __future__ import annotations

import re

_MARKS = "*_~"
_EMPHASIS = re.compile(
    r"(?<![\w*_~\\])[*_~]+(?=[^\s*_~])"  # opening
    r"|(?<=[^\s*_~\\])[*_~]+(?![\w*_~])"  # closing
)


def blank_emphasis(text: str) -> str:
    """`text` with markdown emphasis marks replaced by spaces (same length)."""
    if not any(mark in text for mark in _MARKS):
        return text
    return _EMPHASIS.sub(lambda m: " " * len(m.group()), text)

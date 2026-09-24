"""Reverses coded identifiers in LLM/agent output back to real values.

Per the project instructions' explicit design decision: exact-match only for
v1, not fuzzy matching. If the LLM paraphrases or mangles a code (e.g.
`Person A` instead of `PERSON_A`), it will NOT be reversed - that's a
deliberate safety tradeoff (a missed reversal is an inconvenience the human
can fix by hand; an incorrect fuzzy-matched reversal silently substitutes
the wrong real value into the wrong place). Revisit only with a specific,
tested fuzzy-matching design, not as a quick enhancement.

Only codes that exist in the mapping store are ever substituted. A
code-shaped token the store doesn't know (an LLM inventing `PERSON_Z`) is
left exactly as written. A code only matches as a whole token: it must not
be preceded or followed by a letter, digit, or underscore, so `PERSON_A`
never matches inside `PERSON_AB` or `XPERSON_A`, while `PERSON_A's` and
`(PERSON_A)` still reverse.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Mapping, Sequence

from pii_redact.anonymize.mapping_store import MappingStore

# A whole run of ASCII word characters that contains an underscore - the
# shape of every issued code (ENTITY_TYPE + "_" + letters, see
# mapping_store._make_code). The lookarounds pin a match to the entire run,
# which is then looked up exactly: that is what makes codes match only as
# whole tokens, and it keeps the cost linear in the text however many codes
# the store holds (an alternation of every code would not be).
_CODE_SHAPED_TOKEN = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_]*_[A-Za-z0-9_]*(?![A-Za-z0-9_])")


def find_codes(text: str, known_codes: Collection[str]) -> list[tuple[int, int]]:
    """(start, end) of every whole-token occurrence of a known code in
    `text`, in order. Used on the redact side to leave codes that are
    already in a text alone."""
    if not known_codes:
        return []
    return [m.span() for m in _CODE_SHAPED_TOKEN.finditer(text) if m.group(0) in known_codes]


def reverser_for(codes_to_values: Mapping[str, str]) -> Callable[[str], str]:
    """A function that reverses every known code in a text - built once so
    reversing many texts reads the mapping store only once."""
    if not codes_to_values:
        return lambda text: text

    def _reverse(text: str) -> str:
        return _CODE_SHAPED_TOKEN.sub(
            lambda m: codes_to_values.get(m.group(0), m.group(0)), text
        )

    return _reverse


def reverse(text: str, mapping_store: MappingStore) -> str:
    return reverser_for(mapping_store.all_codes())(text)


def reverse_many(texts: Sequence[str], mapping_store: MappingStore) -> list[str]:
    reverse_one = reverser_for(mapping_store.all_codes())
    return [reverse_one(text) for text in texts]

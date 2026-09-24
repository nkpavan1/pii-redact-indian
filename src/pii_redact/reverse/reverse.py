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

from pii_redact.anonymize.mapping_store import MappingStore


def reverse(text: str, mapping_store: MappingStore) -> str:
    codes_to_values = mapping_store.all_codes()
    if not codes_to_values:
        return text

    # The token-boundary lookarounds are what stop partial matches; sorting
    # longest-first additionally keeps alternation order deterministic.
    codes_by_length_desc = sorted(codes_to_values, key=len, reverse=True)
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        + "|".join(re.escape(code) for code in codes_by_length_desc)
        + r")(?![A-Za-z0-9_])"
    )
    return pattern.sub(lambda m: codes_to_values[m.group(0)], text)

"""Reverses coded identifiers in LLM/agent output back to real values.

Per the project instructions' explicit design decision: exact-match only for
v1, not fuzzy matching. If the LLM paraphrases or mangles a code (e.g.
`Person A` instead of `PERSON_A`), it will NOT be reversed - that's a
deliberate safety tradeoff (a missed reversal is an inconvenience the human
can fix by hand; an incorrect fuzzy-matched reversal silently substitutes
the wrong real value into the wrong place). Revisit only with a specific,
tested fuzzy-matching design, not as a quick enhancement.
"""

from __future__ import annotations

import re

from pii_redact.anonymize.mapping_store import MappingStore


def reverse(text: str, mapping_store: MappingStore) -> str:
    codes_to_values = mapping_store.all_codes()
    if not codes_to_values:
        return text

    # Longest-code-first avoids a shorter code (e.g. PAN_A) partially
    # matching inside a longer one (e.g. PAN_A1) if codes ever share a
    # prefix.
    codes_by_length_desc = sorted(codes_to_values, key=len, reverse=True)
    pattern = re.compile(
        "|".join(re.escape(code) for code in codes_by_length_desc)
    )
    return pattern.sub(lambda m: codes_to_values[m.group(0)], text)

"""Long texts are analyzed in overlapping chunks (see detect/analyzer.py:
one analyze() call is quadratic in text length). Chunking must not change
what is found."""

import random

from pii_redact.config.allowlists import allowlist_for
from pii_redact.detect import analyzer as analyzer_module
from pii_redact.detect.analyzer import SCORE_THRESHOLD, get_analyzer

NAMES = ["Ravi Kumar", "Asha Rao", "Vikram Singh", "Meera Nair"]
WORDS = "the loan account statement interest payment quarter branch request review summary balance".split()


def _synthetic(chars: int, seed: int) -> str:
    rng = random.Random(seed)
    parts, size = [], 0
    while size < chars:
        filler = " ".join(rng.choice(WORDS) for _ in range(rng.randint(6, 14)))
        roll = rng.randrange(6)
        if roll == 0:
            sentence = f"{rng.choice(NAMES)} asked about the {filler}."
        elif roll == 1:
            sentence = f"The PAN ABCP{rng.choice('ABCDE')}{rng.randrange(10000):04d}F was quoted for the {filler}."
        elif roll == 2:
            sentence = f"Write to someone{rng.randrange(99)}@example.com about the {filler}."
        else:
            sentence = filler.capitalize() + "."
        parts.append(sentence + ("\n\n" if rng.randrange(8) == 0 else " "))
        size += len(parts[-1])
    return "".join(parts)


def _found(results):
    return {(r.entity_type, r.start, r.end) for r in results}


def test_chunk_bounds_cover_the_text_and_cut_at_boundaries(monkeypatch):
    monkeypatch.setattr(analyzer_module, "_CHUNK_CHARS", 1000)
    text = _synthetic(8000, seed=3)
    bounds = analyzer_module._chunk_bounds(text)
    assert bounds[0][0] == 0 and bounds[-1][1] == len(text)
    for (_, end), (next_start, _) in zip(bounds, bounds[1:]):
        assert end == next_start
        assert text[end - 1] in " \n"  # never inside a word
    assert all(end - start <= 1000 for start, end in bounds)


def test_chunked_analysis_finds_exactly_what_one_pass_finds(monkeypatch):
    text = _synthetic(12_000, seed=1)
    entities = allowlist_for("chat")
    whole = get_analyzer().analyze(text=text, entities=entities, language="en", score_threshold=SCORE_THRESHOLD)
    assert len(whole) > 20  # the text really does carry PII

    monkeypatch.setattr(analyzer_module, "_CHUNK_CHARS", 1500)
    monkeypatch.setattr(analyzer_module, "_CHUNK_OVERLAP_CHARS", 300)
    chunked = analyzer_module._analyze(text, entities, "en", SCORE_THRESHOLD)

    assert _found(chunked) == _found(whole)
    assert len(chunked) == len(_found(chunked))  # nothing counted twice


def test_short_texts_are_not_chunked(monkeypatch):
    calls = []
    real = get_analyzer().analyze

    def counting(**kwargs):
        calls.append(len(kwargs["text"]))
        return real(**kwargs)

    monkeypatch.setattr(get_analyzer(), "analyze", counting)
    analyzer_module._analyze("Ravi Kumar called.", allowlist_for("chat"), "en", SCORE_THRESHOLD)
    assert calls == [len("Ravi Kumar called.")]

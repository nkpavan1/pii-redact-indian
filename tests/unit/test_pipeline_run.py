"""End-to-end pipeline tests: real detection (spaCy + Presidio), real
extract/render, a real encrypted MappingStore with an explicit key. All
data is synthetic.

Note on the synthetic PAN: ABCPE1234F, not ABCDE1234F. A PAN's 4th
character is the holder type (P = person, C = company, ...), and Presidio's
IN_PAN recognizer only scores a PAN with a valid holder-type character high
enough to pass SCORE_THRESHOLD. ABCDE1234F ('D') is not a valid PAN and is
not detected at all.
"""

import json
import zipfile

import pytest
from cryptography.fernet import Fernet

from pii_redact import pipeline
from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.audit.logger import AuditLogger
from pii_redact.pipeline import run_batch, run_pipeline
from pii_redact.reverse.reverse import reverse
from pii_redact.types import DocFormat, Mode

NOTE = "Ravi Kumar, PAN ABCPE1234F\n\nMeeting notes: nothing else sensitive here.\n"


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "store" / "mapping.enc", key=Fernet.generate_key())


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit" / "audit.log.jsonl")


def _audit_entries(audit):
    return [json.loads(line) for line in audit.log_path.read_text(encoding="utf-8").splitlines()]


def _run(path, out_dir, store, audit, mode=Mode.REDACT):
    return run_pipeline(path, out_dir, mode, None, store, audit, non_interactive=True)


@pytest.mark.parametrize("name", ["note.md", "note.txt"])
def test_text_note_with_pii_on_first_line_is_redacted(tmp_path, store, audit, name):
    # B1: this file used to go down the CSV path, which treated line 1 as
    # a header and never scanned it.
    src = tmp_path / name
    src.write_text(NOTE, encoding="utf-8")

    result = _run(src, tmp_path / "out", store, audit)

    assert result.written, result.failure_reason
    out = result.output_path.read_text(encoding="utf-8")
    assert "Ravi Kumar" not in out
    assert "ABCPE1234F" not in out
    assert out.startswith("<PERSON>, PAN <IN_PAN>\n\n")
    assert out.endswith("Meeting notes: nothing else sensitive here.\n")


def test_pseudonymize_then_reverse_round_trip_restores_display_form(tmp_path, store, audit):
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")

    result = _run(src, tmp_path / "out", store, audit, mode=Mode.PSEUDONYMIZE)

    out = result.output_path.read_text(encoding="utf-8")
    assert out.startswith("PERSON_A, PAN IN_PAN_A\n\n")
    # Casing survives the round trip (B3): not "RAVI KUMAR".
    assert reverse(out, store) == NOTE


def test_same_person_gets_same_code_across_documents(tmp_path, store, audit):
    a = tmp_path / "a.md"
    b = tmp_path / "b.txt"
    a.write_text("Ravi Kumar approved the transfer.\n", encoding="utf-8")
    b.write_text("Letter from Ravi Kumar's bank.\n", encoding="utf-8")

    out_a = _run(a, tmp_path / "out", store, audit, Mode.PSEUDONYMIZE).output_path.read_text()
    out_b = _run(b, tmp_path / "out", store, audit, Mode.PSEUDONYMIZE).output_path.read_text()

    # The possessive is trimmed from the PERSON span, so both sightings key
    # to the same person.
    assert out_a == "PERSON_A approved the transfer.\n"
    assert out_b == "Letter from PERSON_A's bank.\n"


def test_unsupported_file_is_skipped_not_fatal(tmp_path, store, audit):
    src = tmp_path / "resume.docx"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("word/document.xml", "<document/>")

    result = _run(src, tmp_path / "out", store, audit)

    assert not result.written
    assert not result.failed
    assert result.failure_reason.startswith("unsupported format:")
    assert _audit_entries(audit)[0]["written"] is False


def test_render_failure_leaves_no_output_and_no_partial_file(tmp_path, store, audit, monkeypatch):
    class ExplodingRenderer:
        def render(self, source_path, extracted, replacements, output_path):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("half-written")
            raise RuntimeError("disk full")

    monkeypatch.setitem(pipeline._RENDERERS, DocFormat.TEXT, ExplodingRenderer)
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")
    out_dir = tmp_path / "out"

    result = _run(src, out_dir, store, audit)

    assert not result.written
    assert result.failed
    assert result.failure_reason == "RuntimeError: disk full"
    assert list(out_dir.iterdir()) == []


def test_render_failure_does_not_clobber_a_previous_good_output(tmp_path, store, audit, monkeypatch):
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")
    out_dir = tmp_path / "out"
    first = _run(src, out_dir, store, audit)
    good = first.output_path.read_bytes()

    class ExplodingRenderer:
        def render(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setitem(pipeline._RENDERERS, DocFormat.TEXT, ExplodingRenderer)
    assert _run(src, out_dir, store, audit).failed
    assert first.output_path.read_bytes() == good


def test_rejected_at_review_gate_is_not_a_failure(tmp_path, store, audit, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")

    result = run_pipeline(src, tmp_path / "out", Mode.REDACT, None, store, audit)

    assert not result.written
    assert not result.failed
    assert result.failure_reason == "rejected at review gate"


def test_batch_continues_past_unsupported_and_failing_files(tmp_path, store, audit, monkeypatch):
    # B2: an unsupported file used to abort the whole batch, because
    # detect_format ran outside any error handling.
    class ExplodingExtractor:
        def extract(self, path):
            raise RuntimeError("cannot parse")

    monkeypatch.setitem(pipeline._EXTRACTORS, DocFormat.JSON, ExplodingExtractor)

    in_dir = tmp_path / "in"
    in_dir.mkdir()
    with zipfile.ZipFile(in_dir / "a_resume.docx", "w") as zf:
        zf.writestr("word/document.xml", "<document/>")
    (in_dir / "b_data.json").write_text('{"k": "v"}', encoding="utf-8")
    (in_dir / "c_note.md").write_text(NOTE, encoding="utf-8")
    (in_dir / "d_note.txt").write_text(NOTE, encoding="utf-8")

    results = run_batch(in_dir, tmp_path / "out", Mode.REDACT, None, store, audit, non_interactive=True)

    by_name = {r.source_path.name: r for r in results}
    assert not by_name["a_resume.docx"].written and not by_name["a_resume.docx"].failed
    assert by_name["b_data.json"].failed
    assert by_name["b_data.json"].failure_reason == "RuntimeError: cannot parse"
    assert by_name["c_note.md"].written
    assert by_name["d_note.txt"].written
    assert len(_audit_entries(audit)) == 4


def test_batch_survives_an_exception_escaping_run_pipeline(tmp_path, store, audit, monkeypatch):
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    (in_dir / "a.md").write_text(NOTE, encoding="utf-8")
    (in_dir / "b.md").write_text(NOTE, encoding="utf-8")

    real_run_pipeline = pipeline.run_pipeline

    def flaky(path, *args, **kwargs):
        if path.name == "a.md":
            raise OSError("audit log unwritable")
        return real_run_pipeline(path, *args, **kwargs)

    monkeypatch.setattr(pipeline, "run_pipeline", flaky)
    results = run_batch(in_dir, tmp_path / "out", Mode.REDACT, None, store, audit, non_interactive=True)

    assert [r.failed for r in results] == [True, False]
    assert results[1].written


def test_audit_log_never_contains_detected_values(tmp_path, store, audit):
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")
    _run(src, tmp_path / "out", store, audit, mode=Mode.PSEUDONYMIZE)

    raw = audit.log_path.read_text(encoding="utf-8")
    assert "Ravi" not in raw
    assert "ABCPE1234F" not in raw
    assert _audit_entries(audit)[0]["counts_by_entity"] == {"PERSON": 1, "IN_PAN": 1}

"""Smoke tests for the existing `redact <input> -o <dir>` command, to keep it
backward compatible as new commands are added. The CLI builds its own
MappingStore from --mapping-store, which would go through the OS credential
store; these tests swap in one with an explicit key instead."""

import zipfile

import pytest
from cryptography.fernet import Fernet

from pii_redact import cli
from pii_redact.anonymize.mapping_store import MappingStore

NOTE = "Ravi Kumar, PAN ABCPE1234F\n"


@pytest.fixture(autouse=True)
def _keyed_store(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setattr(cli, "MappingStore", lambda path: MappingStore(path, key=key))


def _args(tmp_path, *extra):
    return [
        "--mapping-store", str(tmp_path / "state" / "mapping.enc"),
        "--audit-log", str(tmp_path / "state" / "audit.log.jsonl"),
        *extra,
    ]


def test_single_file_redact(tmp_path, capsys):
    src = tmp_path / "note.md"
    src.write_text(NOTE, encoding="utf-8")
    out_dir = tmp_path / "out"

    code = cli.main([str(src), "-o", str(out_dir), "--mode", "redact", "--yes", *_args(tmp_path)])

    assert code == 0
    assert (out_dir / "note.md").read_text(encoding="utf-8") == "<PERSON>, PAN <IN_PAN>\n"
    lines = capsys.readouterr().out.splitlines()
    assert lines[-2].startswith("OK   ")
    assert lines[-1] == "1 written, 0 skipped, 0 failed"


def test_default_mode_is_pseudonymize(tmp_path):
    src = tmp_path / "note.txt"
    src.write_text(NOTE, encoding="utf-8")
    out_dir = tmp_path / "out"

    assert cli.main([str(src), "-o", str(out_dir), "--yes", *_args(tmp_path)]) == 0
    assert (out_dir / "note.txt").read_text(encoding="utf-8") == "PERSON_A, PAN IN_PAN_A\n"


def test_directory_batch_reports_summary_and_nonzero_exit(tmp_path, capsys):
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    (in_dir / "note.md").write_text(NOTE, encoding="utf-8")
    with zipfile.ZipFile(in_dir / "resume.docx", "w") as zf:
        zf.writestr("word/document.xml", "<document/>")
    out_dir = tmp_path / "out"

    code = cli.main([str(in_dir), "-o", str(out_dir), "--mode", "redact", "--yes", *_args(tmp_path)])

    assert code == 1  # not everything was written
    assert (out_dir / "note.md").exists()
    out = capsys.readouterr().out
    assert "SKIP " in out and "unsupported format" in out
    assert out.splitlines()[-1] == "1 written, 1 skipped, 0 failed"


def test_missing_input_exits_2(tmp_path, capsys):
    code = cli.main([str(tmp_path / "nope.md"), "-o", str(tmp_path / "out"), "--yes", *_args(tmp_path)])
    assert code == 2
    assert "does not exist" in capsys.readouterr().err

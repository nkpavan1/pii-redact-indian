"""redact-publish (Tool 1), end to end on temporary folders: real detection,
a real encrypted store with an explicit key, synthetic data only. Nothing
here touches the real vaults or H:\\ai\\redaction."""

import hashlib
import json
import zipfile
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace

import pytest
import yaml
from cryptography.fernet import Fernet
from filelock import FileLock

from pii_redact import keytool, publish
from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.api import redact_text
from pii_redact.audit.logger import AuditLogger
from pii_redact.publish import PublishConfig, run_publish

NOTE = "Ravi Kumar, PAN ABCPE1234F, asked about the loan.\n"


@pytest.fixture
def env(tmp_path):
    outbox = tmp_path / "vaults" / "personal" / "outbox"
    outbox.mkdir(parents=True)
    home = tmp_path / "redaction"
    store = MappingStore(home / "mapping_store.enc", key=Fernet.generate_key())
    cfg = PublishConfig(
        outbox=outbox, published=tmp_path / "vaults" / "reference" / "redacted", home=home, assume_yes=True
    )
    return SimpleNamespace(outbox=outbox, cfg=cfg, store=store, audit=AuditLogger(home / "audit.log.jsonl"))


def _run(env, **overrides):
    return run_publish(replace(env.cfg, **overrides), env.store, env.audit)


def _drop(env, name, text):
    path = env.outbox / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


def _published(env, name):
    text = (env.cfg.published / name).read_text(encoding="utf-8")
    _, frontmatter, body = text.split("---\n", 2)
    return yaml.safe_load(frontmatter), body


def _state(env):
    """Everything a run could write, for 'nothing changed' checks."""
    files = sorted(p for p in env.cfg.published.parent.parent.rglob("*") if p.is_file())
    files += sorted(p for p in env.cfg.home.rglob("*") if p.is_file() and not p.name.endswith(".lock"))
    return {str(p): (p.stat().st_mtime_ns, p.read_bytes()) for p in files}


def _drop_detections_of(monkeypatch, entity_type):
    """Simulate the pipeline missing every `entity_type` - the residual gate
    has to catch what the first pass let through."""
    real = publish.analyze_document

    def missing(path, doc_type):
        extracted, detections = real(path, doc_type)
        return extracted, [d for d in detections if d.entity_type != entity_type]

    monkeypatch.setattr(publish, "analyze_document", missing)


# --- publishing


def test_publishes_redacted_markdown_with_frontmatter(env):
    source = _drop(env, "note.md", NOTE)

    summary = _run(env)

    assert len(summary.published) == 1
    name = summary.published[0]
    assert name.startswith("document-") and name.endswith(".md")
    meta, body = _published(env, name)
    assert meta["type"] == "source"
    assert meta["redacted"] is True
    assert meta["doc_type"] == "generic"
    assert meta["source_hash"] == hashlib.sha256(source.read_bytes()).hexdigest()
    datetime.fromisoformat(meta["redacted_at"])
    assert body == "\nPERSON_A, PAN IN_PAN_A, asked about the loan.\n"


def test_output_names_never_carry_the_original_name(env):
    _drop(env, "Ravi Kumar PAN ABCPE1234F.txt", NOTE)
    name = _run(env).published[0]
    assert "Ravi" not in name and "ABCPE" not in name


def test_readable_names_are_redacted_names(env):
    _drop(env, "Ravi Kumar loan letter.txt", NOTE)
    name = _run(env, readable_names=True).published[0]
    assert name.startswith("PERSON-A-loan-letter-")
    assert "Ravi" not in name


def test_folder_name_selects_the_doc_type(env):
    _drop(env, "bank_statement/march.txt", NOTE)
    name = _run(env).published[0]
    assert name.startswith("bank_statement-")
    assert _published(env, name)[0]["doc_type"] == "bank_statement"


def test_markdown_source_frontmatter_is_nested_and_redacted(env):
    _drop(env, "note.md", "---\nauthor: Ravi Kumar\ntitle: Loan\n---\nBody text.\n")
    meta, body = _published(env, _run(env).published[0])
    assert meta["source_frontmatter"] == {"author": "PERSON_A", "title": "Loan"}
    assert body == "\nBody text.\n"


def test_recursive_walk_skips_unsupported_hidden_and_lock_files(env):
    _drop(env, "sub/deeper/notes.txt", NOTE)
    with zipfile.ZipFile(env.outbox / "resume.docx", "w") as zf:
        zf.writestr("word/document.xml", "<document/>")
    _drop(env, ".obsidian/workspace.md", NOTE)
    _drop(env, "~$resume.docx", "lock")

    summary = _run(env)

    assert len(summary.published) == 1
    assert summary.skipped == ["resume.docx"]
    assert summary.failed == []


def test_same_person_gets_the_same_code_in_documents_and_chat(env):
    _drop(env, "a.txt", "Ravi Kumar approved the transfer.\n")
    _drop(env, "b.txt", "Letter to Ravi Kumar about the loan.\n")
    names = _run(env).published
    bodies = sorted(_published(env, n)[1] for n in names)
    assert bodies == ["\nLetter to PERSON_A about the loan.\n", "\nPERSON_A approved the transfer.\n"]
    assert redact_text("Call Ravi Kumar today.", env.store).text == "Call PERSON_A today."


def test_audit_log_has_no_paths_or_values(env):
    _drop(env, "Ravi Kumar statement.txt", NOTE)
    _run(env)
    audit = env.audit.log_path.read_text(encoding="utf-8")
    assert "Ravi" not in audit and "statement" not in audit and "ABCPE1234F" not in audit
    entry = json.loads(audit.splitlines()[0])
    assert entry["document_id"].startswith("publish:")
    assert entry["written"] is True


# --- review


def test_declined_review_writes_nothing(env, monkeypatch):
    _drop(env, "note.txt", NOTE)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    summary = _run(env, assume_yes=False)

    assert summary.declined == 1
    assert not env.cfg.published.exists() or list(env.cfg.published.iterdir()) == []
    assert not env.cfg.manifest_path.exists()


def test_review_shows_the_redacted_preview_never_the_original(env, monkeypatch, capsys):
    _drop(env, "note.txt", NOTE)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    _run(env, assume_yes=False)
    out = capsys.readouterr().out
    assert "PERSON_A, PAN IN_PAN_A" in out
    assert "Ravi" not in out.replace("note.txt", "")


# --- incremental behavior


def test_rerun_without_changes_writes_nothing(env):
    _drop(env, "note.txt", NOTE)
    _run(env)
    before = _state(env)

    summary = _run(env)

    assert summary.unchanged == 1
    assert summary.published == []
    assert _state(env) == before


def test_edited_original_is_republished_under_the_same_name(env):
    source = _drop(env, "note.txt", NOTE)
    name = _run(env).published[0]
    source.write_bytes(b"Asha Rao replied to the loan request.\n")

    summary = _run(env)

    assert summary.published == [name]
    meta, body = _published(env, name)
    assert body == "\nPERSON_B replied to the loan request.\n"
    assert meta["source_hash"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_removed_original_is_unpublished(env):
    removed = _drop(env, "old.txt", NOTE)
    _drop(env, "kept.txt", "Asha Rao replied.\n")
    names = _run(env).published
    removed_name = next(n for n in names if "IN_PAN_A" in _published(env, n)[1])
    removed.unlink()

    summary = _run(env)

    assert summary.unpublished == [removed_name]
    assert not (env.cfg.published / removed_name).exists()
    assert len(json.loads(env.cfg.manifest_path.read_text())["entries"]) == 1


def test_an_empty_outbox_never_unpublishes_everything(env, capsys):
    source = _drop(env, "note.txt", NOTE)
    name = _run(env).published[0]
    source.unlink()

    summary = _run(env)

    assert summary.unpublished == []
    assert (env.cfg.published / name).exists()
    assert "not removing" in capsys.readouterr().err


def test_a_published_file_that_was_changed_by_hand_is_not_deleted(env, capsys):
    removed = _drop(env, "old.txt", NOTE)
    _drop(env, "kept.txt", "Asha Rao replied.\n")
    names = _run(env).published
    target = next(n for n in names if "IN_PAN_A" in _published(env, n)[1])
    (env.cfg.published / target).write_text("someone else's note\n", encoding="utf-8")
    removed.unlink()

    summary = _run(env)

    assert summary.unpublished == []
    assert (env.cfg.published / target).exists()
    assert "not removed" in capsys.readouterr().err


# --- residual gate


def test_a_seeded_miss_is_held_not_published(env, monkeypatch):
    _drop(env, "note.txt", NOTE)
    _drop_detections_of(monkeypatch, "IN_PAN")

    summary = _run(env)

    assert summary.published == []
    assert len(summary.held) == 1
    report = summary.held[0]
    assert report.parent == env.cfg.reports_dir
    assert not env.cfg.published.exists() or list(env.cfg.published.iterdir()) == []
    text = report.read_text(encoding="utf-8")
    assert "ABCPE1234F" not in text  # the report masks what it flags
    assert "[[IN_PAN" in text
    assert "note.txt" in text  # so the original can be found and fixed

    again = _run(env)
    assert again.still_held == 1 and again.held == []


def test_held_edit_keeps_the_previous_published_version(env, monkeypatch):
    source = _drop(env, "note.txt", "Asha Rao replied.\n")
    name = _run(env).published[0]
    published_before = (env.cfg.published / name).read_bytes()

    source.write_bytes(NOTE.encode())
    _drop_detections_of(monkeypatch, "IN_PAN")
    summary = _run(env)

    assert len(summary.held) == 1
    assert (env.cfg.published / name).read_bytes() == published_before
    assert _run(env).still_held == 1


# --- command line


def test_main_refuses_without_an_initialized_store(tmp_path, fake_keyring, capsys):
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    code = publish.main(
        ["--outbox", str(outbox), "--published", str(tmp_path / "pub"), "--home", str(tmp_path / "home"), "--yes"]
    )
    assert code == 2
    assert "redact-key init" in capsys.readouterr().err


def test_main_end_to_end_after_redact_key_init(tmp_path, fake_keyring, capsys):
    home = tmp_path / "home"
    assert keytool.main(["init", "--store", str(home / "mapping_store.enc")]) == 0
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    (outbox / "note.txt").write_bytes(NOTE.encode())
    args = ["--outbox", str(outbox), "--published", str(tmp_path / "pub"), "--home", str(home), "--yes"]

    assert publish.main(args) == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith("1 published")
    assert publish.main(args) == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith("0 published, 1 unchanged")


def test_main_rejects_overlapping_folders(tmp_path, capsys):
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    code = publish.main(["--outbox", str(outbox), "--published", str(outbox / "pub"), "--home", str(tmp_path / "h")])
    assert code == 2
    assert "must not be inside" in capsys.readouterr().err


def test_a_second_concurrent_run_is_refused(env):
    env.cfg.home.mkdir(parents=True, exist_ok=True)
    with FileLock(str(env.cfg.home / "publish.lock")):
        with pytest.raises(RuntimeError, match="in progress"):
            _run(env)

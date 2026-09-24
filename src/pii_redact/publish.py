"""redact-publish: turn documents dropped in an outbox into reviewed,
redacted markdown copies (Tool 1 of Phase 7).

    redact-publish [--outbox DIR] [--published DIR] [--home DIR]
                   [--doc-type TYPE] [--yes] [--force] [--readable-names]

For every file under the outbox (recursively):

1. Skip it if it's unchanged since it was last published or held (a
   manifest of content hashes lives in the redaction home, never in a
   vault). Unsupported formats are skipped, never fatal.
2. Extract, detect and pseudonymize it with the same document pipeline as
   `redact` (layout-aware detection, the one shared mapping store), and
   render it to markdown.
3. Residual gate: scan that markdown again for PII still in the clear. Any
   hit holds the document - nothing is published, and a report (values
   masked) is written to <home>/reports/.
4. Review: show the redacted preview and the counts by entity type, and ask
   (skipped with --yes).
5. Write <published>/<name>.md with frontmatter: type, redacted, doc_type,
   source_hash (sha256 of the original), redacted_at.

Originals that disappeared from the outbox have their published copy
removed. Nothing here ever deletes or modifies an original.

Published file names never carry the original name by default (names often
contain one): `<doc_type>-<keyed hash>.md`. --readable-names derives the
name from the redacted original name instead; see _output_name for why
that is opt-in.

Audit entries identify documents by a keyed hash of their outbox path,
never the path itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from filelock import FileLock, Timeout

from pii_redact.anonymize.mapping_store import MappingStore, MappingStoreError
from pii_redact.api import Finding, find_pii, redact_text
from pii_redact.audit.logger import AuditLogger
from pii_redact.config import paths
from pii_redact.config.allowlists import DOC_TYPE_ALLOWLISTS, allowlist_for
from pii_redact.detect.analyzer import SCORE_THRESHOLD
from pii_redact.extract.text import frontmatter_bounds
from pii_redact.ingest.format_detect import UnsupportedFormatError
from pii_redact.pipeline import _anonymize_blocks, _describe_failure, analyze_document, build_preview
from pii_redact.render.markdown import to_markdown
from pii_redact.review.preview import confirm
from pii_redact.types import Mode, OutputFormat

MANIFEST_VERSION = 1
PREVIEW_LINES = 30
_IGNORED_FILE_NAMES = {"desktop.ini", "thumbs.db"}


@dataclass
class PublishConfig:
    outbox: Path
    published: Path
    home: Path
    doc_type: str | None = None
    assume_yes: bool = False
    force: bool = False
    readable_names: bool = False
    threshold: float = SCORE_THRESHOLD

    @property
    def manifest_path(self) -> Path:
        return self.home / paths.PUBLISH_MANIFEST_FILE_NAME

    @property
    def reports_dir(self) -> Path:
        return self.home / paths.REPORTS_DIR_NAME


@dataclass
class PublishSummary:
    published: list[str] = field(default_factory=list)
    unchanged: int = 0
    held: list[Path] = field(default_factory=list)
    still_held: int = 0
    declined: int = 0
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unpublished: list[str] = field(default_factory=list)

    @property
    def needs_attention(self) -> bool:
        return bool(self.held or self.still_held or self.failed)

    def line(self) -> str:
        return (
            f"{len(self.published)} published, {self.unchanged} unchanged, "
            f"{len(self.held)} held, {self.still_held} still held, {self.declined} declined, "
            f"{len(self.skipped)} skipped, {len(self.failed)} failed, {len(self.unpublished)} unpublished"
        )


# --- manifest


def _load_manifest(path: Path) -> dict:
    if not path.exists():
        return {"version": MANIFEST_VERSION, "entries": {}}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("version") != MANIFEST_VERSION:
        raise ValueError(f"{path}: unsupported manifest version {manifest.get('version')!r}")
    return manifest


def _write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(f".{path.name}.partial")
    with open(partial, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(partial, path)


# --- sources


def _sources(outbox: Path) -> list[Path]:
    """Every file under the outbox, skipping hidden files and folders (such
    as .obsidian) and Office lock files (~$...)."""
    found = []
    for path in sorted(outbox.rglob("*")):
        relative = path.relative_to(outbox)
        if any(part.startswith((".", "~$")) for part in relative.parts):
            continue
        if path.name.lower() in _IGNORED_FILE_NAMES or not path.is_file():
            continue
        found.append(path)
    return found


def _doc_type_for(relative: Path, configured: str | None) -> str | None:
    """--doc-type wins; otherwise a top-level outbox folder named after a
    known document type (outbox/bank_statement/...) selects it."""
    if configured is not None:
        return configured
    if len(relative.parts) > 1 and relative.parts[0] in DOC_TYPE_ALLOWLISTS:
        return relative.parts[0]
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- output naming and content


def _output_name(relative: Path, source_id: str, doc_type: str | None, store: MappingStore, cfg: PublishConfig) -> str:
    """Opaque by default: `<doc_type>-<keyed hash of the outbox path>.md`.

    --readable-names runs the original file name through redaction first.
    That is opt-in because file names defeat NER far more often than prose:
    lowercase (`ravi_kumar_form16`), run together (`RaviKumar_Form16`) or
    abbreviated names are routinely missed, and a missed name in a file name
    is published in every link to it. A readable name that still looks like
    PII after redaction falls back to the opaque one."""
    opaque = f"{doc_type or 'document'}-{source_id[:10]}.md"
    if not cfg.readable_names:
        return opaque
    entities = allowlist_for(doc_type)
    words = re.sub(r"[_.\-]+", " ", relative.stem).strip()
    redacted = redact_text(words, store, entities=entities, threshold=cfg.threshold).text if words else ""
    if not redacted or find_pii(redacted, store, entities=entities, threshold=cfg.threshold):
        return opaque
    slug = re.sub(r"[^A-Za-z0-9]+", "-", redacted).strip("-")[:60].strip("-")
    return f"{slug}-{source_id[:8]}.md" if slug else opaque


def _split_source_frontmatter(markdown: str) -> tuple[dict | None, str]:
    """A markdown source's own (already redacted) frontmatter moves under
    `source_frontmatter:` in the published file's frontmatter, so the output
    has exactly one frontmatter block and no key collisions."""
    bounds = frontmatter_bounds(markdown)
    if bounds is None:
        return None, markdown
    content_start, content_end, body_start = bounds
    try:
        parsed = yaml.safe_load(markdown[content_start:content_end])
    except yaml.YAMLError:
        return None, markdown
    if not isinstance(parsed, dict):
        return None, markdown
    return parsed, markdown[body_start:].lstrip("\r\n")


def _published_document(body: str, *, doc_type: str | None, source_hash: str) -> str:
    source_frontmatter, body = _split_source_frontmatter(body)
    meta = {
        "type": "source",
        "redacted": True,
        "doc_type": doc_type or "generic",
        "source_hash": source_hash,
        "redacted_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    if source_frontmatter:
        meta["source_frontmatter"] = source_frontmatter
    return "---\n" + yaml.safe_dump(meta, sort_keys=False, allow_unicode=True) + "---\n\n" + body


def _written_by_us(path: Path, source_hash: str) -> bool:
    """Only ever delete a published file whose own frontmatter says it is
    the redacted copy of the source the manifest recorded."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    bounds = frontmatter_bounds(text)
    if bounds is None:
        return False
    try:
        meta = yaml.safe_load(text[bounds[0]:bounds[1]])
    except yaml.YAMLError:
        return False
    return isinstance(meta, dict) and meta.get("redacted") is True and meta.get("source_hash") == source_hash


# --- held reports


def _masked(text: str, findings: list[Finding]) -> str:
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[: f.start] + f"[[{f.entity_type} {f.score:.2f}]]" + text[f.end :]
    return text


def _write_report(cfg: PublishConfig, relative: Path, output_name: str, markdown: str, findings: list[Finding]) -> Path:
    """What the residual gate found, with every flagged value masked. Lives
    in the redaction home - never in a vault - and names the outbox file so
    it can be fixed."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = cfg.reports_dir / f"{stamp}-{Path(output_name).stem}.md"
    masked_lines = _masked(markdown, findings).splitlines()
    flagged_lines = sorted({markdown.count("\n", 0, f.start) for f in findings})
    lines = [
        f"# Held: {relative.as_posix()}",
        "",
        f"- would have been published as: `{output_name}`",
        f"- held at: {datetime.now(timezone.utc).replace(microsecond=0).isoformat()}",
        "- findings by type: "
        + ", ".join(f"{t}: {sum(1 for f in findings if f.entity_type == t)}" for t in sorted({f.entity_type for f in findings})),
        "",
        "After redaction, the residual check still found likely PII on these lines of the",
        "redacted markdown (each flagged value is masked as [[TYPE score]]):",
        "",
    ]
    for index in flagged_lines:
        line = masked_lines[index] if index < len(masked_lines) else ""
        lines.append(f"- line {index + 1}: `{line[:300]}`")
    lines += [
        "",
        "Nothing was published. Fix the original (or accept the finding by raising",
        "--threshold) and run redact-publish again.",
    ]
    _write_atomically(report, "\n".join(lines) + "\n")
    return report


# --- the run


def _unpublish(cfg: PublishConfig, entry: dict, summary: PublishSummary) -> None:
    name = entry.get("output_name")
    if not name or entry.get("status") != "published":
        return
    target = cfg.published / name
    if not target.exists():
        return
    if _written_by_us(target, entry["source_hash"]):
        target.unlink()
        summary.unpublished.append(name)
    else:
        print(f"WARN {name}: not removed - it no longer looks like the copy this tool published", file=sys.stderr)


def _process_one(
    path: Path,
    relative: Path,
    source_id: str,
    source_hash: str,
    previous: dict | None,
    cfg: PublishConfig,
    store: MappingStore,
    audit: AuditLogger,
    summary: PublishSummary,
    manifest: dict,
) -> None:
    doc_type = _doc_type_for(relative, cfg.doc_type)
    audit_id = f"publish:{source_id}"
    try:
        extracted, detections = analyze_document(path, doc_type)
    except UnsupportedFormatError:
        summary.skipped.append(relative.as_posix())
        print(f"SKIP {relative.as_posix()}: unsupported format")
        return
    except Exception as exc:
        summary.failed.append(relative.as_posix())
        print(f"FAIL {relative.as_posix()}: {_describe_failure(exc)}")
        return

    preview = build_preview(path, extracted, detections, output_format=OutputFormat.MARKDOWN)
    try:
        replacements = _anonymize_blocks(
            extracted, detections, Mode.PSEUDONYMIZE, store, include_read_only=True
        )
        markdown = to_markdown(path, extracted, replacements)
        output_name = _output_name(relative, source_id, doc_type, store, cfg)
        findings = find_pii(markdown, store, entities=allowlist_for(doc_type), threshold=cfg.threshold)
    except Exception as exc:
        summary.failed.append(relative.as_posix())
        print(f"FAIL {relative.as_posix()}: {_describe_failure(exc)}")
        audit.log(audit_id, Mode.PSEUDONYMIZE.value, preview, written=False)
        return

    if findings:
        report = _write_report(cfg, relative, output_name, markdown, findings)
        summary.held.append(report)
        # An earlier published version of this document stays published
        # (it passed the gate); only this new content is held.
        if previous and previous.get("status") == "published":
            entry = dict(previous)
        else:
            entry = {"status": "held", "source_hash": source_hash}
        entry.update(held_source_hash=source_hash, report=report.name)
        manifest["entries"][source_id] = entry
        print(f"HELD {relative.as_posix()}: {len(findings)} possible PII left after redaction - see {report}")
        audit.log(audit_id, Mode.PSEUDONYMIZE.value, preview, written=False)
        return

    print(f"\n=== {relative.as_posix()} -> {output_name}")
    preview_lines = markdown.splitlines()
    print("\n".join(preview_lines[:PREVIEW_LINES]))
    if len(preview_lines) > PREVIEW_LINES:
        print(f"... ({len(preview_lines) - PREVIEW_LINES} more lines)")
    if not confirm(preview, non_interactive=cfg.assume_yes):
        summary.declined += 1
        audit.log(audit_id, Mode.PSEUDONYMIZE.value, preview, written=False)
        return

    _write_atomically(cfg.published / output_name, _published_document(markdown, doc_type=doc_type, source_hash=source_hash))
    if previous and previous.get("status") == "published" and previous.get("output_name") not in (None, output_name):
        _unpublish(cfg, previous, summary)
    manifest["entries"][source_id] = {
        "status": "published",
        "source_hash": source_hash,
        "output_name": output_name,
        "published_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    summary.published.append(output_name)
    audit.log(audit_id, Mode.PSEUDONYMIZE.value, preview, written=True)


def run_publish(cfg: PublishConfig, store: MappingStore, audit: AuditLogger) -> PublishSummary:
    summary = PublishSummary()
    cfg.home.mkdir(parents=True, exist_ok=True)
    try:
        run_lock = FileLock(str(cfg.home / "publish.lock"), timeout=0)
        run_lock.acquire()
    except Timeout:
        raise RuntimeError("another redact-publish run is in progress") from None
    try:
        manifest = _load_manifest(cfg.manifest_path)
        before = json.dumps(manifest, sort_keys=True)
        sources = _sources(cfg.outbox)
        seen: set[str] = set()

        for path in sources:
            relative = path.relative_to(cfg.outbox)
            source_id = store.keyed_digest("publish-source:" + relative.as_posix().casefold())
            seen.add(source_id)
            source_hash = _sha256_file(path)
            previous = manifest["entries"].get(source_id)
            if previous and not cfg.force:
                if previous.get("status") == "published" and previous.get("source_hash") == source_hash:
                    if (cfg.published / previous["output_name"]).exists():
                        summary.unchanged += 1
                        continue
                if previous.get("held_source_hash") == source_hash:
                    summary.still_held += 1
                    print(f"HELD {relative.as_posix()}: unchanged since it was held - see {previous.get('report')}")
                    continue
            _process_one(path, relative, source_id, source_hash, previous, cfg, store, audit, summary, manifest)

        gone = [source_id for source_id in manifest["entries"] if source_id not in seen]
        if gone and not sources:
            # An empty or unreachable outbox looks exactly like "every
            # original was deleted". Never unpublish everything on that basis.
            print(
                f"WARN the outbox has no files; not removing {len(gone)} published "
                "document(s). Delete them by hand if that is really intended.",
                file=sys.stderr,
            )
        else:
            for source_id in gone:
                _unpublish(cfg, manifest["entries"][source_id], summary)
                del manifest["entries"][source_id]

        if json.dumps(manifest, sort_keys=True) != before:
            _write_atomically(cfg.manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    finally:
        run_lock.release()
    return summary


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact-publish",
        description="Publish reviewed, redacted markdown copies of the documents in an outbox.",
    )
    parser.add_argument("--outbox", type=Path, default=paths.DEFAULT_OUTBOX,
                        help=f"Folder of originals, read recursively (default: {paths.DEFAULT_OUTBOX})")
    parser.add_argument("--published", type=Path, default=paths.DEFAULT_PUBLISHED,
                        help=f"Folder for the redacted markdown (default: {paths.DEFAULT_PUBLISHED})")
    parser.add_argument("--home", type=Path, default=None,
                        help=f"Redaction home: store, audit log, manifest, reports "
                             f"(default: $env:{paths.HOME_ENV}, else {paths.DEFAULT_HOME})")
    parser.add_argument("--doc-type", dest="doc_type", choices=sorted(DOC_TYPE_ALLOWLISTS), default=None,
                        help="Entity allow-list for every document (default: the top-level outbox "
                             "folder's name if it is a document type, else generic)")
    parser.add_argument("--yes", action="store_true",
                        help="Publish without the per-document review prompt (the residual gate still applies)")
    parser.add_argument("--force", action="store_true",
                        help="Reprocess every document, including unchanged and held ones")
    parser.add_argument("--readable-names", action="store_true",
                        help="Name outputs after the redacted original name instead of an opaque hash")
    parser.add_argument("--threshold", type=float, default=SCORE_THRESHOLD,
                        help=f"Minimum detection score for the residual gate (default {SCORE_THRESHOLD})")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    home = args.home if args.home is not None else paths.redaction_home()
    cfg = PublishConfig(
        outbox=args.outbox, published=args.published, home=home, doc_type=args.doc_type,
        assume_yes=args.yes, force=args.force, readable_names=args.readable_names, threshold=args.threshold,
    )
    if not cfg.outbox.is_dir():
        print(f"error: outbox {cfg.outbox} does not exist", file=sys.stderr)
        return 2
    for a, b in ((cfg.published, cfg.outbox), (cfg.outbox, cfg.published), (cfg.home, cfg.outbox), (cfg.home, cfg.published)):
        if _inside(a, b):
            print(f"error: {a} must not be inside {b}", file=sys.stderr)
            return 2
    try:
        store = MappingStore(home / paths.STORE_FILE_NAME, create=False)
        store.load()
    except MappingStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    cfg.published.mkdir(parents=True, exist_ok=True)
    try:
        summary = run_publish(cfg, store, AuditLogger(home / paths.AUDIT_LOG_FILE_NAME))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(summary.line())
    return 1 if summary.needs_attention else 0


if __name__ == "__main__":
    sys.exit(main())

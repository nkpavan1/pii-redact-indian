"""CLI entry point.

    redact <input> -o <output_dir> --mode {redact|pseudonymize} [--doc-type TYPE] [--yes]

`<input>` may be a single file or a directory (batch mode, non-recursive).
`--yes` skips the interactive y/N prompt but still refuses to write output
for any document that fails extraction or has a failed section (fail-closed
- see project instructions and pipeline.py).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.audit.logger import AuditLogger
from pii_redact.config.allowlists import DOC_TYPE_ALLOWLISTS
from pii_redact.pipeline import run_batch, run_pipeline
from pii_redact.types import Mode, PipelineResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact",
        description="Local PII redaction/pseudonymization for Indian personal documents.",
    )
    parser.add_argument("input", type=Path, help="File or directory to process")
    parser.add_argument(
        "-o", "--output", dest="output_dir", type=Path, required=True,
        help="Directory to write output into (created if missing)",
    )
    parser.add_argument(
        "--mode", type=Mode, choices=list(Mode), default=Mode.PSEUDONYMIZE,
        help="redact: remove PII. pseudonymize: replace with a reversible coded identifier.",
    )
    parser.add_argument(
        "--doc-type", dest="doc_type", choices=sorted(DOC_TYPE_ALLOWLISTS), default=None,
        help="Selects the entity allow-list for this document type (default: generic).",
    )
    parser.add_argument(
        "--mapping-store", dest="mapping_store_path", type=Path,
        default=Path.home() / ".pii_redact" / "mapping_store.enc",
        help="Path to the encrypted pseudonym mapping store.",
    )
    parser.add_argument(
        "--audit-log", dest="audit_log_path", type=Path,
        default=Path.home() / ".pii_redact" / "audit.log.jsonl",
        help="Path to the audit log (entity type/count/doc id only, never raw values).",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help=(
            "Skip the interactive confirmation prompt (still fail-closed on "
            "extraction errors and on any unredactable/formula-derived detections)."
        ),
    )
    return parser


def _print_result(result: PipelineResult) -> None:
    if result.written:
        print(f"OK   {result.source_path} -> {result.output_path}")
    else:
        print(f"SKIP {result.source_path}: {result.failure_reason}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    mapping_store = MappingStore(args.mapping_store_path)
    audit_logger = AuditLogger(args.audit_log_path)

    if not args.input.exists():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 2

    if args.input.is_dir():
        results = run_batch(
            args.input, args.output_dir, args.mode, args.doc_type,
            mapping_store, audit_logger, non_interactive=args.yes,
        )
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        results = [
            run_pipeline(
                args.input, args.output_dir, args.mode, args.doc_type,
                mapping_store, audit_logger, non_interactive=args.yes,
            )
        ]

    for result in results:
        _print_result(result)

    return 0 if all(r.written for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

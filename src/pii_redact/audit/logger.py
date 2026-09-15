"""Audit logging: entity type, count, and document identifier only - never
the actual detected value (see project instructions, security section).
Confidence scores are logged per-entity-type-per-run (aggregated, not tied
to a single raw value) so detection thresholds can be tuned without ever
needing to look at real data.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from pii_redact.types import PreviewSummary


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    document_id: str
    mode: str
    counts_by_entity: dict[str, int]
    written: bool


class AuditLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path

    def log(self, document_id: str, mode: str, preview: PreviewSummary, written: bool) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            document_id=document_id,
            mode=mode,
            counts_by_entity=preview.counts_by_entity,
            written=written,
        )
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

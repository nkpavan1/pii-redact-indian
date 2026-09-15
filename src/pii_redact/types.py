"""Shared data types passed between pipeline stages.

Kept dependency-free (no Presidio imports) so extract/detect/render stages
don't need to import each other's internals - they only need to agree on
these shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class DocFormat(str, Enum):
    PDF = "pdf"
    XLSX = "xlsx"
    CSV = "csv"
    JSON = "json"
    IMAGE = "image"


class Mode(str, Enum):
    REDACT = "redact"
    PSEUDONYMIZE = "pseudonymize"


@dataclass(frozen=True)
class Location:
    """Where a detection occurred, in format-specific coordinates.

    Exactly one of the optional fields is populated depending on `DocFormat`:
    page+bbox for PDF/image, sheet+cell for XLSX, row+column for CSV,
    json_path for JSON.
    """

    page: int | None = None
    bbox: tuple[float, float, float, float] | None = None  # x0, y0, x1, y1
    sheet: str | None = None
    cell: str | None = None
    row: int | None = None
    column: str | None = None
    json_path: str | None = None


@dataclass(frozen=True)
class TextBlock:
    """A unit of extracted text plus enough info to map detections back to
    the source location and, on write, back into the original structure."""

    text: str
    location: Location
    source_ref: Any = None  # extractor-specific handle, e.g. an openpyxl cell
    # True for values surfaced for visibility only - e.g. a formula's cached
    # result. The render stage must never overwrite one of these in place
    # (it isn't a standalone cell value); the pipeline/preview must still
    # report detections in it, flagged as needing manual review.
    read_only: bool = False


@dataclass
class ExtractedDocument:
    doc_format: DocFormat
    source_path: Path
    blocks: list[TextBlock]
    needs_ocr_pages: list[int] = field(default_factory=list)
    # Format-specific round-trip state the renderer needs but detection
    # doesn't: e.g. CSV's {encoding, delimiter, has_header, header}. Kept
    # generic here rather than adding a field per format.
    format_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    entity_type: str
    start: int
    end: int
    score: float
    block_index: int
    location: Location


@dataclass
class PreviewSummary:
    """What the human review gate shows before anything is written.

    Never carries a raw detected value - only type, count, and location.
    """

    document: Path
    counts_by_entity: dict[str, int]
    locations_by_entity: dict[str, list[Location]]
    failed_pages_or_sections: list[str] = field(default_factory=list)
    # Detections inside a read_only TextBlock (formula-derived results,
    # defined names - see extract/xlsx.py) that the render stage will
    # refuse to overwrite. These still count in counts_by_entity/
    # locations_by_entity above; this is what tells the review gate (and
    # the human) that some of those occurrences will NOT be redacted, so
    # approval isn't mistaken for "everything shown will be handled."
    unredactable_counts_by_entity: dict[str, int] = field(default_factory=dict)

    @property
    def has_unredactable(self) -> bool:
        return sum(self.unredactable_counts_by_entity.values()) > 0

    @property
    def total_detections(self) -> int:
        return sum(self.counts_by_entity.values())


@dataclass
class PipelineResult:
    source_path: Path
    output_path: Path | None
    mode: Mode
    preview: PreviewSummary
    written: bool
    failure_reason: str | None = None

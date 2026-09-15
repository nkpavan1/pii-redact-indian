"""Orchestrates the pipeline stages defined in the project instructions:
ingest -> extract -> detect -> preview/review gate -> anonymize -> render ->
audit log. This module owns the control flow and the fail-closed policy;
it deliberately does not know the internals of any one stage.
"""

from __future__ import annotations

from pathlib import Path

from presidio_analyzer import RecognizerResult
from presidio_anonymizer.entities import OperatorConfig

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.anonymize.operators import get_anonymizer_engine
from pii_redact.audit.logger import AuditLogger
from pii_redact.config.allowlists import allowlist_for
from pii_redact.detect.analyzer import detect_in_block
from pii_redact.extract.base import Extractor
from pii_redact.extract.csv_ import CsvExtractor
from pii_redact.extract.image import ImageExtractor
from pii_redact.extract.json_ import JsonExtractor
from pii_redact.extract.pdf import PdfExtractor
from pii_redact.extract.xlsx import XlsxExtractor
from pii_redact.ingest.format_detect import detect_format
from pii_redact.render.base import Renderer
from pii_redact.render.csv_ import CsvRenderer
from pii_redact.render.image import ImageRenderer
from pii_redact.render.json_ import JsonRenderer
from pii_redact.render.pdf import PdfRenderer
from pii_redact.render.xlsx import XlsxRenderer
from pii_redact.review.preview import confirm
from pii_redact.types import (
    DocFormat,
    Detection,
    ExtractedDocument,
    Mode,
    PipelineResult,
    PreviewSummary,
    TextBlock,
)

# Formats where "the previous/next block in the list" means "the
# previous/next line on the same page" - a meaningful spatial/semantic
# adjacency that justifies sharing context between them (see
# _context_window). CSV/XLSX/JSON blocks are cells/values with no such
# relationship - block N+1 in the list is not "near" block N in any sense
# Presidio's context matching should exploit, so they're deliberately
# excluded; that gap is real and is documented in detect/analyzer.py
# instead of papered over here.
_CONTEXT_WINDOW_FORMATS = {DocFormat.PDF, DocFormat.IMAGE}
_CONTEXT_WINDOW_RADIUS = 1
_CONTEXT_WINDOW_SEPARATOR = " | "

_EXTRACTORS: dict[DocFormat, type[Extractor]] = {
    DocFormat.PDF: PdfExtractor,
    DocFormat.XLSX: XlsxExtractor,
    DocFormat.CSV: CsvExtractor,
    DocFormat.JSON: JsonExtractor,
    DocFormat.IMAGE: ImageExtractor,
}

_RENDERERS: dict[DocFormat, type[Renderer]] = {
    DocFormat.PDF: PdfRenderer,
    DocFormat.XLSX: XlsxRenderer,
    DocFormat.CSV: CsvRenderer,
    DocFormat.JSON: JsonRenderer,
    DocFormat.IMAGE: ImageRenderer,
}


def _same_page(a: TextBlock, b: TextBlock) -> bool:
    return a.location.page is not None and a.location.page == b.location.page


_OVERLAP_THRESHOLD = 0.3


def _horizontal_overlap_fraction(
    a_bbox: tuple[float, float, float, float], b_bbox: tuple[float, float, float, float]
) -> float:
    """Fraction of the NARROWER box's width that overlaps the other box's
    X-range, used as a "these two blocks sit in the same column" test.
    Deliberately overlap-based rather than "left edges within N points of
    each other": it still works for center- or right-aligned columns and
    naturally scales with content width, without a magic-number tolerance
    tuned to one document's exact coordinates."""
    a_x0, _, a_x1, _ = a_bbox
    b_x0, _, b_x1, _ = b_bbox
    overlap = min(a_x1, b_x1) - max(a_x0, b_x0)
    narrower_width = min(a_x1 - a_x0, b_x1 - b_x0)
    if narrower_width <= 0:
        return 0.0
    return max(0.0, overlap) / narrower_width


def _vertical_overlap_fraction(
    a_bbox: tuple[float, float, float, float], b_bbox: tuple[float, float, float, float]
) -> float:
    """Mirror of _horizontal_overlap_fraction on the Y axis - "these two
    blocks sit on the same row" test."""
    _, a_y0, _, a_y1 = a_bbox
    _, b_y0, _, b_y1 = b_bbox
    overlap = min(a_y1, b_y1) - max(a_y0, b_y0)
    narrower_height = min(a_y1 - a_y0, b_y1 - b_y0)
    if narrower_height <= 0:
        return 0.0
    return max(0.0, overlap) / narrower_height


def _nearest_in_direction(
    candidates: list[TextBlock], current_pos: float, axis: int, forward: bool, radius: int
) -> list[TextBlock]:
    """Nearest `radius` blocks from `candidates` that lie before (forward=
    False) or after (forward=True) `current_pos` along `axis` (0 = X, 1 =
    Y), sorted by distance. Caller pre-filters `candidates` to whichever
    overlap test (horizontal or vertical) makes them a meaningful neighbor
    in the first place."""
    if forward:
        matching = [b for b in candidates if b.location.bbox[axis] > current_pos]
        key = lambda b: b.location.bbox[axis] - current_pos  # noqa: E731
    else:
        matching = [b for b in candidates if b.location.bbox[axis] < current_pos]
        key = lambda b: current_pos - b.location.bbox[axis]  # noqa: E731
    return sorted(matching, key=key)[:radius]


def _context_window(
    blocks: list[TextBlock], index: int, radius: int = _CONTEXT_WINDOW_RADIUS
) -> tuple[str, int]:
    """Builds a wider text window around blocks[index] from its same-page
    neighbors in all four directions, so a field label directly above,
    below, or beside its value shares a single analyze() call instead of
    two isolated ones that can never see each other - see the real
    observed failure this fixes: Date of Birth/Name of Assessee/Mobile
    Number values on AIS documents sitting in their own line with the
    label on a different line, so every context-scoped recognizer never
    saw the label at all.

    CORRECTED THREE TIMES on real documents - this is the third. History,
    because each correction was wrong for a layout the previous one hadn't
    been tested against:
    1. First version: index-adjacent neighbors in `blocks` (assumed
       extraction order matches visual order - false for a PDF built from
       a separate label layer and value overlay).
    2. Second version: same-page blocks sorted by (top-Y, left-X), nearest
       in that flat order - correct for a single column, wrong for a
       multi-column table (a real AIS document lays 3 label-value pairs
       side by side per row; the flat sort picked a DIFFERENT column's
       label as "nearest" to a value it had nothing to do with). Fixed by
       requiring horizontal bbox overlap before two blocks count as
       neighbors at all - i.e. nearest neighbor in the SAME COLUMN
       (vertically stacked label above/below value).
    3. This version: column-only adjacency broke a DIFFERENT, at least as
       common, layout - confirmed on a real bank interest certificate,
       where every field is "Label : Value" side by side on ONE row
       (e.g. "Customer Id" at one X position, "10023456" immediately to
       its right at the SAME Y). Requiring horizontal overlap (same
       column) explicitly excludes same-row/different-column pairs -
       which is exactly the relationship this layout needs. There is no
       single adjacency rule that covers both a label-above-value layout
       and a label-beside-value layout, so this version checks all four
       cardinal directions independently: nearest same-COLUMN neighbor
       above/below (vertical overlap use case) AND nearest same-ROW
       neighbor left/right (horizontal placement use case). A block gets
       context from whichever directions actually have a neighbor;
       harmless if a direction's neighbor turns out irrelevant (see
       _merge_detections and the " | " separator below for why extra,
       unrelated neighbor text doesn't create new false positives).

    Blocks without a bbox (shouldn't happen for PDF/image extractors
    today, but handled defensively) get no neighbors - never guess at
    position for something that doesn't have one.

    Joined with " | ", not a bare newline/space - verified directly, not
    assumed: a plain "\\n" is whitespace, and this project's own date
    regexes accept whitespace as a separator between date components
    (`[\\s\\-]+`), so a date could otherwise be assembled by BRIDGING two
    unrelated blocks that happen to sit next to each other. "|" is not in
    any of those character classes, so regex patterns can never bridge
    across it, while Presidio's context-word matching (token-distance
    based) and spaCy's NER (which stops a PERSON span at the "|" token
    rather than swallowing into the next block) both still work correctly
    across it - confirmed by direct probe, not assumed.

    Returns (window_text, offset_of_blocks[index]_within_window).
    """
    current = blocks[index]
    if current.location.bbox is None or current.location.page is None:
        return current.text, 0

    current_bbox = current.location.bbox
    same_page_others = [
        b for b in blocks if b is not current and _same_page(b, current) and b.location.bbox is not None
    ]

    same_column = [
        b for b in same_page_others
        if _horizontal_overlap_fraction(current_bbox, b.location.bbox) >= _OVERLAP_THRESHOLD
    ]
    same_row = [
        b for b in same_page_others
        if _vertical_overlap_fraction(current_bbox, b.location.bbox) >= _OVERLAP_THRESHOLD
    ]

    above = _nearest_in_direction(same_column, current_bbox[1], axis=1, forward=False, radius=radius)
    below = _nearest_in_direction(same_column, current_bbox[1], axis=1, forward=True, radius=radius)
    left = _nearest_in_direction(same_row, current_bbox[0], axis=0, forward=False, radius=radius)
    right = _nearest_in_direction(same_row, current_bbox[0], axis=0, forward=True, radius=radius)

    left.sort(key=lambda b: b.location.bbox[0])
    above.sort(key=lambda b: b.location.bbox[1])
    below.sort(key=lambda b: b.location.bbox[1])
    right.sort(key=lambda b: b.location.bbox[0])

    before = [b.text for b in (*left, *above)]
    after = [b.text for b in (*below, *right)]
    offset = len(_CONTEXT_WINDOW_SEPARATOR.join(before) + _CONTEXT_WINDOW_SEPARATOR) if before else 0
    window = _CONTEXT_WINDOW_SEPARATOR.join([*before, current.text, *after])
    return window, offset


def _spans_overlap(a: Detection, b: Detection) -> bool:
    return a.start < b.end and b.start < a.end


def _merge_detections(base: list[Detection], windowed: list[Detection]) -> list[Detection]:
    """Combines a block-alone detection pass with a context-widened one,
    always preferring the LARGER span when both find the same entity type
    at an overlapping position.

    This exists because widening context can shrink a NER span instead of
    only ever helping it - confirmed directly, not assumed: spaCy detects
    "RAHUL KUMAR SHARMA" as one PERSON span when analyzed alone, but only
    "KUMAR SHARMA" when the preceding line "Name of Assessee" is included
    as context (a real AIS document's actual layout). Running the
    block-alone pass unconditionally and only ever using the windowed
    pass's results to ADD detections or REPLACE an existing one with a
    strictly bigger span - never to shrink it - makes context widening a
    pure improvement for entities that need it (dates, phone numbers)
    without regressing entities that already worked fine without it
    (whole-name PERSON detection).
    """
    merged = list(base)
    for w in windowed:
        replaced_existing = False
        for i, b in enumerate(merged):
            if b.entity_type == w.entity_type and _spans_overlap(b, w):
                if (w.end - w.start) > (b.end - b.start):
                    merged[i] = w
                replaced_existing = True
                break
        if not replaced_existing:
            merged.append(w)
    return merged


def _anonymize_blocks(
    extracted: ExtractedDocument,
    detections: list[Detection],
    mode: Mode,
    mapping_store: MappingStore,
) -> dict[int, str]:
    """Groups detections by block (a block can contain more than one
    entity, e.g. a free-text note mentioning both a name and a PAN) and
    runs Presidio's AnonymizerEngine once per block, so overlapping/
    adjacent spans in the same string are resolved correctly instead of
    naively string-replacing each detection independently.

    read_only blocks (formula-derived results, defined names - see
    extract/xlsx.py) are skipped entirely, never entering the returned
    dict, which is exactly what tells the render stage to leave them
    untouched (see Renderer.render's docstring). The caller is responsible
    for making sure a human actually saw that this happened - see
    PreviewSummary.unredactable_counts_by_entity and review/preview.py.
    """
    detections_by_block: dict[int, list[Detection]] = {}
    for d in detections:
        detections_by_block.setdefault(d.block_index, []).append(d)

    if not detections_by_block:
        return {}

    engine = get_anonymizer_engine()
    if mode == Mode.PSEUDONYMIZE:
        operators = {
            "DEFAULT": OperatorConfig("consistent_pseudonym", {"mapping_store": mapping_store})
        }
    else:
        operators = {"DEFAULT": OperatorConfig("replace")}

    replacements: dict[int, str] = {}
    for block_index, block_detections in detections_by_block.items():
        block = extracted.blocks[block_index]
        if block.read_only:
            continue
        recognizer_results = [
            RecognizerResult(entity_type=d.entity_type, start=d.start, end=d.end, score=d.score)
            for d in block_detections
        ]
        result = engine.anonymize(
            text=block.text, analyzer_results=recognizer_results, operators=operators
        )
        replacements[block_index] = result.text

    return replacements


def run_pipeline(
    input_path: Path,
    output_dir: Path,
    mode: Mode,
    doc_type: str | None,
    mapping_store: MappingStore,
    audit_logger: AuditLogger,
    *,
    non_interactive: bool = False,
) -> PipelineResult:
    doc_format = detect_format(input_path)
    extractor = _EXTRACTORS[doc_format]()

    try:
        extracted = extractor.extract(input_path)
    except Exception as exc:  # fail-closed: report, never pass the original through
        preview = PreviewSummary(
            document=input_path,
            counts_by_entity={},
            locations_by_entity={},
            failed_pages_or_sections=[str(exc)],
        )
        audit_logger.log(str(input_path), mode.value, preview, written=False)
        return PipelineResult(
            source_path=input_path,
            output_path=None,
            mode=mode,
            preview=preview,
            written=False,
            failure_reason=str(exc),
        )

    entities = allowlist_for(doc_type)
    detections: list[Detection] = []
    for i, block in enumerate(extracted.blocks):
        base_detections = detect_in_block(block, i, entities)
        if doc_format in _CONTEXT_WINDOW_FORMATS:
            window_text, offset = _context_window(extracted.blocks, i)
            windowed_detections = detect_in_block(
                block, i, entities, context_text=window_text, context_offset=offset
            )
            detections.extend(_merge_detections(base_detections, windowed_detections))
        else:
            detections.extend(base_detections)

    counts_by_entity: dict[str, int] = {}
    locations_by_entity: dict[str, list] = {}
    unredactable_counts_by_entity: dict[str, int] = {}
    for d in detections:
        counts_by_entity[d.entity_type] = counts_by_entity.get(d.entity_type, 0) + 1
        locations_by_entity.setdefault(d.entity_type, []).append(d.location)
        if extracted.blocks[d.block_index].read_only:
            unredactable_counts_by_entity[d.entity_type] = (
                unredactable_counts_by_entity.get(d.entity_type, 0) + 1
            )

    preview = PreviewSummary(
        document=input_path,
        counts_by_entity=counts_by_entity,
        locations_by_entity=locations_by_entity,
        unredactable_counts_by_entity=unredactable_counts_by_entity,
    )

    if not confirm(preview, non_interactive=non_interactive):
        audit_logger.log(str(input_path), mode.value, preview, written=False)
        return PipelineResult(
            source_path=input_path,
            output_path=None,
            mode=mode,
            preview=preview,
            written=False,
            failure_reason="rejected at review gate",
        )

    replacements = _anonymize_blocks(extracted, detections, mode, mapping_store)

    output_path = output_dir / input_path.name
    renderer = _RENDERERS[doc_format]()
    renderer.render(input_path, extracted, replacements, output_path)

    audit_logger.log(str(input_path), mode.value, preview, written=True)
    return PipelineResult(
        source_path=input_path,
        output_path=output_path,
        mode=mode,
        preview=preview,
        written=True,
    )


def run_batch(
    input_dir: Path,
    output_dir: Path,
    mode: Mode,
    doc_type: str | None,
    mapping_store: MappingStore,
    audit_logger: AuditLogger,
    *,
    non_interactive: bool = False,
) -> list[PipelineResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for path in sorted(p for p in input_dir.iterdir() if p.is_file()):
        results.append(
            run_pipeline(
                path,
                output_dir,
                mode,
                doc_type,
                mapping_store,
                audit_logger,
                non_interactive=non_interactive,
            )
        )
    return results

"""The mandatory human review gate (see project instructions: there is no
fully-automated 'detect and ship' mode). Renders counts + locations by
entity type - never a raw detected value - and asks for confirmation before
the pipeline is allowed to write anything.
"""

from __future__ import annotations

from pii_redact.types import PreviewSummary


def render_preview_text(preview: PreviewSummary) -> str:
    lines = [f"Preview for {preview.document}:"]
    if not preview.counts_by_entity:
        lines.append("  No entities detected.")
    for entity_type, count in sorted(preview.counts_by_entity.items()):
        locations = preview.locations_by_entity.get(entity_type, [])
        location_hint = _summarize_locations(locations)
        unredactable = preview.unredactable_counts_by_entity.get(entity_type, 0)
        unredactable_hint = (
            f" [{unredactable} of these CANNOT be auto-redacted - see below]"
            if unredactable
            else ""
        )
        lines.append(f"  {entity_type}: {count} occurrence(s){location_hint}{unredactable_hint}")
    if preview.has_unredactable:
        lines.append(
            "  WARNING: some detections are formula-derived results or defined "
            "names and will be left AS-IS in the output (overwriting them risks "
            "breaking the workbook) - review these locations manually before "
            "using the output."
        )
    if preview.failed_pages_or_sections:
        lines.append("  FAILED to process (fail-closed, output will be refused):")
        for failure in preview.failed_pages_or_sections:
            lines.append(f"    - {failure}")
    return "\n".join(lines)


def _summarize_locations(locations: list) -> str:
    pages = sorted({loc.page for loc in locations if loc.page is not None})
    if pages:
        return f" on page(s) {pages}"
    sheets = sorted({loc.sheet for loc in locations if loc.sheet is not None})
    if sheets:
        return f" in sheet(s) {sheets}"
    return ""


def confirm(preview: PreviewSummary, *, non_interactive: bool = False) -> bool:
    """Returns True if the user (or an explicit --yes flag) approves writing
    output. Fail-closed: any failed section blocks approval outright.
    Unredactable (formula-derived/defined-name) detections don't block an
    interactive human who has seen the warning above and can make an
    informed call - but DO block non_interactive/--yes, the same as a
    failed section, because nobody has actually looked at them; letting
    --yes sail past unredactable PII would silently defeat the "no
    fully-automated detect-and-ship mode" guarantee this gate exists for."""
    print(render_preview_text(preview))
    if preview.failed_pages_or_sections:
        print("Refusing to proceed: one or more sections failed to process.")
        return False
    if preview.has_unredactable and non_interactive:
        print(
            "Refusing to proceed non-interactively: unredactable detections "
            "need a human to look at them first (see warning above)."
        )
        return False
    if non_interactive:
        return True
    answer = input("Proceed with this output? [y/N] ").strip().lower()
    return answer == "y"

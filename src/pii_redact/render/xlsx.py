"""XLSX re-rendering via openpyxl.

Opens a fresh copy of source_path (data_only=False, so formulas stay
formulas) and mutates it in place before saving to output_path - same
"renderer re-reads the source, extracted+replacements only say what to
change" philosophy as render/csv_.py and render/json_.py.

Only `value` and `comment` blocks (see extract/xlsx.py's source_ref
tagging) are ever overwritten. `formula_result` and `defined_name` blocks
are both `read_only=True` at extraction time, and this renderer REFUSES to
write to them - see project instructions: "never overwrite a cell that's a
formula input... without an explicit, deliberate policy decision", which
this project hasn't made yet for either case (renaming a defined name
safely requires validating the replacement against Excel's identifier
rules; overwriting a formula's cached result requires deciding whether to
also touch the formula's real inputs elsewhere in the workbook). Surfacing
these in the review-gate preview without silently rewriting them is the
safe default - refusing loudly (XlsxRenderError) rather than skipping
quietly, so a bug upstream that tries to redact one is caught, not hidden.

Metadata scrub (project instructions: "Strip or sanitize... on every
processed [file]"): unconditionally clears the textual identity fields in
docProps/core.xml (creator, lastModifiedBy, title, subject, description,
keywords, category, identifier) on every render, not just when a
detection targets them.

Verified quirk, not a bug here: openpyxl's DocumentProperties defaults
`creator` to the literal string "openpyxl" (every other field defaults to
None) and re-applies that default on save whenever the field is falsy - so
after this scrub, `creator` comes back as "openpyxl" rather than empty/
None. The original PII value is genuinely gone; don't mistake the
"openpyxl" placeholder for a bug or for scrubbing having silently failed.

KNOWN GAP, verified against openpyxl directly, not assumed: openpyxl has
no write API for docProps/app.xml extended properties (Company, Manager,
Application name) - only core.xml is exposed via wb.properties. Company/
Manager can therefore survive a "redacted" output untouched. Closing this
would require direct XML patching of app.xml (the same technique used to
build this project's formula-cache test fixtures) - not done here. Don't
tell a user metadata is fully scrubbed without mentioning this.

Also not scrubbed: a comment's `author` field (only `comment.text` is
extracted/redacted - the author name itself is a smaller, separate gap).

Hidden sheet/row/column state is preserved automatically - we mutate the
loaded workbook object rather than rebuilding one, so nothing about
visibility state is touched unless we explicitly touch it.
"""

from __future__ import annotations

from pathlib import Path

import openpyxl

from pii_redact.render.base import Renderer
from pii_redact.types import ExtractedDocument

_SCRUBBED_CORE_PROPERTIES = (
    "creator",
    "lastModifiedBy",
    "title",
    "subject",
    "description",
    "keywords",
    "category",
    "identifier",
)


class XlsxRenderError(ValueError):
    pass


class XlsxRenderer(Renderer):
    def render(
        self,
        source_path: Path,
        extracted: ExtractedDocument,
        replacements: dict[int, str],
        output_path: Path,
    ) -> None:
        try:
            wb = openpyxl.load_workbook(source_path, data_only=False)
        except Exception as exc:
            raise XlsxRenderError(f"{source_path}: could not open workbook ({exc})") from exc

        for block_index, new_text in replacements.items():
            block = extracted.blocks[block_index]
            if block.read_only:
                raise XlsxRenderError(
                    f"block {block_index} ({block.source_ref}) is read-only "
                    "(formula-derived or a defined name) - refusing to overwrite it in place"
                )

            kind, sheet_name, ref = block.source_ref
            if sheet_name is None or sheet_name not in wb.sheetnames:
                raise XlsxRenderError(
                    f"block {block_index}: sheet {sheet_name!r} no longer exists in the "
                    "re-read source - refusing to write a mismatched output"
                )
            ws = wb[sheet_name]

            if kind == "value":
                cell = ws[ref]
                if not isinstance(cell.value, str):
                    raise XlsxRenderError(
                        f"block {block_index}: {sheet_name}!{ref} is no longer a string "
                        "cell in the re-read source - refusing to overwrite it"
                    )
                cell.value = new_text
            elif kind == "comment":
                cell = ws[ref]
                if cell.comment is None:
                    raise XlsxRenderError(
                        f"block {block_index}: {sheet_name}!{ref} no longer has a comment "
                        "in the re-read source - refusing to write a mismatched output"
                    )
                cell.comment.text = new_text
            else:
                raise XlsxRenderError(
                    f"block {block_index}: unrecognized source_ref kind {kind!r}"
                )

        for field in _SCRUBBED_CORE_PROPERTIES:
            setattr(wb.properties, field, None)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        wb.save(output_path)

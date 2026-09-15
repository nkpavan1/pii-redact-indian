# pii-redact — Implementation & Usage

Detailed status, setup, and usage reference. See [README.md](README.md) for
the project overview (why this exists, the pipeline, dependencies, and the
one-command setup script) and
[claude_project_instructions_build_redaction_tool.md](claude_project_instructions_build_redaction_tool.md)
for the full design/constraints doc this implementation follows.

## Status

All five formats (PDF, XLSX, CSV, JSON, JPEG/PNG) work end to end: extract
→ detect → review gate → anonymize → render, in both `redact` and
`pseudonymize` mode. What's real:

- Pipeline orchestration (`pipeline.py`), CLI (`cli.py`), format detection
  (`ingest/format_detect.py`), the entity allow-list config
  (`config/allowlists.py`), all custom Indian-entity `PatternRecognizer`s
  (`detect/recognizers/`), Luhn/Verhoeff checksum validators
  (`detect/checksum.py`), and the Presidio analyzer wiring
  (`detect/analyzer.py`).
- Extractors and renderers for every format (`extract/`, `render/`):
  CSV, JSON, XLSX (formula/comment/defined-name aware), PDF (native text +
  AcroForm fields + per-page OCR routing, true redaction via PyMuPDF's
  redaction annotations, not cosmetic overlay), and JPEG/PNG (OCR-based,
  sharing `extract/ocr.py` with the PDF scanned-page path).
- The anonymize-stage wiring (`pipeline.py::_anonymize_blocks` +
  `anonymize/operators.py`): groups detections per block, runs Presidio's
  `AnonymizerEngine` once per block, and skips `read_only` blocks
  (formula-derived XLSX results, defined names) rather than overwriting
  them — the review gate surfaces those as an explicit "cannot be
  auto-redacted" warning and refuses non-interactive (`--yes`) approval
  until a human has actually seen it.
- The mapping store (`anonymize/mapping_store.py`): Fernet-encrypted at
  rest, one key per store file via `keyring` (Windows Credential
  Manager/DPAPI, confirmed working on this machine), file-locked for
  concurrent access, with consistent per-entity-type coded identifiers
  (`PERSON_A`, `IN_PAN_A`, ...).
- The exact-match reversal pass (`reverse/reverse.py`), the audit logger,
  and the review-gate preview renderer (`review/preview.py`).

**Verified end to end, not just unit-tested**: a real CLI run against
synthetic CSV data, with the real Presidio/spaCy stack installed (not
mocked), correctly detected PII, wrote pseudonymized output, persisted the
mapping store, and `reverse()` recovered the original values from a
simulated LLM response. Three real bugs surfaced only by this run, none of
which any unit test caught (each fixed and now has a regression test —
see `tests/unit/test_analyzer_integration.py`):
1. A custom recognizer named `CreditCardRecognizer` crashed registry
   construction outright — Presidio resolves predefined-recognizer classes
   by a **global name match** across every loaded `EntityRecognizer`
   subclass, not by module path, and Presidio ships its own
   `CreditCardRecognizer`. Fixed by deleting the duplicate (Presidio's own
   already does Luhn validation) — see the project instructions'
   "Naming collision risk" correction.
2. **None of Presidio's India-specific built-ins were actually active** —
   `IN_PAN`, `IN_GSTIN`, etc. all ship `enabled: false` by default in this
   presidio-analyzer release; `load_predefined_recognizers()` alone never
   activates them. Fixed in `detect/analyzer.py::_INDIA_BUILTINS`.
3. `analyzer.analyze()` had no `score_threshold`, so every deliberately
   low-base-score custom recognizer fired unconditionally, and separately,
   every multi-word `context` list entry (`"account number"`) silently
   matched nothing since Presidio's context matcher checks single lemmas,
   not phrases. Both fixed — see `detect/analyzer.py`'s `SCORE_THRESHOLD`
   and every recognizer file's now-single-word `CONTEXT` lists.

**A fourth, subtler class of the same bug** surfaced later while building
the `IN_DATE_OF_BIRTH` recognizer (`detect/recognizers/dates.py`): even a
single-word context entry silently does nothing if it isn't the word's
**lemma**. `context=["born"]` never matches "Born on 15/08/1990" — spaCy
lemmatizes "born" to `"bear"` (its base verb form) — and the exact same
bug was already present in two other recognizers (`"driving"` → lemma
`"drive"`, `"filing"` → lemma `"file"` in `other_documents.py`), found only
by proactively auditing every context word's lemma after understanding the
mechanism, not by another smoke test. All three fixed, each with a
regression test (`test_analyzer_integration.py`'s
`test_dob_context_words_correctly_lemma_matched`,
`test_driving_license_context_lemma_is_correct`,
`test_itr_ack_context_lemma_is_correct`). See the project instructions'
"Presidio's context-word matching" bullet for the generalized rule.

**A real user's AIS (Annual Information Statement) document surfaced five
more findings**, none caught by any synthetic test up to that point — see
the project instructions' corresponding bullets for full detail:
1. Field labels and values on separate PDF lines never shared context
   (a bare mobile number scored 0.4, the same number with "Mobile:"
   nearby scored 0.75) — fixed with `pipeline.py::_context_window`
   (same-page neighbor blocks, joined with `" | "` specifically so regex
   patterns can't bridge across it while context-word matching and NER
   both still work) plus `_merge_detections` (a context-free pass and a
   windowed pass are both run per block; the larger span for a given
   entity always wins, so widening context can only add detections or
   grow a span, never shrink one — confirmed necessary: "Name of
   Assessee" as *preceding* context caused spaCy to drop "RAHUL" from
   "RAHUL KUMAR SHARMA").
2. spaCy tags short, decontextualized, non-sentence-like strings as
   `PERSON` regardless of context — a TDS quarter label, `"Q4(Jan-Mar)"`,
   scored 0.85 both with and without surrounding text. Fixed with a
   digit-plausibility filter on `PERSON` in `detect_in_block`
   (`_looks_like_a_person_name` — real names don't contain digits).
3. `"Q1(Apr-Jun)"`-style quarter ranges needed an explicit regex guard in
   `detect/recognizers/dates.py` (a month immediately followed by
   `-AnotherMonth` is now rejected) so they're never mistaken for a date.
4. The AIS/TIS portal's "Download ID" (`PAN + YYYYMMDD + HHMM`, no
   separator, e.g. `ABCDE1234F202501151030`) embeds a full PAN that
   `IN_PAN` can never see — every `IN_PAN` pattern ends in `\b`, and
   there's no word boundary between the PAN's last letter and the
   immediately-following digit. `detect/recognizers/ais.py` adds
   `AisDownloadIdRecognizer` (entity `AIS_DOWNLOAD_ID`) with
   `validate_result` checking the embedded date/time are plausible.
5. A new `ais` doc type (`config/allowlists.py`) — `_ALWAYS_SAFE` +
   the DOB entity, same reasoning as `form16`.

All five verified against a real end-to-end pipeline run (a synthetic PDF
reproducing the actual AIS layout: label/value pairs on separate lines,
a quarter label, and a Download ID), not just isolated analyzer probes —
every case now redacts correctly and the quarter label survives untouched.
Each has a regression test in `test_analyzer_integration.py`,
`test_context_window.py`, and `test_recognizers.py`.

**A second real bug in the same fix, reported after the above shipped**:
the user's actual AIS document still didn't redact any of the three
label/value pairs, even though a synthetic reproduction had. Root cause:
`_context_window`'s first version picked neighbors by *list index*
(`blocks[index-1]`/`blocks[index+1]`), silently assuming PDF extraction
order matches visual reading order. That's true for a test PDF built with
sequential `insert_text()` calls (which is all the original fix was tested
against) and **confirmed false and reproducible** for a PDF where a label
layer and a value overlay are drawn as separate passes, common for
portal-generated forms: a synthetic PDF inserting all labels first, then
all values second, confirmed directly that `page.get_text("dict")` returns
them in insertion order, not page-position order — so list-adjacency paired
every label with the wrong neighbor. Fixed by sorting same-page blocks by
`(bbox top-Y, bbox left-X)` before picking neighbors
(`pipeline.py::_reading_order_key`) instead of trusting list order.
Re-verified against the scrambled-insertion-order reproduction (not just
the original sequential-order test) — all three values now redact
correctly. Lesson generalized in the project instructions: a fix's test
suite that only exercises the happy-path construction method (here,
sequential `insert_text()`) can pass completely while missing the actual
real-world failure mode.

**But the column-aware fix still wasn't enough on the user's actual file** —
two more real, distinct bugs, found by inspecting the raw extracted bytes
of the real document directly rather than trusting printed/visual text:

1. **Multi-column tables need column-aware adjacency, not just visual
   sorting.** The bbox-sort fix above still sorted ALL same-page blocks in
   one flat (Y, X) order, which is wrong for a genuine multi-column table:
   the real AIS document lays out "PAN | Aadhaar | Name" as one label row
   and their values as the next row, three columns wide. For "Date of
   Birth" (column 1), the nearest block in a flat sort is "E-mail Address"
   (column 3's label, one row up) - not "Date of Birth" directly above it
   in column 1. Confirmed exactly why PAN/Email/Name still worked (they
   don't need context) while DOB/Mobile (context-dependent) didn't. Fixed
   by requiring horizontal bbox overlap before a block counts as a
   candidate neighbor at all (`pipeline.py::_horizontal_overlap_fraction`),
   then picking the nearest such same-column candidates above/below -
   nearest neighbor in the same column, not nearest neighbor in reading
   order. Re-verified against a synthetic 3-column reproduction and the
   real document.
2. **Some PDF generators encode word-separating spaces as Unicode control
   characters instead of actual spaces** - confirmed exactly `0x08`
   (backspace) and `0x05` (ENQ) in this document's font/cmap. This broke
   things at a more fundamental level than either context fix could
   touch: spaCy tokenizes `"Date\x08of\x08Birth"` as ONE token (confirmed
   directly), which can never match any context word regardless of how
   correctly its neighbor is found, and `"RAHUL\x05KUMAR\x05SHARMA"`
   similarly becomes one unrecognizable token instead of a normal
   three-word name NER can identify. Fixed in
   `extract/pdf.py::_normalize_text` (strips Unicode category-"Cc"
   control characters, collapses whitespace), applied once at extraction
   so detection, anonymization, and rendering all see the same clean text.

**A fifth bug surfaced once detection started actually firing correctly**:
PyMuPDF's redaction text-insertion silently renders nothing (or garbage -
confirmed: an 18-character marker in a box sized for a 10-character date
came out as the single stray character `"1"`) when a replacement doesn't
fit the original text's box, even at the original font size. Fixed with
`render/pdf.py::_safe_replacement_text` - only a replacement no longer
than the original text is trusted to fit (the original's own presence
proves its own length fits), falling back through shorter generic markers
(`"[REDACTED]"`, `"***"`, `"X"`) otherwise; `extract/pdf.py` now also
captures each line's real font size so replacements are sized correctly
instead of using PyMuPDF's 11pt default. Real, non-hidden consequence for
`pseudonymize` mode: a coded identifier that doesn't fit becomes a generic
fallback for that one occurrence, no longer parseable by `reverse()` (the
mapping store itself is unaffected).

All five bugs verified against the user's actual `sample/AIS.pdf`, not
just synthetic reproductions - the final run redacts Name/DOB/Mobile/PAN/
Email/Download ID cleanly with no garbled text and no leaked PII.

**A sixth gap, reported after all five above were confirmed working**: the
free-text "Address" field wasn't being redacted at all - a different kind
of gap than the previous five (those were all mechanism bugs; this was
missing coverage). Neither Presidio's built-ins nor any recognizer in this
project targeted unstructured postal addresses - spaCy's NER caught only
the trailing state name as `LOCATION` on the real address, and `LOCATION`
is deliberately excluded from every allow-list anyway. Added
`detect/recognizers/address.py::AddressRecognizer` (entity `IN_ADDRESS`,
in `_ALWAYS_SAFE`): a broad 20+-character address-punctuation pattern,
context-scoped on "address" - checked `presidio_analyzer.predefined_recognizers`
first (only an unrelated `MacAddressRecognizer` exists) before writing it.
Explicitly accepted, not hidden: this pattern can fire on ordinary long
prose sitting near an incidental "address" mention, same class of
tradeoff already accepted for `MutualFundFolioRecognizer`/
`RationCardNumberRecognizer` - no fixed format exists to match more
precisely. Verified against the real document: the address value now
redacts to `<IN_ADDRESS>` with the label untouched.

**A seventh bug, on a structurally different document**: a bank interest
certificate (`IntStatement.pdf`) redacted nothing at all, even after all
six AIS fixes above. Root cause was the opposite layout problem from the
AIS fix: AIS lays a field out as label-above-value (same column, different
row) — the exact relationship `_context_window`'s column-overlap search
was built to require. This document lays every field out as
label-*beside*-value on one row (e.g. `"Customer Id"` at one X position,
`"10023456"` immediately to its right, confirmed via bbox: same Y-range
274.2–289.3, non-overlapping X) — a value with no same-column neighbor at
all, so the existing search legitimately found zero context for it, not a
bug in the search itself so much as a layout the search was never built to
handle. There is no single adjacency rule that covers both conventions, so
`_context_window` now runs the column-overlap (up/down) search AND a
mirror-image row-overlap (left/right) search (`_vertical_overlap_fraction`,
analogous to the existing `_horizontal_overlap_fraction`), independently,
and merges whichever neighbors each direction finds. Confirmed non-breaking
for the AIS 3-column-table case: a value's same-row neighbors there are
just other columns' unrelated *values* (harmless extra context, not a
wrong label), while the correct label is still found by the unchanged
column search — verified by re-running the full AIS-derived test suite
(no regressions) plus a new same-row reproduction. Verified end to end
against the real `IntStatement.pdf`: the account number (`12345678901234`)
now redacts correctly (previously nothing did).

That same verification run also surfaced two *separate*, not-yet-fixed
gaps on this document, neither caused by the context-window layout bug:
the customer's name (`"MR. R RAJESH KUMAR"`, all-caps, first name
abbreviated to an initial) gets zero PERSON detections from spaCy even
with correct context sharing — confirmed via direct `analyzer.analyze()`
probe, an NER model limitation, not a pipeline bug — and the postal
address, while now sharing context correctly, still never fires because
`AddressRecognizer` is context-scoped on the literal word "address"
(see the sixth gap above) and this document's label is "Customer
Details", not "Address". Left open rather than papered over — see "Known,
deliberately unclosed gaps" below.

**Known, deliberately unclosed gaps** (each documented in its module's
docstring, not silently missing):
- **Structured per-cell extraction (CSV/XLSX/JSON only — PDF/image line
  blocks got a real fix, see above) gives the analyzer no sentence
  context** — a cell's value is analyzed on its own, so every
  context-word-scoped custom recognizer is effectively inert on structured
  data (a bank account number alone in its own cell won't cross the score
  threshold, even though the column header would tell a human instantly
  what it is). Real and current, not hypothetical — see `detect/
  analyzer.py`'s docstring. The fix is a field-name-driven fast path,
  already flagged as deferred in `extract/json_.py`/`extract/csv_.py` —
  "adjacent block in the list" has no spatial meaning for a cell the way
  it does for a PDF line, so the `_context_window` fix deliberately
  doesn't apply here.
- **Image/ID-card redaction only covers OCR'd text.** Faces, photos, and
  QR codes (an Aadhaar QR encodes the same data as the printed text) are
  untouched — see `extract/image.py`. Closing this needs either a
  full-image-blackout policy for a document type like `id_card_scan`
  (which would require extending `Renderer.render()`'s signature to carry
  `doc_type` — deliberately not done yet, see that module) or dedicated
  face/QR detection.
- **PDF**: XMP metadata and embedded thumbnails aren't scrubbed (only the
  classic docinfo dict is) — see `render/pdf.py`.
- **XLSX**: `docProps/app.xml` extended properties (Company, Manager) have
  no write API in openpyxl at all and can't be scrubbed — see
  `render/xlsx.py`. Whether a literal cell is itself a formula's input
  elsewhere in the workbook isn't determined (would need a full
  formula-dependency graph) — see `extract/xlsx.py`.
- **CSV**: line endings normalize to `\r\n` on write regardless of the
  source's actual line endings (a `csv.Sniffer` quirk, not a choice) — see
  `render/csv_.py`.
- **spaCy's NER misses all-caps, initial-abbreviated names** (e.g.
  `"MR. R RAJESH KUMAR"` — zero PERSON detections, confirmed via direct
  `analyzer.analyze()` probe, not a pipeline bug). No mitigation
  implemented; a real gap on documents that print names this way.
- **`AddressRecognizer` (see the sixth gap above) only fires near the
  literal word "address"** — a document whose label is e.g. "Customer
  Details" instead never triggers it even though the same free-text
  address block is present. Confirmed on `IntStatement.pdf`.
- **Overlapping detections of different entity types at the exact same
  span pick one label somewhat arbitrarily (highest score wins)** — e.g.
  a 14-digit account number matches `PHONE_NUMBER`, `BANK_ACCOUNT_NUMBER`,
  and `ITR_ACK_NUMBER` simultaneously and renders as `<PHONE_NUMBER>`. The
  value itself is still correctly redacted either way, but the marker
  text can be misleading in `redact` mode. Not fixed — would need an
  entity-type priority order, not just "highest score."

Run `pytest` to see what's covered today (214 tests as of this writing).

## Setup (Windows)

One-time, needs internet. After this, the tool runs fully offline — see
"No network calls" in the project instructions. See README.md for the
one-command `setup.ps1` script that does the following automatically.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
python -m spacy download en_core_web_lg
```

Install Tesseract OCR separately — it's a native binary, not a pip package
(e.g. the [UB Mannheim build](https://github.com/UB-Mannheim/tesseract/wiki)).
Either add it to `PATH` or point `pytesseract.pytesseract.tesseract_cmd` at
`tesseract.exe` in config. Without it, any scanned PDF page or JPEG/PNG
input fails closed with a clear error rather than silently skipping
detection on that content.

## Usage

```bash
redact input.pdf -o output/ --mode pseudonymize --doc-type form16
redact ./tax_docs/ -o ./tax_docs_redacted/ --mode redact
```

Every run stops at a human review gate before writing anything — see
"Human review is mandatory" in the project instructions. `--yes` skips the
interactive prompt but still refuses to write output for a document that
failed extraction or has unredactable (formula-derived/defined-name)
detections — those need a human to actually look at them first.

## Tests

```bash
pytest
```

Everything runs without Tesseract installed (OCR call sites are exercised
via monkeypatching or via their real, verified failure path when the
binary is absent). Two groups need extra setup and skip cleanly without
it: the Presidio-recognizer-shape tests (need `presidio-analyzer`
importable) and `test_analyzer_integration.py` (needs the spaCy model —
`python -m spacy download en_core_web_lg`). The latter is the one that
actually builds the real registry end to end and would have caught all
three bugs above; run it before trusting a change to `detect/analyzer.py`
or any recognizer's `CONTEXT`/entity name.

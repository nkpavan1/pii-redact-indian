# Claude Project Instructions — PII Redaction Wrapper Tool (Build Project)

## Project purpose

This project is for designing, building, and maintaining a local PII redaction and
pseudonymization tool for Indian personal documents (PDF, XLSX, CSV, JSON, and
standalone image scans — JPEG/PNG — of ID documents). The tool sits between the user's
raw documents and any LLM/AI agent: raw documents never leave the user's machine, only
redacted/pseudonymized output does. This is an engineering project — you are helping
write, review, and evolve the tool's code, not processing the user's actual personal
documents through it.

**Interface shape: CLI tool.** e.g. `redact <input> -o <output_dir> --mode
{redact|pseudonymize} [--doc-type <type>]`. Batch mode (a directory of mixed file
types) is a first-class case, not an afterthought — most real usage will be "redact
this folder of tax documents," not one file at a time.

**Human review is mandatory, not optional.** The pipeline always stops after detection
and before finalizing output, and shows the user a preview of what will be
redacted/pseudonymized — entity type, count, and location (page/cell/line), never the
raw value — for confirmation. There is no fully-automated "detect and ship" mode. This
is the primary defense against false negatives silently reaching an LLM; treat any
design that skips this gate as a regression, not an optimization. `--yes`/
non-interactive flags may exist for batch convenience but should still default to
writing output to a staging directory the user inspects before it's used, not directly
feeding an LLM pipeline.

## Environment: OS and hardware requirements

- **Primary target OS: Windows 11** (the user's actual machine) — pin setup
  instructions and testing to Windows first. The stack is pure Python except one
  native binary, so don't spend effort on cross-platform portability that isn't being
  tested.
- **Tesseract OCR is a separate native binary, not a pip package.** `pytesseract`
  only wraps it. On Windows: install it (e.g. the UB Mannheim build) and either add it
  to `PATH` or set `pytesseract.pytesseract.tesseract_cmd` explicitly in config.
  `pip install pytesseract` alone will not work — verify this at setup time, don't
  assume it.
- **Key storage backend**: use the `keyring` package so the mapping store's Fernet key
  lands in Windows Credential Manager (DPAPI-backed) rather than a plain file on disk —
  this is what "OS keychain" (mentioned in the security section) concretely means on
  this platform.
- **No GPU required.** Presidio, spaCy, and Tesseract all run CPU-only by default;
  this is a personal single-user tool, not something needing production throughput.
- **spaCy model choice is a real tradeoff, pick one deliberately**: `en_core_web_lg`
  (~500-600MB, fast, decent name recall) vs `en_core_web_trf` (transformer-based,
  better recall on Indian names in freeform text, noticeably slower on CPU). Start
  with `en_core_web_lg` for responsiveness; revisit `_trf` only if recall on Indian
  names proves inadequate in practice.
- **OCR is the slow stage** — expect on the order of a few seconds per scanned page on
  CPU. Don't optimize for throughput preemptively, but the CLI should show batch
  progress rather than appear to hang on a multi-page scanned document.
- Rough disk footprint (dependencies + spaCy model + Tesseract install) lands in the
  low single-digit GB — not worth engineering around, just don't be surprised by it.

## Architecture already decided — don't relitigate without reason

- **Core engine: Microsoft Presidio**, now maintained under the Data Privacy Stack
  organization (`github.com/data-privacy-stack/presidio`, MIT license). Use
  `presidio-analyzer` + `presidio-anonymizer` as the detection/anonymization core,
  `presidio-structured` for CSV/XLSX/JSON, `presidio-image-redactor` for scanned
  PDFs/images (OCR via Tesseract).
  - **`presidio-image-redactor` only redacts OCR-recognized text.** It does not do
    face detection and does not decode QR codes/barcodes. Indian ID cards (Aadhaar
    especially) carry a QR code encoding the same demographic data in machine-readable
    form, plus a photo — neither is touched by text redaction. For standalone
    JPEG/PNG scans of ID cards, treat the photo and any QR/barcode region as
    known gaps: document them explicitly, and consider either (a) full-image
    replacement/blackout for a defined set of "ID card" document types where the
    whole image is sensitive, or (b) a follow-up task to add face detection (e.g.
    OpenCV Haar/DNN) and QR-region blanking (`pyzbar` to locate, then blackout) if
    per-region redaction is needed. Don't ship a v1 that silently passes through a
    readable QR code while claiming the document is redacted.
- **PDF text extraction**: `pdfplumber` or `PyMuPDF` (need bounding boxes, not just
  text, to support visual redaction of the original PDF for audit purposes).
  - **True redaction, not cosmetic redaction**: drawing a black box over text is not
    redaction — the original characters remain in the content stream and are
    selectable/copyable/extractable. Use PyMuPDF's actual redaction annotations
    (`apply_redactions`), which remove the underlying text objects, not just an
    overlay. Any implementation that only draws a rectangle over PII is a security bug,
    not a cosmetic issue — treat it as such in code review.
  - **Scrub metadata too**: XMP metadata, document info dictionary (author, subject,
    custom properties), and embedded thumbnails can carry PII independent of page
    content. Strip or sanitize these on every processed PDF.
  - **AcroForm fields**: filled form field values (common in bank/tax PDFs) aren't
    always part of the page's visible text layer — extract and redact field values
    explicitly, don't assume page-text extraction catches them.
  - **Per-page native-vs-OCR routing**: a single PDF can mix native text pages with
    scanned/image pages (e.g., a signed page or embedded photo ID). Detect this
    per-page (e.g., page has near-zero extractable text → route that page through
    OCR) rather than picking one mode for the whole document.
  - **Reading-order/bbox alignment**: multi-column layouts and tables can make
    extracted text order diverge from visual layout, which can misalign a detected
    entity's character offsets with its bounding box. Validate bbox-to-text mapping
    with a test case that includes a multi-column page before trusting visual
    redaction placement.
  - Digital signatures will be invalidated by any redaction that modifies page
    content — document this as expected behavior, don't try to preserve signatures on
    a redacted output.
- **Built-in Indian recognizers already available in Presidio**: `IN_PAN`,
  `IN_AADHAAR`, `IN_PASSPORT`, `IN_VOTER`, `IN_VEHICLE_REGISTRATION`, `IN_GSTIN`
  (yes, GSTIN too — see the correction below). Don't rewrite these — extend the
  registry instead.
  - **CORRECTION, verified directly against an installed presidio-analyzer
    (2.2.364, `data-privacy-stack/presidio`), not assumed from docs**: every one of
    these ships with `enabled: false` in Presidio's own default recognizer conf —
    `registry.load_predefined_recognizers()` alone does **not** activate any
    country-specific recognizer, India's included. `countries=["in"]` does not
    override this either (it only filters among recognizers already enabled). The
    fix is to import and `registry.add_recognizer()` each India-specific class
    explicitly, exactly like a custom recognizer (see
    `src/pii_redact/detect/analyzer.py::_INDIA_BUILTINS` for the working
    implementation). This was found only by an end-to-end smoke test — every
    recognizer-level unit test instantiated the class directly, bypassing the
    registry-loading path where the gate lives. If a future session is debugging
    "IN_PAN isn't detecting anything," check this first before assuming the pattern
    or scoring is wrong.
  - **GSTIN correction**: Presidio's own `InGstinRecognizer` (entity `IN_GSTIN`)
    already exists and does real checksum validation, better than a hand-rolled
    format-only duplicate would. An earlier version of this project built a custom
    `GstinRecognizer` before this was discovered — don't reintroduce it.
- **Still need custom `PatternRecognizer`s for**: IFSC code, UPI ID, bank
  account number, driving license number, EPF/UAN, demat/DP ID, TAN (Tax Deduction
  Account Number), CIN (Corporate Identification Number), ITR acknowledgement number,
  CKYC number, mutual fund folio number, and ration card number. Credit/debit card
  numbers are also **not** custom — Presidio's own `CreditCardRecognizer` (entity
  `CREDIT_CARD`) already does Luhn validation. A custom recognizer literally named
  `CreditCardRecognizer` was built once, before this was discovered, and its
  identical class name to Presidio's own built-in **crashed registry construction**
  with a bare `TypeError` (Presidio resolves predefined-recognizer classes by a
  global name match across every currently-loaded `EntityRecognizer` subclass, not
  by module path) — a real, load-bearing lesson: **before adding any custom
  recognizer, check `presidio_analyzer.predefined_recognizers` for whatever class
  name you're about to use**, both to avoid duplicating existing coverage and to
  avoid a name collision that won't surface until the full registry is built (no
  isolated unit test of the recognizer class will catch it).
  - **Naming collision risk**: "PAN" means Permanent Account Number (Presidio's
    `IN_PAN`) in this domain, but card numbers are also colloquially "PAN" (Primary
    Account Number) in payments contexts. Keep these as distinct recognizer/entity
    names (e.g. `IN_PAN` vs `CREDIT_CARD`) and never let the abbreviation collide in
    code, config, or allow-lists.
  - Confirm Indian mobile numbers (10-digit, +91) are actually caught by Presidio's
    generic `PHONE_NUMBER` recognizer with the `en_IN`/India locale context before
    assuming coverage — don't assume, write a test.
- **Consistent pseudonymization ("coded names")**: a custom Presidio anonymizer
  operator backed by a local key-value mapping store (same real value → same code,
  e.g. `PERSON_A`, `PAN_A`, persisted across documents/sessions). This mapping store
  is the single most sensitive artifact in the system — see security requirements
  below.
- **Entity scoping discipline**: never blanket-redact by entity type when the type
  overlaps with computation-relevant data. `DATE_TIME` and `LOCATION` are the known
  problem cases — date of birth must be redacted, but transaction dates and holding
  periods must not be. Use context-word-scoped recognizers (e.g. DOB only fires near
  "date of birth"/"DOB"/"born on") rather than anonymizing the whole entity type.
  Maintain an explicit per-document-type allow-list of which entities actually get
  anonymized.
- **`analyzer.analyze()` needs an explicit `score_threshold` — it does not filter
  anything on its own.** Found the hard way: several of this project's custom
  recognizers are deliberately given a low base score (0.15–0.3) so they stay silent
  without a context-word boost — that design is inert unless something actually
  filters low scores, which nothing does by default. `src/pii_redact/detect/
  analyzer.py::SCORE_THRESHOLD = 0.5` is what makes the low-base-score design work;
  don't call `analyze()` anywhere without passing it.
- **Presidio's context-word matching is single-lemma, not phrase-based — and it
  compares the LITERAL context-list string against the LEMMA of each surrounding
  document token, without lemmatizing the context list itself.** Two distinct ways
  to get this wrong, both found in this project's own code, both silent (nothing
  fails loudly — the boost just never happens):
  1. **Phrases don't match at all.** A `context=["account number"]` entry never
     matches anything — the doc tokenizes it as two separate words. Every context
     list must be individual words (`["account", "acc", "bank"]`, not `["account
     number", "bank account"]`).
  2. **The wrong surface form doesn't match either, even as a single word.**
     `context=["born"]` never matches "Born on 15/08/1990" — spaCy lemmatizes
     "born"/"Born" to **"bear"** (its base verb form), and the context list must
     contain the lemma, not the word you'd naturally write. Same root cause hit
     `"driving"` (lemma `"drive"`) and `"filing"` (lemma `"file"`) in
     `other_documents.py`. Before adding any new context word, check its lemma
     directly: `import spacy; spacy.load("en_core_web_lg")(word)[0].lemma_` — do not
     assume a word lemmatizes to itself just because most nouns do.
  Both classes are easy to reintroduce by accident when adding a new recognizer;
  write a with-context-vs-without-context score comparison test for any new
  context-scoped recognizer to catch either one immediately (see
  `test_analyzer_integration.py` for the pattern).
- **Structured per-cell extraction (CSV/XLSX/JSON) gives the analyzer no sentence
  context.** A cell's value is handed to `analyze()` on its own — the column/field
  name is not part of that string — so every context-word-scoped recognizer above is
  effectively inert on structured data: a bank account number sitting alone in its
  own cell will not cross the score threshold even though a human reading the column
  header would recognize it instantly. This is real and currently unmitigated, not
  just a theoretical edge case. The correct fix is a field-name-driven fast path
  (redact by known column/key name, falling back to NER only for unrecognized
  fields) — already flagged as a deferred TODO in `extract/json_.py` and
  `extract/csv_.py`'s docstrings — not a scoring tweak. **PDF/image line blocks got a
  different, real fix instead** (see next bullet) — this gap is now CSV/XLSX/JSON-only.
- **PDF/image label-value pairs on separate lines share context now — found via a
  real user's AIS document, not a synthetic test.** A real AIS PDF puts "Date of
  Birth" as one line and the actual date on the next; "Name of Assessee" as one line,
  the name on the next. Since `detect_in_block` originally analyzed each line block
  completely alone, neither the DOB recognizer's context words nor Presidio's own
  `PHONE_NUMBER` context boost ever saw the label — confirmed directly: a bare mobile
  number scores 0.4 (below threshold), the same number with "Mobile:" nearby scores
  0.75. Fixed in `pipeline.py::_context_window`: for `PDF`/`IMAGE` blocks only (CSV/
  XLSX/JSON blocks have no meaningful "next line" relationship — see previous bullet),
  build a window from same-page neighbor blocks (radius 1) and analyze that instead,
  translating offsets back to the target block. Three non-obvious design points, each
  verified by direct probe before committing to it:
  1. **Join with `" | "`, never a bare newline/space.** A plain `"\n"` is whitespace,
     and this project's date regexes accept whitespace as a separator between date
     components (`[\s\-]+`), so a date could otherwise be assembled by BRIDGING two
     unrelated blocks that happen to sit next to each other (e.g. a day number ending
     one line, a month starting the next). `"|"` isn't in any of those character
     classes, so regex patterns can never bridge across it, while Presidio's
     token-distance-based context matching and spaCy's NER (which stops a `PERSON`
     span at the `"|"` token rather than swallowing into the next block) both still
     work correctly across it.
  2. **Clip an out-of-range detection to the block's own bounds — never reject it
     outright.** A NER span can bleed a token or two past the intended line boundary
     (confirmed: `PERSON` on `"RAHUL KUMAR SHARMA\nName of Assessee"` swallowed
     `"\nName"` when joined with a bare newline). Clipping to `[context_offset,
     context_offset + len(block.text))` is safe specifically because that boundary is
     a real separator the caller inserted, not an arbitrary cut through the block's
     own content — the clipped-off part was never actually this block's text.
  3. **Run the block ALONE too, and merge — widened context must only ever ADD
     detections or GROW a span, never shrink one.** Confirmed directly: analyzed
     alone, spaCy correctly finds all of `"RAHUL KUMAR SHARMA"` as one `PERSON` span;
     with `"Name of Assessee"` as *preceding* context, it finds only `"KUMAR SHARMA"`
     — the first name silently drops. `pipeline.py::_merge_detections` runs both a
     context-free pass and a windowed pass per block and keeps whichever span is
     larger for the same entity type at an overlapping position, so this widening is
     a pure improvement rather than trading one bug for another.
  4. **CORRECTED on the same real document, second round: "neighbor" means
     adjacent by VISUAL POSITION, not adjacent by list index.** The first version of
     `_context_window` used `blocks[index-1]`/`blocks[index+1]` — i.e. it assumed PDF
     text extraction order matches visual reading order. True for a test PDF built
     with sequential `insert_text()` calls; **false and confirmed reproducible** for a
     PDF where a label layer and a value overlay are drawn as separate passes (common
     for portal-generated forms): built a synthetic PDF inserting ALL labels first,
     then ALL values second, and confirmed directly that `page.get_text("dict")`
     returns them in that INSERTION order, not sorted by page position — "Name of
     Assessee" (y=60), "Date of Birth" (y=120), "Mobile Number" (y=180), THEN "RAHUL
     KUMAR SHARMA" (y=80), "15/08/1990" (y=140), "9876543210" (y=200), even though
     visually each value sits directly below its label. List-adjacency paired every
     block with the wrong neighbor in that arrangement. Fixed by sorting same-page
     blocks by `(bbox top-Y, bbox left-X)` before picking neighbors
     (`pipeline.py::_reading_order_key`), not by their position in `extracted.blocks`.
     Still an accepted, separately-documented limitation for genuine multi-column
     pages (pure Y-sorting can interleave two side-by-side columns) — see
     `extract/pdf.py`'s existing reading-order caveat, which this directly confirms is
     not just theoretical. **Generalized lesson: don't assume any extractor's output
     list order reflects visual layout — check it directly against a document built
     to violate that assumption, the same way this was found**, rather than trusting
     a single happy-path synthetic test (the original context-window fix shipped with
     tests that all used sequential-insertion PDFs, which is exactly why this second
     bug wasn't caught the first time).
  5. **A THIRD real bug, on the same document, hiding underneath the first two**:
     some PDF generators encode a space between words as a Unicode CONTROL character
     instead (confirmed exactly `0x08` backspace and `0x05` ENQ — almost certainly a
     font/cmap substitution bug in whatever tool produced this AIS PDF). Neither of
     the two fixes above could matter until this was found, because the corrupted
     text broke tokenization before context-sharing was even relevant: spaCy
     tokenizes `"Date\x08of\x08Birth"` as ONE token (lemma `"date\x08of\x08birth"`,
     confirmed directly), which can never match `context=["dob","birth","bear"]` no
     matter how correctly its neighbor is found, and `"RAHUL\x05KUMAR\x05SHARMA"`
     similarly becomes one unrecognizable token instead of a normal three-word name
     NER can identify. Fixed in `extract/pdf.py::_normalize_text` — replaces every
     Unicode control character (category `"Cc"`) with a space and collapses
     whitespace runs, applied once at extraction so detection, anonymization, AND
     rendering all see the same clean `TextBlock.text`. **Generalized lesson: text
     corruption can masquerade as a detection/scoring/context problem** - the first
     symptom (DOB/Mobile/Name not redacting) looked identical whether the cause was
     "wrong neighbor" or "corrupted tokens"; only inspecting the actual raw extracted
     bytes (not just visually plausible-looking printed text) distinguished them.
  6. **A FOURTH real bug, found only after the first three were fixed and detection
     started actually firing**: PyMuPDF's redaction text-insertion does not auto-fit
     or overflow-and-still-render when a replacement is wider than the original
     text's box — it silently renders NOTHING, or truncates into garbage. Confirmed
     directly: a 10-character date replaced with the 18-character marker
     `"<IN_DATE_OF_BIRTH>"` came out as the single stray character `"1"` — even after
     matching the original font size exactly, and even at font sizes small enough
     that `pymupdf.get_text_length()` predicted the text should fit. PyMuPDF's
     internal fitting logic is stricter than that measurement in ways that could not
     be reliably reverse-engineered by testing. Fixed in `render/pdf.py`:
     `_safe_replacement_text` only trusts a replacement no longer than the original
     text (the original's own presence is proof its own length fits that box),
     falling back through progressively shorter generic markers (`"[REDACTED]"`,
     `"***"`, `"X"`) otherwise — and `extract/pdf.py` now captures each line's
     original font size (`source_ref`'s third element) so the replacement is drawn
     at the right size, not PyMuPDF's default 11pt. **Real, documented consequence
     for `pseudonymize` mode**: a coded identifier that doesn't fit renders as a
     generic fallback instead, so that specific occurrence is no longer parseable by
     `reverse()` — the mapping store itself is unaffected, only that one rendered
     occurrence loses its visible code. **Generalized lesson: don't trust a
     rendering library's internal text-fitting logic to fail safely (overflow
     visibly, or raise) — verify what it actually does when content doesn't fit,
     because silent garbage or silent blankness are both real, observed failure
     modes here, not just failure BY exception.**
- **A short, decontextualized, non-sentence-like string can fool spaCy's `PERSON`
  NER regardless of context — this is NOT a context-window side effect.** Found on
  the same AIS document: a TDS quarter label, `"Q4(Jan-Mar)"`, is tagged `PERSON` at
  0.85 confidence whether analyzed alone or with real surrounding context. Fixed with
  a plausibility filter in `detect_in_block` (`_looks_like_a_person_name`): a `PERSON`
  detection is discarded if its matched text contains a digit — real names don't
  contain digits, so this is cheap and safe, same spirit as this project's other
  `validate_result`-style checksum/format checks, just applied to a built-in
  NER-based entity this project can't subclass `validate_result` on directly.
- **A well-known Indian tax-document convention needed an explicit regex guard:
  quarter ranges look date-adjacent but are not dates.** `"Q1(Apr-Jun)"`,
  `"Q4(Jan-Mar)"`, etc. must never match the DOB day-month-year/month-day-year
  patterns. `detect/recognizers/dates.py` now rejects a month name immediately
  followed by a dash and a second month name. (Manual regex tracing could not
  conclusively reproduce the exact match path from the original bug report against
  the patterns as they stood — this guard was added proactively because the shape is
  common and predictable in this document class. If it recurs, the actual extracted
  line of text is needed to diagnose further; the true cause could also be a PDF
  extraction reading-order/adjacency quirk rather than the regex.)
- **A concatenated ID can embed a full PAN and still be invisible to `IN_PAN`.** The
  AIS/TIS portal's "Download ID" (printed on every AIS/TIS download) is `PAN +
  YYYYMMDD + HHMM` with no separator, e.g. `ABCDE1234F202501151030`. Every `IN_PAN`
  pattern ends in `\b` (a word-boundary assertion), and there is no boundary between
  the PAN's last letter and the immediately-following date digit — both are "word"
  characters to a regex engine. Confirmed directly: none of `InPanRecognizer`'s three
  patterns match anywhere in a real Download ID string. `detect/recognizers/ais.py`
  adds `AisDownloadIdRecognizer` (entity `AIS_DOWNLOAD_ID`) specifically for this,
  with `validate_result` checking the embedded date/time are plausible (real
  year/month/day/hour/minute ranges) rather than relying on shape alone. **General
  lesson: a fixed-length ID that concatenates a known-sensitive field with other data
  and no separator is a blind spot for any recognizer whose pattern relies on a
  trailing `\b`** — worth checking for on any new document type.
- **`ais` doc type added** (`config/allowlists.py`) for AIS (Annual Information
  Statement) documents: includes `_ALWAYS_SAFE` + the DOB entity (AIS has a genuine
  Date of Birth field, same reasoning as `form16`) and, via `_ALWAYS_SAFE`,
  `AIS_DOWNLOAD_ID`. Bare `DATE_TIME`/`LOCATION` are deliberately absent, same as
  every other entry — AIS is dense with quarterly TDS/TCS and SFT transaction/
  reporting dates that must survive.
- **A sixth real bug on the same document, after the first five were all fixed**: the
  free-text "Address" field wasn't redacted at all. Neither Presidio's built-ins nor
  any recognizer in this project targets unstructured postal addresses — confirmed
  directly: spaCy's NER caught only the trailing state name ("PRADESH") as `LOCATION`
  on the real address, and `LOCATION` is deliberately excluded from every allow-list
  anyway (a city name can be computation-relevant elsewhere). Checked
  `presidio_analyzer.predefined_recognizers` first, per the lesson above — only
  `MacAddressRecognizer` exists (network MAC addresses, unrelated) — before adding
  `detect/recognizers/address.py::AddressRecognizer` (entity `IN_ADDRESS`): a broad
  20+-character pattern of typical address punctuation, context-scoped on
  `"address"`, favoring completeness over precision since no fixed format exists to
  match more precisely. **Explicitly accepted tradeoff, not hidden**: this pattern
  can and does fire on ordinary long prose sitting near an incidental "address"
  mention (confirmed directly, has a regression test) — same class of tradeoff
  already accepted for `MutualFundFolioRecognizer`/`RationCardNumberRecognizer`.
  Added to `_ALWAYS_SAFE` (a postal address is never computation-relevant, unlike
  dates/amounts). **Generalized lesson: "all other fixes are working" does not mean
  "nothing else is missing"** — a document can have several independent PII fields,
  each needing its own coverage; fixing the mechanism (context-sharing, text
  normalization, rendering) doesn't automatically mean every entity TYPE has a
  recognizer for it yet. Audit what fields exist in a document class before
  declaring it "handled."
- **A seventh real bug, on a structurally DIFFERENT document than the six AIS
  fixes above**: a bank interest certificate (`IntStatement.pdf`) redacted nothing
  at all, even with every AIS fix in place. Root cause: the column-overlap adjacency
  fix (`_horizontal_overlap_fraction`, second bullet's item 4-successor above) was
  built specifically to require a VERTICAL (same-column, different-row) relationship
  between a block and its context neighbors — correct for AIS's label-above-value
  convention, but this document uses the OPPOSITE convention, label-BESIDE-value on
  one row (confirmed via exact bbox: `"Customer Id"` and `"10023456"` share the same
  Y-range 274.2–289.3 with non-overlapping X — same row, different column). A value
  in this layout has no same-column neighbor at all, so the existing search correctly
  found nothing — not a logic bug in that search, but a second, equally common layout
  convention it was never built to cover. **There is no single adjacency rule that
  covers both conventions.** Fixed by running the column-overlap (up/down) search AND
  a mirror-image row-overlap (left/right) search, independently, in
  `pipeline.py::_context_window` — added `_vertical_overlap_fraction` (identical logic
  to `_horizontal_overlap_fraction`, transposed to the Y axis) and a shared
  `_nearest_in_direction` helper for all four directions. Confirmed non-breaking for
  the ORIGINAL AIS 3-column-table bug this replaced: a value's new same-row neighbors
  in that layout are other columns' unrelated VALUES (e.g. the DOB value's row-neighbor
  is the mobile-number value, not a label) — harmless extra context, not a wrong label,
  since the correct label is still found by the unchanged column search. Re-verified
  the entire AIS-derived regression suite passes unchanged, plus new tests for the
  same-row case, plus a live run against the real `IntStatement.pdf`: the account
  number now redacts correctly (previously nothing did). **Generalized lesson: an
  adjacency/layout fix tuned tightly to one real document's exact convention (here,
  "neighbors must share a column") can be simultaneously CORRECT for the document it
  was built against and a hard blocker for a different, equally valid layout
  convention — a fix scoped by "and NOT this other relationship" is a narrower claim
  than "and this relationship", and needs re-examination against a structurally
  different document, not just more documents in the same family.**
  Two further gaps surfaced by this same verification run, left open (not fixed) —
  see "Known, deliberately unclosed gaps" in IMPLEMENTATION.md: spaCy's NER emits zero
  `PERSON` detections for `"MR. R RAJESH KUMAR"` (all-caps, initial-abbreviated first
  name — confirmed via direct `analyzer.analyze()` probe, a model limitation, not a
  pipeline bug), and `AddressRecognizer`'s context-scoping on the literal word
  "address" (sixth bullet above) means it never fires on this document, whose label is
  "Customer Details" — the address text itself is otherwise unchanged from the AIS
  case that motivated that recognizer.
- **Before adding ANY custom recognizer, check whether Presidio already ships one**
  by inspecting `presidio_analyzer.predefined_recognizers` (`dir()` it, or check the
  installed version's `conf/default_recognizers.yaml`) — for both the entity and the
  exact class name. Two custom recognizers in this project (GSTIN, credit card) were
  built before this was checked, one merely redundant, the other crashing registry
  construction outright via a class-name collision — see the correction above. This
  check takes thirty seconds and would have caught both before they were written.
- **Aadhaar/PAN precision**: regex confirms format, not the checksum digit. Add a
  Verhoeff-algorithm validator as a second-pass filter on `IN_AADHAAR` if false
  positive/negative rate matters for a given use case.

Deviating from this stack is fine if there's a concrete reason (a gap Presidio can't
cover, a performance problem, etc.) — but default to extending Presidio's
recognizer/operator framework rather than building a parallel detection system. If
you're about to write a general-purpose NER model or regex engine from scratch, stop
and check whether Presidio already has a hook for it first.

## Pipeline stages

Keep these as separate, independently testable stages — a bug or format quirk in one
should never require touching another:

1. **Ingest**: resolve input (single file or directory), detect format (extension +
   magic-byte sniff, don't trust extensions alone), route to the matching extractor.
2. **Extract**: pull text + layout (bounding boxes / cell coordinates / JSON paths)
   without pulling PII into logs. For PDFs, decide native-text vs OCR *per page*, not
   per document — a scanned signature or ID-card photo can be one page inside an
   otherwise-native tax PDF.
3. **Detect**: run the Presidio analyzer with the per-document-type entity allow-list
   (see below) against extracted text/cells.
4. **Preview / human review gate**: show counts + locations by entity type, wait for
   confirmation (see interface section above). Nothing is written past this point
   without explicit go-ahead.
5. **Anonymize/pseudonymize**: apply the chosen operator (mask, redact, or the
   consistent-code operator backed by the mapping store).
6. **Re-render output**: write the redacted/pseudonymized artifact in the *same
   format* as the input where feasible (redacted PDF stays a PDF with searchable
   non-PII text intact, not flattened to an image — flattening kills accessibility and
   usefulness for the eventual LLM consumer).
7. **Audit log**: entity type, count, document identifier only — see security section.

**Fail-closed is a hard requirement**: if extraction fails, a page can't be OCR'd, or a
sheet/column can't be parsed, the pipeline must refuse to emit that document rather
than passing the unprocessed original (or a partially-processed one) through silently.
Surface the failure to the user in the preview step instead.

## Structured data (XLSX/CSV/JSON) gaps to handle explicitly

- **XLSX**: formulas that reference a cell whose value gets replaced will silently
  recompute against the redacted/pseudonymized value — decide per-column whether a
  cell is a formula input (preserve) or a display value (safe to replace), don't just
  overwrite in place. Also handle: hidden sheets, hidden/grouped rows and columns
  (PII often hidden rather than deleted), cell comments/notes, defined names, and
  workbook/document properties (author, company) — all can carry PII the visible
  grid doesn't.
- **CSV**: don't assume UTF-8 — Indian bank/tax exports often use UTF-8-with-BOM or
  legacy encodings; sniff encoding and delimiter rather than hardcoding both. Handle
  header vs. headerless files explicitly (field-name-based allow-lists need a header
  row to key off).
- **JSON**: recursive traversal of arbitrary nesting/arrays is required — don't assume
  a flat record. Decide the detection strategy up front: field-name-driven (redact by
  key, e.g. `"pan_number"`) is fast and precise but misses PII in oddly-named or
  free-text fields; value-level NER scanning of every string catches more but is much
  slower on large files. Likely need both: a fast field-name allow/deny list for known
  keys, falling back to NER scanning for unrecognized string fields.

## Coding standards for this project

- Prefer Presidio's documented extension points (`PatternRecognizer`, custom
  operators, `registry.add_recognizer`) over monkeypatching or forking Presidio
  internals.
- Every new recognizer (built-in or custom) needs a short comment noting what it
  detects, its known false-positive/negative risks, and whether it has checksum
  validation.
- Keep the ingestion layer (format detection → extraction) decoupled from the
  detection/anonymization layer, so adding a new document format doesn't touch
  recognizer logic.
- No network calls anywhere in the redaction path — this tool's entire value
  proposition is that nothing leaves the machine before redaction happens. Flag it
  immediately if a suggested dependency phones home (telemetry, license checks,
  cloud-backed NER models, etc.). **Scope of this rule**: one-time setup (`pip
  install`, `spacy download` for the NER model, Tesseract install) is expected to need
  internet once; after setup, the tool must run fully offline with zero network
  access. Verify any new dependency doesn't do first-run telemetry pings or
  license-check calls at *runtime* even if install itself is online.
- Write unit tests with synthetic Indian PII (fabricated PAN/Aadhaar-shaped values,
  fake names) — never real personal data — covering: correct detection, correct
  consistent-code reuse across multiple documents, and correct preservation of
  computation-relevant fields (dates, amounts) that share an entity type with
  redacted fields. Also required:
  - **True-redaction verification**: after redacting a PDF, re-extract its text and
    assert the raw PII pattern is *absent* from the content stream — not just visually
    covered. This is the automated guard against the cosmetic-overlay bug described
    above.
  - **Round-trip reversal test**: pseudonymize a synthetic document, simulate an
    LLM echoing the coded identifiers back, run `reverse()`, and assert the original
    synthetic values come back correctly.
  - **Negative tests for scoped entities**: assert transaction dates/amounts and
    holding-period dates survive a `DATE_TIME`-adjacent redaction pass unchanged, per
    document type.
  - Pin the Presidio version and re-run the full synthetic test suite before bumping
    it — recognizer behavior/confidence scores can shift between releases.
- Document known limitations plainly in code comments and in any README (e.g. NER
  recall on Indian names, checksum coverage) rather than implying the tool guarantees
  100% detection — Presidio itself doesn't claim that, and neither should this wrapper.

## Security requirements for the mapping store

- The real-value ↔ coded-identifier mapping is encrypted at rest (e.g. Fernet/AES)
  with a key that stays local and is never logged, committed, or transmitted. Decide
  and document explicitly where the key itself lives (OS keychain preferred over a
  plain key file) — the mapping store's encryption is worthless if the key sits
  unprotected next to it.
- **Key loss = permanent unreversibility.** Losing the local key means every
  pseudonymized document becomes permanently unreversible (this is arguably a feature,
  not just a risk, but it must be a documented, deliberate tradeoff — not a surprise).
  Consider whether the tool should support an optional encrypted backup/export of the
  key, and if so, make that an explicit opt-in, not a default.
- **Value normalization before lookup**: the same real-world value can appear in
  multiple surface forms (`"Rahul Kumar"` vs `"RAHUL KUMAR"` vs extra whitespace, or a
  PAN with/without spaces). Normalize before using a value as the mapping-store key,
  or the same person/document will silently get multiple different codes across
  documents — which defeats the entire point of *consistent* pseudonymization. Also
  consider (and document) the inverse risk: two distinct real values normalizing to
  the same key.
- **Concurrency**: if batch processing can run multiple documents in parallel, the
  mapping store needs real locking/transactional writes — a race on "is this value
  already mapped" can produce duplicate codes for the same value.
- Design for the mapping store to be the thing that lets a human reverse a coded
  identifier back to a real value at the very end of a workflow — the LLM/agent side
  never has access to it and never should.
- **Reversal workflow needs its own design, not just the mapping store.** The stated
  end goal is: send pseudonymized document → LLM/agent processes it and returns
  output containing the coded identifiers (e.g. `PERSON_A`, `PAN_A`) → tool substitutes
  real values back in for the human. That reverse-substitution step doesn't exist yet
  in the plan. It needs to handle: the LLM echoing codes back verbatim (the easy case,
  just an exact-match substitution pass) vs. the LLM paraphrasing, mis-transcribing, or
  partially reproducing a code (e.g. `Person A` instead of `PERSON_A`) — decide
  up front whether the tool only does exact-match reversal (simpler, safer, recommend
  starting here) or attempts fuzzy matching (higher recall, higher risk of
  reversing/substituting the wrong value into the wrong place). Build this as an
  explicit `reverse(text, mapping_store) -> text` function with its own tests, not an
  afterthought bolted onto the anonymizer.
- Any audit logging records entity type, count, and document identifier — never the
  actual detected value. Also log confidence scores per detection (not the value) —
  useful for tuning thresholds without ever needing to look at real data.

## Scope boundaries

- This project's job is building and testing the tool, not running it against the
  user's real tax/financial documents — that happens locally, outside this
  conversation, once the tool exists.
- If asked to help debug an issue using real output from the tool, treat any
  unredacted-looking values in logs or test output the same as elsewhere: flag them,
  don't propagate them into further discussion.

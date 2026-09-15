# Personal Identity Information (PII) Redaction Tool 

A local command-line tool that redacts or pseudonymizes PII in Indian
personal documents — PDF, XLSX, CSV, JSON, and JPEG/PNG ID scans — so raw
documents never have to leave your machine before you hand them to an
LLM, an AI agent, or anyone else.

## Why this exists

Sending a real bank statement, Form 16, or Aadhaar scan to an AI tool for
help means trusting that tool (and its provider, and its logs) with a
name, PAN, Aadhaar number, account number, and more. `pii-redact` sits
between your raw documents and any AI/LLM workflow: it finds the PII,
replaces it — either with a plain `<ENTITY_TYPE>` marker or with a
consistent coded identifier you can reverse later (`PERSON_A`, `IN_PAN_A`)
— and only the redacted output ever leaves your machine. Detection,
redaction, and (for pseudonymize mode) reversal all happen locally; no
document content is ever sent anywhere over the network.

## How it works

Every document goes through the same seven-stage pipeline, regardless of
format:

```
ingest → extract → detect → review gate → anonymize → render → audit log
```

1. **Ingest** — the file's real format is detected from its bytes, not
   trusted from its extension.
2. **Extract** — a format-specific extractor (PDF, XLSX, CSV, JSON, image)
   pulls out every string that could plausibly hold PII, together with
   exactly where it came from (a cell reference, a page/bbox, a JSON path
   — whatever lets it be found again).
3. **Detect** — each extracted string is run through Presidio (see
   below) with a per-document-type allow-list, so e.g. a date of birth
   gets flagged but a transaction date on a bank statement doesn't. For
   PDF and image pages, a value shares detection context with the
   nearest label above, below, or beside it on the same page — some
   documents put a field's label on the line above its value (e.g. "Date
   of Birth" / "15/08/1990"), others put label and value side by side on
   the same row (e.g. "Customer Id : 10023456") — and neither means
   anything to the detector on its own either way.
4. **Review gate** — nothing is written yet. You see counts and
   locations by entity type — never a raw value — and confirm before
   anything is touched. This step cannot be skipped; there is no fully
   automated "detect and ship" mode.
5. **Anonymize** — approved detections are replaced: a plain marker in
   `redact` mode, or a stable coded identifier (backed by a local
   encrypted mapping store) in `pseudonymize` mode.
6. **Render** — the format-specific writer puts the anonymized values
   back in place — a real redacted PDF (not a page flattened to an
   image), a valid XLSX with formulas intact, etc. — and strips document
   metadata (author, title, ...) on every file it touches.
7. **Audit log** — entity type, count, and document name only. The
   actual PII value is never logged.

For `pseudonymize` mode, once an AI tool has processed the pseudonymized
document and handed back a response referencing `PERSON_A` or `IN_PAN_A`,
the same local mapping store lets you reverse those codes back to the
real values — the AI never sees them, but you still get a normal answer.

## Presidio: the detection core

PII detection and anonymization are built on
[**Microsoft Presidio**](https://github.com/data-privacy-stack/presidio)
(now maintained by the community under the Data Privacy Stack
organization, MIT licensed) rather than a hand-rolled NER/regex engine:

- **`presidio-analyzer`** finds PII in text — a mix of an NLP model
  (spaCy, for names/organizations/locations) and pattern recognizers
  (regex + validation, for structured IDs like card numbers or Aadhaar).
- **`presidio-anonymizer`** applies an action to what was found — replace,
  mask, or (via a custom operator this project adds) swap in a
  consistent coded identifier backed by the local mapping store.

Presidio ships broad built-in coverage, including several Indian
identifiers (`IN_PAN`, `IN_AADHAAR`, `IN_GSTIN`, `IN_PASSPORT`, `IN_VOTER`,
`IN_VEHICLE_REGISTRATION`) — this project activates those explicitly (they
ship disabled by default) and layers on custom pattern recognizers for
everything else India-specific that Presidio doesn't cover: IFSC code, UPI
ID, bank account number, driving license, EPF/UAN, demat/DP ID, TAN, CIN,
ITR acknowledgement number, CKYC number, mutual fund folio number, ration
card number, a context-scoped date-of-birth recognizer (`IN_DATE_OF_BIRTH`
— a plain date is never redacted, only one that appears near "DOB"/"date
of birth"), an AIS/TIS "Download ID" recognizer (`AIS_DOWNLOAD_ID` —
this concatenated PAN+date+time ID is invisible to `IN_PAN` itself, since
IN_PAN's pattern requires a word boundary right after the PAN that a
directly-appended digit never provides), and a free-text postal address
recognizer (`IN_ADDRESS`, context-scoped on "address" — no fixed format
exists for an Indian address, so this favors completeness over precision).
Where a real checksum exists (Aadhaar's Verhoeff
digit, GSTIN's own check character), it's validated, not just
pattern-matched — see [IMPLEMENTATION.md](IMPLEMENTATION.md) for exactly
which entities have checksum validation and which are pattern-only.

## Dependencies

| Purpose | Package |
|---|---|
| PII detection (NLP + pattern recognizers) | `presidio-analyzer` |
| PII anonymization | `presidio-anonymizer` |
| NLP model powering `presidio-analyzer` | `spacy` + the `en_core_web_lg` model |
| PDF read/write, true redaction | `pymupdf` |
| XLSX read/write | `openpyxl` |
| OCR for scanned PDF pages and JPEG/PNG scans | `pytesseract` (wraps the **Tesseract OCR** native binary) |
| Image handling for OCR | `pillow` |
| Mapping-store encryption | `cryptography` (Fernet) |
| Mapping-store key storage | `keyring` (OS credential manager — Windows Credential Manager on Windows) |
| Concurrent-safe mapping-store access | `filelock` |
| Tests | `pytest`, `pytest-cov` |

Everything above is a `pip` package **except Tesseract OCR**, which is a
separate native binary — the setup script below installs everything it
can, then tells you how to get Tesseract. Without Tesseract, every format
except scanned PDF pages and image scans still works fully; a scanned
page fails closed with a clear error rather than silently skipping
detection on it.

## Setup

One command, one time, needs internet. Nothing downloaded here is
contacted again at runtime — the tool runs fully offline afterwards.

```powershell
.\setup.ps1
```

This creates a `.venv`, installs `pii-redact` and every Python dependency
above, and downloads the spaCy model (~587MB). Pass `-SkipSpacyModel` to
skip that download if you're not ready to run detection yet. The script
is idempotent — safe to re-run any time (e.g. after pulling changes) to
pick up new dependencies.

The one thing it can't do for you: installing Tesseract OCR (a native
Windows installer, not a `pip` package). The script prints the link and
what to do with it when it finishes.

## Usage

```powershell
.venv\Scripts\Activate.ps1

# Pseudonymize one file - PII becomes reversible coded identifiers
redact input.pdf -o output\ --mode pseudonymize --doc-type form16

# Redact a whole folder - PII becomes plain <ENTITY_TYPE> markers
redact .\tax_docs\ -o .\tax_docs_redacted\ --mode redact
```

Key flags:

| Flag | Meaning |
|---|---|
| `-o / --output` | Output directory (created if missing) |
| `--mode` | `redact` (plain markers, one-way) or `pseudonymize` (reversible coded identifiers, default) |
| `--doc-type` | Tunes which entities get acted on for a known layout: `form16`, `bank_statement`, `demat_statement`, `id_card_scan`, `ais`, or the conservative default `generic` |
| `--mapping-store` | Path to the encrypted mapping store (default `~/.pii_redact/mapping_store.enc`) — needed to reverse pseudonymized output later |
| `--audit-log` | Path to the audit log (default `~/.pii_redact/audit.log.jsonl`) |
| `--yes` | Skip the interactive confirmation prompt — still refuses to write output for a document that failed extraction or has content it can't safely auto-redact |

`<input>` can be a single file or a directory (non-recursive batch mode).
Every run stops at the review gate first — you'll see entity counts and
locations before anything is written, and must confirm (or pass `--yes`,
with the caveats above).

Full stage-by-stage detail, current test coverage, and exactly what's
been verified end-to-end are in [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Limitations & improvement scope

Honest gaps, not hidden ones — each is documented in its own module's
code, not just here:

- **Structured data (CSV/XLSX/JSON) has no sentence context** (PDF/image
  lines do — see "How it works" above). A cell's value is analyzed on its
  own, so a bank account number sitting alone in a cell often won't be
  confident enough to flag, even though the column header would tell a
  human instantly what it is. The real fix is a field-name-driven fast
  path (redact by known column/key name) — planned, not yet built.
- **A short, decontextualized, non-sentence-like string can occasionally
  fool the NER model into tagging it as a person's name** (e.g. a table
  quarter label). Mitigated with a plausibility filter (a `PERSON` match
  containing a digit is discarded), not eliminated in general — other
  odd short strings could in principle still be misclassified.
- **The postal-address recognizer favors completeness over precision.**
  With no fixed format to match against, it can occasionally flag ordinary
  long prose sitting near an incidental "address" mention as an address
  too. Accepted, not hidden — same tradeoff as this project's other
  free-form-number recognizers (mutual fund folio, ration card).
- **ID-card image redaction only covers OCR'd text.** Faces, photos, and
  QR codes are untouched — an Aadhaar QR code encodes the same data as
  the printed text on the card. Closing this needs either a
  full-image-blackout policy for ID-scan documents or dedicated face/QR
  detection, neither implemented yet.
- **PDF**: XMP metadata and embedded thumbnails aren't scrubbed (only the
  classic document-info dictionary is).
- **XLSX**: `Company`/`Manager` document properties can't be scrubbed —
  the underlying library has no write API for them. Whether a literal
  cell feeds a formula elsewhere in the workbook isn't tracked, so
  formula-adjacent cells may need manual review before trusting an
  automatic overwrite.
- **CSV**: line endings normalize to `\r\n` on write regardless of the
  source file's original line endings.
- **No GUI.** CLI only, by design (see the project instructions doc) —
  a visual preview of what's about to be redacted, before confirming,
  would be a natural next step.
- **Single-machine, single-user.** No multi-user access control on the
  mapping store beyond OS file permissions and the encryption key living
  in the OS credential store.

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the full list with exact
file references, and
[claude_project_instructions_build_redaction_tool.md](claude_project_instructions_build_redaction_tool.md)
for the underlying design decisions and constraints this project follows.

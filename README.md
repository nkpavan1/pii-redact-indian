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

## Commands at a glance

| Command | What it does |
|---|---|
| `redact` | Redact or pseudonymize files or a folder, in their own format or as markdown (`--format markdown`) |
| `redact-publish` | Publish reviewed, redacted markdown copies of an outbox folder (incremental) |
| `redact-service` | Localhost HTTP service that pseudonymizes chat text for cloud models and restores codes in replies |
| `redact-key` | Set up, check, back up and restore the mapping store's key |

All four share one mapping store, so a person gets the same code
(`PERSON_A`) everywhere. From Python: `from pii_redact import MappingStore,
redact_text, reverse_text`.

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
| `--format` | `native` (default): same format as the input. `markdown`: a `.md` rendering of any input (`statement.pdf` → `statement.pdf.md`), which is what LLMs and wikis read best |

`<input>` can be a single file or a directory (non-recursive batch mode).
Every run stops at the review gate first — you'll see entity counts and
locations before anything is written, and must confirm (or pass `--yes`,
with the caveats above).

Full stage-by-stage detail, current test coverage, and exactly what's
been verified end-to-end are in [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Publishing redacted copies: `redact-publish`

Drop originals into an outbox folder, and `redact-publish` turns each one
into a reviewed, redacted markdown copy in a published folder:

```powershell
redact-publish                    # outbox H:\ai\vaults\personal\outbox -> H:\ai\vaults\reference\redacted
redact-publish --outbox X --published Y --home Z --doc-type bank_statement
```

- **Recursive and incremental.** Unchanged originals are skipped. Edited ones
  are re-published under the same name. An original that disappears has its
  copy removed, but never when the outbox is empty or unreachable, and never
  if the copy was changed by hand.
- **Residual gate.** After redaction, the markdown is scanned again. Anything
  that still looks like PII **holds** the document: nothing is published, and
  a report with the flagged values masked goes to `<home>\reports\`.
- **Review.** Each document shows a redacted preview and counts, and asks
  before publishing. `--yes` skips the prompt; the residual gate still
  applies.
- **Names.** Published names are opaque (`bank_statement-3f9a1c2b7d.md`),
  because file names often contain a name. `--readable-names` derives them
  from the redacted original name instead, but that is less reliable than
  redacting text.
- **Frontmatter.** Each copy carries `type: source`, `redacted: true`,
  `doc_type`, `source_hash` (SHA-256 of the original) and `redacted_at`.
- **Document type.** A top-level outbox folder named after a document type
  (`outbox\bank_statement\...`) selects it automatically.

It needs an initialized store (`redact-key init`, below) and never creates
one on its own.

## Redacting chat traffic: `redact-service`

A localhost HTTP service for a gateway hook: it pseudonymizes every text
before it goes to a cloud model, and restores the codes in the reply. It
shares the mapping store with `redact-publish`, so a person has the same
code in published documents and in chat.

```powershell
redact-service --port 8787 --home H:\ai\redaction
```

- Binds `127.0.0.1` only.
- `/v1/redact` and `/v1/reverse` need `Authorization: Bearer <token>`. The
  token comes from `$env:PII_REDACT_SERVICE_TOKEN`, or else the first line of
  `<home>\service.token`. The service refuses to start without a token of at
  least 32 characters.
- `GET /health` needs no auth. It returns 503 until the NLP model is loaded
  and warmed up, then 200.
- `--ephemeral-store` runs it against a throwaway store (random in-memory
  key, deleted at exit) for end-to-end tests. It's refused on the default
  port.
- Logs hold request ids, counts and latency, never text. Nothing from a
  request is written to disk.

The full HTTP contract, start/stop commands and measured latency are in
[HANDOFF.md](HANDOFF.md).

## The mapping store and its key

Pseudonymized output is only reversible while you still have **both** the
encrypted store file and its key. The key lives in Windows Credential
Manager, bound to the store file's full resolved path, so never move or
rename a store once it's in use, and run every tool as the same Windows
user.

`redact-key` manages the key. Run it yourself, at a terminal; it's never
meant for scripts or agents. `--store` defaults to
`$env:PII_REDACT_HOME\mapping_store.enc`, or `H:\ai\redaction\mapping_store.enc`
if `PII_REDACT_HOME` isn't set.

```powershell
redact-key init                           # one time: new empty store + key
redact-key check                          # key present? decrypts the store? (never shows the key)
redact-key export --clip --i-understand   # back the key up to your password manager
redact-key import                         # restore it (hidden prompt); refuses a key that doesn't decrypt the store
redact-key forget --code PERSON_F         # remove an entry (shows it and asks first); its code never reverses again
```

`forget` is for test data, or a value that should never have been stored.
Anything the store knows is masked everywhere it appears, so a wrongly
stored "name" matters. A removed code is never issued again.

`export --clip` copies the key without adding it to clipboard history
(Win+V) or cloud clipboard sync, and clears the clipboard once you press
Enter. Without `--clip` it prints the key; clear your terminal scrollback
afterwards.

**Backup:** keep the key in your password manager, and copy the `.enc`
file (plus nothing else from that folder) to your usual backups whenever
you like. It's encrypted, so the copy is safe anywhere. To restore on a
new machine or Windows profile, put the file back at exactly the same path,
then run `redact-key import`.

## Limitations & improvement scope

Honest gaps, not hidden ones — each is documented in its own module's
code, not just here:

- **What is not masked in free text.** This was checked on synthetic
  sentences; the full table is in [HANDOFF.md](HANDOFF.md), section 5.
  - Place names, organizations, amounts, plain dates and medical terms are
    never masked.
  - Several identifiers are masked only with a context word nearby: bank
    account numbers, UPI IDs, voter IDs, passport numbers, dates of birth,
    and phone numbers other than Indian mobiles.
  - Indian mobile numbers are masked without context in chat (the
    service), but documents still need a context word, because statements
    are full of 10-digit references.
  - Addresses are masked when they end in a PIN code or follow an address
    label ("Address:", "my address is"). The verb ("please address
    this") never counts.
  - Names after a title (Mr, Shri, Smt, Dr., ...) are caught even in all
    caps with initials; untitled names depend on spaCy the first time
    they're seen.
  - **Anything already known is masked everywhere.** Multi-word names and
    identifiers the mapping store knows, or that were found elsewhere in
    the same document or request, are masked wherever they appear, even
    where detection misses them (`detect/known_values.py`). Single-word
    names are never swept.
- **Latency.** NER costs roughly 0.17 s per 1K tokens of new text.
  `redact-service` caches the detection of repeated texts. See HANDOFF.md,
  section 6.
- **Structured data (CSV/XLSX/JSON) gets its context from field names.**
  Each value is analyzed as `<label>: <value>`, where the label is:
  - for CSV and XLSX, the column header and the label cell to its left;
  - for JSON, the key.

  So an account number under an "Account No" (or "A/C No") header is
  masked. Remaining gaps:
  - Numeric XLSX cells are still not scanned. An account number stored as
    a number rather than as text is missed.
  - A label that says nothing ("Value", "Field 3") adds nothing.
- **Random 12-digit references can be masked as Aadhaar.** About 1 in 10
  random 12-digit numbers passes the Aadhaar checksum, which is treated as
  certain without context. So some UPI and UTR references on statements
  are masked as `IN_AADHAAR`. That's the safe direction, but noisy.
- **A short, decontextualized, non-sentence-like string can occasionally
  fool the NER model into tagging it as a person's name** (e.g. a table
  quarter label). Mitigated with a plausibility filter (a `PERSON` match is
  cut at its first word with a digit, and a lone word left before a number
  is discarded), not eliminated in general — other odd short strings could
  in principle still be misclassified.
- **Name spans are cleaned up with a word list** (`detect/person_spans.py`):
  greetings, contact verbs, roles and statement words glued to a name are
  trimmed off, so "Ping Ravi Kumar" and "Ravi Kumar" get one code. A glue
  word missing from the list still gives that person a second code; adding
  it is a one-line change.
- **The labeled-address recognizer favors completeness over precision.**
  With no fixed format to match against, it masks whatever follows an
  address label, to the end of the sentence, if it has a digit or a
  comma. So a label followed by something else ("Address | Part B1 -
  Information relating to tax…" in an AIS header) is masked too. Accepted,
  not hidden — same tradeoff as this project's other free-form-number
  recognizers (mutual fund folio, ration card).
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

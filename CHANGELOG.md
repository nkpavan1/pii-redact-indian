# Changelog

## 0.3.0 (unreleased)

The HTTP contract is unchanged. Only what gets masked changes (HANDOFF.md,
section 5).

### Added
- **Indian mobile numbers are masked in chat without a context word**
  (`9876543210`, `98765 43210`, `+91 98765 43210`, ...), reported as
  `PHONE_NUMBER`. Every format of one number gets one code. Document
  allow-lists keep context-scoped phone detection.
- **Passport numbers are masked next to "passport"**, via a new recognizer
  that replaces Presidio's. Presidio's could never reach the threshold.
- **Field names are context for structured data.** CSV headers and
  left-hand labels, XLSX column headers (found even below a preamble) and
  left-hand labels, and JSON keys now count as context for their values.
  An account number under "Account No" or "A/C No" is masked.

- `scripts/measure_cold_start.ps1`: the time from launching the service
  to `/health` reporting ready.

### Changed
- **Ration card numbers must contain a digit.** Words like "Narration" or
  "Registration" were being masked as ration card numbers.
- **Runtime venv.** The recommended one is now
  `H:\ai\engines\pii-redact\.venv`, on the NVMe drive with pinned package
  versions (HANDOFF.md, section 2).
- **Phone lookup keys** drop a `+91`/`91`/`0` prefix from Indian mobile
  numbers.

## 0.2.0 (2026-09-25)

Phase 7: the tool becomes the shared core of two new tools that share one
mapping store, so a person gets the same code in documents and in chat.
The design decisions and known gaps behind each change are in
[DECISIONS.md](DECISIONS.md); the service contract is in
[HANDOFF.md](HANDOFF.md).

### Added
- **String API** `redact_text` / `redact_texts` / `reverse_text` /
  `reverse_texts` / `RedactResult`, importable from `pii_redact`:
  - Codes already in a text pass through unchanged.
  - Unknown entity names are rejected rather than silently ignored.
  - `find_pii` is a read-only scan for PII still in the clear.
- **`redact-service`**, a localhost HTTP service for a LiteLLM hook:
  - `/v1/redact`, `/v1/reverse` and `/health`.
  - Bearer token, 127.0.0.1 only, warm-up readiness.
  - In-memory result cache.
  - Logs never contain text.
- **`redact-publish`**: reviewed, redacted markdown copies of an outbox
  folder.
  - A residual gate holds anything that still looks like PII.
  - Incremental via a hash manifest; removed originals are unpublished.
  - Opaque output names by default.
- **`redact-key`**: `init`, `check`, `export` (also `--clip`, kept out of
  clipboard history and cloud sync) and `import` for the mapping store's
  key.
- **Markdown and text input** (`.md`, `.markdown`, `.txt`), with
  frontmatter scanned line by line.
- **`redact --format markdown`**: a `.md` rendering of any input format.
- **Mapping store features:**
  - `cache=True` in-memory mode that re-reads only when the file changes;
  - `transaction()` (one lock and one save for many codes);
  - `create=False`, which refuses to start a new store silently;
  - `lock_timeout`, `refresh()` and `keyed_digest()`.
- `scripts/bench_service.py` latency benchmark.
- **Names after a title** (Mr, Mrs, Miss, Shri, Sri, Smt, Kumari, Dr.,
  Ms.), including the all-caps-with-initials names spaCy misses entirely
  (`MR. R RAJESH KUMAR` → `MR. PERSON_A`).
- **Addresses anchored on a PIN code**, with no "address" label needed
  (`12 MG Road, Indiranagar, Bengaluru 560038`, `BHOPAL - 462001`,
  `pincode is 560038`). Banking prefixes (`NEFT-123456`) and amounts are
  excluded.

### Changed
- **Reversal returns the display form.** Codes reverse to the surface form
  seen in the document ("Ravi Kumar"), not the upper-cased lookup key. A
  later mixed-case sighting replaces an all-caps one.
- **Whole-token reversal.** `PERSON_A` no longer matches inside
  `PERSON_AB`, and codes the store never issued are left as written.
- **Atomic store writes.** The store writes a temporary file and renames it
  over the store. A crash can no longer leave an undecryptable store.
- **Batch isolation.** One bad file no longer stops a batch.
  - Unsupported files are skipped.
  - Any stage error fails that file closed.
  - Outputs are written to a partial file and renamed into place.
  - The CLI prints `N written, M skipped, K failed`.
- **CSV header cells are scanned** like any other cell.
- **Possessives.** A trailing possessive is trimmed from person names, so
  "Ravi Kumar's" and "Ravi Kumar" get the same code.
- **Long texts** (over 10,000 characters) are analyzed in overlapping
  chunks. Presidio's context step is quadratic in text length. A 50K-token
  text now takes about 8.8 s instead of 16 s, with identical results.
- **`redact` pseudonymize mode** issues a document's codes in one store
  transaction.
- **Tests never touch the OS credential store.** The one keyring test is
  opt-in: `PII_REDACT_KEYRING_TESTS=1`.
- **New dependency:** `pyyaml`, which was already installed with
  presidio-analyzer.

### Fixed
- `.md` and `.txt` files went through the CSV path, which skipped their
  first line (B1).
- An unsupported file aborted a whole batch (B2).
- Reversal returned upper-cased, run-together values (B3).
- Partial code matches during reversal.

### Compatibility
- **Existing mapping stores** work unchanged; no migration step is needed.
  Existing codes stay the same.
- **`redact <input> -o <dir>`** behaves as before, apart from the new
  summary line and the opt-in `--format`. `--doc-type` also accepts `chat`.
- **The new tools** (`redact-publish`, `redact-service`) need a store set up
  once with `redact-key init`. They never create one on their own.

# Phase 7 build log: decisions, gaps and caveats

A record, per step, of what was decided along the way that the plan didn't
spell out, what is knowingly left open, and what to watch for. It's written
for whoever reviews or extends this work (including the stack session that
builds the LiteLLM hook). `HANDOFF.md` has the service contract;
`CHANGELOG.md` has the user-facing changes.

---

## Step 0: repo sync and test isolation

**Decisions**
- Work happens in the git clone. The old working copy
  (`F:\claude\projects\redaction tool`) is no longer updated. Its `.venv` is
  reused, with this clone installed into it in editable mode.
- The test suite must never touch the real OS credential store:
  - Test doubles pass explicit keys.
  - An autouse fixture makes any credential-store access raise.
  - The one real-keyring test is opt-in (`PII_REDACT_KEYRING_TESTS=1`).

**Caveats**
- The GitHub repo is **public**. A count-only scan of its history found only
  synthetic fixture values, and the pushed tree matched the already-scrubbed
  local copy. One commit's author email is a personal address. Rewriting that
  is the owner's call.

## Step 1: B1 (text files), B2 (batch isolation), B3 (display form), reverse boundaries

**Decisions**
- **Lookup keys unchanged.** `normalize_value` keys stay the same: they are
  still upper-cased, with separators stripped for IDs. Reversal now uses the
  stored `display` form, so the key's shape no longer matters for output, and
  changing keys would have given existing entries a second code.
- **Display upgrades.** An all-caps display is replaced by a later mixed-case
  sighting, never the reverse. Old entries without `display` reverse to their
  key until the next sighting records one.
- **Text files.** `.md` and `.txt` files are read one block per **paragraph**,
  not per line, to give NER sentence context. The renderer splices
  replacements back byte for byte.
- **CSV header cells are always scanned,** not only when the header guess is
  uncertain.
- **Atomic outputs.** Output is rendered to a hidden partial file and renamed
  into place only when it's complete.
- **Possessives.** A trailing possessive (`'s`) is trimmed from spaCy PERSON
  spans. "Ravi Kumar's" was otherwise a different key from "Ravi Kumar".

**Gaps and caveats**
- **Invalid synthetic PAN.** `ABCDE1234F` is **not a valid PAN**. The 4th
  character must be a holder type (P, C, H, F, A, T, B, L, J, G), so Presidio
  never detects it. Use e.g. `ABCPE1234F` in tests. Any test that "passes"
  with `ABCDE1234F` isn't testing PAN detection.
- **Frontmatter.** Frontmatter is scanned as an ordinary paragraph. Proper
  frontmatter-aware handling came in Step 4.

## Step 2: public string API

**Decisions**
- **Protected codes.** Only codes the store actually issued are protected from
  re-redaction. A generic `ENTITY_[A-Z]+` pattern could shield real text
  (`PERSON_RAM`). As a result, an invented `PERSON_Z` in input is scanned as
  ordinary text.
- **Detections across a code.** A detection that runs across an existing code
  is cut down to the parts outside it. This was found for real: the address
  recognizer's pattern crosses codes when "Address" is nearby.
- **Unknown entity names are rejected,** not ignored. Presidio silently skips
  types it has no recognizer for.
- **Output shape.** `RedactResult.spans` offsets point into the **output**
  text. `repr()` shows counts only.
- **`reverse()` implementation.** It now matches code-shaped tokens and looks
  each one up, which is linear in text size however large the store is.
- **Lazy package exports.** Package-root exports are lazy, so
  `import pii_redact` doesn't load Presidio or spaCy.

**Gaps and caveats**
- **Idempotency.** The guarantee is about codes: they are never altered. Text
  *around* codes is re-scanned and can occasionally pick up an extra
  redaction. The direction is always safe: more redaction, never less.
- **Text length limit.** spaCy refuses texts over 1,000,000 characters.
  `redact_text` rejects them up front with `TextTooLongError`, before
  anything is written.
- **Thread safety.** The analyzer isn't thread-safe, so callers must
  serialize calls (the service does).

## Step 3: mapping store upgrades and `redact-key`

**Decisions**
- **Atomic saves.** The store writes to `<store>.tmp`, fsyncs it, then does
  `os.replace`. It retries for about 2 seconds on Windows sharing violations
  (antivirus, indexers).
- **Caching.**
  - `cache=True` keeps the decrypted store in memory and re-reads only when
    the file's stat signature (mtime, size, file ID) changes.
  - **Writes never rely on that signature.** Under the file lock they always
    compare the actual file bytes, so a stale cache can never hand out a
    duplicate code.
  - `H:` was checked: it is NTFS, where the signature is reliable.
- **`transaction()`.** One lock and at most one save for a whole batch of new
  codes. The string API uses one transaction per call, after detection, so
  the lock is never held while NER runs. The document pipeline uses one per
  document.
- **`create=False` (unplanned, deliberate).**
  - The new tools open the store with `create=False`: they refuse to run
    unless the key **and** the store file already exist.
  - The legacy `redact` default still auto-creates a store on first use.
  - Why: a mistyped or differently-resolved path would otherwise silently
    start a second store that issues `PERSON_A` for a different person, and
    reversal would then substitute the wrong real name.
  - Consequence: a store is now set up once, explicitly, with
    `redact-key init`.
- **`lock_timeout`.** A lock wait can be bounded. The service will use this
  so a stuck writer produces an error rather than a hang.
- **`redact-key`.**
  - `init`, `check`, `export` and `import`.
  - `check` never prints the key or its length.
  - `export` requires `--i-understand` plus an interactive terminal.
  - `import` reads with a hidden prompt, and refuses a key that doesn't
    decrypt the existing store or that would silently replace a different
    stored key.
- **`export --clip` (unplanned upgrade over `clip.exe`).**
  - It copies through the Win32 clipboard API with the
    `ExcludeClipboardContentFromMonitorProcessing`,
    `CanIncludeInClipboardHistory = 0` and `CanUploadToCloudClipboard = 0`
    formats, so the key stays out of clipboard history (Win+V) and cloud
    clipboard sync. `clip.exe` can't do that.
  - After you press Enter, it clears the clipboard, but only if nothing else
    was copied since.
  - It prints a one-line confirmation to stderr (never the key).
- **Default home.** `H:\ai\redaction`, overridable with `PII_REDACT_HOME`.

**Gaps and caveats**
- **Clipboard code not exercised live.** The clipboard code is unit-tested
  against a recording fake of the Win32 calls. It has **not** run against the
  real clipboard in this session, because that would overwrite the user's
  clipboard. The first real run is `redact-key export --clip --i-understand`.
  If it fails, it reports the error and nothing is copied.
- **Store backups.** No automatic backup of the store file is made. Backing up
  the `.enc` file (plus the key in a password manager) is manual and
  documented in the README.
- **Read staleness off NTFS.** On a file system with coarse timestamps,
  cached reads could be briefly stale (writes are still correct). This
  doesn't apply to NTFS.
- **Measured throughput.** A new code costs roughly 6 ms under full
  8-process contention (lock, read, encrypt, fsync, rename). Lookups of
  existing codes in cache mode cost one `stat()`.

## Step 4: markdown and text in, markdown out

**Decisions**
- **Frontmatter.**
  - Handled line by line, not by parsing YAML. Each non-blank line between
    the opening `---` and a closing `---` or `...` is its own block, so a
    key (`dob:`) is the context word for its own value only.
  - Delimiter lines are never scanned. An unclosed block is ordinary text.
  - Applies to `.md` and `.markdown` only, not `.txt`.
- **Fenced code blocks** needed no special case. They're scanned as ordinary
  paragraphs, and because rendering splices only the detected spans back in,
  everything else in them stays byte-for-byte.
- **Markdown output for every format** (`render/markdown.py`), from the same
  replacements as native output, so codes are identical either way:
  - text/markdown: the source, spliced in place;
  - PDF and images: lines in reading order under `## Page N`, with
    side-by-side lines on one row joined by ` | `;
  - CSV and XLSX: markdown tables, with cell comments listed under each
    sheet;
  - JSON: a fenced, pretty-printed block, fenced with more backticks than
    any run in the content.
- **Formula results in markdown.** Markdown output **does** replace
  PII-bearing formula results, which native XLSX output must leave in place.
  So `build_preview` counts read-only detections as "unredactable" only for
  native output, and `--yes` proceeds for markdown.
- **Never rendered, because nothing in them is scanned:** sheet names (shown
  as `## Sheet N`), defined names, PDF metadata and annotations, images
  embedded in PDFs, and the input file name.
- **Output file names.** `note.md` stays `note.md`; anything else gets
  `.md` appended (`statement.pdf.md`), so inputs that differ only by
  extension can't collide.
- **CLI.** `redact --format {native,markdown}`, defaulting to `native`, so
  existing invocations behave as before.
- **Reusable stages.** `run_pipeline` is now built from public stages
  (`analyze_document`, `build_preview`, `markdown_output_name`), so
  redact-publish can run the same detection without the CLI's printouts.

**Gaps and caveats**
- **No table reconstruction for PDFs.** Tables in PDFs come out as rows of
  ` | `-joined lines.
- **Markdown tables in `.md` input are one paragraph.** A header cell's
  context doesn't reach values in later rows.
- **Structured data still lacks field-name context.** A CSV, XLSX or JSON
  value is analyzed alone, not as `column: value`. This is the long-standing
  README gap. Analyzing `column: value` the way frontmatter lines are handled
  would close much of it. Not done, because it isn't in the plan; proposed
  as a follow-up.
- **Numeric cells and values, and JSON object keys, are not scanned.** This
  is unchanged from before, and markdown output shows them as-is.
- **Hidden rows and sheets are included.** Markdown shows hidden XLSX rows
  and sheets like any other, the same way extraction treats them.
- **CSV header detection is still a heuristic.** The sniffer can call an
  all-text first row data, not a header. That affects only the table's
  header line, since header cells are scanned either way.
- **DOCX not added.** The prompt asks to check first: it needs the
  `python-docx` dependency.

## Step 5: `redact-publish` (Tool 1)

**Decisions**
- **Detection uses the document pipeline, not `redact_text`.** The plan said
  to redact through the string API, but the pipeline's layout-aware detection
  is better for documents: it pairs PDF labels with their values, reads
  frontmatter line by line, and so on. Codes are identical either way,
  because both use the same store. The string API is used for the
  **residual gate** (`find_pii`, a new read-only scan that ignores issued
  codes).
- **Output names are opaque by default** (`<doc_type>-<keyed hash>.md`). The
  plan said to use the original name run through `redact_text`, but NER
  routinely misses names in file names (`ravi_kumar`, `RaviKumar_Form16`).
  `--readable-names` keeps the planned behavior as an opt-in, and falls back
  to the opaque name if the redacted name still looks like PII.
- **Keyed hashes for identifiers.** Manifest keys and audit IDs are an
  HMAC-SHA256 of the outbox-relative path (`MappingStore.keyed_digest`, keyed
  from the store key). A plain hash of a short, guessable file name can be
  reversed by trying candidates. `source_hash` in the published frontmatter
  is a plain SHA-256 of the original, as specified; a whole document isn't
  guessable.
- **Frontmatter.** A markdown source's own (redacted) frontmatter moves under
  `source_frontmatter:`, so the published file has exactly one frontmatter
  block and no key collisions.
- **Held documents.**
  - If an edited document is held, the previous published version (which
    passed the gate) stays published.
  - An unchanged held document is not reprocessed on the next run
    ("still held"); `--force` reprocesses everything.
  - Reports mask every flagged value and name the outbox file, so it can be
    fixed. They live in `<home>\reports\` and never in a vault.
- **Unpublishing guards** (unplanned, deliberate):
  - Nothing is unpublished when the outbox has no files: an unmounted drive
    looks exactly like "everything was deleted".
  - A published file is deleted only if its own frontmatter still says it's
    this tool's copy of that source.
- **Other guards.**
  - A second concurrent run is refused (a lock in the redaction home).
  - The outbox, the published folder and the home must not be inside one
    another.
  - Hidden files and folders (`.obsidian`) and Office lock files (`~$...`)
    are ignored.
- **Document type.** `--doc-type` applies to everything; otherwise a
  top-level outbox folder named after a known document type selects it.
- **Exit code.** 1 when anything was held or failed, so a script notices.

**Gaps and caveats**
- **Codes are issued before review.** They're issued while building the
  preview, so a declined or held document still leaves its codes in the
  store. That's harmless: they're just unused.
- **`--threshold` applies only to the residual gate.** The first pass always
  uses the project threshold (0.5).
- **The gate can hold documents the first pass got right.** It scans
  differently-shaped text (for example PDF rows joined into lines, or the
  address pattern running across codes), so it can flag new things. This is
  the conservative direction, but expect some holds on real documents.
  Reports show exactly what was flagged.
- **No dry-run mode.**
- **Not run against the real vault folders here.** Everything was tested on
  temporary folders.

## Step 6: `redact-service` (Tool 2)

**Decisions** (the contract itself is in `HANDOFF.md`)
- **stdlib only.** `ThreadingHTTPServer`, as agreed, with no new
  dependencies.
- **Locking.** Redaction is serialized by one processing lock. `/v1/reverse`
  doesn't take it, since it needs no NER. `/health` reads plain status
  attributes and never takes any lock. It answers in milliseconds while a
  50K-token request is running (tested by holding the lock).
- **Startup checks happen before binding the port:** the host, the token,
  and the store (key present, file decrypts). A misconfiguration exits with
  code 2 at once instead of serving 503 forever. Warm-up runs in the
  background after binding, and `/health` reports `starting` until it ends.
  A failed warm-up reports `failed` and stops the process with exit code 1.
- **Warm-up issues no codes.** It uses the read-only `find_pii`, so
  starting the service never writes synthetic entries into the real store.
- **Endpoints before warm-up.** `/v1/*` return 503 until warm-up ends,
  after the auth check, so an unauthenticated caller gets 401 either way.
- **Token.**
  - `$PII_REDACT_SERVICE_TOKEN` wins whenever it is **set**; a set but too
    short variable is an error, never a fallback to the file. Otherwise the
    first line of the token file is used.
  - UTF-16 and UTF-8-with-BOM files are accepted, because Windows
    PowerShell 5.1 writes those by default.
  - Error messages never contain the token or its length.
  - Comparison uses `hmac.compare_digest`.
- **Result cache.**
  - Keys are SHA-256 over the settings (sorted entity list and threshold)
    and the text, so a result from different settings can never be
    returned.
  - It's bounded at 2,000 entries **and** 64M characters, so a few huge
    texts can't take all memory.
  - It's memory-only.
  - It's cleared whenever another process changes the store
    (`MappingStore.refresh()` generation). The service's own writes don't
    clear it.
- **Hardening beyond the brief.**
  - The port is bound with `SO_EXCLUSIVEADDRUSE` and without
    `SO_REUSEADDR`, so another local process can't take over port 8787.
  - The stdlib handler's raw request-line logging and HTML error pages
    (which echo the request line) are replaced.
  - Query strings are ignored for routing and never logged; only known
    routes are logged by name.
  - Every error response closes the connection, so an unread body can't
    corrupt the next request.
  - The per-request limit is 10,000 texts. The store lock wait is 10 s,
    after which the service returns 503 `store unavailable`.
- **Long-text performance fix (unplanned, measured).**
  - One Presidio `analyze()` call is quadratic in text length. Its
    context enhancer walks every token for every candidate result:
    profiled at about 84M token visits for a 200K-character text, which
    took 16 s where spaCy alone takes 5.8 s.
  - Texts over 10,000 characters are now analyzed in chunks cut at
    paragraph, line, sentence or word boundaries, each with 1,000
    characters of overlap on both sides. A result belongs to the chunk it
    starts in.
  - A test checks that chunked analysis finds exactly what one pass finds.
  - 50K tokens went from 16.2 s to 8.8 s at p50.
- **`--pid-file`** is available for scripted stops.

**Measured latency** (in-process, loopback HTTP, synthetic text with PII
about every 5 sentences, Python 3.10, desktop AMD Ryzen 5 9600X with 6
cores / 12 threads (corrected in step 12; this first said "AMD64 laptop
CPU"), idle machine; `scripts/bench_service.py`; 0.2.0 numbers, see step
12 for 0.3.0):

| Scenario | p50 | p95 |
|---|---|---|
| 12K-token prompt, one new text | 2.06 s | 2.12 s |
| 50K-token prompt, one new text | 8.82 s | 8.93 s |
| 20-message history (about 12K tokens), last one new, cache on | 97 ms | 108 ms |
| same, cache off | 1.68 s | 1.71 s |
| reverse, 12K-token reply | 1.1 ms | 1.3 ms |

Warm-up took 0.8 s with the model files in the OS file cache. A cold start
(first run after boot) is slower; see HANDOFF.md for the readiness wait.

**Gaps and caveats**
- **Latency scales with new text.** Cost is roughly 0.17 s per 1K tokens of
  *new* text, and requests are serialized, so two simultaneous 50K-token
  requests take about 18 s for the second. The hook timeout recommendation
  in HANDOFF.md allows for that.
- **Crash dumps.** A hard crash of the Python process could leave a Windows
  Error Reporting dump containing process memory (and so request text), if
  WER local dumps are enabled for `python.exe`. They are off by default.
  This is outside the tool's control; noted for completeness.
- **One text over 1,000,000 characters** gets 413 `text too large` (spaCy's
  limit), even under the 4 MB body cap.
- **No TLS.** It isn't needed on loopback with WSL mirrored networking. The
  token is still sent in clear over loopback.
- **Settings are fixed per process.** The contract has no per-request
  entities or threshold, so they're set at startup (`--threshold`; the
  entity list is the `chat` allow-list).

## Step 7: docs, version 0.2.0, HANDOFF

**Decisions**
- **Version.** Bumped to 0.2.0.
- **Declared dependency.** `pyyaml` is now declared: it was already
  installed as a Presidio dependency, but this code imports it directly.
- **`.gitignore` gap closed.** It only matched `*.mapping.enc`, not
  `mapping_store.enc`. It now also covers `*.enc`, the lock files, the token
  and pid files, the manifest, the audit log and reports.
- **Masking table checked, not written from the code.** HANDOFF.md's "what
  gets masked" table comes from running `redact_text` on synthetic
  sentences. This corrected two assumptions: UPI IDs and voter IDs **do**
  need a context word.
- **Venv location.** HANDOFF.md gives the start command for the venv this
  build is installed into today (`F:\claude\projects\redaction tool\.venv`,
  with this clone installed in editable mode) and the path to use if the
  venv is recreated in the clone.
- **Readiness wait.** A warm process start is about 1.5 s (model files in
  the OS cache). The 120 s readiness wait allows for a first start after
  boot.
- **Test added.** `redact-service`'s `main()` now has an end-to-end test
  (fake credential store, `redact-key init`, warm-up, a real request, pid
  file lifecycle).
- **Real bug found through a flaky test.**
  - `test_body_over_the_cap_is_413` failed about 1 run in 7. The service
    answered 413 without reading the oversized body, then closed the
    socket. Windows answers a close with unread data with a TCP reset,
    which sometimes reached the client before the response did. The same
    race applied to a 401 sent before the body was read.
  - The service now reads and discards an unread body of up to 64 MB before
    sending any error. The discarded bytes are never inspected.
  - The tests now send 15 × 300 KB bodies. They fail 3 of 3 times with the
    drain disabled and passed 8 of 8 service-suite runs with it.

**Detection gaps found while checking, now PROPOSALS awaiting a decision**
(not implemented):
1. **Phone numbers.**
   - Presidio's phone recognizer scores 0.4, under the 0.5 threshold. Only
     "phone", "mobile", "telephone", "cell" and "number" lift it, and
     "call" did not in testing.
   - So `call me on 9876543210`, `whatsapp …` and `+91 98765 43210` stay in
     the clear. This is the biggest gap for chat.
   - Proposal: an Indian-mobile pattern (`+91`/`0` optional, `[6-9]` plus
     9 digits) that is confident enough on its own, in the **chat**
     allow-list only, so document types keep today's context-scoped
     behavior. Plus more context words: whatsapp, contact, ph, tel, reach.
2. **Passport numbers.**
   - Presidio's passport pattern starts at 0.1, so even next to "passport"
     it reaches only 0.45. `IN_PASSPORT` is in every allow-list but can
     never fire.
   - Proposal: a context-scoped passport recognizer at 0.15, reaching 0.5
     with "passport" nearby, the same scheme as the other context-scoped
     IDs.
3. **Field-name context for CSV, XLSX and JSON** (from step 4): analyze
   `column: value` so a header like `account_number` counts as context.

**Approved and built next (step 8):** all-caps names after a title, and
PIN-code-anchored addresses.

- **Found through a flaky test: stale compiled test files.** A traceback
  pointed at the old working copy. The clone's `__pycache__` folders had
  been copied along with the source, and pytest reuses a cached compiled
  file whenever the source's mtime and size match. The code was identical,
  so no result was wrong, but the paths were misleading. The (untracked)
  `__pycache__` folders were deleted; they rebuild automatically.

## Step 8: names after a title, addresses anchored on a PIN code (approved B8)

**Decisions**
- **`SalutationNameRecognizer`** (entity `PERSON`, score 0.85, the same as
  spaCy's PERSON):
  - A name is 0–3 initials, then 1–3 capitalized words, with an optional
    middle or trailing initial, after Mr, Mrs, Miss, Shri, Sri, Smt, Kumari
    or Kum (period optional), or after "Dr." or "Ms." (period required).
  - The title is **not** part of the match (a variable-width lookbehind;
    Presidio compiles with the `regex` package, which supports it), so the
    output reads `MR. PERSON_A` and reversal restores just the name.
  - The false-positive guards are each tied to something observed:
    - a bare `DR` is the debit marker on bank statements, and `MS Excel`
      is not a person, so those two need the period;
    - a stop list (ACCOUNT, SAVINGS, BANK, ...) ends a name, so
      `MR RAJESH KUMAR SAVINGS ACCOUNT` stops before `SAVINGS`;
    - a trailing initial may not be followed by `/`, so the `W` of `W/O`
      isn't taken.
- **`PinCodeAddressRecognizer`** (entity `IN_ADDRESS`). A PIN code is 6
  digits, first digit 1–9, optionally written `560 038`, with no digit
  before it directly or through a comma. Three patterns:
  - comma-separated segments + a capitalized place + PIN, optionally
    followed by a capitalized state: 0.6;
  - `Place - PIN`, excluding banking prefixes (NEFT, IMPS, RTGS, UPI, ATM,
    POS, CHQ, REF, TXN, INV, ORDER, ID, NO, EMI, OTP): 0.5;
  - the number alone after `PIN`/`pincode (is|no.|number)`, with the
    keyword kept visible: 0.5.
  - The place before the PIN must start with a capital letter. That rule
    was added after a probe turned `"..., and the fee is 450000"` into an
    address.
- **Flags.** Both recognizers are compiled **without** Presidio's default
  IGNORECASE (a name or place is known by its capital letter); the titles
  and keywords are case-insensitive groups.
- **Test change.** One existing test asserted the old gap (a bare address
  with a PIN code was *not* detected). It now asserts detection, plus a
  new test that an address with no PIN still needs "address" context.
- **No latency cost.** Re-benchmarked: 12K tokens 2.06 s and 50K tokens
  8.82 s at p50, the same as before.

**Gaps and caveats**
- **Known false positives (the safe direction):**
  - product names after "MR" (`MR Plus`);
  - up to six leading words swept into an address (`Send it to 12 MG
    Road, ...`);
  - a comma phrase ending in a capitalized word and any 6-digit number
    (`..., Pune 411001` is intended, but so is
    `Total, Balance 123456`);
  - `Word - 123456` for words not on the banking list.
- **Different codes for the same person.** `R RAJESH KUMAR` (titled) and
  `RAJESH KUMAR` (untitled, from spaCy) are different lookup keys, so the
  same person can get two codes across documents.
- **Letterhead addresses.** A multi-line address is masked only on its
  PIN line. Expanding to the lines above was designed but not approved.
- **Untitled names are still spaCy's call.** A spaCy mis-span such as
  `PRIYA SHARMA W/O RAJESH` (it tags only "SHARMA W/O") leaves PRIYA and
  RAJESH in the clear. That behavior predates this work and is noted in
  HANDOFF.md.
- **Still awaiting a decision:** phone numbers without context, passport
  numbers, and field-name context (step 7 proposals).

---

# Review round 2 (stack session review of 0.2.0)

The stack session accepted the 0.2.0 contract and approved the step 7
proposals. Steps 9–12 below; the contract is unchanged (see step 12).

## Step 9: Indian mobile numbers without context (chat only), passport numbers

**Decisions**
- **Mobile numbers.** A new `IndianMobileRecognizer`:
  - Pattern: optional `+91`/`91`/`0`, then `[6-9]` and 9 more digits,
    either contiguous or split 5-5 by a space or hyphen.
  - Score 0.6, so it passes 0.5 with no context.
  - Context words (as lemmas): mobile, phone, number, whatsapp, contact,
    ph, tel, reach, call.
- **Chat only, through an internal entity type.**
  - Allow-lists select by entity type, and every allow-list has
    `PHONE_NUMBER`, so the recognizer emits `IN_MOBILE`, which **only** the
    `chat` allow-list requests.
  - `detect_in_block` reports it as `PHONE_NUMBER`. Codes and entity counts
    are unchanged for callers, and a number that Presidio's own phone
    recognizer also catches ("mobile 98…") gets one code, not a second
    `IN_MOBILE_A`.
  - `detect_in_block` now also keeps one detection per (type, span),
    keeping the highest score, so double-caught spans aren't counted twice
    in previews.
- **One code per mobile number.** The `PHONE_NUMBER` lookup key now drops
  a `+91`/`91`/`0` prefix from Indian mobiles: `+91 98765 43210`,
  `098765 43210` and `9876543210` share one key and one code. Other phone
  numbers keep the key they always had.
- **False-positive guards,** each tested:
  - no letter, digit, `+` or `/` directly before, and no letter or digit
    directly after, so not inside longer digit runs, `TXN9876543210` or
    `UPI/9876543210/`;
  - no digit before through a comma or period, and no `.digit` after, so
    not inside amounts (`12,50,000`, `9,876,543,210`, `9876543210.50`).
- **Passports: replaced, not stacked.** Presidio's `InPassportRecognizer`
  was **replaced** by `PassportNumberRecognizer`: letter + 7 digits, base
  0.15, reaching 0.5 with "passport" nearby. Replacing it rather than
  adding a second recognizer makes double-firing impossible: the registry
  now has exactly one `IN_PASSPORT` recognizer (tested). Presidio's
  version had two problems:
  - it could never reach the threshold (0.1 + context = 0.45);
  - its pattern demanded the 2nd and last digits be 1–9, which would
    silently miss numbers such as `J8369850`.

**Gaps and caveats**
- **Known false positive (safe direction):** in chat, any standalone
  10-digit number starting 6–9 is a mobile. So `account 9876543210` is
  masked as `PHONE_NUMBER` (it scores higher than
  `BANK_ACCOUNT_NUMBER`).
- **Still need a context word:** landlines (`080-23456789`) and non-Indian
  numbers (`+1 555 010 0199`). "call" still doesn't lift Presidio's phone
  recognizer.
- **Key change for existing entries.** An existing store entry for a
  `+91…` or `0…` form of a mobile keeps its old key. A later sighting of
  the same number gets the new canonical key and so a new code. That's a
  one-time split, and only for the legacy `redact` store; the Phase 7 store
  isn't created yet.
- **Documents are unchanged,** as required: no `IN_MOBILE` in any
  document allow-list (tested).

## Step 10: field names as context for CSV, XLSX and JSON

**Decisions**
- **Labels.** Each structured value that has a label is analyzed a second
  time as `<label>: <value>` (the frontmatter trick), and the result is
  merged with the value-alone pass using the same "context only adds"
  merge as PDF context windows. The label is:
  - **CSV:** the column header (when the file has one), plus the cell to
    the left in the same row (for label-beside-value exports).
  - **XLSX:** the **nearest label-like cell above** in the same column, not
    row 1, because real statement exports start their table below a
    preamble. Plus the label-like cell to the left. One top-to-bottom walk
    per column, so linear.
  - **JSON:** the value's key, or for an array item the nearest enclosing
    key.
- **"Label-like" means letters and no digits,** so an amount, a date or
  another account number next to a value is never used as its label, and
  a long column of account numbers keeps its header.
- **Labels become words:**
  - `account_number` and `accountNumber` become "account number" (spaCy
    keeps `account_number` as one token);
  - "A/C" and "Acct" become "account" (spaCy splits "A/C" into "A", "/",
    "C", so it can never match).
- **Ration-card fix (found by this step).** The ration-card pattern now
  requires a digit. A synthetic statement's "Narration" header (and
  "Registration", "Cardholder") was masked as `RATION_CARD_NUMBER_A`.
  Presidio matches context words as **substrings** of nearby lemmas, and a
  candidate word counts as its own neighbor. No real ration card number is
  letters only.

**Measured.** A 500-row, 7-column synthetic statement takes 16.4 s to
analyze instead of 7.4 s (2.2×), because labeled cells are analyzed twice.
The value-alone pass is kept deliberately: dropping it could lose a
detection, and fail-closed comes first. A possible optimization is to
skip the second pass when the label contains no recognizer's context word
and no person-label word. Not done.

**Gaps and caveats**
- **Numeric XLSX cells are still not extracted,** so an account number
  stored as a number (not text) is missed, even under its header. This is
  the next gap before real XLSX statements; closing it needs a decision
  about replacing a numeric cell (a formula input) with a code.
- **Context words are matched as substrings** (Presidio's default
  `context_matching_mode="substring"`): "acc" matches "according", "pan"
  matches "company", "fund" matches "refund". This over-masks (the safe
  direction). Whole-word mode is a one-line analyzer setting but costs
  recall ("birth" would stop matching "birthday"), so it's a proposal, not
  a change.
- **Pre-existing, found while measuring:** about 8% of random 12-digit
  reference numbers pass the Aadhaar Verhoeff checksum, and a valid
  checksum is treated as certain without context. So statement UPI/UTR
  references are sometimes masked as `IN_AADHAAR`. Proposal: require
  Aadhaar context, or the `4-4-4` spaced format, when there's no context.
  Not changed.
- **`Customer Id` values are still unmasked.** The customer-ID recognizer
  is on hold.
- **Uninformative labels add nothing.** A label with no context words in
  it ("Value", "Field 3") changes nothing; that's harmless.

## Step 11: runtime venv on the NVMe drive

**Decisions** (the user approved writing under `H:\ai\engines`, and
reusing the installed model instead of downloading it)
- **The venv.** `H:\ai\engines\pii-redact\.venv`, created from the same
  base Python as before: Python 3.10.11, via the Microsoft Store Python's
  app-execution-alias folder, which stays stable across Store updates. It's
  the only Python on the machine.
- **Pinned versions.** Installed as `pip install -c <constraints> -e
  "F:\Github Repos\pii-redact-indian[dev]"`, where the constraints are the
  old venv's exact versions (76 packages, including presidio 2.2.364,
  spacy 3.8.15, regex 2026.7.19). A fresh resolve could have pulled newer
  Presidio or spaCy releases, whose detection the suite never saw. The
  `dev` extras (pytest) are included, so the suite can run from this
  interpreter.
- **The model.** `en_core_web_lg` 3.8.0 was **copied** from the old venv
  (package plus dist-info) instead of downloaded again. `spacy.load` works,
  `pip show` lists it, and `pip check` is clean.
- **Verified.** The full suite passes under the new interpreter (526
  passed, 1 opt-in skipped). All four console scripts are present.
  Imports plus model load take 1.5 s warm.
- **The old venv** in `F:\claude\projects\redaction tool\.venv` is left
  untouched and still works (it also has the clone installed in editable
  mode). The user deletes it once the stack has switched.
- **HANDOFF.md updated.** Section 2 has the new interpreter path; section
  1's `redact-key` commands now name the new venv's `redact-key.exe`
  explicitly (a bare `redact-key` only works in an activated venv).
- **`scripts/measure_cold_start.ps1`** starts the service on port 8799 (so
  it can't clash with a running one), polls `/health` until
  `ready: true`, prints the seconds taken, and stops the service again.
  `-ModelOnly` needs no store or token.

**Open, for the user**
- **Measure one real cold start after a reboot,** after HANDOFF section 1:
  `F:\Github Repos\pii-redact-indian\scripts\measure_cold_start.ps1`.
  Record the number here and confirm the 120 s budget. It can't be
  measured in this session: the full run opens the real store, which
  means a Credential Manager lookup, and a true cold start needs a reboot.
  The 1.5 s warm figure says little about a cold read of the 425 MB model.

## Step 12: benchmark re-run, CPU description, version 0.3.0

**Decisions**
- **CPU corrected.** The benchmark machine is a desktop **AMD Ryzen 5
  9600X (6 cores / 12 threads)**, confirmed with `Win32_Processor`. HANDOFF
  section 6 and step 6 above said "AMD64 laptop CPU", which came from
  `platform.processor()` and was wrong.
- **Benchmark re-run** after steps 9–11 (new recognizers, field context,
  new venv). Two full runs gave the same result:

  | Request | 0.2.0 (step 6) | 0.3.0, p50 / p95 |
  |---|---|---|
  | 12K tokens, all new | 2.06 / 2.12 s | 1.88 / 1.91 s |
  | 50K tokens, all new | 8.82 / 8.93 s | 7.96 / 8.08 s |
  | 20-message history, cache on | 97 / 108 ms | 94 / 96 ms |
  | same, cache off | 1.68 / 1.71 s | 1.61 / 1.62 s |
  | reverse, 12K tokens | 1.1 / 1.3 ms | 1.1 / 1.2 ms |

  - **The new recognizers cost nothing measurable.** The ~9% improvement is
    **not** from this release's code, which only added work. An A/B on
    the same code gave identical numbers from the old F: venv and the new
    H: venv (12K: 1.86 vs 1.87 s; 50K: 7.94 vs 7.94 s). So the difference
    is the machine's state between the two sessions.
  - HANDOFF section 6 now shows the 0.3.0 numbers. The 30 s hook timeout
    stands (3.7× the 50K p95).
  - Field context (step 10) doesn't affect these numbers: it applies to
    CSV, XLSX and JSON documents, not to the service.
- **Version 0.3.0,** not 0.2.1: new detection features (context-free
  mobiles in chat, passports, field-name context) and a changed default
  runtime, but no API or contract change.

**What changed in the contract (review round 2): nothing but the masking
table.**
- Endpoints, request and response shapes, auth, error codes, `/health`
  states, env vars and limits are unchanged.
- The `version` in `/health` now reads `0.3.0`.
- **Entity names callers can see are unchanged.** Context-free mobiles are
  reported as `PHONE_NUMBER`; the internal `IN_MOBILE` type never appears
  in codes or counts (tested).
- **`IN_PASSPORT` now actually occurs** in codes and in the `entities`
  counts. It was always a possible entity type but could never fire
  before.
- **More masked in chat:** Indian mobile numbers without context, and
  passport numbers next to "passport" (HANDOFF section 5).
- **Other phone-code keys merge:** existing `+91…` or `0…` phone codes now
  share one code with the bare 10-digit form. There's no store on `H:` yet,
  so nothing is split in practice.

---

# Review round 3 (stack session black-box test of the 0.3.0 service)

The stack session tested the running 0.3.0 service over HTTP from WSL,
synthetic data only (`H:\ai\setup\reviews\pii-redact-0.3.0-service-test.md`).
The HTTP contract passed completely. Three detection issues, a request for
a throwaway test store, and a first-request timing question. Steps 13–16
below.

Reproduced first, in-process against a throwaway store, with the stack's
own probe: 6 names × 10 sentence frames gave 58 fully masked, 1 partial
and 1 missed, and every name got two or three codes. Same numbers as the
stack's.

## Step 13: PERSON spans: trim glued words, extend names cut short

**What spaCy actually does** (probed per token, synthetic names, 20 sentence
frames):
- **A sentence-initial word is swallowed into the name:** "Ping Ravi
  Kumar", "Customer …", "Email …", "Remind …", "Call …", "Dear …". The
  tagger calls "Ping", "Dear" and "Pay" proper nouns there, so it can't be
  what decides.
- **A name is cut short:** "Ping Periwinkle" + "Zanzibar", "Periwinkle" +
  "Zanzibar", "NARAYANAN" without "LAKSHMI".
- **Missed entirely,** even for ordinary Indian names: "Pay Ram Kumar 500
  rupees", "PRIYA SHARMA PAID THE BILL", and many frames with the
  unfamiliar "Periwinkle Zanzibar" (tagged GPE or ORG, or nothing). Step 14.
- **Found while probing: a name run on into an identifier.** "Ravi Kumar
  PAN ABCPE1234F" and "Ravi Kumar UPI 9876543210" come back as one PERSON
  span each. 0.3.0 dropped any PERSON span containing a digit, so **the
  name leaked**. A pre-existing bug, not in the stack's report.

**Decisions** (`detect/person_spans.py`, applied to every PERSON result,
including the title-anchored recognizer's, so documents and chat both get
it)
- **Cut at the first word with a digit** instead of dropping the span. The
  words before it are kept if they're still a plausible name:
  - two words or more; or
  - a name followed by a label that gets trimmed ("Ravi PAN …").
  A lone word before a number with no label ("Form 16", "Q4(Jan-Mar)") is
  dropped, as before.
- **Trim with a curated list, not the tagger.** Words that are never a name
  are removed from either edge, repeatedly: greetings, contact verbs,
  roles, statement vocabulary, days, months, bank names, business
  suffixes. Titles are removed from the front only ("Kumari" is a surname
  after a name).
  - Words that are also given names are **deliberately left out**: Ram,
    Bill, Will, Mark, Rose, Sunny, and the months Jan, Mar, April, May,
    June and August. There's a test that they stay out.
  - Trimming is the only step that can unmask a word, so it never guesses.
  - A span with nothing left is dropped ("Dear Sir").
- **Extend over the rest of the name, using the tagger.** An adjacent word
  joins the name only when all of these hold:
  - spaCy tags it `PROPN`;
  - only spaces separate it from the name (no punctuation, no line break,
    and so never across the ` | ` of a PDF context window);
  - it's letters only, 2+ characters;
  - its case matches the name's: Title-case next to Title-case, all caps
    next to all caps, never next to a lower-case name;
  - it's not a stop word, a listed word or a title;
  - it's not part of a DATE, TIME, number or ORG entity.
  At most two words per side. Here the tagger does help: "PAID" is VERB,
  "LAKSHMI" is PROPN.
  - Place entities (GPE) are allowed to join, because surnames that are
    place names get tagged GPE ("Zanzibar"). Extending can only mask more,
    so a wrong guess costs a second code, never a leak.
- **Overlapping PERSON spans are merged** into one.
- **No second NLP pass.** `_analyze_one` computes the spaCy Doc once,
  hands it to `analyze(nlp_artifacts=…)` and refines against it.

**Result.** The stack's probe, widened to 12 names × 10 frames: every name
gets exactly one code, with no partial masks. The 8 remaining misses are
sentences where NER finds no name at all (step 14 covers those for
anyone already known). "Ravi Kumar PAN ABCPE1234F" is now `PERSON_A PAN
IN_PAN_A`.

**Not done: "map a new PERSON value to an existing entry it contains."**
The stack suggested it as an alternative. With "Ravi Kumar" known, a new
span "Ravi Kumar Sharma" would become `PERSON_A Sharma`: a leak, and the
wrong person. So a span that contains a known name but also has an extra,
unlisted word keeps its full span and gets its own code. Unlisted glue
words therefore still split a person into two codes. The fix for one of
those is adding the word to the list, which is a one-line change with a
test.

**Gaps and caveats**
- **Unknown names that NER misses entirely are still missed** on first
  sight ("Tell Periwinkle Zanzibar to call me"). Step 14 only helps once a
  name is known.
- **Over-extension (safe direction).** A capitalized word right after a
  name, not on the list and tagged PROPN, joins it ("Ravi Kumar Zanzibar
  Traders" stops at "Traders", but an unlisted business word wouldn't).
  The cost is an extra code, not a leak.

## Step 14: sweep for values already known

**The problem** (stack issue 3): NER misses a name it has seen before,
depending on the sentence. After "Periwinkle Zanzibar" was stored, "Ask
Periwinkle Zanzibar about it." came back unchanged. "PRIYA SHARMA PAID THE
BILL." was missed although "Priya Sharma" was stored earlier in the same
request. Step 13's probing showed more: "Pay Ram Kumar 500 rupees", "Tell
Periwinkle Zanzibar to call me" and "Meeting with Periwinkle Zanzibar
tomorrow" get no PERSON at all.

**Decisions** (`detect/known_values.py`)
- **A deterministic sweep after analysis.** Every text is also searched
  for values that are already known, and a match reuses the existing code:
  the matched text normalizes to the stored key, so the store returns the
  same code.
- **Known means** the store's entries plus this call's own detections. A
  name found in one text of a request, or on one line of a document, is
  masked in all of them, whatever the order. In documents the store is
  consulted only in pseudonymize mode (`redact-publish`, `redact --mode
  pseudonymize`); redact mode sweeps the document's own findings only.
- **Types covered** (only those the caller asked for):
  - **PERSON, two words or more.** Matched case-insensitively, as whole
    words, longest first. The text between the words must normalize like
    the key: spaces are fine, and "R." initials must be written the same
    way.
  - **Never swept:** single-word names ("Asha" is a word, "Kumar" is half
    the country); names under 5 letters; names with a digit or a stop
    word; names that start or end with a step-13 glue word. The last rule
    keeps pre-0.4.0 entries like "Ping Ravi Kumar" out of the sweep.
  - **Identifiers** (`ID_TYPES`: PAN, Aadhaar, account numbers, e-mail,
    phone, and the other ID types in the allow-lists). Matched as one whole
    token of 8+ characters containing a digit or "@". Tokens break at
    whitespace and field separators (`/ : , ( )`), so
    `UPI/50100123456789/` matches but `TXN50100123456789` doesn't.
    Indian mobile numbers match in any prefix form. **The main gain is
    context-scoped types:** an account number stored from a statement is
    masked in chat without "account" nearby.
  - **Not covered:** `IN_ADDRESS` (free-form; the PIN-code recognizer
    already finds repeats) and `IN_DATE_OF_BIRTH` (the same date recurs as
    a transaction date).
- **Merging with detections** (`merge_known`):
  - a match covering NER's shorter span wins ("LAKSHMI NARAYANAN" over
    "NARAYANAN");
  - a longer NER span that contains a match keeps its own span ("Ravi
    Kumar Sharma" doesn't become "PERSON_A Sharma");
  - partial overlaps of the same type become one span;
  - an exact span detected under another type takes the known type, so the
    value keeps its code;
  - a partial overlap with another type leaves the detection alone.
- **Never inside codes.** Matches overlapping a code already in the text
  are dropped, so redacting twice changes nothing (tested).
- **The residual gate uses it too.** `find_pii` flags a known value left in
  the clear, so `redact-publish` holds a document where one slipped
  through.
- **The store's index.** `MappingStore.derived(name, build)` keeps values
  computed from the entries with the store snapshot. The index is built
  once per store version, updated in place when this instance issues a code
  (`add_entry`), and rebuilt when another process changes the file. The
  service builds it during warm-up.

**The service cache had to change.** Before, it cached redacted text per
input text. With the sweep, a text's redaction depends on what the store
knows: a text cached as "nothing to mask" would keep coming back unmasked
after the name was learned. That's a leak (tested:
`test_a_cached_text_picks_up_a_name_the_store_learned_since`).
- **It now caches detections only.** Per text it holds the entity types
  and offsets (`api.analyze_texts`, the slow NER half), under the same
  hashed key. The sweep and the codes (`api.redact_analyzed`) run on every
  request.
- **Consequences:** nothing cached ever goes stale, so the "drop the cache
  when another process writes" rule is gone, and the cache holds no text
  at all, not even redacted text. It's bounded by entries (2,000) and by
  total detections (1M).
- **`redact_texts` is now `analyze_texts` + `redact_analyzed`,** with
  unchanged behavior; both halves are public.

**Measured** (synthetic store of 18,836 entries: 10K names, 9K account
numbers):
- Building the index takes 140 ms, once per store version (at warm-up, or
  after another process writes).
- Adding one entry to it takes 0.1 ms.
- Sweeping a 55K-token text takes 36 ms, against about 8 s for NER on the
  same text. The sweep is one pass over the words with dictionary lookups,
  so it doesn't grow with the store.

**Result.** The stack's probe (12 names × 10 frames, one request): 120/120
fully masked, one code per name. It was 58/60 with two or three codes per
name.

**Gaps and caveats**
- **First sightings still depend on NER.** A name NER misses, in a request
  where nothing else finds it, stays in the clear until it's known.
- **A stored NER mistake is swept everywhere.** If spaCy once tagged two
  ordinary words as a PERSON and they got a code, the sweep masks them in
  every later text. The filters (stop words, glue words, two words
  minimum) keep most of these out. `redact-key forget` (step 15) removes
  one.
- **Different spellings are different values.** "R Rajesh Kumar" vs "R.
  Rajesh Kumar", or a hyphenated form, don't match each other.
- **An all-caps known prefix.** With "RAVI KUMAR" known and NER missing
  "RAVI KUMAR SHARMA" entirely, the sweep masks "RAVI KUMAR" and leaves
  "SHARMA". The sweep doesn't extend matches: that needs the tagger, and it
  runs after analysis. It needs NER to miss the longer name and the shorter
  one to be known.

**Benchmark after this step** (`scripts/bench_service.py`, same machine,
p50):

| Request | 0.3.0 | now |
|---|---|---|
| 12K tokens, all new | 1.88 s | 1.92 s |
| 50K tokens, all new | 7.96 s | 8.19 s |
| 20-message history, cache on | 94 ms | 111 ms |
| same, cache off | 1.61 s | 1.65 s |

The history case pays for the sweep and code lookup now running on all 20
cached messages (+17 ms). The rest is within 3%, about the run-to-run
spread seen in step 12.

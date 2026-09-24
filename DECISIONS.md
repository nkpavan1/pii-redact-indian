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

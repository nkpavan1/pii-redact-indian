# HANDOFF: redact-service for the stack session

This is what the stack session (LiteLLM hook, `start-stack.ps1`) needs from
pii-redact 0.4.0. Background and every design decision are in
[DECISIONS.md](DECISIONS.md), the user-facing changes are in
[CHANGELOG.md](CHANGELOG.md), and README.md has the rest of the tool.

## 1. One-time setup (the user runs these)

Everything here touches Credential Manager or ACLs, so it's the user's to
run. Nothing in this repo runs it.

```powershell
$redactKey = "H:\ai\engines\pii-redact\.venv\Scripts\redact-key.exe"

# 1. Create the one shared store and its key (key -> Windows Credential Manager).
& $redactKey init --store H:\ai\redaction\mapping_store.enc

# 2. Back the key up to the password manager (not added to clipboard history
#    or cloud sync; the clipboard is cleared when you press Enter).
& $redactKey export --store H:\ai\redaction\mapping_store.enc --clip --i-understand

# 3. Create the service token: 32 random bytes as base64 (44 characters),
#    readable only by you.
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[IO.File]::WriteAllText("H:\ai\redaction\service.token", [Convert]::ToBase64String($bytes))
Remove-Variable bytes
icacls "H:\ai\redaction\service.token" /inheritance:r /grant:r "${env:USERNAME}:(R,W)"

# 4. Check: key present, store decrypts (never shows the key).
& $redactKey check --store H:\ai\redaction\mapping_store.enc
```

- **Same Windows user.** The key is bound to the store's resolved path and
  to the Windows user. Run the service, `redact-publish` and `redact-key` as
  the **same Windows user**, and never move or rename the store.
- **Token in WSL.** The hook needs the same token. From WSL it can read
  `/mnt/h/ai/redaction/service.token` (the ACL grants the Windows user,
  which WSL file access runs as). How the hook gets the token is the stack
  session's call.

## 2. Start, stop, health

**Start** (from `start-stack.ps1`, before LiteLLM):

```powershell
& "H:\ai\engines\pii-redact\.venv\Scripts\python.exe" -m pii_redact.service `
    --port 8787 --home H:\ai\redaction --pid-file H:\ai\redaction\service.pid
```

- **Interpreter.** `H:\ai\engines\pii-redact\.venv` is on the NVMe drive.
  - It holds an editable install of `F:\Github Repos\pii-redact-indian`, the
    package versions the test suite passed with (pinned), and the spaCy
    model `en_core_web_lg` 3.8.0.
  - The whole suite passes under it.
  - The old venv in `F:\claude\projects\redaction tool\.venv` still works,
    but is deprecated; the user deletes it once the stack is switched.
- **Code changes need no reinstall.** It's an editable install, so a
  `git pull` in the clone takes effect on the next service start. A new
  dependency (a change to `pyproject.toml`) needs
  `H:\ai\engines\pii-redact\.venv\Scripts\python.exe -m pip install -e "F:\Github Repos\pii-redact-indian"`.
- **Defaults.** `--home` defaults to `$env:PII_REDACT_HOME`, else
  `H:\ai\redaction`. The token file defaults to `<home>\service.token`.
- **Logs go to stderr.** Redirect them if you want a file; they never
  contain text.

**Exit codes**
- 2: refused to start (config problem). The reason is on stderr: bad host,
  no or short token, store missing, key missing, or wrong key. Nothing was
  bound.
- 1: warm-up failed after binding (e.g. the spaCy model is missing). It
  reports `failed` on `/health` briefly, then exits.
- 0: stopped normally (Ctrl+C).

**Health states** (`GET http://127.0.0.1:8787/health`, no auth):

| State | HTTP | Body |
|---|---|---|
| not running / not yet bound | connection refused | — |
| warming up | 503 | `{"status": "starting", "ready": false}` |
| ready | 200 | `{"status": "ok", "ready": true, "store_loaded": true, "ephemeral": false, "version": "0.4.0"}` |
| warm-up failed (exits right after) | 503 | `{"status": "failed", "ready": false}` |

**Readiness wait for `start-stack.ps1`:** poll `/health` every 1 s until
`ready: true`, for **up to 120 s**, before starting LiteLLM.
- **Warm start:** the imports and the model load take 1.5 s (model files
  in the OS cache, measured from the H: venv).
- **Cold start:** the first start after boot reads the 425 MB model from
  the NVMe drive. **To be measured by the user after a reboot**:
  ```powershell
  & "F:\Github Repos\pii-redact-indian\scripts\measure_cold_start.ps1"
  ```
  It prints the seconds from launch to `ready: true`. That needs section 1
  done; `-ModelOnly` times just the imports and model load. The 120 s
  budget stands until that number is in (see DECISIONS.md step 11).
- `/health` never waits on the redaction lock, so it answers even during a
  long request.

**Stop:**

```powershell
Stop-Process -Id (Get-Content H:\ai\redaction\service.pid)
```

- **Hard kill is safe.** Store writes are atomic, so a kill can't damage the
  store. The pid file is removed on a clean stop; after a hard kill, the
  next start overwrites it.
- **Foreground:** Ctrl+C.

**Testing against a throwaway store** (for the end-to-end suite, so it
never writes synthetic entries into the real store):

```powershell
& "H:\ai\engines\pii-redact\.venv\Scripts\python.exe" -m pii_redact.service `
    --ephemeral-store --port 8788 --home H:\ai\redaction
```

- **The store.** It's a real, encrypted store, so tests exercise the real
  code, but:
  - its key is random and lives only in that process's memory, with **no
    Credential Manager entry**;
  - its file is in a new `%TEMP%\pii-redact-ephemeral-*` folder;
  - it starts empty.
- **Leaving no trace.** Ctrl+C deletes the folder. After a hard kill
  (`Stop-Process`) the folder stays behind, but nobody can decrypt it, since
  the key died with the process; delete it at leisure.
- **`/health` says `"ephemeral": true`.** A test suite should check this
  before sending anything.
- **Refused on port 8787,** the real service's port (exit code 2).
- **Token.** Same rules as the real service: `$env:PII_REDACT_SERVICE_TOKEN`
  or `--token-file`, else `<home>\service.token`. With `--home
  H:\ai\redaction` it uses the real token, so the suite's token handling is
  unchanged.
- **Verified with the stack's own scripts.** `redact_service_tests.py` and
  `redact_name_probe.py`, changed only to port 8788, pass against it: 14/14,
  and 60/60 names masked.

## 3. HTTP contract

Base URL `http://127.0.0.1:8787`. The service binds 127.0.0.1 only; WSL
reaches it through mirrored networking.

**Auth:** `/v1/*` require `Authorization: Bearer <token>`. `/health` needs
none. Its `ephemeral` field is `true` only for a service started with
`--ephemeral-store` (section 2).

**`POST /v1/redact`**

```json
request:  {"texts": ["Ravi Kumar, PAN ABCPE1234F, asked about the loan.", "Asha Rao replied."]}
response: {"texts": ["PERSON_A, PAN IN_PAN_A, asked about the loan.", "PERSON_B replied."],
           "entities": {"PERSON": 2, "IN_PAN": 1}}
```

- **Order and shape.** Output texts are 1:1 with input texts, in order.
  Empty strings are fine.
- **One request per call.** Send every message part of one LLM call in one
  request: one analyzer pass, one store transaction.
- **`entities`** counts what was redacted in this request, by entity type.
- **Codes already in a text pass through unchanged,** so redacting text that
  already contains codes (redacted documents, echoed history) is safe and
  idempotent.

**`POST /v1/reverse`**

```json
request:  {"texts": ["Thanks, PERSON_A. PERSON_Z is unknown."]}
response: {"texts": ["Thanks, Ravi Kumar. PERSON_Z is unknown."]}
```

- **Exact, whole-token matches only.** `Person A` or `PERSON_A1` are not
  reversed.
- **Invented codes stay as written.** Codes the store never issued (a model
  inventing `PERSON_Z`) are left alone.
- **Display form.** The restored value is the form first seen, upgraded to
  mixed case if an all-caps form was seen first (`RAVI KUMAR`, then
  `Ravi Kumar`).

**Codes** have the form `{ENTITY_TYPE}_{A..Z, AA, AB, ...}`, using the
entity type names in section 5 (`PERSON_A`, `IN_PAN_A`, `EMAIL_ADDRESS_B`,
`PHONE_NUMBER_A`). They are plain ASCII `[A-Z0-9_]`, so nothing needs
escaping in JSON. One store means the same person has the same code in
chat and in published documents.

**Response headers:** `Content-Type: application/json; charset=utf-8`,
`Cache-Control: no-store`, and `X-Request-Id` (matches the `req=` field in
the service log).

**Errors:** always non-2xx with `{"error": "<short reason>"}`. They never
echo input. Error responses close the connection. When an error is decided
before the body is read (401, 413, ...), the service first reads and
discards a body of up to 64 MB, so the client reliably receives the JSON
error. A larger body may instead see the connection reset, which the hook
treats as a block anyway.

| HTTP | `error` | When |
|---|---|---|
| 400 | `invalid json` / `texts must be a list of strings` / `invalid request` | malformed body |
| 401 | `unauthorized` | missing or wrong token (also sends `WWW-Authenticate: Bearer`) |
| 404 | `not found` | unknown path |
| 405 | `method not allowed` | e.g. GET /v1/redact |
| 411 | `length required` | no `Content-Length` (chunked bodies aren't accepted) |
| 413 | `body too large` | body over the cap (default 4 MB, `--max-body-bytes`), checked before reading |
| 413 | `text too large` | one text over 1,000,000 characters (spaCy's limit) |
| 413 | `too many texts` | more than 10,000 texts in one request |
| 500 | `internal error` | anything unexpected (logged by exception class only) |
| 503 | `service not ready` | before warm-up has finished |
| 503 | `busy` | waited over 300 s for the redaction lock |
| 503 | `store unavailable` | store lock not obtained within 10 s, or the store can't be read |

**The hook must treat any non-2xx response, and any timeout, as block**
(fail closed).

## 4. Environment variables

| Variable | Meaning |
|---|---|
| `PII_REDACT_SERVICE_TOKEN` | If set, used as the token instead of the token file, even if it's invalid (a set-but-short value refuses to start). Leave it unset to use the file, so the token isn't inherited by every process. |
| `PII_REDACT_HOME` | Redaction home (store, token, audit log, manifest, reports). Default `H:\ai\redaction`. |

## 5. What gets masked (the `chat` allow-list)

Masked when detected, with any context requirement:

| Entity type | Detected when |
|---|---|
| `PERSON` | spaCy finds a name (mixed case, all caps, even lowercase in the probes), **or** a name follows a title: Mr, Mrs, Miss, Shri, Sri, Smt, Kumari, "Dr." or "Ms." (with the period), including all-caps names with initials (`MR. R RAJESH KUMAR` → `MR. PERSON_A`), **or** the name is already known (below). Software names spaCy mistakes for people (`Markdown`, `Docker`, `Python`, …) are never masked. Words glued to a name are trimmed (`Ping Ravi Kumar` → `Ping PERSON_A`), and a name spaCy cut short is completed (`LAKSHMI NARAYANAN PAID` → `PERSON_A PAID`), so one person gets one code. |
| `IN_PAN` | A valid-shape PAN: the 4th character is a holder type (P, C, H, F, A, T, B, L, J, G). `ABCDE1234F` is **not** a valid PAN and is never detected, so don't use it in tests; use e.g. `ABCPE1234F`. |
| `IN_AADHAAR` | 12 digits with a valid Verhoeff checksum. No context needed. |
| `EMAIL_ADDRESS`, `IFSC`, `IN_GSTIN`, `IN_VEHICLE_REGISTRATION`, `DRIVING_LICENSE`, `TAN`, `CIN`, `CREDIT_CARD` (Luhn-valid), `AIS_DOWNLOAD_ID`, `DEMAT_DP_ID` (NSDL `IN` + 14 digits) | Format match, no context needed (each checked). |
| `UPI_ID` | **Near "upi", "vpa", "gpay", "phonepe" or "paytm"**. A bare `name@bank` is not masked. |
| `IN_VOTER` | **Near "voter" or "epic"** |
| `BANK_ACCOUNT_NUMBER` | 9–18 digits **near "account", "acc" or "bank"** |
| `EPF_UAN`, `CKYC_NUMBER`, `MF_FOLIO_NUMBER`, `RATION_CARD_NUMBER`, `ITR_ACK_NUMBER`, `DEMAT_DP_ID` (CDSL form) | The number **near its context word** (uan/epf, ckyc/kyc, folio, ration/card, itr/acknowledgement, demat/dp) |
| `IN_DATE_OF_BIRTH` | A date **near "dob", "birth" or "born"**. Other dates are never masked. |
| `IN_ADDRESS` | The value **after an address label**: `Address: …`, `my address is …`, `Address of the assessee: …`, a label line with the address on the lines under it, or a label block beside the value in a PDF. It counts only if it has a house number or a comma, and it stops at the end of the sentence. **Or** anything ending in a 6-digit PIN code: `12 MG Road, Indiranagar, Bengaluru 560038`, `BHOPAL - 462001`, or just the number after `PIN`/`pincode`. The verb ("please address this", "Addressing the user") never counts, and neither do e-mail, IP or web addresses. |
| `PHONE_NUMBER` | **Indian mobile numbers with no context needed** (chat only): an optional `+91`/`91`/`0`, then 6–9 and 9 more digits, as `9876543210`, `98765 43210`, `98765-43210`, `+91 98765 43210`. All forms of one number get **one code**. Any other phone number (landlines, non-Indian numbers) only near "phone", "mobile", "telephone", "cell" or "number". |
| `IN_PASSPORT` | One letter + 7 digits (`M1234567`, `M12 34567`) **near "passport"**. |

**Values the store already knows are masked wherever they appear,** even
where detection misses them:
- **Which:** names of two or more words, and identifiers of 8+ characters
  (PAN, Aadhaar, account numbers, e-mail, phone numbers, and every other
  ID type above). They're matched case-insensitively for names, as whole
  words or tokens, longest first, and reuse the existing code.
- **From where:** everything in the shared store (from chat and from
  published documents), plus whatever the other texts of the **same
  request** found. So a name found in one message of the history is masked
  in all of them.
- **Examples:** once `Periwinkle Zanzibar` is known, `Ask Periwinkle
  Zanzibar about it.` becomes `Ask PERSON_A about it.`, although NER finds
  no name there. An account number stored from a statement is masked in
  chat without the word "account".
- **Not swept:** single-word names (`Asha`, `Kumar`), addresses, dates of
  birth.

**Not masked** (checked on synthetic sentences; the model sees these in the
clear):
- **Landlines and non-Indian phone numbers without a context word**:
  `080-23456789`, `+1 555 010 0199`, and `call +44 20 7946 0958` ("call"
  doesn't lift Presidio's phone recognizer).
- **UPI IDs, voter IDs and passport numbers without their context word.**
- **Addresses with neither a PIN code nor an address label**, e.g.
  `12 MG Road, Indiranagar` (no PIN, no label). Unlabeled multi-line
  addresses (letterheads) are masked only on the line that carries the
  PIN code. A labeled value with neither a digit nor a comma ("my address
  is Lotus Towers") isn't masked either.
- **Place names, organizations and employers**: `Pune`, `Infosys`.
- **Plain dates and times**, apart from a date of birth with its context
  word.
- **Money, salaries and amounts**: `12,50,000`.
- **Medical terms and conditions, age, gender, religion, caste, job
  titles, relations.**
- **Names NER misses, the first time they're seen, when there's no
  title.** spaCy misses some names in ordinary sentences (`Tell Periwinkle
  Zanzibar to call me`, `Pay Ram Kumar 500 rupees`). Once a name is known
  (from anywhere, including earlier in the same request), it's masked
  everywhere; until then it isn't.
- **Bare numbers with no context word** that the store doesn't know yet,
  such as an account number without "account".

**False positives, known and accepted (the safe direction):**
- Product names after "MR" (`MR Plus`).
- A leading phrase swept into an address (`Send it to 12 MG Road, …`).
- spaCy tagging some capitalized words as names (`DR NEFT`, `Ms Excel`).
- A label followed by something that isn't an address but has a digit or
  a comma: `Address | Part B1 - Information relating to tax…` in an AIS
  header.
- A capitalized word right after a name can be taken as part of it
  (`Ravi Kumar Zanzibar` becomes one `PERSON`): an extra code, not a leak.
- Any standalone 10-digit number starting 6–9 is treated as a mobile in
  chat. For example, `account 9876543210` is masked as `PHONE_NUMBER`
  rather than `BANK_ACCOUNT_NUMBER`. Amounts with separators, numbers
  inside longer digit runs, and references like `TXN9876543210` or
  `UPI/9876543210/` are not matched.

## 6. Latency and the hook timeout

Measured with `scripts/bench_service.py`: loopback HTTP, synthetic prompts
with PII about every 5 sentences, on a desktop AMD Ryzen 5 9600X
(6 cores / 12 threads), idle machine, version 0.4.0 from the
`H:\ai\engines` venv. Token counts are estimated at 4 characters per
token.

| Request | p50 | p95 |
|---|---|---|
| `/v1/redact`, 12K-token prompt, all new text | 1.82 s | 1.94 s |
| `/v1/redact`, 50K-token prompt, all new text | 7.84 s | 8.40 s |
| `/v1/redact`, 20-message history (about 12K tokens), only the last new, cache on | 109 ms | 114 ms |
| same, cache off | 1.61 s | 1.67 s |
| `/v1/reverse`, 12K-token reply | 1.1 ms | 1.3 ms |

- **Cost scales with new text.** It's roughly 0.16 s per 1K tokens of *new*
  text. Detection for anything the service has seen before (a repeated
  system prompt, earlier turns) comes from its cache; only the cheap
  known-value sweep and code lookup run again. That's why the cached
  history case went from 94 ms (0.3.0) to 109 ms.
- **There is no first-request cost.** Warm-up loads the model, the
  recognizers and the index of known values before `/health` says ready.
  So the first request after a start costs what any request does.
- **The cost depends on the text, not just its length.** The stack's
  12.7K-token S7 filler took 4.6 s on 0.3.0 on every run, first or not,
  against 1.9 s for the benchmark's 12K prompt.
  - Most of the difference was a Presidio PAN pattern that scanned ahead
    to the next four-digit number from every word. That text has none, so
    each scan ran to its end. It's fixed in 0.4.0: that text now takes
    2.7 s.
  - Text dense with numbers or candidate names still costs more per token
    than prose.
- **Tara's ~64K-token requests** should take about 10–11 s when entirely
  new.
- **Requests are serialized,** so a request can wait behind one already in
  progress.

**Recommended hook timeouts:**
- `/v1/redact`: **30 s**, unchanged. That's about 3.7× the 50K-token p95,
  enough to wait behind one other large request.
- `/v1/reverse`: **10 s**.
- On timeout: block.

## 7. Notes for the hook

- **Streaming.** A code can be split across streamed chunks (`PERS` +
  `ON_A`) and then won't reverse. Either reverse the full reply, or buffer
  a streamed reply until a whitespace or punctuation boundary before
  reversing each piece.
- **Tool calls.** Reverse string values inside tool calls and JSON
  arguments as well; `/v1/reverse` works on any list of strings.
- **Where codes can come from.** Text the model sees can already contain
  codes: published documents under `reference/redacted/` use the same
  store. Sending such text back through `/v1/redact` is safe.
- **Settings are fixed per service process.** The entity list is the
  `chat` allow-list and the threshold is `--threshold`, default 0.5. The
  contract has no per-request settings.

## 8. Where this differs from the original brief

- **Command name.** The CLI is `redact`, not `pii-redact`. The new commands
  are separate console scripts: `redact-key`, `redact-publish`,
  `redact-service`.
- **Entity type names.** Codes and entity counts use Presidio's names
  (`IN_PAN_A`, `EMAIL_ADDRESS_A`, `{"IN_PAN": 1}`), not `PAN_A` or `EMAIL_B`.
  This keeps existing stores compatible.
- **`/health` has a `ready` field** and a `starting`/`failed` status, per
  the later amendment, and an `ephemeral` field (0.4.0) for test
  services.
- **No automatic store creation.** A store must be created once with
  `redact-key init`; the service and `redact-publish` never create one.
  This prevents a second store silently issuing the same codes for
  different people.
- **Store identity.** Opening a store checks that it decrypts, not just
  that it exists.
- **`redact-publish` output names are opaque by default.**
  `--readable-names` opts into redacted original names.
- **`redact-publish` detection.** It detects with the document pipeline
  (layout-aware) and uses the string API for the residual gate.
- **What is cached.** The service caches detection results per text
  (entity types and offsets, never text), bounded by entry count and by
  total detections (1M). The known-value sweep and the codes run on every
  request, so a cached text still picks up a name the store learned
  since.
- **Long texts** are analyzed in chunks, for linear latency.

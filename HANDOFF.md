# HANDOFF: redact-service for the stack session

This is what the stack session (LiteLLM hook, `start-stack.ps1`) needs from
pii-redact 0.2.0. Background and every design decision are in
[DECISIONS.md](DECISIONS.md), the user-facing changes are in
[CHANGELOG.md](CHANGELOG.md), and README.md has the rest of the tool.

## 1. One-time setup (the user runs these)

Everything here touches Credential Manager or ACLs, so it's the user's to
run. Nothing in this repo runs it.

```powershell
# 1. Create the one shared store and its key (key -> Windows Credential Manager).
redact-key init --store H:\ai\redaction\mapping_store.enc

# 2. Back the key up to the password manager (not added to clipboard history
#    or cloud sync; the clipboard is cleared when you press Enter).
redact-key export --store H:\ai\redaction\mapping_store.enc --clip --i-understand

# 3. Create the service token: 32 random bytes as base64 (44 characters),
#    readable only by you.
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[IO.File]::WriteAllText("H:\ai\redaction\service.token", [Convert]::ToBase64String($bytes))
Remove-Variable bytes
icacls "H:\ai\redaction\service.token" /inheritance:r /grant:r "${env:USERNAME}:(R,W)"

# 4. Check: key present, store decrypts (never shows the key).
redact-key check --store H:\ai\redaction\mapping_store.enc
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
& "F:\claude\projects\redaction tool\.venv\Scripts\python.exe" -m pii_redact.service `
    --port 8787 --home H:\ai\redaction --pid-file H:\ai\redaction\service.pid
```

- **Which venv.** That is the venv this build is installed into today (an
  editable install of `F:\Github Repos\pii-redact-indian`). If the venv is
  recreated inside the clone (`setup.ps1` there), the path becomes
  `F:\Github Repos\pii-redact-indian\.venv\Scripts\python.exe`.
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
| ready | 200 | `{"status": "ok", "ready": true, "store_loaded": true, "version": "0.2.0"}` |
| warm-up failed (exits right after) | 503 | `{"status": "failed", "ready": false}` |

**Readiness wait for `start-stack.ps1`:** poll `/health` every 1 s until
`ready: true`, for **up to 120 s**, before starting LiteLLM. A warm start
(model files in the OS cache) is ready in about 1.5 s, but the first start
after boot reads the ~600 MB spaCy model from disk. `/health` never waits
on the redaction lock, so it answers even during a long request.

**Stop:**

```powershell
Stop-Process -Id (Get-Content H:\ai\redaction\service.pid)
```

- **Hard kill is safe.** Store writes are atomic, so a kill can't damage the
  store. The pid file is removed on a clean stop; after a hard kill, the
  next start overwrites it.
- **Foreground:** Ctrl+C.

## 3. HTTP contract

Base URL `http://127.0.0.1:8787`. The service binds 127.0.0.1 only; WSL
reaches it through mirrored networking.

**Auth:** `/v1/*` require `Authorization: Bearer <token>`. `/health` needs
none.

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
| `PERSON` | spaCy finds a name (mixed case, all caps, even lowercase in the probes). See the gaps below. |
| `IN_PAN` | A valid-shape PAN: the 4th character is a holder type (P, C, H, F, A, T, B, L, J, G). `ABCDE1234F` is **not** a valid PAN and is never detected, so don't use it in tests; use e.g. `ABCPE1234F`. |
| `IN_AADHAAR` | 12 digits with a valid Verhoeff checksum. No context needed. |
| `EMAIL_ADDRESS`, `IFSC`, `IN_GSTIN`, `IN_VEHICLE_REGISTRATION`, `DRIVING_LICENSE`, `TAN`, `CIN`, `CREDIT_CARD` (Luhn-valid), `AIS_DOWNLOAD_ID`, `DEMAT_DP_ID` (NSDL `IN` + 14 digits) | Format match, no context needed (each checked). |
| `UPI_ID` | **Near "upi", "vpa", "gpay", "phonepe" or "paytm"**. A bare `name@bank` is not masked. |
| `IN_VOTER` | **Near "voter" or "epic"** |
| `BANK_ACCOUNT_NUMBER` | 9–18 digits **near "account", "acc" or "bank"** |
| `EPF_UAN`, `CKYC_NUMBER`, `MF_FOLIO_NUMBER`, `RATION_CARD_NUMBER`, `ITR_ACK_NUMBER`, `DEMAT_DP_ID` (CDSL form) | The number **near its context word** (uan/epf, ckyc/kyc, folio, ration/card, itr/acknowledgement, demat/dp) |
| `IN_DATE_OF_BIRTH` | A date **near "dob", "birth" or "born"**. Other dates are never masked. |
| `IN_ADDRESS` | Text **near the word "address"** only. |
| `PHONE_NUMBER` | **Only near "phone", "mobile", "telephone", "cell" or "number"**. See the gaps below. |

**Not masked** (checked on synthetic sentences; the model sees these in the
clear):
- **Phone numbers without one of those words nearby**: `9876543210`,
  `call me on 9876543210`, `reach me at +91 98765 43210`,
  `whatsapp 9876543210`, `contact 9876543210` and `ph 9876543210` all
  passed through, while `my number is 9876543210` was masked. "call" did
  not boost the score in testing.
- **UPI IDs and voter IDs without their context word.**
- **Passport numbers, even next to "passport"**: Presidio's passport pattern
  tops out at 0.45 with context, below the 0.5 threshold, so `IN_PASSPORT`
  is effectively never masked.
- **Addresses without the word "address"**, e.g.
  `12 MG Road, Indiranagar, Bengaluru 560038`.
- **Place names, organizations and employers**: `Pune`, `Infosys`.
- **Plain dates and times**, apart from a date of birth with its context
  word.
- **Money, salaries and amounts**: `12,50,000`.
- **Medical terms and conditions, age, gender, religion, caste, job
  titles, relations.**
- **Names NER misses.** In the probes, all caps with initials after a
  title left the initial behind (`MR. R RAJESH KUMAR` → `MR. R PERSON_B`),
  and names run together in one word are missed.
- **Bare numbers with no context word**, such as an account number without
  "account".

**Approved, not yet built:** two detection improvements, all-caps names
after a title and PIN-code-anchored addresses. **Proposed, awaiting a
decision:** see DECISIONS.md step 7.

## 6. Latency and the hook timeout

Measured with `scripts/bench_service.py`: loopback HTTP, synthetic prompts
with PII about every 5 sentences, AMD64 laptop CPU, idle machine. Token
counts are estimated at 4 characters per token.

| Request | p50 | p95 |
|---|---|---|
| `/v1/redact`, 12K-token prompt, all new text | 2.06 s | 2.12 s |
| `/v1/redact`, 50K-token prompt, all new text | 8.82 s | 8.93 s |
| `/v1/redact`, 20-message history (about 12K tokens), only the last new, cache on | 97 ms | 108 ms |
| same, cache off | 1.68 s | 1.71 s |
| `/v1/reverse`, 12K-token reply | 1.1 ms | 1.3 ms |

- **Cost scales with new text.** It's roughly 0.17 s per 1K tokens of *new*
  text. Anything the service has seen before (a repeated system prompt,
  earlier turns) comes from its cache.
- **Tara's ~64K-token requests** should take about 11–12 s when entirely
  new.
- **Requests are serialized,** so a request can wait behind one already in
  progress.

**Recommended hook timeouts:**
- `/v1/redact`: **30 s**. That's about 3× the 50K-token p95, enough to
  wait behind one other large request.
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
  the later amendment.
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
- **Cache size.** The result cache is also bounded by total size (64M
  characters), not only by entry count.
- **Long texts** are analyzed in chunks, for linear latency.

"""redact-service: a localhost HTTP service that pseudonymizes text before
it goes to a cloud model and restores the codes in the reply (Tool 2 of
Phase 7). A LiteLLM hook calls it; see HANDOFF.md for the contract.

    redact-service [--port 8787] [--token-file PATH] [--home DIR] [--store PATH | --ephemeral-store]

Endpoints:
- POST /v1/redact  {"texts": [...]} -> {"texts": [...], "entities": {TYPE: n}}
- POST /v1/reverse {"texts": [...]} -> {"texts": [...]}
- GET  /health     -> 200 {"status": "ok", "ready": true, "store_loaded": true, "ephemeral": false, "version": ...}
                      503 {"status": "starting" | "failed", "ready": false}

Security properties, each one deliberate:
- It binds 127.0.0.1 only, and refuses any other host. The port is bound
  exclusively (SO_EXCLUSIVEADDRUSE on Windows), so another local process
  can't take it over.
- /v1/* require `Authorization: Bearer <token>`. The token comes from
  $PII_REDACT_SERVICE_TOKEN if set, else the first line of the token file
  (default <home>/service.token). The service refuses to start if the
  token is missing or shorter than 32 characters. The token (or its
  length) is never printed or logged.
- The service fails closed. Before warm-up finishes (spaCy loaded, one
  scan run, store loaded) /v1/* return 503. Any error is a non-2xx JSON
  {"error": "<short reason>"} that never echoes input. The store is opened
  without create, so a wrong path or missing key stops startup instead of
  silently starting a second store.
- Nothing from a request is persisted or logged. Logs carry a request id,
  route, status, counts and latency. The analysis cache lives in memory
  and holds hashes as keys and detections (offsets and entity types) as
  values - never input text.
- /health never waits on the lock that serializes redaction, so a long
  request can't make a health check time out.

Concurrency: requests are handled on threads. Redaction is serialized by
one processing lock (spaCy and Presidio are shared singletons). Reverse
needs no NER, so it doesn't wait for that lock.

Testing: `--ephemeral-store` runs the service against a throwaway store,
so an end-to-end test suite never writes into the real one. Its key is
random and exists only in this process's memory (no Credential Manager
entry); its file lives in a new temporary folder that is deleted at exit
(and is undecryptable if the process dies first). /health says
`"ephemeral": true`, so a test can check what it is talking to before
sending anything. It is refused on the default port, which belongs to the
real service.

Caching: a chat client re-sends the whole history every turn, so the slow
half of redaction - detection - is cached per text (api.analyze_texts).
The fast half - the known-value sweep and the codes - runs on every
request (api.redact_analyzed), so a cached text still picks up a name the
store learned since, from this service or from another process.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
import hmac
import json
import logging
import os
import socket
import socketserver
import sys
import threading
import time
import uuid
from collections import Counter, OrderedDict
from collections.abc import Callable, Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet

import pii_redact
from pii_redact.anonymize.mapping_store import MappingStore, MappingStoreError
from pii_redact.config import paths

log = logging.getLogger("pii_redact.service")

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_CACHE_ENTRIES = 2000
DEFAULT_CACHE_DETECTIONS = 1_000_000
TOKEN_ENV = "PII_REDACT_SERVICE_TOKEN"
TOKEN_FILE_NAME = "service.token"
MIN_TOKEN_CHARS = 32
MAX_TEXTS_PER_REQUEST = 10_000
STORE_LOCK_TIMEOUT_S = 10
QUEUE_TIMEOUT_S = 300
# An error sent before the request body was read (401, 413, ...) would
# otherwise close a socket with unread data, which Windows answers with a
# TCP reset that can reach the client before the response does. Bodies up to
# this size are read and discarded first, so the client gets the JSON error.
DRAIN_LIMIT_BYTES = 64 * 1024 * 1024
DRAIN_TIMEOUT_S = 5

EPHEMERAL_DIR_PREFIX = "pii-redact-ephemeral-"

_ROUTES = ("/health", "/v1/redact", "/v1/reverse")
_WARM_UP_TEXT = "Warm-up: Ravi Kumar, PAN ABCPE1234F, mobile 9876543210, ravi@example.com."


class ConfigError(Exception):
    """A reason to refuse to start."""


class ServiceBusy(Exception):
    pass


# --- startup checks


def check_host(host: str) -> str:
    if host in (LOOPBACK, "localhost"):
        return LOOPBACK
    raise ConfigError(f"refusing to bind {host!r}: this service only listens on {LOOPBACK}")


def _read_token_file(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"token file {path} not found (and {TOKEN_ENV} is not set)") from None
    except OSError as exc:
        raise ConfigError(f"token file {path} could not be read ({type(exc).__name__})") from None
    # PowerShell 5.1 writes UTF-16 by default and adds a BOM to UTF-8.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig", errors="strict")
    lines = text.splitlines()
    return lines[0].strip() if lines else ""


def load_token(environ: Mapping[str, str], token_file: Path) -> str:
    """$PII_REDACT_SERVICE_TOKEN wins when it is set at all; otherwise the
    first line of the token file. Error messages never include the token
    or its length."""
    if TOKEN_ENV in environ:
        token, source = environ[TOKEN_ENV].strip(), TOKEN_ENV
    else:
        token, source = _read_token_file(token_file), f"token file {token_file}"
    if not token:
        raise ConfigError(f"{source} is empty")
    if len(token) < MIN_TOKEN_CHARS:
        raise ConfigError(f"{source}: token is shorter than {MIN_TOKEN_CHARS} characters")
    return token


# --- analysis cache


class AnalysisCache:
    """In-memory LRU of detection results (api.Analysis: entity types and
    offsets), bounded by entry count and by total detections stored. Keys
    are SHA-256 hashes over the settings and the text, so the cache never
    holds input text, and a result computed under different settings can
    never be returned. Never persisted.

    Detection doesn't depend on the mapping store, so nothing here goes
    stale when the store changes (redaction itself is never cached)."""

    def __init__(self, max_entries: int, max_detections: int):
        self.max_entries = max_entries
        self.max_detections = max_detections
        self._entries: OrderedDict[str, tuple] = OrderedDict()
        self._size = 0
        self._lock = threading.Lock()

    @staticmethod
    def key(settings_key: str, text: str) -> str:
        return hashlib.sha256(f"{settings_key}\0{text}".encode("utf-8")).hexdigest()

    @staticmethod
    def _size_of(analysis: tuple) -> int:
        return len(analysis) + 1

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: str) -> tuple | None:
        with self._lock:
            value = self._entries.get(key)
            if value is not None:
                self._entries.move_to_end(key)
            return value

    def put(self, key: str, analysis: tuple) -> None:
        size = self._size_of(analysis)
        if self.max_entries <= 0 or size > self.max_detections:
            return
        with self._lock:
            if key in self._entries:
                self._size -= self._size_of(self._entries.pop(key))
            self._entries[key] = analysis
            self._size += size
            while len(self._entries) > self.max_entries or self._size > self.max_detections:
                _, evicted = self._entries.popitem(last=False)
                self._size -= self._size_of(evicted)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._size = 0


# --- the service


class RedactionService:
    def __init__(
        self,
        store: MappingStore,
        *,
        entities: list[str] | None = None,
        threshold: float | None = None,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
        cache_detections: int = DEFAULT_CACHE_DETECTIONS,
        ephemeral: bool = False,
    ):
        from pii_redact import api  # Presidio/spaCy load here, after the startup checks

        self._api = api
        self.store = store
        self.entities = api._resolve_entities(entities)
        self.threshold = api._resolve_threshold(threshold)
        self.settings_key = json.dumps({"entities": sorted(self.entities), "threshold": self.threshold})
        self.cache = AnalysisCache(cache_entries, cache_detections)
        self.processing_lock = threading.Lock()
        self.ephemeral = ephemeral
        # Plain attributes, read by /health without any lock.
        self.status = "starting"
        self.store_loaded = False

    @property
    def ready(self) -> bool:
        return self.status == "ok"

    def warm_up(self) -> None:
        """Loads the store and the NLP model, builds the index of values the
        store knows, and runs one read-only scan, so the first real request
        isn't the slow one. Issues no codes."""
        from pii_redact.anonymize.operators import get_anonymizer_engine
        from pii_redact.detect.analyzer import get_analyzer
        from pii_redact.detect.known_values import store_index

        self.store.load()
        self.store_loaded = True
        get_analyzer()
        get_anonymizer_engine()
        store_index(self.store)
        self._api.find_pii(_WARM_UP_TEXT, self.store, entities=self.entities, threshold=self.threshold)
        self.status = "ok"

    def start_warm_up(self, on_failure: Callable[[], None] | None = None) -> threading.Thread:
        def run():
            started = time.perf_counter()
            try:
                self.warm_up()
            except Exception as exc:
                self.status = "failed"
                log.error("warm-up failed: %s", type(exc).__name__)
                if on_failure is not None:
                    on_failure()
                return
            log.info("ready (warm-up %.1fs)", time.perf_counter() - started)

        thread = threading.Thread(target=run, name="warm-up", daemon=True)
        thread.start()
        return thread

    def redact(self, texts: list[str]) -> tuple[list[str], dict[str, int], int]:
        """(redacted texts, entity counts, cache hits)."""
        if not self.processing_lock.acquire(timeout=QUEUE_TIMEOUT_S):
            raise ServiceBusy
        try:
            keys = [AnalysisCache.key(self.settings_key, t) for t in texts]
            analyses = [self.cache.get(k) for k in keys]
            misses = [i for i, a in enumerate(analyses) if a is None]
            if misses:
                fresh = self._api.analyze_texts(
                    [texts[i] for i in misses], entities=self.entities, threshold=self.threshold
                )
                for i, analysis in zip(misses, fresh):
                    analyses[i] = analysis
                    self.cache.put(keys[i], analysis)
            results = self._api.redact_analyzed(texts, analyses, self.store, entities=self.entities)
        finally:
            self.processing_lock.release()
        totals: Counter[str] = Counter()
        for result in results:
            totals.update(result.entities)
        return [result.text for result in results], dict(totals), len(texts) - len(misses)

    def reverse(self, texts: list[str]) -> list[str]:
        return self._api.reverse_texts(texts, self.store)


# --- HTTP


class _RequestError(Exception):
    def __init__(self, status: HTTPStatus, reason: str):
        self.status, self.reason = status, reason


class _Handler(BaseHTTPRequestHandler):
    server_version = "pii-redact"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # The defaults log the raw request line (which could carry anything a
    # client put in the URL) and echo it in HTML error pages. Neither is
    # acceptable here, so both are replaced.
    def log_message(self, format, *args):  # noqa: A002
        pass

    def send_error(self, code, message=None, explain=None):
        log.info("req=- route=other status=%d malformed request", code)
        self._reply(code, {"error": HTTPStatus(code).phrase.lower()})

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET

    def _dispatch(self) -> None:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex[:12]
        route = urlsplit(self.path).path
        info = ""
        self._body_consumed = False
        try:
            status, payload, info = self._handle(route, request_id)
        except _RequestError as exc:
            status, payload = exc.status, {"error": exc.reason}
        except Exception as exc:
            log.error("req=%s internal error: %s", request_id, type(exc).__name__)
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"}
        self._reply(status, payload, request_id)
        log.info(
            "req=%s method=%s route=%s status=%d%s ms=%.1f",
            request_id,
            self.command,
            route if route in _ROUTES else "other",
            status,
            info,
            (time.perf_counter() - started) * 1000,
        )

    def _handle(self, route: str, request_id: str) -> tuple[HTTPStatus, dict, str]:
        service: RedactionService = self.server.service
        if route == "/health":
            if self.command != "GET":
                raise _RequestError(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
            if service.ready:
                return HTTPStatus.OK, {
                    "status": "ok",
                    "ready": True,
                    "store_loaded": service.store_loaded,
                    "ephemeral": service.ephemeral,
                    "version": pii_redact.__version__,
                }, ""
            return HTTPStatus.SERVICE_UNAVAILABLE, {"status": service.status, "ready": False}, ""
        if route not in ("/v1/redact", "/v1/reverse"):
            raise _RequestError(HTTPStatus.NOT_FOUND, "not found")
        if self.command != "POST":
            raise _RequestError(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
        if not self._authorized():
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if not service.ready:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "service not ready")

        texts = self._read_texts()
        try:
            if route == "/v1/redact":
                out, entities, hits = service.redact(texts)
                counts = ",".join(f"{t}:{n}" for t, n in sorted(entities.items())) or "-"
                return HTTPStatus.OK, {"texts": out, "entities": entities}, (
                    f" texts={len(texts)} entities={counts} cache_hits={hits}"
                )
            return HTTPStatus.OK, {"texts": service.reverse(texts)}, f" texts={len(texts)}"
        except service._api.TextTooLongError:
            raise _RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "text too large") from None
        except ServiceBusy:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "busy") from None
        except MappingStoreError:
            log.error("req=%s mapping store unavailable", request_id)
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "store unavailable") from None

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, provided = header.partition(" ")
        if scheme.lower() != "bearer" or not provided:
            return False
        return hmac.compare_digest(provided.strip().encode("utf-8"), self.server.token.encode("utf-8"))

    def _read_texts(self) -> list[str]:
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            raise _RequestError(HTTPStatus.LENGTH_REQUIRED, "length required")
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise _RequestError(HTTPStatus.LENGTH_REQUIRED, "length required")
        try:
            length = int(length_header)
        except ValueError:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid request") from None
        if length < 0:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid request")
        if length > self.server.max_body_bytes:
            raise _RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
        body = self.rfile.read(length)
        self._body_consumed = True
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid json") from None
        texts = payload.get("texts") if isinstance(payload, dict) else None
        if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "texts must be a list of strings")
        if len(texts) > MAX_TEXTS_PER_REQUEST:
            raise _RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too many texts")
        return texts

    def _drain_unread_body(self) -> None:
        """Reads and discards a request body that was never read (see
        DRAIN_LIMIT_BYTES). The discarded bytes are never looked at."""
        if getattr(self, "_body_consumed", True):
            return
        self._body_consumed = True
        try:
            remaining = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return
        if remaining <= 0 or remaining > DRAIN_LIMIT_BYTES:
            return
        try:
            self.connection.settimeout(DRAIN_TIMEOUT_S)
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 16, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _reply(self, status: int, payload: dict, request_id: str | None = None) -> None:
        if status >= 400:
            self._drain_unread_body()
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if request_id:
            self.send_header("X-Request-Id", request_id)
        if status == HTTPStatus.UNAUTHORIZED:
            self.send_header("WWW-Authenticate", "Bearer")
        if status >= 400:
            # The body may not have been read; never reuse this connection.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class ServiceServer(ThreadingHTTPServer):
    daemon_threads = True
    # SO_REUSEADDR on Windows would let another process bind the same port
    # and receive traffic meant for this one.
    allow_reuse_address = False

    def __init__(self, port: int, service: RedactionService, token: str, max_body_bytes: int):
        self.service = service
        self.token = token
        self.max_body_bytes = max_body_bytes
        super().__init__((LOOPBACK, port), _Handler)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        # Skips HTTPServer.server_bind's reverse-DNS lookup of the host,
        # which can stall for seconds on Windows.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address) -> None:
        log.error("connection error: %s", sys.exc_info()[0].__name__)


def create_server(
    service: RedactionService, token: str, *, host: str = LOOPBACK, port: int = DEFAULT_PORT,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> ServiceServer:
    check_host(host)
    if len(token) < MIN_TOKEN_CHARS:
        raise ConfigError(f"token is shorter than {MIN_TOKEN_CHARS} characters")
    return ServiceServer(port, service, token, max_body_bytes)


def open_ephemeral_store() -> tuple[MappingStore, Path]:
    """A throwaway store in a new temporary folder, with a random key that
    lives only in this process (never in the OS credential store). The
    caller deletes the folder when done."""
    folder = Path(tempfile.mkdtemp(prefix=EPHEMERAL_DIR_PREFIX))
    store = MappingStore(
        folder / paths.STORE_FILE_NAME, key=Fernet.generate_key(), cache=True, lock_timeout=STORE_LOCK_TIMEOUT_S
    )
    return store, folder


# --- command line


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redact-service",
        description="Localhost HTTP service: pseudonymize text for cloud models, restore codes in replies.",
    )
    parser.add_argument("--host", default=LOOPBACK, help=f"Must be {LOOPBACK} (anything else is refused)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--home", type=Path, default=None,
                        help=f"Redaction home (default: $env:{paths.HOME_ENV}, else {paths.DEFAULT_HOME})")
    store_choice = parser.add_mutually_exclusive_group()
    store_choice.add_argument("--store", type=Path, default=None, help="Mapping store (default: <home>\\mapping_store.enc)")
    store_choice.add_argument("--ephemeral-store", action="store_true",
                              help="Tests only: a throwaway store (random in-memory key, temporary folder deleted "
                                   f"at exit). Refused on port {DEFAULT_PORT}.")
    parser.add_argument("--token-file", type=Path, default=None,
                        help=f"Bearer token file, first line (default: <home>\\{TOKEN_FILE_NAME}); "
                             f"${TOKEN_ENV} takes precedence when set")
    parser.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES,
                        help=f"Largest accepted request body (default {DEFAULT_MAX_BODY_BYTES})")
    parser.add_argument("--cache-entries", type=int, default=DEFAULT_CACHE_ENTRIES,
                        help=f"Detection cache size in texts, 0 to disable (default {DEFAULT_CACHE_ENTRIES})")
    parser.add_argument("--threshold", type=float, default=None, help="Minimum detection score (default 0.5)")
    parser.add_argument("--pid-file", type=Path, default=None, help="Write the process id here while running")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    home = args.home if args.home is not None else paths.redaction_home()
    ephemeral_folder: Path | None = None
    try:
        try:
            check_host(args.host)
            if args.ephemeral_store and args.port == DEFAULT_PORT:
                raise ConfigError(
                    f"--ephemeral-store is refused on port {DEFAULT_PORT}, the real service's port "
                    "(use another, e.g. --port 8788)"
                )
            token = load_token(os.environ, args.token_file or home / TOKEN_FILE_NAME)
            if args.ephemeral_store:
                store, ephemeral_folder = open_ephemeral_store()
            else:
                store = MappingStore(
                    args.store or home / paths.STORE_FILE_NAME,
                    create=False,
                    cache=True,
                    lock_timeout=STORE_LOCK_TIMEOUT_S,
                )
            store.load()
        except (ConfigError, MappingStoreError) as exc:
            print(f"redact-service: refusing to start: {exc}", file=sys.stderr)
            return 2
        if args.ephemeral_store:
            log.warning(
                "EPHEMERAL STORE: codes live only in this process and are lost when it exits "
                "- for tests, never for real traffic"
            )

        service = RedactionService(
            store, threshold=args.threshold, cache_entries=args.cache_entries, ephemeral=args.ephemeral_store
        )
        try:
            server = create_server(service, token, port=args.port, max_body_bytes=args.max_body_bytes)
        except OSError as exc:
            print(f"redact-service: cannot listen on {LOOPBACK}:{args.port} ({exc.strerror})", file=sys.stderr)
            return 2
        if args.pid_file:
            args.pid_file.write_text(str(os.getpid()), encoding="ascii")
        log.info("listening on http://%s:%d (warming up)", LOOPBACK, server.server_port)
        service.start_warm_up(on_failure=lambda: threading.Thread(target=server.shutdown, daemon=True).start())
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            if args.pid_file:
                args.pid_file.unlink(missing_ok=True)
        return 1 if service.status == "failed" else 0
    finally:
        if ephemeral_folder is not None:
            shutil.rmtree(ephemeral_folder, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

"""redact-service (Tool 2) over real HTTP on 127.0.0.1 with an ephemeral
port: a real server, real detection, and a real encrypted store with an
explicit key. Synthetic data only; never the real store or token."""

import http.client
import json
import logging
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from pii_redact import api, service
from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.service import (
    ConfigError,
    RedactionService,
    ResultCache,
    check_host,
    create_server,
    load_token,
)

TOKEN = "synthetic-test-token-" + "x" * 24  # 45 characters, never a real one
NOTE = "Ravi Kumar, PAN ABCPE1234F, asked about the loan."
MARKER = "ZQXMARKER"  # a string that must never show up in logs or files


@pytest.fixture
def key():
    return Fernet.generate_key()


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "home" / "mapping_store.enc"


@pytest.fixture
def store(store_path, key):
    return MappingStore(store_path, key=key, cache=True)


def _start(store, **server_options):
    svc = RedactionService(store)
    server = create_server(svc, TOKEN, port=0, **server_options)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return SimpleNamespace(service=svc, server=server, port=server.server_port, thread=thread)


@pytest.fixture
def running(store):
    handle = _start(store)
    yield handle
    handle.server.shutdown()
    handle.server.server_close()


@pytest.fixture
def ready(running):
    running.service.warm_up()
    return running


def _call(port, method, path, payload=None, *, token=TOKEN, raw_body=None, headers=None, timeout=30):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    all_headers = dict(headers or {})
    if token is not None:
        all_headers["Authorization"] = f"Bearer {token}"
    body = raw_body if raw_body is not None else (json.dumps(payload).encode() if payload is not None else None)
    if body is not None:
        all_headers.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=body, headers=all_headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, (json.loads(data) if data else None), response


def _raw(port, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


# --- readiness


def test_health_is_503_starting_before_warm_up(running):
    status, body, _ = _call(running.port, "GET", "/health", token=None)
    assert status == 503
    assert body == {"status": "starting", "ready": False}


def test_v1_endpoints_are_503_before_warm_up(running):
    for path in ("/v1/redact", "/v1/reverse"):
        status, body, _ = _call(running.port, "POST", path, {"texts": [NOTE]})
        assert status == 503
        assert body == {"error": "service not ready"}


def test_health_after_warm_up_needs_no_auth(ready):
    status, body, _ = _call(ready.port, "GET", "/health", token=None)
    assert status == 200
    assert body == {"status": "ok", "ready": True, "store_loaded": True, "version": service.pii_redact.__version__}


def test_warm_up_issues_no_codes(ready, store):
    assert store.all_codes() == {}


def test_failed_warm_up_reports_failed(running, monkeypatch):
    def broken():
        raise OSError("model missing")

    monkeypatch.setattr(running.service, "warm_up", broken)
    stopped = threading.Event()
    running.service.start_warm_up(on_failure=stopped.set).join(10)

    assert stopped.is_set()
    status, body, _ = _call(running.port, "GET", "/health", token=None)
    assert status == 503 and body == {"status": "failed", "ready": False}


def test_health_never_waits_for_the_redaction_lock(ready):
    # A long redaction holds this lock; /health must still answer at once.
    ready.service.processing_lock.acquire()
    try:
        started = time.perf_counter()
        status, _, _ = _call(ready.port, "GET", "/health", token=None, timeout=5)
        assert status == 200
        assert time.perf_counter() - started < 2
    finally:
        ready.service.processing_lock.release()


# --- auth


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-token-" + "y" * 30},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": f"Bearer {TOKEN[:-1]}"},
        {"Authorization": "Bearer"},
    ],
)
def test_missing_or_wrong_token_is_401(ready, headers):
    status, body, response = _call(ready.port, "POST", "/v1/redact", {"texts": [NOTE]}, token=None, headers=headers)
    assert status == 401
    assert body == {"error": "unauthorized"}
    assert response.getheader("WWW-Authenticate") == "Bearer"


# --- the contract


def test_redact_then_reverse_round_trip(ready):
    texts = [NOTE, "", "Asha Rao replied."]
    status, body, response = _call(ready.port, "POST", "/v1/redact", {"texts": texts})

    assert status == 200
    assert body["texts"] == ["PERSON_A, PAN IN_PAN_A, asked about the loan.", "", "PERSON_B replied."]
    assert body["entities"] == {"PERSON": 2, "IN_PAN": 1}
    assert response.getheader("X-Request-Id")

    status, back, _ = _call(ready.port, "POST", "/v1/reverse", {"texts": body["texts"] + ["PERSON_Z stays."]})
    assert status == 200
    assert back == {"texts": texts + ["PERSON_Z stays."]}


def test_redacting_codes_again_changes_nothing(ready):
    _, first, _ = _call(ready.port, "POST", "/v1/redact", {"texts": [NOTE]})
    _, second, _ = _call(ready.port, "POST", "/v1/redact", {"texts": first["texts"]})
    assert second == {"texts": first["texts"], "entities": {}}


def test_unknown_route_and_wrong_methods(ready):
    assert _call(ready.port, "GET", "/v1/nothing")[0] == 404
    assert _call(ready.port, "GET", "/v1/redact")[0] == 405
    assert _call(ready.port, "POST", "/health", {"texts": []})[0] == 405


@pytest.mark.parametrize(
    "raw_body, reason",
    [
        (b"{not json " + MARKER.encode(), "invalid json"),
        (b"\xff\xfe" + MARKER.encode(), "invalid json"),
        (json.dumps({"texts": MARKER}).encode(), "texts must be a list of strings"),
        (json.dumps({"texts": [MARKER, 3]}).encode(), "texts must be a list of strings"),
        (json.dumps([MARKER]).encode(), "texts must be a list of strings"),
    ],
)
def test_bad_requests_are_400_and_never_echo_input(ready, raw_body, reason):
    status, body, _ = _call(ready.port, "POST", "/v1/redact", raw_body=raw_body)
    assert status == 400
    assert body == {"error": reason}


def test_body_over_the_cap_is_413(store):
    # Repeated, with a body far over the cap: the response must arrive every
    # time. Closing a socket with unread data makes Windows send a reset
    # that could beat the 413 to the client; the server drains the body
    # first so it can't.
    handle = _start(store, max_body_bytes=200)
    try:
        handle.service.warm_up()
        for _ in range(15):
            status, body, _ = _call(handle.port, "POST", "/v1/redact", {"texts": ["x" * 300_000]})
            assert status == 413
            assert body == {"error": "body too large"}
    finally:
        handle.server.shutdown()
        handle.server.server_close()


def test_unauthorized_request_with_a_large_body_still_gets_its_401(ready):
    for _ in range(15):
        status, body, _ = _call(ready.port, "POST", "/v1/redact", {"texts": ["x" * 300_000]}, token="wrong" * 10)
        assert status == 401
        assert body == {"error": "unauthorized"}


def test_missing_content_length_is_411(ready):
    request = (
        f"POST /v1/redact HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
    ).encode()
    response = _raw(ready.port, request)
    assert response.startswith(b"HTTP/1.1 411")
    assert b'{"error": "length required"}' in response


def test_malformed_request_line_is_not_echoed(ready):
    response = _raw(ready.port, f"GARBAGE {MARKER}\r\n\r\n".encode())
    assert MARKER.encode() not in response


def test_query_strings_are_ignored_and_never_logged(ready, caplog):
    caplog.set_level(logging.INFO, logger="pii_redact.service")
    status, _, _ = _call(ready.port, "POST", f"/v1/redact?note={MARKER}", {"texts": ["hello"]})
    assert status == 200
    assert MARKER not in caplog.text


# --- no content in logs or on disk


def test_logs_never_contain_input_or_output_text(ready, caplog):
    caplog.set_level(logging.INFO, logger="pii_redact.service")
    secret = f"Ravi Kumar {MARKER}, PAN ABCPE1234F"
    _call(ready.port, "POST", "/v1/redact", {"texts": [secret]})
    _call(ready.port, "POST", "/v1/reverse", {"texts": [f"PERSON_A {MARKER}"]})
    _call(ready.port, "POST", "/v1/redact", raw_body=b"{" + MARKER.encode())
    _raw(ready.port, f"GARBAGE {MARKER}\r\n\r\n".encode())

    logged = caplog.text
    for forbidden in (MARKER, "Ravi", "ABCPE1234F", "PERSON_A", TOKEN):
        assert forbidden not in logged
    assert "route=/v1/redact status=200 texts=1 entities=IN_PAN:1,PERSON:1 cache_hits=0" in logged


def test_nothing_from_a_request_is_written_to_disk(tmp_path, ready, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = {p for p in tmp_path.rglob("*")}
    _call(ready.port, "POST", "/v1/redact", {"texts": [f"Ravi Kumar {MARKER}"]})
    _call(ready.port, "POST", "/v1/redact", raw_body=b"{" + MARKER.encode())

    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert MARKER.encode() not in path.read_bytes(), path
    new_files = {p for p in tmp_path.rglob("*")} - before
    # Only the store itself (encrypted, now holding PERSON_A) may appear.
    assert {p.name for p in new_files if p.is_file()} <= {"mapping_store.enc", "mapping_store.enc.lock"}


# --- result cache


def _count_redact_calls(monkeypatch):
    calls = []
    real = api.redact_texts

    def counting(texts, *args, **kwargs):
        calls.append(len(texts))
        return real(texts, *args, **kwargs)

    monkeypatch.setattr(api, "redact_texts", counting)
    return calls


def test_repeated_history_is_served_from_the_cache(ready, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="pii_redact.service")
    calls = _count_redact_calls(monkeypatch)
    history = [NOTE, "Asha Rao replied."]
    _, first, _ = _call(ready.port, "POST", "/v1/redact", {"texts": history})
    _, second, _ = _call(ready.port, "POST", "/v1/redact", {"texts": history + ["Thanks, Ravi Kumar."]})

    assert calls == [2, 1]  # only the new message was analyzed
    assert second["texts"][:2] == first["texts"]
    assert second["texts"][2] == "Thanks, PERSON_A."
    assert second["entities"] == {"PERSON": 3, "IN_PAN": 1}
    assert "cache_hits=2" in caplog.text


def test_cache_is_dropped_when_another_process_changes_the_store(ready, monkeypatch, store_path, key):
    calls = _count_redact_calls(monkeypatch)
    _call(ready.port, "POST", "/v1/redact", {"texts": [NOTE]})
    MappingStore(store_path, key=key).get_or_create_code("PERSON", "SOMEONE ELSE")  # "Tool 1"
    _call(ready.port, "POST", "/v1/redact", {"texts": [NOTE]})
    assert calls == [1, 1]


def test_cache_key_covers_settings_as_well_as_text(store):
    assert ResultCache.key("settings-a", NOTE) != ResultCache.key("settings-b", NOTE)
    default = RedactionService(store)
    stricter = RedactionService(store, threshold=0.8)
    narrower = RedactionService(store, entities=["IN_PAN"])
    assert len({default.settings_key, stricter.settings_key, narrower.settings_key}) == 3


def test_cache_is_bounded_by_entries_and_size():
    cache = ResultCache(max_entries=2, max_chars=10)
    cache.put("a", ("aaaa", {}))
    cache.put("b", ("bbbb", {}))
    cache.get("a")  # "a" is now the most recent
    cache.put("c", ("cccc", {}))
    assert cache.get("b") is None and cache.get("a") and cache.get("c")
    cache.put("big", ("x" * 11, {}))  # larger than the whole cache: not stored
    assert cache.get("big") is None
    assert len(ResultCache(0, 100)) == 0
    disabled = ResultCache(0, 100)
    disabled.put("a", ("aaaa", {}))
    assert disabled.get("a") is None


# --- concurrency with redact-publish


def test_concurrent_publish_writes_and_service_requests_lose_no_codes(ready, store_path, key):
    service_pans = [f"ABCPE{n:04d}F" for n in range(1, 16)]
    tool_pans = [f"ABCPT{n:04d}G" for n in range(1, 16)]
    service_results = {}

    def tool_one():
        tool_store = MappingStore(store_path, key=key)  # a separate process's view
        for pan in tool_pans:
            tool_store.get_or_create_code("IN_PAN", pan, display=pan)

    tool = threading.Thread(target=tool_one)
    tool.start()
    for pan in service_pans:
        status, body, _ = _call(ready.port, "POST", "/v1/redact", {"texts": [f"PAN {pan} on file."]})
        assert status == 200
        service_results[pan] = body["texts"][0].split()[1]
    tool.join(60)

    final = MappingStore(store_path, key=key).all_codes()
    assert len(final) == len(service_pans) + len(tool_pans)  # nothing lost or duplicated
    for pan, code in service_results.items():
        assert final[code] == pan
    status, back, _ = _call(ready.port, "POST", "/v1/reverse", {"texts": list(service_results.values())})
    assert back["texts"] == list(service_results)


# --- refusing to start


def test_token_from_the_environment_wins(tmp_path):
    token_file = tmp_path / "service.token"
    token_file.write_text("f" * 40, encoding="utf-8")
    assert load_token({"PII_REDACT_SERVICE_TOKEN": "e" * 40}, token_file) == "e" * 40


def test_token_from_the_first_line_of_the_file(tmp_path):
    token_file = tmp_path / "service.token"
    token_file.write_bytes(("  " + "f" * 40 + "  \r\nsecond line\r\n").encode())
    assert load_token({}, token_file) == "f" * 40


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_token_file_written_by_powershell_is_accepted(tmp_path, encoding):
    token_file = tmp_path / "service.token"
    token_file.write_bytes(("f" * 40 + "\r\n").encode(encoding))
    assert load_token({}, token_file) == "f" * 40


def test_missing_token_file_refuses(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_token({}, tmp_path / "service.token")


def test_empty_token_file_refuses(tmp_path):
    token_file = tmp_path / "service.token"
    token_file.write_text("\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="empty"):
        load_token({}, token_file)


@pytest.mark.parametrize("source", ["env", "file"])
def test_short_token_refuses_without_revealing_it_or_its_length(tmp_path, source):
    short = "s" * 31
    token_file = tmp_path / "service.token"
    token_file.write_text(short if source == "file" else "f" * 40, encoding="utf-8")
    environ = {"PII_REDACT_SERVICE_TOKEN": short} if source == "env" else {}
    with pytest.raises(ConfigError) as info:
        load_token(environ, token_file)
    message = str(info.value)
    assert short not in message and "31" not in message
    assert "shorter than 32" in message


def test_short_env_token_refuses_even_with_a_valid_file(tmp_path):
    token_file = tmp_path / "service.token"
    token_file.write_text("f" * 40, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_token({"PII_REDACT_SERVICE_TOKEN": "short"}, token_file)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "::1", "example.com"])
def test_non_loopback_bind_refuses(host, store):
    with pytest.raises(ConfigError):
        check_host(host)
    with pytest.raises(ConfigError):
        create_server(RedactionService(store), TOKEN, host=host, port=0)


def test_localhost_means_ipv4_loopback():
    assert check_host("localhost") == "127.0.0.1"


def test_main_refuses_a_non_loopback_host(capsys):
    assert service.main(["--host", "0.0.0.0"]) == 2
    assert "only listens on 127.0.0.1" in capsys.readouterr().err


def test_main_refuses_without_a_token(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PII_REDACT_SERVICE_TOKEN", raising=False)
    assert service.main(["--home", str(tmp_path)]) == 2
    assert "not found" in capsys.readouterr().err


def test_main_runs_end_to_end_after_redact_key_init(tmp_path, monkeypatch, fake_keyring):
    from pii_redact import keytool

    home = tmp_path / "home"
    assert keytool.main(["init", "--store", str(home / "mapping_store.enc")]) == 0
    (home / "service.token").write_text(TOKEN + "\n", encoding="utf-8")
    monkeypatch.delenv("PII_REDACT_SERVICE_TOKEN", raising=False)
    pid_file = tmp_path / "service.pid"
    seen = {}

    def serve_once(self, poll_interval=0.5):
        # Stands in for the endless loop: serve until warm-up is done, make
        # one real request, then return as if stopped.
        thread = threading.Thread(target=service.ThreadingHTTPServer.serve_forever, args=(self, 0.05), daemon=True)
        thread.start()
        deadline = time.time() + 60
        while not self.service.ready and time.time() < deadline:
            time.sleep(0.05)
        seen["pid_file"] = pid_file.exists()
        seen["health"] = _call(self.server_port, "GET", "/health", token=None)[:2]
        seen["redact"] = _call(self.server_port, "POST", "/v1/redact", {"texts": [NOTE]})[:2]
        self.shutdown()

    monkeypatch.setattr(service.ServiceServer, "serve_forever", serve_once)
    assert service.main(["--home", str(home), "--port", "0", "--pid-file", str(pid_file)]) == 0
    assert seen["pid_file"] is True
    assert seen["health"][0] == 200
    assert seen["redact"] == (200, {"texts": ["PERSON_A, PAN IN_PAN_A, asked about the loan."], "entities": {"PERSON": 1, "IN_PAN": 1}})
    assert not pid_file.exists()


def test_main_refuses_without_an_initialized_store(tmp_path, monkeypatch, fake_keyring, capsys):
    monkeypatch.setenv("PII_REDACT_SERVICE_TOKEN", TOKEN)
    assert service.main(["--home", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "redact-key init" in err
    assert TOKEN not in err

"""Several processes issuing codes into one store at the same time - the
redact CLI, redact-publish and redact-service can all run at once. No code
may be lost, duplicated, or handed to two different values."""

import multiprocessing
import queue

from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore, _make_code
from tests.unit._store_workers import issue_codes

WORKERS = 4
OWN_VALUES = 15
SHARED_VALUES = 5


def test_concurrent_processes_never_lose_or_duplicate_codes(tmp_path):
    context = multiprocessing.get_context("spawn")
    key = Fernet.generate_key()
    store_path = tmp_path / "mapping.enc"
    start = context.Event()
    results = context.Queue()

    processes = [
        context.Process(
            target=issue_codes,
            # Half the workers use the in-memory cache (the service), half
            # re-read every time (the CLI tools).
            args=(str(store_path), key, worker_id, OWN_VALUES, SHARED_VALUES, worker_id % 2 == 0, start, results),
        )
        for worker_id in range(WORKERS)
    ]
    for process in processes:
        process.start()
    start.set()

    issued_by_worker = []
    try:
        for _ in processes:
            issued_by_worker.append(results.get(timeout=120))
    except queue.Empty:
        raise AssertionError("a worker did not finish in time")
    finally:
        for process in processes:
            process.join(30)
            if process.is_alive():
                process.kill()
    assert all(process.exitcode == 0 for process in processes)

    final = MappingStore(store_path, key=key).all_codes()  # code -> value
    code_for_value = {value: code for code, value in final.items()}

    expected_values = WORKERS * OWN_VALUES + SHARED_VALUES
    assert len(final) == expected_values  # nothing lost, no value stored twice
    assert len(code_for_value) == expected_values  # no code shared by two values
    # Ordinals were handed out without gaps or reuse.
    assert sorted(final) == sorted(_make_code("PERSON", n) for n in range(1, expected_values + 1))

    for issued in issued_by_worker:
        for value, code in issued.items():
            # Every code a worker was given is the one that persisted.
            assert code_for_value[value] == code

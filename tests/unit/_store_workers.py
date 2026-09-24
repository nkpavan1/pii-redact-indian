"""Worker for the multi-process store test. Kept in its own module so the
spawned processes import only the mapping store, not pytest or Presidio."""

from pathlib import Path

from pii_redact.anonymize.mapping_store import MappingStore


def issue_codes(store_path, key, worker_id, own_values, shared_values, use_cache, start, results):
    store = MappingStore(Path(store_path), key=key, cache=use_cache)
    start.wait(60)
    issued = {}
    for i in range(own_values):
        value = f"WORKER {worker_id} PERSON {i}"
        issued[value] = store.get_or_create_code("PERSON", value)
        # Every worker also asks for the same shared values, interleaved
        # with its own, to force contention on identical keys.
        if i < shared_values:
            shared = f"SHARED PERSON {i}"
            issued[shared] = store.get_or_create_code("PERSON", shared)
    results.put(issued)

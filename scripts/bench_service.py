"""Latency benchmark for redact-service, over real HTTP on 127.0.0.1.

Runs the service in-process against a throwaway store (fresh key, temp
folder) - never the real store, token or home - with synthetic text only.

    python scripts/bench_service.py [--runs-12k 15] [--runs-50k 7] [--json results.json]

Scenarios (token counts are estimated at ~4 characters per token):
- 12K-token prompt as one text, every run new (no cache help)
- 50K-token prompt as one text, every run new
- a 20-message history (~12K tokens) where only the last message is new,
  with the result cache on and with it off
- reverse of a 12K-token reply
"""

from __future__ import annotations

import argparse
import http.client
import json
import platform
import random
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet

from pii_redact.anonymize.mapping_store import MappingStore
from pii_redact.service import RedactionService, create_server

TOKEN = "bench-token-" + "b" * 40
NAMES = ["Ravi Kumar", "Asha Rao", "Vikram Singh", "Meera Nair", "Arjun Mehta", "Kavya Iyer", "Rohan Das", "Priya Menon"]
WORDS = (
    "the loan account statement interest payment quarter branch request review summary balance "
    "transfer policy premium return filing notes meeting schedule update detail please confirm "
    "whether amount received pending approved tax invoice document section agent reply draft"
).split()


def _pan(rng: random.Random) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(rng.choice(letters) for _ in range(3)) + "P" + rng.choice(letters) + f"{rng.randrange(10000):04d}" + rng.choice(letters)


def synthetic_text(tokens: int, seed: int) -> str:
    """Prose with roughly one piece of synthetic PII every five sentences."""
    rng = random.Random(seed)
    target_chars = tokens * 4
    sentences, size = [], 0
    while size < target_chars:
        words = " ".join(rng.choice(WORDS) for _ in range(rng.randint(8, 18)))
        roll = rng.randrange(20)
        if roll == 0:
            sentence = f"{rng.choice(NAMES)} asked about the {words}."
        elif roll == 1:
            sentence = f"The PAN {_pan(rng)} was quoted for the {words}."
        elif roll == 2:
            sentence = f"Call mobile {rng.randrange(6, 10)}{rng.randrange(10**8, 10**9)} about the {words}."
        elif roll == 3:
            sentence = f"Write to {rng.choice(NAMES).split()[0].lower()}@example.com about the {words}."
        else:
            sentence = words.capitalize() + "."
        sentences.append(sentence)
        size += len(sentence) + 1
    return " ".join(sentences)


class Client:
    def __init__(self, port: int):
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=600)

    def post(self, path: str, texts: list[str]) -> tuple[float, dict]:
        body = json.dumps({"texts": texts}).encode("utf-8")
        started = time.perf_counter()
        self.conn.request("POST", path, body=body, headers={
            "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json",
        })
        response = self.conn.getresponse()
        data = response.read()
        elapsed = (time.perf_counter() - started) * 1000
        if response.status != 200:
            raise RuntimeError(f"{path} -> HTTP {response.status}: {data[:200]!r}")
        return elapsed, json.loads(data)


def _stats(samples: list[float]) -> dict:
    ordered = sorted(samples)
    p95_index = max(0, int(round(0.95 * len(ordered))) - 1)
    return {
        "runs": len(ordered),
        "p50_ms": round(statistics.median(ordered), 1),
        "p95_ms": round(ordered[p95_index], 1),
        "max_ms": round(ordered[-1], 1),
    }


def _server(store: MappingStore, cache_entries: int):
    service = RedactionService(store, cache_entries=cache_entries)
    server = create_server(service, TOKEN, port=0, max_body_bytes=16 * 1024 * 1024)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    started = time.perf_counter()
    service.warm_up()
    return server, (time.perf_counter() - started) * 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs-12k", type=int, default=15)
    parser.add_argument("--runs-50k", type=int, default=7)
    parser.add_argument("--runs-history", type=int, default=15)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    results: dict = {"python": sys.version.split()[0], "platform": platform.platform(), "processor": platform.processor()}
    with tempfile.TemporaryDirectory() as tmp:
        key = Fernet.generate_key()
        store_path = Path(tmp) / "mapping_store.enc"

        server, warm_ms = _server(MappingStore(store_path, key=key, cache=True), cache_entries=2000)
        results["warm_up_ms"] = round(warm_ms, 1)
        client = Client(server.server_port)
        client.post("/v1/redact", [synthetic_text(500, seed=-1)])  # first-request effects out of the way

        for label, tokens, runs in (("redact_12k", 12_000, args.runs_12k), ("redact_50k", 50_000, args.runs_50k)):
            samples = []
            for run in range(runs):
                text = synthetic_text(tokens, seed=run + tokens)  # a new text every run: no cache hits
                elapsed, _ = client.post("/v1/redact", [text])
                samples.append(elapsed)
            results[label] = _stats(samples) | {"chars": len(text)}
            print(label, results[label], flush=True)

        reply = client.post("/v1/redact", [synthetic_text(12_000, seed=424242)])[1]["texts"]
        results["reverse_12k"] = _stats([client.post("/v1/reverse", reply)[0] for _ in range(args.runs_12k)])
        print("reverse_12k", results["reverse_12k"], flush=True)

        history = [synthetic_text(600, seed=9000 + i) for i in range(19)]
        client.post("/v1/redact", history)  # the earlier turns, already seen once
        samples = []
        for run in range(args.runs_history):
            elapsed, _ = client.post("/v1/redact", history + [synthetic_text(600, seed=7000 + run)])
            samples.append(elapsed)
        results["history_20_msgs_cache_on"] = _stats(samples)
        print("history_20_msgs_cache_on", results["history_20_msgs_cache_on"], flush=True)
        server.shutdown()
        server.server_close()

        server, _ = _server(MappingStore(store_path, key=key, cache=True), cache_entries=0)
        client = Client(server.server_port)
        samples = []
        for run in range(args.runs_history):
            elapsed, _ = client.post("/v1/redact", history + [synthetic_text(600, seed=8000 + run)])
            samples.append(elapsed)
        results["history_20_msgs_cache_off"] = _stats(samples)
        print("history_20_msgs_cache_off", results["history_20_msgs_cache_off"], flush=True)
        server.shutdown()
        server.server_close()

    if args.json:
        args.json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

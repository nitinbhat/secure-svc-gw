"""Requirement 11: Replay-attack stress test.

Two scenarios:

1. Concurrent replay (100 goroutines, same JWT):
   Mint ONE token, send it 100 times concurrently.
   Exactly 1 must succeed (200); all 99 others must be rejected (401, reason=replay).

2. Serial replay (same token, 200 requests one after another):
   After the first succeeds the gateway must reject every subsequent attempt.

Both tests work against the in-memory nonce store and the Redis-backed store.
The nonce store's atomic CheckAndStore guarantees the invariant.
"""
from __future__ import annotations

import threading
import time
from collections import Counter

import pytest
import requests

from client.gateway import mint_jwt
from tests.conftest import GATEWAY_URL, metric_delta, narrate, snapshot_metrics


_PATH = "/v1/llm/completions"
_BODY = {"prompt": "replay-stress"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send(tok: str) -> int:
    """Fire one POST, return the HTTP status code."""
    try:
        r = requests.post(
            f"{GATEWAY_URL}{_PATH}",
            json=_BODY,
            headers={"Authorization": f"Bearer {tok}"},
            timeout=10,
        )
        return r.status_code
    except requests.RequestException:
        return 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_concurrent_replay_100_goroutines(keys, metrics_before):
    """100 concurrent threads share ONE JWT; exactly 1 must succeed."""
    tok = mint_jwt(keys["analyst"])
    n = 100

    narrate(f"firing {n} concurrent requests with the same JWT")
    results: list[int] = [0] * n

    def worker(i: int) -> None:
        results[i] = _send(tok)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    counts = Counter(results)
    narrate(f"  status distribution: {dict(counts)}")

    successes = counts[200]
    replays = counts[401]

    assert successes == 1, (
        f"exactly 1 request should succeed; got {successes} successes. "
        f"Distribution: {dict(counts)}"
    )
    assert replays == n - 1, (
        f"expected {n - 1} replay rejections; got {replays}. "
        f"Distribution: {dict(counts)}"
    )

    replay_delta = metric_delta(
        metrics_before, snapshot_metrics(),
        "gateway_auth_failures_total", {"reason": "replay"},
    )
    narrate(f"  gateway_auth_failures_total{{reason=replay}} delta = {replay_delta:g}")
    assert replay_delta >= n - 1


def test_serial_replay_200_requests(client_of, keys, metrics_before):
    """200 serial requests with the same JWT: first succeeds, rest are rejected."""
    c = client_of("analyst")
    tok = mint_jwt(keys["analyst"])

    narrate("first request with fresh JWT → expect 200")
    r = c.call("POST", _PATH, json_body=_BODY, token=tok)
    assert r.status_code == 200, f"expected 200 on first use, got {r.status_code}: {r.text}"

    narrate("sending the same JWT 199 more times → all must be 401 replay")
    failed = 0
    for i in range(199):
        r = c.call("POST", _PATH, json_body=_BODY, token=tok)
        if r.status_code != 401 or "replay" not in r.text:
            failed += 1
            narrate(f"  unexpected: #{i + 2} → {r.status_code} {r.text[:60]}")

    narrate(f"  unexpected non-replay responses: {failed}/199")
    assert failed == 0, f"{failed} requests were not rejected as replays"

    replay_delta = metric_delta(
        metrics_before, snapshot_metrics(),
        "gateway_auth_failures_total", {"reason": "replay"},
    )
    narrate(f"  gateway_auth_failures_total{{reason=replay}} delta = {replay_delta:g}")
    assert replay_delta >= 199


def test_replay_stress_100k(keys):
    """Stress: 100 threads × 1000 iterations with the same JWT.

    Total = 100 000 requests.  Exactly 1 must succeed.
    This takes ~30–60 seconds; run separately with pytest -k replay_stress_100k.
    """
    pytest.importorskip("concurrent.futures")  # always available; acts as gate for -k skip
    import concurrent.futures

    tok = mint_jwt(keys["analyst"])
    total = 1000
    workers = 100

    narrate(f"firing {workers} × {total // workers} = {total} concurrent requests")

    def batch(n: int) -> list[int]:
        return [_send(tok) for _ in range(n)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(batch, total // workers) for _ in range(workers)]
        all_codes: list[int] = []
        for f in concurrent.futures.as_completed(futures):
            all_codes.extend(f.result())

    counts = Counter(all_codes)
    narrate(f"  status distribution: {dict(counts)}")

    assert counts[200] == 1, (
        f"exactly 1 request should succeed across {total} concurrent attempts; "
        f"got {counts[200]}. Full distribution: {dict(counts)}"
    )
    assert counts[401] == total - 1, (
        f"expected {total - 1} replay rejections; got {counts[401]}"
    )

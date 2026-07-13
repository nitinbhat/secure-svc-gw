"""Requirement 12: authentication + routing latency benchmarks.

Measures end-to-end latency of a request through the full JWT auth stack
(Ed25519 verify → nonce check → scope check → P2C pick → mTLS proxy).

Reports P50 / P95 / P99 in milliseconds and asserts they stay below
configurable thresholds (defaults are intentionally loose to survive a
loaded CI runner; tighten with env vars for production acceptance testing).

    P50_THRESHOLD_MS   default 500
    P95_THRESHOLD_MS   default 1000
    P99_THRESHOLD_MS   default 2000

Run the dedicated perf suite with:

    pytest tests/test_12_perf_latency.py -v -s
"""
from __future__ import annotations

import os
import statistics
import time

import pytest
import requests

from client.gateway import mint_jwt
from tests.conftest import GATEWAY_URL, narrate

P50_MS = float(os.getenv("P50_THRESHOLD_MS", "500"))
P95_MS = float(os.getenv("P95_THRESHOLD_MS", "1000"))
P99_MS = float(os.getenv("P99_THRESHOLD_MS", "2000"))

_WARMUP = 10
_SAMPLES = 100


def _measure(client_factory, *, n: int, route: str, body: dict) -> list[float]:
    """Return a list of per-request latencies in milliseconds."""
    c = client_factory("analyst")
    latencies: list[float] = []
    for _ in range(n):
        start = time.perf_counter()
        r = c.call("POST", route, json_body=body)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert r.status_code == 200, f"unexpected {r.status_code}: {r.text[:120]}"
        latencies.append(elapsed_ms)
    return latencies


def _percentile(data: list[float], p: float) -> float:
    idx = int(len(data) * p / 100)
    return sorted(data)[min(idx, len(data) - 1)]


def _print_histogram(latencies: list[float]) -> None:
    buckets = [0, 5, 10, 25, 50, 100, 200, 500, 1000, float("inf")]
    counts = [0] * (len(buckets) - 1)
    for v in latencies:
        for i, hi in enumerate(buckets[1:]):
            if v < hi:
                counts[i] += 1
                break
    labels = [f"<{buckets[i + 1]}ms" if buckets[i + 1] != float("inf") else "≥1000ms"
              for i in range(len(counts))]
    max_count = max(counts) or 1
    for label, count in zip(labels, counts):
        bar = "█" * int(count / max_count * 40)
        print(f"    {label:>10}  {bar} {count}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_llm_completions_latency(client_of):
    """End-to-end latency through JWT auth + P2C LB + mTLS proxy to llm backend."""
    c_factory = client_of.__wrapped__ if hasattr(client_of, "__wrapped__") else None

    # Use client_of directly (it's a factory fixture).
    c = client_of("analyst")

    narrate(f"warming up with {_WARMUP} requests")
    for i in range(_WARMUP):
        r = c.complete(f"warmup-{i}")
        assert r.status_code == 200, f"warmup failed: {r.text}"

    narrate(f"measuring {_SAMPLES} requests")
    latencies: list[float] = []
    for _ in range(_SAMPLES):
        tok = mint_jwt(c.key)
        start = time.perf_counter()
        r = c.call("POST", "/v1/llm/completions",
                   json_body={"prompt": "perf"}, token=tok)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert r.status_code == 200, f"unexpected {r.status_code}: {r.text[:120]}"
        latencies.append(elapsed_ms)

    p50 = statistics.median(latencies)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)
    p_min = min(latencies)
    p_max = max(latencies)

    narrate(f"\n  min={p_min:.1f}ms  P50={p50:.1f}ms  P95={p95:.1f}ms  P99={p99:.1f}ms  max={p_max:.1f}ms")
    narrate("  latency histogram:")
    _print_histogram(latencies)

    assert p50 < P50_MS, f"P50={p50:.1f}ms exceeds threshold {P50_MS}ms"
    assert p95 < P95_MS, f"P95={p95:.1f}ms exceeds threshold {P95_MS}ms"
    assert p99 < P99_MS, f"P99={p99:.1f}ms exceeds threshold {P99_MS}ms"


def test_embed_latency(client_of):
    """Same measurement for the embed service route."""
    c = client_of("analyst")

    narrate(f"warming up embed route with {_WARMUP} requests")
    for i in range(_WARMUP):
        assert c.embed(f"warmup-{i}").status_code == 200

    narrate(f"measuring {_SAMPLES} embed requests")
    latencies: list[float] = []
    for _ in range(_SAMPLES):
        tok = mint_jwt(c.key)
        start = time.perf_counter()
        r = c.call("POST", "/v1/embed/vectors",
                   json_body={"text": "perf"}, token=tok)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert r.status_code == 200
        latencies.append(elapsed_ms)

    p50 = statistics.median(latencies)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)
    narrate(f"\n  P50={p50:.1f}ms  P95={p95:.1f}ms  P99={p99:.1f}ms")

    assert p50 < P50_MS
    assert p95 < P95_MS
    assert p99 < P99_MS


def test_auth_rejection_latency(client_of, keys):
    """Rejected requests (bad token) must also be fast — no slow path."""
    narrate("measuring latency of 50 authentication failures")
    latencies: list[float] = []
    for _ in range(50):
        start = time.perf_counter()
        r = requests.post(
            f"{GATEWAY_URL}/v1/llm/completions",
            json={"prompt": "hi"},
            headers={"Authorization": "Bearer garbage.garbage.garbage"},
            timeout=5,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert r.status_code == 401
        latencies.append(elapsed_ms)

    p99 = _percentile(latencies, 99)
    narrate(f"  auth-failure P99={p99:.1f}ms")
    # Rejections should be faster than successes — no backend involved.
    assert p99 < P99_MS / 2, (
        f"auth rejection P99={p99:.1f}ms should be faster than success P99 threshold "
        f"({P99_MS / 2:.0f}ms)"
    )

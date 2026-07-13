"""Requirement 3: backend identity is verified before traffic is sent.
                  (a.k.a. the "spoofed backend" negative security case)

Story:
    An attacker has slipped a 4th 'llm' replica into the cluster (host
    `llm-4`). It runs the same code as the real llm-1..3 backends and is
    listed alongside them in the gateway config -- as if a rogue operator
    or compromised CI pipeline had added it. But its TLS cert is signed
    by rogue-ca.crt -- NOT the secure-svc-gw CA -- so the gateway's mTLS
    handshake to it fails at CA verification.

Expectations:
    * gateway_backend_healthy{backend="llm-4"} = 0 after a few probes
    * every /v1/llm/completions call routes to llm-1, llm-2, or llm-3
      -- never to llm-4
    * real callers keep succeeding
"""
import time

import pytest

from tests.conftest import narrate, snapshot_metrics


@pytest.fixture(scope="module", autouse=True)
def wait_for_probes():
    """The gateway takes 3 probes (~6s) to eject an unhealthy backend."""
    time.sleep(7)


def _health(snap, backend: str) -> float | None:
    key = ("gateway_backend_healthy",
           tuple(sorted({"service": "llm", "backend": backend}.items())))
    return snap.get(key)


def test_rogue_backend_is_marked_unhealthy():
    snap = snapshot_metrics()
    healthy = {b: _health(snap, b) for b in ("llm-1", "llm-2", "llm-3", "llm-4")}
    narrate(f"llm pool health: {healthy}")
    assert healthy["llm-4"] == 0.0, \
        "gateway should reject the impostor at the TLS handshake"
    assert all(healthy[b] == 1.0 for b in ("llm-1", "llm-2", "llm-3")), \
        "legit replicas should be healthy"


def test_no_client_traffic_is_ever_routed_to_llm_4(client_of):
    c = client_of("analyst")
    upstreams: dict[str, int] = {}
    narrate("firing 20 completion calls; recording upstream distribution")
    for i in range(20):
        r = c.complete(f"probe-{i}")
        assert r.status_code == 200, r.text
        u = r.headers.get("X-Upstream", "?")
        upstreams[u] = upstreams.get(u, 0) + 1
    narrate(f"upstream distribution: {upstreams}")
    assert "llm-4" not in upstreams, \
        f"impostor MUST NEVER receive client traffic, got {upstreams}"
    assert set(upstreams).issubset({"llm-1", "llm-2", "llm-3"}), \
        f"unexpected upstream in {upstreams}"

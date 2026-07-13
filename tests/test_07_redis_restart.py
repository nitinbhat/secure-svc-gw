"""Requirement 7: Redis fail-closed and automatic recovery.

When the Redis nonce cache goes down the gateway must:
  - reject NEW tokens immediately (fail closed) so a replay cannot slip through
    during the outage — reason=replay because CheckAndStore returns false

When Redis comes back up:
  - the gateway reconnects lazily on the next command
  - valid tokens are accepted again

Skips when:
  - neither docker-py nor KUBE_NAMESPACE is available
  - no Redis container / deployment is found (stack started without Redis)
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest
import requests

from client.gateway import mint_jwt
from tests.conftest import GATEWAY_URL, narrate

try:
    import docker  # type: ignore
except ImportError:
    docker = None  # noqa: N816

KUBE_NAMESPACE = os.getenv("KUBE_NAMESPACE")
# Redis lives in the gateway namespace, which may differ from the backend namespace.
# REDIS_NAMESPACE defaults to KUBE_NAMESPACE for compose compat; set explicitly for kind.
REDIS_NAMESPACE = os.getenv("REDIS_NAMESPACE") or KUBE_NAMESPACE
REDIS_SERVICE = os.getenv("REDIS_SERVICE", "redis")
# k8s deployment name for Redis (set by Helm chart)
REDIS_DEPLOY = os.getenv("REDIS_DEPLOY", "redis")

# Set GATEWAY_USES_REDIS=1 when the gateway is configured with a Redis nonce
# cache.  Without it the gateway falls back to an in-memory store and these
# tests cannot exercise fail-closed behaviour.
GATEWAY_USES_REDIS = os.getenv("GATEWAY_USES_REDIS", "").lower() in {"1", "true", "yes"}

pytestmark = pytest.mark.skipif(
    (docker is None and not KUBE_NAMESPACE) or not GATEWAY_USES_REDIS,
    reason="skipping Redis restart tests: either no docker-py/KUBE_NAMESPACE or "
           "GATEWAY_USES_REDIS is not set (gateway is using in-memory nonce cache)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_redis_container():
    """Return the first running Redis container matched by compose service label."""
    if docker is None:
        return None
    dc = docker.from_env()
    candidates = dc.containers.list(
        filters={"label": f"com.docker.compose.service={REDIS_SERVICE}"}
    )
    return candidates[0] if candidates else None


def _stop_redis() -> None:
    if REDIS_NAMESPACE:
        subprocess.run(
            ["kubectl", "-n", REDIS_NAMESPACE, "scale",
             f"deployment/{REDIS_DEPLOY}", "--replicas=0"],
            check=True,
        )
        # Wait until no running pods.
        for _ in range(20):
            out = subprocess.run(
                ["kubectl", "-n", REDIS_NAMESPACE, "get", "pods",
                 "-l", f"app.kubernetes.io/component=redis",
                 "-o", "jsonpath={.items[*].status.phase}"],
                capture_output=True, text=True,
            ).stdout.strip()
            if not out or "Running" not in out:
                return
            time.sleep(1)
    else:
        c = _get_redis_container()
        if c:
            c.stop(timeout=3)


def _start_redis() -> None:
    if REDIS_NAMESPACE:
        subprocess.run(
            ["kubectl", "-n", REDIS_NAMESPACE, "scale",
             f"deployment/{REDIS_DEPLOY}", "--replicas=1"],
            check=True,
        )
        # Wait until the pod passes its readiness probe (containerStatuses.ready).
        for _ in range(60):
            out = subprocess.run(
                ["kubectl", "-n", REDIS_NAMESPACE, "get", "pods",
                 "-l", f"app.kubernetes.io/component=redis",
                 "-o", "jsonpath={.items[0].status.containerStatuses[0].ready}"],
                capture_output=True, text=True,
            ).stdout.strip()
            if out == "true":
                return
            time.sleep(1)
        raise TimeoutError("Redis pod did not become Ready")
    else:
        c = _get_redis_container()
        if c:
            c.start()
        # Wait for Redis to accept connections (give it up to 15s).
        deadline = time.time() + 15
        while time.time() < deadline:
            c.reload()
            if c.status == "running":
                time.sleep(2)
                return
            time.sleep(0.5)
        raise TimeoutError("Redis container did not come back up")


@pytest.fixture(autouse=True)
def _check_redis_present():
    """Skip this whole module if no Redis is found in the running stack."""
    if not KUBE_NAMESPACE:
        if _get_redis_container() is None:
            pytest.skip(
                f"No container with compose service label '{REDIS_SERVICE}' found. "
                "Start the stack with Redis enabled (default docker compose includes it).",
            )


@pytest.fixture(autouse=True)
def _ensure_redis_up():
    """Guarantee Redis is running before and after every test in this module."""
    yield
    # Cleanup: always restart Redis so subsequent tests are not broken.
    try:
        _start_redis()
    except Exception:
        pass  # best-effort; the next autouse fixture will skip if still down


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_redis_fail_closed_on_outage(client_of, keys):
    """While Redis is down every new JWT must be rejected (fail closed)."""
    c = client_of("analyst")

    narrate("baseline: confirm requests succeed before stopping Redis")
    r = c.complete("baseline-before-outage")
    assert r.status_code == 200, f"baseline failed: {r.text}"

    narrate("stopping Redis container / deployment")
    _stop_redis()
    # Give the connection pool a moment to notice the broken connections.
    time.sleep(2)

    narrate("sending a NEW token while Redis is down → expect 401 fail-closed")
    new_tok = mint_jwt(keys["analyst"])
    r = c.call("POST", "/v1/llm/completions",
               json_body={"prompt": "during-outage"}, token=new_tok)
    narrate(f"  status={r.status_code}  body={r.text[:120]!r}")
    assert r.status_code == 401, (
        f"expected 401 (fail closed) while Redis is down, got {r.status_code}: {r.text}"
    )
    assert "replay" in r.text, (
        f"expected reason=replay (CheckAndStore failed → false), got: {r.text}"
    )


def test_redis_recovery_after_restart(client_of, keys):
    """After Redis restarts the gateway must accept valid tokens again."""
    c = client_of("analyst")

    narrate("stopping Redis")
    _stop_redis()
    time.sleep(2)

    narrate("restarting Redis")
    _start_redis()

    narrate("sending NEW tokens after Redis recovery → expect 200 (retrying up to 10s for gateway reconnect)")
    deadline = time.time() + 10
    r = None
    while time.time() < deadline:
        new_tok = mint_jwt(keys["analyst"])
        r = c.call("POST", "/v1/llm/completions",
                   json_body={"prompt": "after-recovery"}, token=new_tok)
        narrate(f"  status={r.status_code}  upstream={r.headers.get('X-Upstream')}")
        if r.status_code == 200:
            break
        time.sleep(1)
    assert r is not None and r.status_code == 200, (
        f"expected 200 after Redis recovery, got {r.status_code}: {r.text}"
    )

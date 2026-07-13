"""Requirement 4: traffic shifts away from an unhealthy backend and
recovers when it comes back.

Story:
  1) analyst makes 15 calls -- upstream distribution across llm-1..3
  2) we mark llm-2 broken by POSTing to its /admin/break endpoint
  3) the gateway ejects llm-2 after 3 failed health probes (~6s).
     gateway_backend_healthy{backend="llm-2"} goes to 0
  4) 15 more calls -- llm-2 no longer appears
  5) we restore llm-2; after ~4s it re-enters the healthy pool

Reaching /admin/break (which is behind mTLS) requires exec-into-pod:

  * Docker Compose  -> docker-py               (default; needs docker.sock)
  * Kind / k8s      -> subprocess kubectl exec  (when KUBE_NAMESPACE is set)
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest

from tests.conftest import metric_value, narrate

try:
    import docker  # type: ignore
except ImportError:
    docker = None  # noqa: N816

# Set by `make test-kind` to activate the kubectl-exec path.
KUBE_NAMESPACE = os.getenv("KUBE_NAMESPACE")

_EXEC_PAYLOAD = (
    "import ssl,http.client;"
    "ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);"
    "ctx.load_cert_chain('/etc/backend/tls/tls.crt','/etc/backend/tls/tls.key');"
    "ctx.load_verify_locations('/etc/backend/tls/ca.crt');"
    "c=http.client.HTTPSConnection('localhost',8443,context=ctx);"
    "c.request('POST','/admin/break?fail={fail}');"
    "r=c.getresponse();print(r.status, r.read().decode())"
)

pytestmark = pytest.mark.skipif(
    docker is None and not KUBE_NAMESPACE,
    reason="neither docker-py nor KUBE_NAMESPACE env var available; skipping",
)


def _break_backend_docker(service_name: str, fail: bool) -> None:
    """Look up by compose service label (independent of project name)."""
    dc = docker.from_env()
    candidates = dc.containers.list(
        filters={"label": f"com.docker.compose.service={service_name}"}
    )
    if not candidates:
        raise RuntimeError(
            f"no running container for compose service {service_name!r} -- "
            "is the stack up? (make up)"
        )
    code, _ = candidates[0].exec_run(
        ["python", "-c", _EXEC_PAYLOAD.format(fail=1 if fail else 0)],
        demux=False,
    )
    if code != 0:
        raise RuntimeError(f"admin/break failed on {service_name} (exit {code})")


def _break_backend_k8s(service_name: str, namespace: str, fail: bool) -> None:
    """Find the pod by sgw/backend label and kubectl exec into it."""
    res = subprocess.run(
        ["kubectl", "-n", namespace, "get", "pods",
         "-l", f"sgw/backend={service_name}",
         "-o", "jsonpath={.items[0].metadata.name}"],
        capture_output=True, text=True, check=True,
    )
    pod = res.stdout.strip()
    if not pod:
        raise RuntimeError(
            f"no pod for sgw/backend={service_name} in namespace {namespace}"
        )
    subprocess.run(
        ["kubectl", "-n", namespace, "exec", pod, "--",
         "python", "-c", _EXEC_PAYLOAD.format(fail=1 if fail else 0)],
        check=True,
    )


def _break_backend(service_name: str, fail: bool) -> None:
    if KUBE_NAMESPACE:
        _break_backend_k8s(service_name, KUBE_NAMESPACE, fail)
    else:
        _break_backend_docker(service_name, fail)


def _distribution(client, n: int) -> dict[str, int]:
    hits: dict[str, int] = {}
    for i in range(n):
        r = client.complete(f"probe-{i}")
        upstream = r.headers.get("X-Upstream", "?")
        hits[upstream] = hits.get(upstream, 0) + 1
    return hits


def test_traffic_shifts_when_llm2_breaks_then_recovers(client_of):
    c = client_of("analyst")

    narrate("baseline: 15 completion calls, observing upstream distribution")
    before = _distribution(c, 15)
    narrate(f"  {before}")
    assert len(before) >= 2, "expected requests to spread across replicas"

    narrate("breaking llm-2 (POST /admin/break?fail=1 inside the container)")
    _break_backend("llm-2", fail=True)

    narrate("waiting 8s for the gateway health checker to eject llm-2")
    time.sleep(8)

    healthy = metric_value("gateway_backend_healthy",
                           {"service": "llm", "backend": "llm-2"})
    narrate(f"gateway_backend_healthy{{llm-2}} = {healthy}")
    assert healthy == 0.0

    narrate("15 more calls -- llm-2 must be gone")
    during = _distribution(c, 15)
    narrate(f"  {during}")
    assert "llm-2" not in during, f"llm-2 must be ejected, saw {during}"

    narrate("restoring llm-2")
    _break_backend("llm-2", fail=False)

    narrate("waiting 8s for llm-2 to pass 2 probes and re-enter the pool")
    time.sleep(8)
    healthy = metric_value("gateway_backend_healthy",
                           {"service": "llm", "backend": "llm-2"})
    narrate(f"gateway_backend_healthy{{llm-2}} = {healthy}")
    assert healthy == 1.0

    narrate("15 more calls -- llm-2 should appear again")
    after = _distribution(c, 15)
    narrate(f"  {after}")
    assert "llm-2" in after, f"llm-2 should be back; got {after}"

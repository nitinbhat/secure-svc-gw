"""Requirement 6: enough logs/metrics to explain every decision.

We only need to prove the *shape* of the observability data here; the
other tests already assert individual counters incremented as expected.

This test asserts:

  * /metrics exposes every documented series
  * every configured backend has a gateway_backend_healthy gauge
    (including the impostor llm-4, whose value should be 0)
"""
import requests

from tests.conftest import METRICS_URL, narrate


REQUIRED_METRICS = {
    "gateway_requests_total",
    "gateway_upstream_requests_total",
    "gateway_upstream_latency_seconds",
    "gateway_backend_healthy",
    "gateway_auth_failures_total",
}

# From the compose config; the chart uses the same names.
# llm-4 is the impostor -- gauge still exists but stays at 0.
EXPECTED_BACKENDS = {
    ("llm", "llm-1"), ("llm", "llm-2"), ("llm", "llm-3"),
    ("llm", "llm-4"),
    ("embed", "embed-1"), ("embed", "embed-2"),
}


def test_metrics_endpoint_exposes_required_series():
    r = requests.get(f"{METRICS_URL}/metrics", timeout=5)
    r.raise_for_status()
    # Collect names from data lines AND from '# TYPE' declarations.
    # Histograms with zero observations only appear in '# TYPE' lines until
    # the first observation arrives, so we must check both.
    names: set[str] = set()
    for ln in r.text.splitlines():
        if ln.startswith("# TYPE"):
            parts = ln.split()
            if len(parts) >= 3:
                names.add(parts[2])
        elif ln and not ln.startswith("#"):
            names.add(ln.split("{")[0].split(" ")[0])
    missing = REQUIRED_METRICS - names
    narrate(f"exposed decision series: {sorted(REQUIRED_METRICS & names)}")
    assert not missing, f"missing series: {missing}"


def test_every_configured_backend_has_health_gauge():
    r = requests.get(f"{METRICS_URL}/metrics", timeout=5)
    r.raise_for_status()
    seen: set[tuple[str, str]] = set()
    for line in r.text.splitlines():
        if not line.startswith("gateway_backend_healthy{"):
            continue
        # gateway_backend_healthy{backend="llm-1",service="llm"} 1
        labels_str = line[len("gateway_backend_healthy{"):].split("}", 1)[0]
        labels = dict(
            (k.strip(), v.strip().strip('"'))
            for k, _, v in (p.partition("=") for p in labels_str.split(","))
        )
        seen.add((labels.get("service", ""), labels.get("backend", "")))
    narrate(f"backends reporting health: {sorted(seen)}")
    missing = EXPECTED_BACKENDS - seen
    assert not missing, f"no health gauge for: {missing}"

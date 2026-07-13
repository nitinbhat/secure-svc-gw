"""Shared fixtures and helpers for the Secure Service Gateway test suite.

The suite is meant to be run against a live gateway that already has the
topology up (either via docker compose or via the Helm chart in a kind
cluster). Configure via env vars:

    GATEWAY_URL       default http://localhost:8080
    METRICS_URL       default http://localhost:9090
    CLIENTS_DIR       default clients/

If the gateway is not reachable the whole suite is skipped with a clear
message instead of exploding.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
import requests

from client.gateway import ClientKey, GatewayClient


GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080")
METRICS_URL = os.getenv("METRICS_URL", "http://localhost:9090")
CLIENTS_DIR = Path(os.getenv("CLIENTS_DIR", "clients"))
_TLS_CA_CERT = os.getenv("TLS_CA_CERT")


def _requests_verify():
    """Return True, False, or a CA bundle path for requests verify= param."""
    if _TLS_CA_CERT and os.path.exists(_TLS_CA_CERT):
        return _TLS_CA_CERT
    return True


def _wait_for(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    verify = _requests_verify() if url.startswith("https://") else False
    while time.time() < deadline:
        try:
            requests.get(url, timeout=2, verify=verify)
            return True
        except requests.RequestException:
            time.sleep(0.5)
    return False


@pytest.fixture(scope="session", autouse=True)
def _require_gateway():
    if not _wait_for(f"{METRICS_URL}/metrics"):
        pytest.skip(
            f"gateway metrics not reachable at {METRICS_URL}. "
            "Bring the stack up with `make up` and retry.",
            allow_module_level=True,
        )


@pytest.fixture(scope="session")
def keys() -> dict[str, ClientKey]:
    """Load every caller's key file. Fails loud if clients/ is empty."""
    result: dict[str, ClientKey] = {}
    for jf in sorted(CLIENTS_DIR.glob("*.json")):
        k = ClientKey.load(jf)
        result[k.sub] = k
    if not result:
        pytest.fail(
            f"no key files under {CLIENTS_DIR}. Run `make certs` first."
        )
    return result


@pytest.fixture()
def client_of(keys):
    """Factory: `client_of("analyst")` -> GatewayClient signed as analyst."""
    def _make(sub: str) -> GatewayClient:
        if sub not in keys:
            pytest.fail(f"unknown caller {sub!r}; have {sorted(keys)}")
        return GatewayClient(GATEWAY_URL, keys[sub])
    return _make


# ---- prometheus helpers ---------------------------------------------

def _parse_metrics(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """Parse the /metrics text format into {(name, sorted_labels): value}."""
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        # name{k="v",k2="v2"} value      OR      name value
        if "{" in line:
            name, rest = line.split("{", 1)
            label_str, _, value = rest.rpartition("}")
            value = value.strip()
            labels: list[tuple[str, str]] = []
            for kv in label_str.split(","):
                if not kv:
                    continue
                k, _, v = kv.partition("=")
                labels.append((k.strip(), v.strip().strip('"')))
            key = (name.strip(), tuple(sorted(labels)))
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            key = (parts[0], ())
            value = parts[1]
        try:
            out[key] = float(value)
        except ValueError:
            pass
    return out


def snapshot_metrics() -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    r = requests.get(f"{METRICS_URL}/metrics", timeout=5)
    r.raise_for_status()
    return _parse_metrics(r.text)


def metric_delta(
    before: dict, after: dict, name: str, labels: dict[str, str]
) -> float:
    """Return the change in a specific counter, defaulting missing to 0."""
    key = (name, tuple(sorted(labels.items())))
    return after.get(key, 0.0) - before.get(key, 0.0)


def metric_value(name: str, labels: dict[str, str]) -> float:
    snap = snapshot_metrics()
    return snap.get((name, tuple(sorted(labels.items()))), 0.0)


# ---- pretty test narration -----------------------------------------

def narrate(msg: str) -> None:
    """Print a scenario step. `pytest -s` shows these inline."""
    print(f"    - {msg}")


@pytest.fixture()
def metrics_before():
    """Return the current metrics snapshot at the start of a test."""
    return snapshot_metrics()

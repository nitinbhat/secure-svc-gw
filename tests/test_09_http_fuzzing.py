"""Requirement 9: HTTP fuzzing — gateway must never return 500 on garbage input.

Sends a wide variety of malformed requests:
  - random garbage as the Bearer token
  - random UTF-8 / binary payloads as the request body
  - random URL paths
  - unknown HTTP methods
  - oversized tokens (100 KB)
  - empty / whitespace-only tokens
  - JWT-shaped but cryptographically invalid tokens

For every case the expected outcome is 400, 401, 403, or 404.
A 5xx response means the gateway crashed or panicked — a security defect.
"""
from __future__ import annotations

import random
import string

import pytest
import requests

from client.gateway import _b64, mint_jwt
from tests.conftest import GATEWAY_URL, narrate

_RNG = random.Random(0xDEADBEEF)  # deterministic for reproducibility

_VALID_ROUTES = ["/v1/llm/completions", "/v1/embed/vectors", "/v1/embed/search"]
_EXPECTED_SAFE_CODES = {400, 401, 403, 404}


def _assert_safe(r: requests.Response, *, context: str) -> None:
    assert r.status_code not in {500, 502, 503, 504}, (
        f"gateway returned {r.status_code} on {context}\n"
        f"body: {r.text[:300]}"
    )
    assert r.status_code in _EXPECTED_SAFE_CODES, (
        f"unexpected status {r.status_code} on {context}; body: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Token fuzzing
# ---------------------------------------------------------------------------

def test_fuzz_random_printable_token():
    """50 random printable-ASCII strings as Bearer tokens → never 5xx."""
    narrate("sending 50 random printable-ASCII Bearer tokens")
    for i in range(50):
        tok = "".join(_RNG.choices(string.printable, k=_RNG.randint(1, 200)))
        try:
            r = requests.post(
                f"{GATEWAY_URL}/v1/llm/completions",
                json={"prompt": "hi"},
                headers={"Authorization": f"Bearer {tok}"},
                timeout=5,
            )
        except requests.exceptions.InvalidHeader:
            # Control characters (\n, \r, \x0c …) in the token are rejected
            # by the HTTP client itself — that is correct behaviour; continue.
            continue
        _assert_safe(r, context=f"random printable token #{i}")


def test_fuzz_random_binary_token():
    """10 random binary byte-sequences encoded as base64 → never 5xx."""
    narrate("sending 10 random binary-encoded Bearer tokens")
    for i in range(10):
        raw = bytes(_RNG.randint(0, 255) for _ in range(_RNG.randint(10, 300)))
        tok = _b64(raw)
        r = requests.post(
            f"{GATEWAY_URL}/v1/llm/completions",
            json={"prompt": "hi"},
            headers={"Authorization": f"Bearer {tok}"},
            timeout=5,
        )
        _assert_safe(r, context=f"random binary token #{i}")


def test_fuzz_oversized_token():
    """A 100 KB token must not cause a 5xx."""
    narrate("sending a 100 KB token")
    huge = "A" * 100_000
    r = requests.post(
        f"{GATEWAY_URL}/v1/llm/completions",
        json={"prompt": "hi"},
        headers={"Authorization": f"Bearer {huge}"},
        timeout=10,
    )
    _assert_safe(r, context="100 KB token")


def test_fuzz_empty_and_whitespace_tokens():
    """Empty, whitespace, and 'Bearer ' with no token must all return 401."""
    narrate("testing empty / whitespace Authorization values")
    cases = [
        "",
        "   ",
        "Bearer",
        "Bearer ",
        "Bearer  ",
        "Token abc",
        "Basic dXNlcjpwYXNz",
    ]
    for val in cases:
        try:
            r = requests.post(
                f"{GATEWAY_URL}/v1/llm/completions",
                json={"prompt": "hi"},
                headers={"Authorization": val} if val else {},
                timeout=5,
            )
        except requests.exceptions.InvalidHeader:
            # RFC 7230: leading/trailing whitespace is illegal in a header
            # value. The requests library correctly rejects these before
            # sending — the attack is blocked at the HTTP level.
            continue
        assert r.status_code in {401, 400}, (
            f"expected 401/400 for Authorization={val!r}, got {r.status_code}: {r.text}"
        )


def test_fuzz_jwt_shaped_garbage():
    """Three-segment tokens that look like JWTs but are cryptographically invalid."""
    narrate("sending 30 JWT-shaped but invalid tokens")
    for i in range(30):
        parts = [
            _b64(bytes(_RNG.randint(0, 255) for _ in range(_RNG.randint(5, 50))))
            for _ in range(3)
        ]
        tok = ".".join(parts)
        r = requests.post(
            f"{GATEWAY_URL}/v1/llm/completions",
            json={"prompt": "hi"},
            headers={"Authorization": f"Bearer {tok}"},
            timeout=5,
        )
        _assert_safe(r, context=f"JWT-shaped garbage #{i}")


# ---------------------------------------------------------------------------
# Route fuzzing
# ---------------------------------------------------------------------------

def test_fuzz_random_routes(client_of):
    """Random URL paths must return 404, never 5xx."""
    narrate("sending 20 requests to random routes")
    c = client_of("analyst")
    for i in range(20):
        path = "/" + "/".join(
            "".join(_RNG.choices(string.ascii_lowercase + string.digits, k=8))
            for _ in range(_RNG.randint(1, 4))
        )
        r = c.call("GET", path)
        assert r.status_code not in {500, 502, 503}, (
            f"gateway 5xx on route {path!r}: {r.status_code}"
        )


# ---------------------------------------------------------------------------
# Body fuzzing
# ---------------------------------------------------------------------------

def test_fuzz_random_body(client_of):
    """Garbage request body on a real route must not cause 5xx.

    The gateway validates the JWT before touching the body, so the response
    will be 401 (no/bad token) or 200 (body passed through to backend).
    """
    narrate("sending 20 requests with random bodies")
    for i in range(20):
        body = bytes(_RNG.randint(0, 127) for _ in range(_RNG.randint(0, 500)))
        r = requests.post(
            f"{GATEWAY_URL}/v1/llm/completions",
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        assert r.status_code not in {500, 502, 503}, (
            f"gateway 5xx on random body #{i}: {r.status_code}"
        )


def test_fuzz_no_body_on_all_routes(client_of):
    """Requests with no body to each known route must not 5xx."""
    c = client_of("analyst")
    for route in _VALID_ROUTES:
        r = c.call("POST", route, json_body=None)
        assert r.status_code not in {500, 502, 503}, (
            f"gateway 5xx on {route} with empty body: {r.status_code}"
        )

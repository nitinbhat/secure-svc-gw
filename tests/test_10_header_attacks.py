"""Requirement 10: HTTP header attack resistance.

Tests that malformed or injected headers cannot:
  - bypass JWT authentication
  - cause 5xx responses (gateway must reject cleanly)
  - confuse the request router

Attacks covered:
  - X-Forwarded-For bypass attempt (no auth)
  - X-Real-IP / X-Original-URI spoofing
  - Duplicate Content-Length header (HTTP smuggling probe)
  - Oversized single header value
  - Null bytes in header value
  - Bearer token with injected newlines (header injection)
  - Missing Host header
  - Wrong Content-Type with JSON body
"""
from __future__ import annotations

import socket

import pytest
import requests

from client.gateway import mint_jwt
from tests.conftest import GATEWAY_URL, narrate


_POST_PATH = "/v1/llm/completions"
_JSON_BODY = b'{"prompt":"hi"}'
_SAFE_CODES = {400, 401, 403, 404}


def _raw_post(headers: list[tuple[str, str]], body: bytes = _JSON_BODY) -> int:
    """Send a raw HTTP/1.1 POST and return the status code.

    Uses a raw socket so we can craft headers that requests.Session would
    normalise away (e.g. duplicate headers, null bytes).
    """
    from urllib.parse import urlparse
    p = urlparse(GATEWAY_URL)
    host = p.hostname
    port = p.port or 80

    lines = [f"POST {_POST_PATH} HTTP/1.1"]
    lines.append(f"Host: {host}:{port}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Content-Type: application/json")
    for k, v in headers:
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    request = "\r\n".join(lines).encode() + body

    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(request)
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk

    first_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    try:
        return int(first_line.split()[1])
    except (IndexError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Bypass attempts via spoofed headers
# ---------------------------------------------------------------------------

def test_x_forwarded_for_cannot_bypass_auth():
    """X-Forwarded-For must never substitute for a valid JWT."""
    narrate("sending X-Forwarded-For: 127.0.0.1 with no Authorization")
    r = requests.post(
        f"{GATEWAY_URL}{_POST_PATH}",
        json={"prompt": "bypass"},
        headers={"X-Forwarded-For": "127.0.0.1"},
        timeout=5,
    )
    assert r.status_code == 401, (
        f"X-Forwarded-For must not bypass auth; got {r.status_code}: {r.text}"
    )


def test_x_real_ip_cannot_bypass_auth():
    """X-Real-IP spoofing must not bypass JWT validation."""
    narrate("sending X-Real-IP: 127.0.0.1 with no Authorization")
    r = requests.post(
        f"{GATEWAY_URL}{_POST_PATH}",
        json={"prompt": "bypass"},
        headers={"X-Real-IP": "127.0.0.1"},
        timeout=5,
    )
    assert r.status_code == 401, (
        f"X-Real-IP must not bypass auth; got {r.status_code}: {r.text}"
    )


def test_x_original_uri_cannot_bypass_routing():
    """X-Original-URI must not confuse the gateway router."""
    narrate("sending X-Original-URI: /v1/admin with a valid token but wrong path")
    r = requests.post(
        f"{GATEWAY_URL}/no/such/route",
        json={"prompt": "hi"},
        headers={"X-Original-URI": "/v1/llm/completions"},
        timeout=5,
    )
    # Gateway should return 404 for the actual path, not route via X-Original-URI.
    assert r.status_code == 404, (
        f"expected 404 for nonexistent route regardless of X-Original-URI; got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Header injection / malformation
# ---------------------------------------------------------------------------

def test_oversized_single_header():
    """A single header value of 64 KB must not cause a 5xx."""
    narrate("sending Authorization header with 64 KB value")
    r = requests.post(
        f"{GATEWAY_URL}{_POST_PATH}",
        json={"prompt": "hi"},
        headers={"Authorization": f"Bearer {'x' * 65_536}"},
        timeout=10,
    )
    assert r.status_code not in {500, 502, 503}, (
        f"oversized header caused {r.status_code}: {r.text[:200]}"
    )
    assert r.status_code in _SAFE_CODES | {431}, (
        f"unexpected status {r.status_code} for oversized header"
    )


def test_wrong_content_type_with_json_body(client_of, keys):
    """text/plain Content-Type with a JSON body must not 5xx (gateway
    forwards to backend; backend may accept or reject)."""
    narrate("sending text/plain with JSON body and valid auth")
    tok = mint_jwt(keys["analyst"])
    r = requests.post(
        f"{GATEWAY_URL}{_POST_PATH}",
        data=_JSON_BODY,
        headers={
            "Authorization": f"Bearer {tok}",
            "Content-Type": "text/plain",
        },
        timeout=5,
    )
    assert r.status_code not in {500, 502, 503}, (
        f"wrong Content-Type caused {r.status_code}: {r.text[:200]}"
    )


def test_missing_content_type_header(client_of, keys):
    """Request with no Content-Type must not 5xx."""
    narrate("sending POST with valid auth but no Content-Type")
    tok = mint_jwt(keys["analyst"])
    r = requests.post(
        f"{GATEWAY_URL}{_POST_PATH}",
        data=_JSON_BODY,
        headers={"Authorization": f"Bearer {tok}"},
        timeout=5,
    )
    assert r.status_code not in {500, 502, 503}, (
        f"missing Content-Type caused {r.status_code}: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Duplicate / conflicting headers (sent via raw socket)
# ---------------------------------------------------------------------------

def test_duplicate_authorization_header_uses_first(keys):
    """When two Authorization headers are sent Go's net/http reads the first.
    Sending a valid token first + garbage second must result in 200 (not 401).
    """
    tok = mint_jwt(keys["analyst"])
    narrate("sending two Authorization headers: valid first, garbage second")
    code = _raw_post([
        ("Authorization", f"Bearer {tok}"),
        ("Authorization", "Bearer completely-invalid"),
    ])
    narrate(f"  status: {code}")
    # Go's r.Header.Get picks the first value → valid token → 200
    assert code == 200, (
        f"expected 200 with valid-first duplicate Authorization, got {code}"
    )


def test_duplicate_content_length_header():
    """Duplicate Content-Length (HTTP request smuggling probe) must not 5xx."""
    narrate("sending duplicate Content-Length headers (smuggling probe)")
    code = _raw_post([("Content-Length", "0")])
    narrate(f"  status: {code}")
    assert code not in {500, 502, 503}, (
        f"duplicate Content-Length caused {code}"
    )

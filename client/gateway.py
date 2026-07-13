"""Secure Service Gateway Python client.

Signs an Ed25519 JWT and calls the gateway.

Also usable as a CLI:

    python -m client complete --caller analyst --prompt "hello"
    python -m client embed    --caller analyst --text "hello"
    python -m client search   --caller analyst --query "hello"

Attack modes for demos (deliberately break the request):

    --tamper       flip one byte of the signature
    --expired      mint a token that is already expired
    --wrong-aud    set aud to a value the gateway does not accept
    --rogue-kid X  put an unregistered kid in the JWT header
    --replay N     send the SAME token N times (nonce-cache trip)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ISSUER = "secure-svc-gw"
AUDIENCE = "secure-svc-gw"


# ---- key file --------------------------------------------------------

@dataclass
class ClientKey:
    """One caller's Ed25519 identity, loaded from clients/<sub>.json."""

    kid: str
    sub: str
    scopes: list[str]
    _priv: Ed25519PrivateKey

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "ClientKey":
        data = json.loads(Path(path).read_text())
        priv_raw = base64.b64decode(data["priv"])
        # ed25519 private keys are 64 bytes on disk (seed || pub); the
        # cryptography lib wants just the 32-byte seed.
        seed = priv_raw[:32]
        return cls(
            kid=data["kid"],
            sub=data["sub"],
            scopes=data.get("scopes", []),
            _priv=Ed25519PrivateKey.from_private_bytes(seed),
        )

    def sign(self, message: bytes) -> bytes:
        return self._priv.sign(message)


# ---- JWT minting -----------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint_jwt(
    key: ClientKey,
    *,
    scopes: list[str] | None = None,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    ttl_seconds: int = 60,
    expired: bool = False,
    wrong_aud: bool = False,
    rogue_kid: str | None = None,
) -> str:
    """Return a signed EdDSA JWT for the given caller."""
    now = int(time.time())
    exp = now + ttl_seconds if not expired else now - 60
    if wrong_aud:
        audience = "not-the-gateway"
    kid = rogue_kid or key.kid

    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    payload = {
        "iss": issuer,
        "sub": key.sub,
        "aud": audience,
        "iat": now,
        "exp": exp,
        "jti": secrets.token_hex(12),
        "scope": scopes if scopes is not None else key.scopes,
    }
    signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64(json.dumps(payload, separators=(',', ':')).encode())}"
    sig = key.sign(signing_input.encode())
    return f"{signing_input}.{_b64(sig)}"


def tamper(token: str) -> str:
    """Flip one byte of the signature so it fails Ed25519 verify."""
    head, payload, sig = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(sig + "=" * ((-len(sig)) % 4)))
    raw[0] ^= 0x01
    return f"{head}.{payload}.{_b64(bytes(raw))}"


# ---- HTTP calls -----------------------------------------------------

class GatewayClient:
    """Thin wrapper around requests that signs + sends."""

    def __init__(self, gateway_url: str, key: ClientKey):
        self.gateway = gateway_url.rstrip("/")
        self.key = key

    def call(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        token: str | None = None,
        scopes: list[str] | None = None,
        timeout: float = 10.0,
    ) -> requests.Response:
        if token is None:
            token = mint_jwt(self.key, scopes=scopes)
        url = f"{self.gateway}{path}"
        return requests.request(
            method,
            url,
            json=json_body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )

    # Convenience wrappers used by tests and the CLI.
    def complete(self, prompt: str, **kw) -> requests.Response:
        return self.call("POST", "/v1/llm/completions", json_body={"prompt": prompt}, **kw)

    def embed(self, text: str, **kw) -> requests.Response:
        return self.call("POST", "/v1/embed/vectors", json_body={"text": text}, **kw)

    def search(self, query: str, k: int = 3, **kw) -> requests.Response:
        return self.call("POST", "/v1/embed/search", json_body={"query": query, "k": k}, **kw)


# ---- CLI ------------------------------------------------------------

def _cli() -> None:
    ap = argparse.ArgumentParser("secure-svc-gw")
    ap.add_argument("action", choices=["complete", "embed", "search"])
    ap.add_argument("--gateway", default=os.getenv("GATEWAY_URL", "http://localhost:8080"))
    ap.add_argument("--caller", default="analyst", help="which clients/<name>.json to use")
    ap.add_argument("--clients-dir", default=os.getenv("CLIENTS_DIR", "clients"))
    ap.add_argument("--prompt", default="Summarize the OSI model in one sentence.")
    ap.add_argument("--text", default="the quick brown fox")
    ap.add_argument("--query", default="foxes and lazy dogs")
    ap.add_argument("--k", type=int, default=3)

    ap.add_argument("--tamper", action="store_true")
    ap.add_argument("--expired", action="store_true")
    ap.add_argument("--wrong-aud", action="store_true")
    ap.add_argument("--rogue-kid", default=None)
    ap.add_argument("--replay", type=int, default=1)
    args = ap.parse_args()

    key_path = Path(args.clients_dir) / f"{args.caller}.json"
    key = ClientKey.load(key_path)
    client = GatewayClient(args.gateway, key)

    token = mint_jwt(
        key,
        expired=args.expired,
        wrong_aud=args.wrong_aud,
        rogue_kid=args.rogue_kid,
    )
    if args.tamper:
        token = tamper(token)

    for i in range(args.replay):
        if args.action == "complete":
            r = client.call("POST", "/v1/llm/completions",
                            json_body={"prompt": args.prompt}, token=token)
        elif args.action == "embed":
            r = client.call("POST", "/v1/embed/vectors",
                            json_body={"text": args.text}, token=token)
        else:
            r = client.call("POST", "/v1/embed/search",
                            json_body={"query": args.query, "k": args.k}, token=token)
        rid = r.headers.get("X-Request-Id", "-")
        upstream = r.headers.get("X-Upstream", "-")
        print(f"[{i+1}] {r.request.method} {r.request.path_url} -> {r.status_code} "
              f"(upstream={upstream} rid={rid})")
        try:
            body = r.json()
            print("    body:", json.dumps(body)[:200])
        except Exception:
            print("    body:", r.text[:200])


if __name__ == "__main__":
    _cli()

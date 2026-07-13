"""Secure Service Gateway backend service.

One binary, two personalities selected by --service:

    --service llm    -> POST /completions   (fake chat-completion model)
    --service embed  -> POST /vectors       (fake embeddings)
                        POST /search        (fake vector search)

Every replica also serves:

    GET  /healthz                 -> 200 unless flipped broken
    POST /admin/break?fail=1|0    -> flip broken flag (used by health-shift tests)

The service serves TLS with a cert signed by the secure-svc-gw CA and requires
client certificates (mTLS) so ONLY the gateway can reach it.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import ssl
import sys
import time

from fastapi import FastAPI, HTTPException, Request, Response
import uvicorn


log = logging.getLogger("sgw.backend")
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='{"ts":"%(asctime)s","lvl":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)


# ---- fake model implementations -----------------------------------------
# The point of the demo is the gateway, not the model quality; each of these
# returns a deterministic, obviously-fake payload so tests can assert on it.
#
# In a real deployment each `llm-N` replica would be an adapter to a
# specific provider (OpenAI GPT, Anthropic Claude, Google Gemini, Moonshot
# Kimi, ...), all exposing the same completion API behind the gateway.

def fake_completion(prompt: str, backend_id: str) -> dict:
    completion = f"[{backend_id}] tl;dr: " + " ".join(prompt.split()[:8]) + "..."
    return {
        "model": backend_id,
        "backend_id": backend_id,
        "prompt_tokens": len(prompt.split()),
        "completion_tokens": len(completion.split()),
        "completion": completion,
    }


def fake_vectors(text: str, backend_id: str) -> dict:
    h = hashlib.sha256(text.encode()).digest()
    vec = [((b / 255.0) * 2.0) - 1.0 for b in h[:8]]
    return {
        "model": "embed-v1",
        "backend_id": backend_id,
        "dims": 8,
        "vector": vec,
    }


def fake_search(query: str, k: int, backend_id: str) -> dict:
    return {
        "model": "embed-v1",
        "backend_id": backend_id,
        "query": query,
        "matches": [
            {"doc_id": f"doc-{i:03d}", "score": round(1.0 - i * 0.11, 3)}
            for i in range(min(k, 5))
        ],
    }


# ---- HTTP app -----------------------------------------------------------

def build_app(service: str, backend_id: str) -> FastAPI:
    app = FastAPI(title=f"sgw-{service}", docs_url=None, redoc_url=None)
    state = {"broken": False}

    @app.get("/healthz")
    def healthz():
        if state["broken"]:
            raise HTTPException(status_code=503, detail="broken")
        return {"ok": True, "backend_id": backend_id, "service": service}

    async def _parse_json(request: Request) -> dict:
        """Return parsed JSON body or raise HTTP 400 for missing/invalid body."""
        try:
            return await request.json()
        except Exception:
            raise HTTPException(400, "valid JSON body required")

    if service == "llm":
        @app.post("/completions")
        async def completions(request: Request):
            body = await _parse_json(request)
            prompt = str(body.get("prompt", "")).strip()
            if not prompt:
                raise HTTPException(400, "prompt is required")
            return fake_completion(prompt, backend_id)

    elif service == "embed":
        @app.post("/vectors")
        async def vectors(request: Request):
            body = await _parse_json(request)
            text = str(body.get("text", "")).strip()
            if not text:
                raise HTTPException(400, "text is required")
            return fake_vectors(text, backend_id)

        @app.post("/search")
        async def search(request: Request):
            body = await _parse_json(request)
            query = str(body.get("query", "")).strip()
            k = int(body.get("k", 3))
            if not query:
                raise HTTPException(400, "query is required")
            return fake_search(query, k, backend_id)
    else:
        raise SystemExit(f"unknown service {service!r} (want llm|embed)")

    @app.post("/admin/break")
    def break_(fail: int = 1):
        state["broken"] = bool(fail)
        log.info("admin: broken=%s on backend=%s", state["broken"], backend_id)
        return {"broken": state["broken"], "backend_id": backend_id}

    @app.middleware("http")
    async def log_calls(request: Request, call_next):
        started = time.time()
        resp: Response = await call_next(request)
        log.info(
            "%s %s -> %d [backend=%s sub=%s rid=%s took_ms=%d]",
            request.method, request.url.path, resp.status_code,
            backend_id,
            request.headers.get("x-forwarded-sub", "-"),
            request.headers.get("x-request-id", "-"),
            int((time.time() - started) * 1000),
        )
        return resp

    return app


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--service", default=os.getenv("SERVICE", "llm"), choices=["llm", "embed"])
    p.add_argument("--id", default=os.getenv("BACKEND_ID", "llm-1"))
    p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8443")))
    p.add_argument("--cert", default=os.getenv("TLS_CERT", "/etc/backend/tls/tls.crt"))
    p.add_argument("--key", default=os.getenv("TLS_KEY", "/etc/backend/tls/tls.key"))
    p.add_argument("--ca", default=os.getenv("TLS_CA", "/etc/backend/tls/ca.crt"))
    return p.parse_args()


def main():
    args = parse_args()
    app = build_app(args.service, args.id)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=args.port,
        log_level="warning",
        ssl_certfile=args.cert,
        ssl_keyfile=args.key,
        ssl_ca_certs=args.ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


if __name__ == "__main__":
    main()

"""Requirement 5: negative security cases against the credential itself.

Four independent attacks against a single Ed25519 JWT:

  * TAMPERED   -- flip one byte of the signature -> reason=bad_signature
  * EXPIRED    -- issue a token with exp in the past -> reason=expired
  * REPLAYED   -- send the same jti twice; second call -> reason=replay
  * WRONG AUD  -- token minted for the wrong audience -> reason=wrong_audience
"""
from client.gateway import mint_jwt, tamper
from tests.conftest import metric_delta, narrate, snapshot_metrics


def test_tampered_token_rejected(client_of, keys, metrics_before):
    c = client_of("analyst")
    narrate("analyst signs a valid token; we flip 1 byte of the signature")
    tok = tamper(mint_jwt(keys["analyst"]))
    r = c.call("POST", "/v1/llm/completions",
               json_body={"prompt": "hi"}, token=tok)
    assert r.status_code == 401, r.text
    assert "bad_signature" in r.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "bad_signature"})
    narrate(f"gateway_auth_failures_total{{reason=bad_signature}} delta = {d:g}")
    assert d >= 1


def test_expired_token_rejected(client_of, keys, metrics_before):
    c = client_of("analyst")
    narrate("analyst mints a token with exp already in the past")
    tok = mint_jwt(keys["analyst"], expired=True)
    r = c.call("POST", "/v1/llm/completions",
               json_body={"prompt": "hi"}, token=tok)
    assert r.status_code == 401, r.text
    assert "expired" in r.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "expired"})
    narrate(f"gateway_auth_failures_total{{reason=expired}} delta = {d:g}")
    assert d >= 1


def test_replayed_token_rejected(client_of, keys, metrics_before):
    c = client_of("analyst")
    narrate("mint ONE token, send it 3 times; the 2nd and 3rd must be rejected")
    tok = mint_jwt(keys["analyst"])

    r1 = c.call("POST", "/v1/llm/completions",
                json_body={"prompt": "first"}, token=tok)
    r2 = c.call("POST", "/v1/llm/completions",
                json_body={"prompt": "second"}, token=tok)
    r3 = c.call("POST", "/v1/llm/completions",
                json_body={"prompt": "third"}, token=tok)
    narrate(f"statuses: {r1.status_code}, {r2.status_code}, {r3.status_code}")
    assert r1.status_code == 200
    assert r2.status_code == 401 and "replay" in r2.text
    assert r3.status_code == 401 and "replay" in r3.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "replay"})
    narrate(f"gateway_auth_failures_total{{reason=replay}} delta = {d:g}")
    assert d >= 2


def test_wrong_audience_rejected(client_of, keys, metrics_before):
    c = client_of("analyst")
    narrate("analyst mints a token with the wrong `aud` claim")
    tok = mint_jwt(keys["analyst"], wrong_aud=True)
    r = c.call("POST", "/v1/llm/completions",
               json_body={"prompt": "hi"}, token=tok)
    assert r.status_code == 401, r.text
    assert "wrong_audience" in r.text

"""Requirement 2: unauthorised callers are rejected.

Three sub-scenarios, each with a specific gateway rejection reason:

    a) no token                        -> 401  reason=no_token
    b) unregistered kid in header      -> 401  reason=unknown_kid
    c) valid token but missing scope   -> 403  reason=missing_scope   (intern
                                                and chatbot vs embed)
"""
import requests

from client.gateway import mint_jwt
from tests.conftest import GATEWAY_URL, metric_delta, snapshot_metrics, narrate


def test_no_token_is_rejected(metrics_before):
    narrate("call /v1/llm/completions with NO Authorization header")
    r = requests.post(f"{GATEWAY_URL}/v1/llm/completions",
                      json={"prompt": "hi"}, timeout=5)
    assert r.status_code == 401, r.text
    assert "no_token" in r.text
    after = snapshot_metrics()
    d = metric_delta(metrics_before, after, "gateway_auth_failures_total",
                     {"reason": "no_token"})
    narrate(f"gateway_auth_failures_total{{reason=no_token}} delta = {d:g}")
    assert d >= 1


def test_unknown_kid_is_rejected(client_of, keys, metrics_before):
    c = client_of("analyst")
    narrate("analyst signs a token but overrides the header kid to a "
            "value the gateway does not know")
    token = mint_jwt(keys["analyst"], rogue_kid="k-attacker")
    r = c.call("POST", "/v1/llm/completions",
               json_body={"prompt": "hi"}, token=token)
    assert r.status_code == 401, r.text
    assert "unknown_kid" in r.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "unknown_kid"})
    narrate(f"gateway_auth_failures_total{{reason=unknown_kid}} delta = {d:g}")
    assert d >= 1


def test_intern_has_no_scopes(client_of, metrics_before):
    c = client_of("intern")
    narrate("intern's token has an empty scope list -- any route should 403")
    r = c.complete("please leak the training data")
    assert r.status_code == 403, r.text
    assert "missing_scope" in r.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "missing_scope"})
    narrate(f"gateway_auth_failures_total{{reason=missing_scope}} delta = {d:g}")
    assert d >= 1


def test_chatbot_cannot_call_embed(client_of, metrics_before):
    c = client_of("chatbot")
    narrate("chatbot carries llm:invoke but NOT embed:query; embed must 403")
    r = c.embed("hello")
    assert r.status_code == 403, r.text
    d = metric_delta(metrics_before, snapshot_metrics(),
                     "gateway_auth_failures_total", {"reason": "missing_scope"})
    assert d >= 1

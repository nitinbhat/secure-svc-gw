"""Requirement 1: a legitimate caller reaches a healthy backend.

Story: the `analyst` app has both llm:invoke and embed:query scopes.
It calls /v1/llm/completions and /v1/embed/vectors and gets real answers.
"""
from tests.conftest import metric_delta, snapshot_metrics, narrate


def test_analyst_can_complete(client_of, metrics_before):
    c = client_of("analyst")
    narrate("analyst signs a JWT (llm:invoke) and POSTs /v1/llm/completions")
    r = c.complete("Explain BGP to a five year old.")
    assert r.status_code == 200, r.text
    body = r.json()
    narrate(f"gateway routed to upstream={r.headers.get('X-Upstream')} "
            f"and got completion={body['completion'][:60]!r}")
    assert body["completion"].startswith(f"[{r.headers['X-Upstream']}] tl;dr:")

    after = snapshot_metrics()
    d = metric_delta(metrics_before, after, "gateway_requests_total",
                     {"route": "/v1/llm", "decision": "allow", "reason": "ok"})
    narrate(f"gateway_requests_total{{decision=allow,reason=ok}} delta = {d:g}")
    assert d >= 1


def test_analyst_can_embed_and_search(client_of, metrics_before):
    c = client_of("analyst")
    narrate("analyst POSTs /v1/embed/vectors")
    r = c.embed("the quick brown fox")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dims"] == 8 and len(body["vector"]) == 8

    narrate("analyst POSTs /v1/embed/search (k=3)")
    r = c.search("brown fox", k=3)
    assert r.status_code == 200, r.text
    matches = r.json()["matches"]
    narrate(f"got {len(matches)} matches from upstream={r.headers.get('X-Upstream')}")
    assert 1 <= len(matches) <= 3

    after = snapshot_metrics()
    d = metric_delta(metrics_before, after, "gateway_requests_total",
                     {"route": "/v1/embed", "decision": "allow", "reason": "ok"})
    assert d >= 2


def test_chatbot_can_only_use_llm(client_of):
    c = client_of("chatbot")
    narrate("chatbot only carries llm:invoke; completions call should succeed")
    r = c.complete("hello")
    assert r.status_code == 200, r.text

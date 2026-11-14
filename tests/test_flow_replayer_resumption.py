import asyncio
import json
import types

from blfinder.core.flows.flow_replayer import FlowReplayer, FlowStep


def _try_parse_json(body: str):
    try:
        return json.loads(body) if body else {}
    except (ValueError, TypeError):
        return {}


def make_replayer(request_fn=None):
    fake_scanner = types.SimpleNamespace(
        config=types.SimpleNamespace(verbose=False),
        _request=request_fn,
        _try_parse_json=_try_parse_json,
    )
    return FlowReplayer(fake_scanner)


def test_resource_url_for_variable_finds_matching_later_step():
    replayer = make_replayer()
    later_steps = [
        FlowStep(id="ship", method="POST", url="/orders/{{order_id}}/ship"),
    ]
    url = replayer._resource_url_for_variable(
        "order_id", later_steps, {"order_id": "123"}, "https://api.target.com",
    )
    assert url == "https://api.target.com/orders/123"


def test_resource_url_for_variable_returns_empty_when_no_match():
    replayer = make_replayer()
    later_steps = [FlowStep(id="unrelated", method="GET", url="/profile")]
    url = replayer._resource_url_for_variable(
        "order_id", later_steps, {"order_id": "123"}, "https://api.target.com",
    )
    assert url == ""


def test_resource_url_for_variable_uses_first_matching_step():
    replayer = make_replayer()
    later_steps = [
        FlowStep(id="unrelated", method="GET", url="/profile"),
        FlowStep(id="ship", method="POST", url="/orders/{{order_id}}/ship"),
        FlowStep(id="refund", method="POST", url="/orders/{{order_id}}/refund"),
    ]
    url = replayer._resource_url_for_variable(
        "order_id", later_steps, {"order_id": "123"}, "https://api.target.com",
    )
    assert url == "https://api.target.com/orders/123"


def test_attempt_invalidation_succeeds_via_delete():
    calls = []

    async def fake_request(method, url, **kwargs):
        calls.append((method, url))
        if method == "DELETE":
            return 204, {}, "", 0.01
        return 500, {}, "", 0.01

    replayer = make_replayer(fake_request)
    invalidated, evidence = asyncio.run(
        replayer._attempt_invalidation("https://api.target.com/orders/123")
    )
    assert invalidated is True
    assert "DELETE" in evidence
    assert calls[0][0] == "DELETE"


def test_attempt_invalidation_falls_back_to_patch():
    async def fake_request(method, url, json=None, **kwargs):
        if method == "DELETE":
            return 403, {}, "", 0.01
        if method == "PATCH":
            return 200, {}, '{"status": "cancelled"}', 0.01
        return 500, {}, "", 0.01

    replayer = make_replayer(fake_request)
    invalidated, evidence = asyncio.run(
        replayer._attempt_invalidation("https://api.target.com/orders/123")
    )
    assert invalidated is True
    assert "PATCH" in evidence
    assert "confirmed in response" in evidence


def test_attempt_invalidation_fails_when_both_methods_rejected():
    async def fake_request(method, url, **kwargs):
        return 403, {}, "", 0.01

    replayer = make_replayer(fake_request)
    invalidated, evidence = asyncio.run(
        replayer._attempt_invalidation("https://api.target.com/orders/123")
    )
    assert invalidated is False
    assert evidence == ""


def test_attack_resume_after_invalidation_flags_stale_precondition():
    async def fake_request(method, url, json=None, params=None, headers=None, token_override=None):
        if method == "POST" and url.endswith("/orders"):
            return 201, {}, '{"order_id": "123"}', 0.01
        if method == "DELETE" and url.endswith("/orders/123"):
            return 204, {}, "", 0.01
        if method == "POST" and url.endswith("/orders/123/ship"):
            if isinstance(json, dict) and json.get("__canary_invalid__"):
                return 400, {}, '{"error": "invalid"}', 0.01
            return 200, {}, '{"shipped": true}', 0.01
        return 404, {}, "", 0.01

    replayer = make_replayer(fake_request)
    steps = [
        FlowStep(id="create_order", method="POST", url="/orders",
                  extract={"order_id": "$.order_id"}),
        FlowStep(id="ship", method="POST", url="/orders/{{order_id}}/ship"),
    ]

    findings = asyncio.run(
        replayer.attack_resume_after_invalidation(steps, base_url="https://api.target.com")
    )

    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert "order_id" in findings[0].title
    assert "DELETE" in findings[0].evidence


def test_attack_resume_after_invalidation_no_finding_when_invalidation_unconfirmed():
    async def fake_request(method, url, json=None, params=None, headers=None, token_override=None):
        if method == "POST" and url.endswith("/orders"):
            return 201, {}, '{"order_id": "123"}', 0.01
        if method in ("DELETE", "PATCH"):
            return 403, {}, "", 0.01
        return 404, {}, "", 0.01

    replayer = make_replayer(fake_request)
    steps = [
        FlowStep(id="create_order", method="POST", url="/orders",
                  extract={"order_id": "$.order_id"}),
        FlowStep(id="ship", method="POST", url="/orders/{{order_id}}/ship"),
    ]

    findings = asyncio.run(
        replayer.attack_resume_after_invalidation(steps, base_url="https://api.target.com")
    )
    assert findings == []


def test_attack_resume_after_invalidation_suppressed_when_canary_also_succeeds():
    async def fake_request(method, url, json=None, params=None, headers=None, token_override=None):
        if method == "POST" and url.endswith("/orders"):
            return 201, {}, '{"order_id": "123"}', 0.01
        if method == "DELETE" and url.endswith("/orders/123"):
            return 204, {}, "", 0.01
        if method == "POST" and url.endswith("/orders/123/ship"):
            return 200, {}, '{"shipped": true}', 0.01
        return 404, {}, "", 0.01

    replayer = make_replayer(fake_request)
    steps = [
        FlowStep(id="create_order", method="POST", url="/orders",
                  extract={"order_id": "$.order_id"}),
        FlowStep(id="ship", method="POST", url="/orders/{{order_id}}/ship"),
    ]

    findings = asyncio.run(
        replayer.attack_resume_after_invalidation(steps, base_url="https://api.target.com")
    )
    assert findings == []

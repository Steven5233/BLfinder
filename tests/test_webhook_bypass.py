import asyncio
import json
import types

from blfinder.core.modules.webhook_bypass import WebhookBypassScanner, _SAMPLE_BODY


def make_scanner(request_fn=None):
    return WebhookBypassScanner(types.SimpleNamespace(
        config=types.SimpleNamespace(verbose=False),
        _request=request_fn,
    ))


def test_ignores_non_post():
    scanner = make_scanner()
    findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "GET", {})
    )
    assert findings == []


def test_ignores_non_webhook_path():
    scanner = make_scanner()
    findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/api/users", "POST", {})
    )
    assert findings == []


def test_ignores_endpoint_when_canary_also_succeeds():
    async def fake_request(method, url, json=None, headers=None):
        return 200, {}, '{"status": "ok"}', 0.01

    scanner = make_scanner(fake_request)
    findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "POST", {})
    )
    assert findings == []


def test_absent_signature_probe_reports_finding():
    call_log = []

    async def fake_request(method, url, json=None, headers=None):
        call_log.append((method, url, headers))
        body_dict = json if isinstance(json, dict) else {}
        if body_dict.get("__blfinder_canary__"):
            return 400, {}, '{"error": "invalid"}', 0.01
        return 200, {}, '{"status": "ok", "processed": true}', 0.01

    scanner = make_scanner(fake_request)
    findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "POST", {})
    )
    assert len(findings) >= 1
    assert findings[0].confirmed is True
    assert "Signature" in findings[0].title or "signature" in findings[0].title.lower()


def test_amount_tamper_probe_fires_after_absent_bypass():
    async def fake_request(method, url, json=None, headers=None):
        body_dict = json if isinstance(json, dict) else {}
        if body_dict.get("__blfinder_canary__"):
            return 400, {}, '{"error": "invalid"}', 0.01
        return 200, {}, '{"status": "ok"}', 0.01

    scanner = make_scanner(fake_request)
    findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "POST", _SAMPLE_BODY)
    )
    titles = [f.title for f in findings]
    assert any("Amount" in t or "amount" in t for t in titles)


def test_set_amount_modifies_top_level_field():
    scanner = make_scanner()
    body = {"event": "payment.success", "amount": 10000}
    result = scanner._set_amount(body, 1)
    assert result is True
    assert body["amount"] == 1


def test_set_amount_modifies_nested_field():
    scanner = make_scanner()
    body = {"event": "payment.success", "data": {"total": 5000}}
    result = scanner._set_amount(body, 1)
    assert result is True
    assert body["data"]["total"] == 1


def test_set_amount_returns_false_when_no_amount_field():
    scanner = make_scanner()
    body = {"event": "payment.success", "reference": "txn_123"}
    result = scanner._set_amount(body, 1)
    assert result is False


def test_accepts_requires_success_status_and_no_error_body():
    scanner = make_scanner()
    assert scanner._accepts('{"status": "ok"}', 200) is True
    assert scanner._accepts('{"error": "invalid"}', 200) is False
    assert scanner._accepts('{"status": "ok"}', 400) is False


def test_deduplication_prevents_double_reporting():
    call_log = []

    async def fake_request(method, url, json=None, headers=None):
        call_log.append(url)
        body_dict = json if isinstance(json, dict) else {}
        if body_dict.get("__blfinder_canary__"):
            return 400, {}, '{"error": "invalid"}', 0.01
        return 200, {}, '{"status": "ok"}', 0.01

    scanner = make_scanner(fake_request)
    asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "POST", {})
    )
    second_findings = asyncio.run(
        scanner.check_endpoint("https://api.target.com/webhook/payment", "POST", {})
    )
    assert second_findings == []


def test_webhook_path_regex_matches_common_patterns():
    from blfinder.core.modules.webhook_bypass import _WEBHOOK_PATH_RE
    assert _WEBHOOK_PATH_RE.search("/webhook/payment")
    assert _WEBHOOK_PATH_RE.search("/api/v1/payment-callback")
    assert _WEBHOOK_PATH_RE.search("/stripe/webhook")
    assert _WEBHOOK_PATH_RE.search("/paystack/notify")
    assert not _WEBHOOK_PATH_RE.search("/api/users")
    assert not _WEBHOOK_PATH_RE.search("/auth/login")

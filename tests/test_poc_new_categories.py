import types

from blfinder.core.poc import PoCGenerator
from blfinder.core.models import Finding, Severity, ScanConfig


def make_config():
    return ScanConfig(target_url="https://api.target.com", auth_token="tok_test")


def make_finding(category: str, title: str = "Test finding") -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        category=category,
        description="test",
        request={"method": "POST", "url": "https://api.target.com/webhook/pay", "body": {"amount": 100}},
        response_summary="HTTP 200",
        evidence="evidence",
        recommendation="fix it",
        endpoint="https://api.target.com/webhook/pay",
        parameter="amount",
    )


def test_webhook_category_routes_to_dedicated_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Webhook — Signature Absent Accepted")
    poc = gen.generate(f)
    assert "hmac" in poc.python_script.lower() or "signature" in poc.python_script.lower()
    assert poc.steps


def test_callback_category_routes_to_webhook_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Webhook — Forged Payment Amount Accepted")
    poc = gen.generate(f)
    assert poc.python_script
    assert len(poc.steps) >= 3


def test_numeric_precision_routes_to_dedicated_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Business Logic — Numeric Precision Abuse", "Sub-Cent Rounding")
    f.request["field"] = "amount"
    f.request["payload"] = 0.0049
    poc = gen.generate(f)
    assert "0.0049" in poc.python_script or "precision" in poc.python_script.lower()


def test_scale_confusion_routes_to_numeric_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Business Logic — Unit/Currency Scale Confusion")
    poc = gen.generate(f)
    assert poc.steps


def test_second_order_routes_to_dedicated_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Business Logic — Second-Order State Reflection")
    f.parameter = "is_admin"
    poc = gen.generate(f)
    assert "second" in poc.summary.lower() or "is_admin" in poc.python_script


def test_stale_precondition_routes_to_dedicated_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Business Logic — Stale Precondition on Resume")
    poc = gen.generate(f)
    assert "invalidat" in poc.python_script.lower() or "cancel" in poc.python_script.lower()


def test_resumption_routes_to_stale_precondition_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Business Logic — Workflow Resumption After Invalidation")
    poc = gen.generate(f)
    assert poc.steps


def test_unknown_category_still_gets_generic_poc():
    gen = PoCGenerator(make_config())
    f = make_finding("Some Future Category Not Yet Mapped")
    poc = gen.generate(f)
    assert poc.curl_command
    assert poc.python_script


def test_hackerone_vuln_short_maps_new_categories():
    from blfinder.core.reporting.hackerone_formatter import _vuln_short
    assert _vuln_short("Webhook — Signature Absent Accepted") == "Webhook Signature Bypass"
    assert _vuln_short("Business Logic — Numeric Precision Abuse") == "Numeric Precision Abuse"
    assert _vuln_short("Business Logic — Second-Order State Reflection") == "Second-Order State Reflection"
    assert _vuln_short("Business Logic — Stale Precondition on Resume") == "Stale Precondition on Resume"


def test_hackerone_vuln_long_maps_new_categories():
    from blfinder.core.reporting.hackerone_formatter import _vuln_long
    assert "webhook" in _vuln_long("Webhook — Signature Absent Accepted").lower()
    assert "precision" in _vuln_long("Business Logic — Numeric Precision Abuse").lower()
    assert "second" in _vuln_long("Business Logic — Second-Order State Reflection").lower()

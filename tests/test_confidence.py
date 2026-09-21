from blfinder.core.confidence import ConfidenceEngine, _safe_json
from blfinder.core.models import Finding, Severity


def make_finding(severity=Severity.HIGH, confirmed=False):
    return Finding(
        title="test", severity=severity, category="test",
        description="test", request={}, response_summary="",
        evidence="", recommendation="", confirmed=confirmed,
    )


def test_price_containing_400_not_treated_as_failure_token():
    engine = ConfidenceEngine()
    finding = make_finding()
    tampered = '{"order_total": "$400.00", "status": "confirmed"}'
    result = engine.score(finding, "{}", tampered, 403, 200)
    assert not any("Failure tokens" in c for c in result.false_positive_checks)


def test_real_4xx_status_still_penalised():
    engine = ConfidenceEngine()
    finding = make_finding()
    result = engine.score(finding, "{}", '{"error":"rejected"}', 200, 403)
    assert any("likely rejected" in c for c in result.false_positive_checks)


def test_safe_json_returns_none_on_parse_failure():
    assert _safe_json("not json at all") is None
    assert _safe_json('{"a": 1}') == {"a": 1}


def test_keyword_field_not_flagged_as_sensitive():
    engine = ConfidenceEngine()
    finding = make_finding()
    tampered = '{"keyword": "sale", "monkey": "business"}'
    result = engine.score(finding, "{}", tampered, 200, 200)
    assert not any("Sensitive fields" in r for r in result.confidence_reasons)


def test_api_key_field_still_flagged_as_sensitive():
    engine = ConfidenceEngine()
    finding = make_finding()
    tampered = '{"api_key": "sk_live_abc123"}'
    result = engine.score(finding, "{}", tampered, 200, 200)
    assert any("Sensitive fields" in r for r in result.confidence_reasons)

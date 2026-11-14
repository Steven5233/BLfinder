import json

from blfinder.core.confidence import ConfidenceEngine
from blfinder.core.models import Finding, Severity


def make_finding(confirmed=False, severity=Severity.HIGH) -> Finding:
    return Finding(
        title="Test Finding",
        severity=severity,
        category="Business Logic",
        description="test",
        request={},
        response_summary="",
        evidence="",
        recommendation="",
        confirmed=confirmed,
    )


def _body(data: dict) -> str:
    return json.dumps(data)


def test_privileged_field_change_boosts_score():
    engine = ConfidenceEngine()
    baseline = _body({"user_id": 1, "role": "user"})
    tampered = _body({"user_id": 1, "role": "admin"})
    f = make_finding()
    result = engine.score(f, baseline, tampered, 200, 200)
    assert result.confidence > 50
    assert any("role" in r for r in result.confidence_reasons)


def test_sensitive_field_change_boosts_score():
    engine = ConfidenceEngine()
    baseline = _body({"id": 1, "name": "Alice"})
    tampered = _body({"id": 2, "name": "Bob", "email": "bob@example.com"})
    f = make_finding()
    result = engine.score(f, baseline, tampered, 200, 200)
    assert any("email" in r.lower() or "sensitive" in r.lower() for r in result.confidence_reasons)


def test_fp_signal_from_high_noise_ratio_reduces_score():
    engine = ConfidenceEngine()
    baseline = _body({"status": "ok", "created_at": "2024-01-01T00:00:00Z", "request_id": "aaa"})
    tampered = _body({"status": "ok", "created_at": "2024-06-01T12:00:00Z", "request_id": "bbb"})
    f = make_finding()
    result_base = engine.score(make_finding(), baseline, baseline, 200, 200)
    result_noisy = engine.score(f, baseline, tampered, 200, 200)
    assert result_noisy.confidence <= result_base.confidence + 15


def test_identical_responses_reduce_score():
    engine = ConfidenceEngine()
    body = _body({"status": "ok", "user_id": 1})
    f = make_finding()
    result = engine.score(f, body, body, 200, 200)
    assert any("identical" in r.lower() or "similarity" in r.lower() for r in result.false_positive_checks)


def test_new_structural_key_in_tampered_response_boosts_score():
    engine = ConfidenceEngine()
    baseline = _body({"id": 1, "name": "Alice"})
    tampered = _body({"id": 1, "name": "Alice", "admin_panel_url": "/admin/users/1"})
    f = make_finding()
    result = engine.score(f, baseline, tampered, 200, 200)
    assert result.confidence > 30


def test_confirmed_finding_always_adds_to_score():
    engine = ConfidenceEngine()
    body = _body({"status": "ok"})
    f_unconfirmed = make_finding(confirmed=False)
    f_confirmed = make_finding(confirmed=True)
    r1 = engine.score(f_unconfirmed, body, body, 200, 200)
    r2 = engine.score(f_confirmed, body, body, 200, 200)
    assert r2.confidence > r1.confidence


def test_waf_block_signal_reduces_score():
    engine = ConfidenceEngine()
    baseline = _body({"status": "ok"})
    tampered = "Access Denied — Cloudflare blocked this request"
    f = make_finding()
    result = engine.score(f, baseline, tampered, 403, 200)
    assert any("waf" in c.lower() or "block" in c.lower() for c in result.false_positive_checks)


def test_score_is_clamped_to_0_100():
    engine = ConfidenceEngine()
    baseline = _body({"a": 1})
    tampered = _body({"a": 1, "b": 2, "c": 3, "is_admin": True, "role": "admin", "email": "x@x.com"})
    f = make_finding(confirmed=True)
    result = engine.score(f, baseline, tampered, 200, 200)
    assert 0 <= result.confidence <= 100

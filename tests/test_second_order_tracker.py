import json

from blfinder.core.analysis.second_order_tracker import SecondOrderTracker
from blfinder.core.models import Finding, Severity


def make_confirmed_finding(parameter: str, endpoint: str) -> Finding:
    return Finding(
        title=f"Mass Assignment — `{parameter}` reflected",
        severity=Severity.CRITICAL,
        category="Business Logic — Mass Assignment",
        description="test",
        request={},
        response_summary="",
        evidence="",
        recommendation="",
        confirmed=True,
        endpoint=endpoint,
        parameter=parameter,
    )


def test_record_finding_ignores_unconfirmed():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    f.confirmed = False
    tracker.record_finding(f)
    assert tracker._tracked == {}


def test_record_finding_ignores_missing_parameter():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("", "https://api.target.com/users/1")
    tracker.record_finding(f)
    assert tracker._tracked == {}


def test_record_finding_tracks_bare_field_name():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("profile.is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)
    assert "is_admin" in tracker._tracked


def test_observe_response_ignores_untracked_fields():
    tracker = SecondOrderTracker()
    body = json.dumps({"is_admin": True})
    tracker.observe_response("https://api.target.com/profile", "GET", 200, body)
    assert tracker._candidates == {}


def test_observe_response_flags_reflection_on_different_endpoint():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)

    body = json.dumps({"is_admin": True})
    tracker.observe_response("https://api.target.com/profile", "GET", 200, body)

    findings = tracker.flush_findings()
    assert len(findings) == 1
    assert findings[0].parameter == "is_admin"
    assert findings[0].confirmed is False


def test_observe_response_ignores_same_origin_endpoint():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)

    body = json.dumps({"is_admin": True})
    tracker.observe_response("https://api.target.com/users/1", "GET", 200, body)

    assert tracker.flush_findings() == []


def test_observe_response_ignores_trivial_values():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)

    body = json.dumps({"is_admin": False})
    tracker.observe_response("https://api.target.com/profile", "GET", 200, body)

    assert tracker.flush_findings() == []


def test_flush_findings_clears_candidates():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)
    body = json.dumps({"is_admin": True})
    tracker.observe_response("https://api.target.com/profile", "GET", 200, body)

    assert len(tracker.flush_findings()) == 1
    assert tracker.flush_findings() == []


def test_observe_response_ignores_non_2xx_status():
    tracker = SecondOrderTracker()
    f = make_confirmed_finding("is_admin", "https://api.target.com/users/1")
    tracker.record_finding(f)

    body = json.dumps({"is_admin": True})
    tracker.observe_response("https://api.target.com/profile", "GET", 403, body)

    assert tracker.flush_findings() == []


def test_bare_field_name_strips_dotted_and_bracket_paths():
    tracker = SecondOrderTracker()
    assert tracker._bare_field_name("order.is_admin") == "is_admin"
    assert tracker._bare_field_name("items[0].is_admin") == "is_admin"
    assert tracker._bare_field_name("is_admin") == "is_admin"

import types

from blfinder.core.modules.tenant_bola import TenantBOLAScanner


def make_scanner():
    fake_scanner = types.SimpleNamespace(
        config=types.SimpleNamespace(second_user_token="", verbose=False),
        _request=None,
    )
    return TenantBOLAScanner(fake_scanner)


def test_benign_error_count_field_does_not_break_looks_ok():
    scanner = make_scanner()
    body = '{"error_count": 0, "org": "acme", "data": [1, 2, 3]}'
    assert scanner._looks_ok(body, 200) is True


def test_real_error_field_fails_looks_ok():
    scanner = make_scanner()
    body = '{"error": "you are not a member of this organization"}'
    assert scanner._looks_ok(body, 200) is False


def test_empty_body_fails_looks_ok():
    scanner = make_scanner()
    assert scanner._looks_ok("", 200) is False


def test_differs_meaningfully_detects_distinct_org_data():
    scanner = make_scanner()
    base = '{"org_id": "acme", "members": ["alice", "bob"], "plan": "enterprise"}'
    other = '{"org_id": "widgetco", "members": ["carol"], "plan": "free"}'
    assert scanner._differs_meaningfully(base, other) is True


def test_differs_meaningfully_rejects_near_identical_response():
    scanner = make_scanner()
    base = '{"org_id": "acme", "members": ["alice", "bob"], "plan": "enterprise"}'
    assert scanner._differs_meaningfully(base, base) is False

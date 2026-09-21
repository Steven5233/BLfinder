from blfinder.core.modules.idor_mass_enum import _classify_status, ResourceStatusType


def test_small_valid_json_body_now_classified_as_exists():
    result = _classify_status(200, '{"id":5}', "somehash", "owned body")
    assert result == ResourceStatusType.EXISTS


def test_error_body_still_classified_as_not_found():
    result = _classify_status(200, '{"error": "not found"}', "somehash", "owned body")
    assert result == ResourceStatusType.NOT_FOUND


def test_identical_body_classified_as_owned():
    body = '{"id":5,"name":"acme"}'
    result = _classify_status(200, body, _hash(body), body)
    assert result == ResourceStatusType.OWNED


def _hash(s):
    import hashlib
    return hashlib.md5(s.encode()).hexdigest()


def test_403_classified_as_forbidden():
    assert _classify_status(403, "", "h", "") == ResourceStatusType.FORBIDDEN


def test_404_classified_as_not_found():
    assert _classify_status(404, "", "h", "") == ResourceStatusType.NOT_FOUND

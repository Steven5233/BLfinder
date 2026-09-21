from blfinder.core.response_heuristics import looks_like_error


def test_empty_body_is_error():
    assert looks_like_error("") is True


def test_genuine_error_phrase_detected():
    assert looks_like_error('{"message": "resource not found"}') is True


def test_error_field_with_failure_value_detected():
    assert looks_like_error('{"error": "invalid credentials supplied"}') is True


def test_benign_error_count_field_not_flagged():
    assert looks_like_error('{"error_count": 0, "name": "widget"}') is False


def test_benign_last_error_null_not_flagged():
    assert looks_like_error('{"last_error": null, "status": "ok"}') is False


def test_status_code_overrides_to_error():
    assert looks_like_error('{"anything": "ok"}', status=404) is True
    assert looks_like_error('{"anything": "ok"}', status=500) is True


def test_normal_success_body_not_flagged():
    assert looks_like_error('{"id": 42, "name": "Acme Corp"}', status=200) is False

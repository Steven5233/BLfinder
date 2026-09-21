from blfinder.core.verifier import _is_success_body


def test_benign_error_count_field_still_counted_as_success():
    body = '{"error_count": 0, "order_id": 42, "status": "confirmed"}'
    assert _is_success_body(body, 200) is True


def test_genuine_error_response_is_not_success():
    body = '{"error": "insufficient permissions"}'
    assert _is_success_body(body, 200) is False


def test_non_2xx_status_is_never_success():
    assert _is_success_body('{"ok": true}', 403) is False


def test_empty_body_is_not_success():
    assert _is_success_body("", 200) is False


def test_timeout_marker_is_not_success():
    assert _is_success_body("TIMEOUT", 200) is False

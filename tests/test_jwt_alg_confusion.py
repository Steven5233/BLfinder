import types

from blfinder.core.modules.jwt_alg_confusion import JWTAlgConfusionScanner


def make_jwt_scanner():
    fake_scanner = types.SimpleNamespace(
        config=types.SimpleNamespace(auth_token="", verbose=False),
        _request=None,
    )
    return JWTAlgConfusionScanner(fake_scanner)


def test_benign_error_count_field_not_treated_as_rejection():
    scanner = make_jwt_scanner()
    body = '{"error_count": 0, "user_id": 42, "role": "admin"}'
    assert scanner._looks_ok(body, 200) is True


def test_real_invalid_token_message_treated_as_rejection():
    scanner = make_jwt_scanner()
    body = '{"error": "invalid token signature"}'
    assert scanner._looks_ok(body, 200) is False

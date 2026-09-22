import asyncio

from blfinder.core.recon.js_secret_extractor import JSSecretExtractor


def run(coro):
    return asyncio.run(coro)


def test_context_reflects_actual_match_position_not_file_start():
    boilerplate = 'import{M as x,_ as P}from".'
    content = boilerplate + ("a" * 300) + '"https://internal-service.example.com/x"' + ("b" * 300)
    secrets, _ = run(JSSecretExtractor().scan_content(content, "https://target.com/vendor.js"))
    assert len(secrets) == 1
    assert "internal-service.example.com" in secrets[0].context
    assert boilerplate not in secrets[0].context


def test_two_distinct_matches_get_distinct_context():
    content = (
        ("a" * 300) + '"https://internal-one.example.com/x"' + ("b" * 300) +
        '"https://internal-two.example.com/y"' + ("c" * 300)
    )
    secrets, _ = run(JSSecretExtractor().scan_content(content, "https://target.com/vendor.js"))
    assert len(secrets) == 2
    assert secrets[0].context != secrets[1].context


def test_vendor_sdk_source_marks_internal_endpoint_as_false_positive():
    content = ("a" * 300) + '"https://internal-api.example.com/config"' + ("b" * 300)
    secrets, _ = run(JSSecretExtractor().scan_content(
        content, "https://target.com/assets/setup-amplitude-BztoBnBv.js"
    ))
    assert len(secrets) == 1
    assert secrets[0].is_false_positive is True
    assert secrets[0].confidence <= 10


def test_non_vendor_source_internal_endpoint_still_flagged():
    content = ("a" * 300) + '"https://internal-billing.example.com/charge"' + ("b" * 300)
    secrets, _ = run(JSSecretExtractor().scan_content(
        content, "https://target.com/assets/app.bundle.js"
    ))
    assert len(secrets) == 1
    assert secrets[0].is_false_positive is False

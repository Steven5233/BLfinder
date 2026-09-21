from urllib.parse import quote

from blfinder.core.modules.ssrf_scanner import _METADATA_SIGNATURES, _METADATA_PAYLOADS


def _matches(body):
    return [name for sig_re, name in _METADATA_SIGNATURES if sig_re.search(body)]


def test_reflected_payload_url_alone_is_stripped_before_matching():
    for label, payload_url, _ in _METADATA_PAYLOADS:
        reflected_body = f"Error: could not fetch {payload_url} — connection refused"
        scan_body = reflected_body.replace(payload_url, "").replace(
            quote(payload_url, safe=""), ""
        )
        assert _matches(scan_body) == [], (
            f"payload for '{label}' still self-matches after reflection stripped"
        )


def test_genuine_metadata_content_still_detected():
    body = '{"AccessKeyId":"ASIA...","SecretAccessKey":"abc","Token":"xyz"}'
    assert _matches(body) != []


def test_etc_passwd_content_still_detected():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"
    assert _matches(body) != []

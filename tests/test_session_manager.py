import itertools
import types

from blfinder.core.scanner import BLFScanner
from blfinder.core.auth.session_manager import (
    SessionManager, RefreshConfig, SessionState, _extract_json_value_fallback,
)


def build_headers(auth_token, session_mgr):
    fake_config = types.SimpleNamespace(
        auth_token=auth_token, api_key_sid="", api_key_secret="",
        headers={}, user_agent_rotate=False,
    )
    fake_self = types.SimpleNamespace(
        config=fake_config,
        _ua_cycle=itertools.cycle(["UA/1"]),
        _session_mgr=session_mgr,
    )
    return BLFScanner._build_headers(fake_self)


def test_refreshed_session_token_is_used_over_stale_static_token():
    mgr = types.SimpleNamespace(state=types.SimpleNamespace(
        token="fresh-refreshed-token", csrf_token=""
    ))
    headers = build_headers(auth_token="", session_mgr=mgr)
    assert headers["Authorization"] == "Bearer fresh-refreshed-token"


def test_stale_config_token_not_used_when_session_has_newer_one():
    mgr = types.SimpleNamespace(state=types.SimpleNamespace(
        token="new-token-after-refresh", csrf_token=""
    ))
    headers = build_headers(auth_token="old-stale-token", session_mgr=mgr)
    assert headers["Authorization"] == "Bearer new-token-after-refresh"


def test_falls_back_to_static_token_when_no_session_manager():
    headers = build_headers(auth_token="static-token", session_mgr=None)
    assert headers["Authorization"] == "Bearer static-token"


def test_ensure_valid_forces_login_when_no_token_yet():
    rc = RefreshConfig(login_url="https://x/login", login_body={"u": "a"})
    fake_config = types.SimpleNamespace(auth_token="", cookies={})
    mgr = SessionManager(fake_config, rc)
    needs_first_login = bool(
        not mgr.state.token
        and mgr.refresh_config is not None
        and (mgr.refresh_config.login_url or mgr.refresh_config.refresh_url)
    )
    assert needs_first_login is True


def test_ensure_valid_does_not_force_login_when_no_refresh_config():
    fake_config = types.SimpleNamespace(auth_token="", cookies={})
    mgr = SessionManager(fake_config, None)
    needs_first_login = (
        not mgr.state.token
        and mgr.refresh_config is not None
        and (mgr.refresh_config.login_url or mgr.refresh_config.refresh_url)
    )
    assert needs_first_login is False


def test_fallback_token_extraction_finds_nested_path():
    assert _extract_json_value_fallback('{"data":{"token":"abcd1234efgh"}}') == "abcd1234efgh"


def test_fallback_token_extraction_finds_top_level_access_token():
    assert _extract_json_value_fallback('{"access_token":"topleveltoken123"}') == "topleveltoken123"


def test_fallback_token_extraction_returns_empty_for_no_match():
    assert _extract_json_value_fallback('{"status":"ok"}') == ""

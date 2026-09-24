from __future__ import annotations

import base64
from dataclasses import dataclass, field

import aiohttp

from .session_manager import SessionManager, RefreshConfig
from ..verifier import _similarity

SAME_RESPONSE_SIMILARITY_THRESHOLD = 0.95


@dataclass
class AuthCheckResult:
    performed: bool = False
    passed: bool = False
    inconclusive: bool = False
    reason: str = ""
    authed_status: int = 0
    unauthed_status: int = 0
    check_url: str = ""


def _has_any_credentials(config) -> bool:
    return bool(
        config.auth_token
        or (config.api_key_sid and config.api_key_secret)
        or config.cookies
        or getattr(config, "refresh_config", None)
    )


def _basic_auth_value(sid: str, secret: str) -> str:
    raw = f"{sid}:{secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


async def run_auth_preflight(config, check_url: str = "") -> AuthCheckResult:
    """
    Make a cheap request with the configured credentials (and one without)
    before the real scan starts, so a bad token/cookie/API key/login flow
    is caught immediately instead of silently producing zero findings.

    Returns an AuthCheckResult; performed=False means nothing to check
    (no credentials were configured at all — a deliberate unauthenticated
    scan, not a failure).
    """
    if not _has_any_credentials(config):
        return AuthCheckResult(performed=False)

    url = check_url or config.target_url
    result = AuthCheckResult(performed=True, check_url=url)

    connector = aiohttp.TCPConnector(ssl=config.verify_ssl, limit=5)
    timeout = aiohttp.ClientTimeout(total=max(10, config.timeout))

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        session_mgr = None
        refresh_cfg: RefreshConfig | None = getattr(config, "refresh_config", None)
        token = config.auth_token

        if refresh_cfg is not None:
            session_mgr = SessionManager(config, refresh_cfg)
            session_mgr.initialize(session)
            ok = await session_mgr._do_refresh() if not token else True
            if not token and not ok and not session_mgr.state.token:
                return AuthCheckResult(
                    performed=True, passed=False, check_url=url,
                    reason=(
                        "Login/refresh flow failed to obtain any token — "
                        "see the warning above for details"
                    ),
                )
            token = session_mgr.state.token or token

        headers = {"User-Agent": "Mozilla/5.0 BLFinder-AuthCheck/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif config.api_key_sid and config.api_key_secret:
            headers["Authorization"] = _basic_auth_value(
                config.api_key_sid, config.api_key_secret
            )
        headers.update(config.headers)

        cookies = dict(config.cookies)
        if session_mgr:
            cookies.update(session_mgr.get_cookies())

        try:
            async with session.get(
                url, headers=headers, cookies=cookies,
                allow_redirects=True, proxy=config.proxy or None,
            ) as resp:
                authed_status = resp.status
                authed_body = (await resp.text(errors="replace"))[:2000]
        except Exception as e:
            return AuthCheckResult(
                performed=True, passed=False, check_url=url,
                reason=f"Authenticated request itself failed: {e}",
            )

        result.authed_status = authed_status

        try:
            async with session.get(
                url, headers={"User-Agent": headers["User-Agent"]},
                allow_redirects=True, proxy=config.proxy or None,
            ) as resp2:
                unauthed_status = resp2.status
                unauthed_body = (await resp2.text(errors="replace"))[:2000]
        except Exception:
            unauthed_status = -1
            unauthed_body = ""

        result.unauthed_status = unauthed_status

        if authed_status in (401, 403):
            result.passed = False
            result.reason = (
                f"Authenticated request to {url} returned HTTP {authed_status} — "
                "the token/cookies/API key are being rejected"
            )
            return result

        if authed_status >= 500:
            result.passed = False
            result.reason = (
                f"Authenticated request to {url} returned HTTP {authed_status} "
                "(server error) — cannot confirm credentials are valid"
            )
            return result

        if (
            unauthed_status == authed_status
            and unauthed_status != -1
            and _similarity(unauthed_body, authed_body) >= SAME_RESPONSE_SIMILARITY_THRESHOLD
        ):
            result.passed = True
            result.inconclusive = True
            result.reason = (
                f"Authenticated and unauthenticated requests to {url} returned "
                f"an equivalent HTTP {authed_status} response (same content, "
                "ignoring timestamps/nonces/tokens) — this may mean the "
                "credentials had no effect, or simply that this URL doesn't "
                "require auth. Pass --auth-check-url pointing at an "
                "authenticated-only endpoint (e.g. /api/me) for a conclusive check"
            )
            return result

        result.passed = True
        result.reason = (
            f"Authenticated request to {url} returned HTTP {authed_status} "
            f"(unauthenticated: HTTP {unauthed_status}, different response)"
        )
        return result


def print_auth_check_result(result: AuthCheckResult) -> None:
    if not result.performed:
        return
    if result.passed and not result.inconclusive:
        print(f"  [✓] Auth check passed — {result.reason}")
        return
    if result.passed and result.inconclusive:
        print(f"  [?] Auth check inconclusive — {result.reason}")
        return
    print(
        "  [!] ════════════════════════════════════════════════\n"
        "  [!] AUTH CHECK FAILED\n"
        f"  [!] {result.reason}\n"
        "  [!] Continuing will likely produce zero/near-zero      \n"
        "  [!] findings — this does NOT mean the target is secure,\n"
        "  [!] it means the scan never authenticated.             \n"
        "  [!] Use --ignore-auth-check to scan anyway.             \n"
        "  [!] ════════════════════════════════════════════════"
    )

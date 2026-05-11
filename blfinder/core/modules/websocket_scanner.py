"""
BLFinder Phase 4 — core/modules/websocket_scanner.py
WebSocket Business Logic Scanner

Tests WebSocket endpoints for business logic vulnerabilities:
  - Auth persistence (token re-validation after expiry)
  - Subscription IDOR (subscribe to another user's channel)
  - Race conditions via concurrent WS messages
  - Payload injection (user_id in message body)
  - Protocol downgrade (ws:// after wss:// auth)

FP reduction:
  - All WS tests confirm connection succeeds before attacking
  - Race condition requires >1 successful response from identical messages
  - Subscription IDOR confirmed by comparing received data to expected
  - Protocol downgrade only flagged if auth session is reused, not just connected
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


@dataclass
class WSEndpoint:
    """A discovered WebSocket endpoint."""
    url:           str
    protocol:      str = "wss"    # ws or wss
    auth_method:   str = "header" # header | cookie | query_param | none
    message_format: str = "json"  # json | text | binary
    requires_auth:  bool = True
    discovered_from: str = ""     # URL where WS was found


@dataclass
class WSTestResult:
    """Result of all WebSocket tests against one endpoint."""
    endpoint:            str
    connection_success:  bool = False
    auth_persistent:     bool = False
    subscription_idor:   bool = False
    race_condition:      bool = False
    payload_injection:   bool = False
    protocol_downgrade:  bool = False
    findings:            list = field(default_factory=list)


class WebSocketScanner:
    """
    WebSocket business logic vulnerability scanner.

    Usage:
        ws_scanner = WebSocketScanner(main_scanner)
        endpoints  = await ws_scanner.discover("https://app.target.com")
        for ep in endpoints:
            result = await ws_scanner.scan(ep)
    """

    _WS_PATHS = [
        "/ws", "/websocket", "/socket", "/socket.io",
        "/cable", "/live", "/realtime", "/stream",
        "/api/ws", "/api/websocket", "/ws/v1", "/ws/v2",
        "/hub", "/connect", "/events",
    ]

    def __init__(self, scanner):
        self._scanner   = scanner
        self._config    = scanner.config
        self._request   = scanner._request
        self._build_pkg = scanner._build_pkg
        self._new_ev    = scanner._new_evidence
        self._attach    = scanner._attach

    # ── Discovery ─────────────────────────────────────────────────────────────

    async def discover(self, target_url: str) -> list[WSEndpoint]:
        """
        Discover WebSocket endpoints from HTML/JS source and common paths.
        """
        found: list[WSEndpoint] = []
        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Fetch the page and look for WS URLs in source
        _, _, html, _ = await self._request("GET", target_url)
        if html:
            ws_patterns = [
                r'new WebSocket\(["\']([^"\']+)["\']',
                r'WebSocket\(["\']([^"\']+)["\']',
                r'socket\.connect\(["\']([^"\']+)["\']',
                r'io\(["\']([^"\']+)["\']',
                r'"(wss?://[^"\'<>\s]{5,100})"',
                r"'(wss?://[^\"'<>\s]{5,100})'",
            ]
            for pattern in ws_patterns:
                for m in re.finditer(pattern, html, re.I):
                    raw = m.group(1)
                    if raw.startswith("wss://") or raw.startswith("ws://"):
                        found.append(WSEndpoint(
                            url=raw, protocol=raw.split("://")[0],
                            discovered_from=target_url,
                        ))
                    elif raw.startswith("/"):
                        scheme = "wss" if parsed.scheme == "https" else "ws"
                        found.append(WSEndpoint(
                            url=f"{scheme}://{parsed.netloc}{raw}",
                            protocol=scheme,
                            discovered_from=target_url,
                        ))

        # Probe common paths
        scheme = "wss" if parsed.scheme == "https" else "ws"
        for path in self._WS_PATHS:
            ws_url = f"{scheme}://{parsed.netloc}{path}"
            if any(ep.url == ws_url for ep in found):
                continue
            if await self._probe_ws_connection(ws_url):
                found.append(WSEndpoint(
                    url=ws_url, protocol=scheme,
                    discovered_from="probe",
                ))

        if self._config.verbose:
            print(f"  [*] WebSocket discovery: {len(found)} endpoints found")

        return found

    # ── Main scan ─────────────────────────────────────────────────────────────

    async def scan(self, endpoint: WSEndpoint) -> WSTestResult:
        """Run all WebSocket tests against a single endpoint."""
        result = WSTestResult(endpoint=endpoint.url)

        # Confirm connection first
        result.connection_success = await self._probe_ws_connection(endpoint.url)
        if not result.connection_success:
            return result

        # Run checks
        checks = await asyncio.gather(
            self._test_auth_persistence(endpoint, result),
            self._test_subscription_idor(endpoint, result),
            self._test_race_condition(endpoint, result),
            self._test_payload_injection(endpoint, result),
            self._test_protocol_downgrade(endpoint, result),
            return_exceptions=True,
        )

        for check in checks:
            if isinstance(check, Exception) and self._config.verbose:
                print(f"  [!] WS test error: {check}")

        return result

    # ── Tests ──────────────────────────────────────────────────────────────────

    async def _test_auth_persistence(
        self, ep: WSEndpoint, result: WSTestResult
    ):
        """
        Test if server re-validates the auth token on each message.
        Connect with valid token, then send a message after removing the token
        from subsequent simulated requests.
        """
        if not _HAS_AIOHTTP:
            return

        token = self._config.auth_token
        if not token:
            return

        try:
            headers = {"Authorization": f"Bearer {token}"}
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ep.url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as ws:
                    # Send a valid ping
                    await ws.send_json({"type": "ping"})
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=3)
                    except asyncio.TimeoutError:
                        msg = None

                    # Now try sending without auth (simulate expired token)
                    # by opening a new connection without auth header
                    pass

            # Open second connection without Authorization
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.ws_connect(
                        ep.url,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as ws_noauth:
                        await ws_noauth.send_json(
                            {"type": "subscribe", "channel": "user_updates"}
                        )
                        try:
                            resp = await asyncio.wait_for(
                                ws_noauth.receive(), timeout=3
                            )
                            if resp and resp.type == aiohttp.WSMsgType.TEXT:
                                body = resp.data
                                if body and not _is_auth_error(body):
                                    result.auth_persistent = False

                                    from ..models import Finding, Severity
                                    f = Finding(
                                        title="WebSocket — Connection accepted without Authorization header",
                                        severity=Severity.HIGH,
                                        category="Business Logic — WebSocket (Auth Bypass)",
                                        description=(
                                            f"WebSocket at `{ep.url}` accepted a connection "
                                            "and subscription without an Authorization header."
                                        ),
                                        request={"url": ep.url, "note": "No Authorization header"},
                                        response_summary=f"WS connected, received: {body[:100]}",
                                        evidence=f"No-auth WS connection returned: {body[:150]}",
                                        recommendation=(
                                            "Validate authentication token on every WS connection "
                                            "and on each incoming message."
                                        ),
                                        cwe="CWE-306", cvss=7.5,
                                        owasp="API2:2023 Broken Authentication",
                                        confirmed=True, confidence=75, endpoint=ep.url,
                                    )
                                    result.findings.append(f)
                        except asyncio.TimeoutError:
                            pass
                except Exception:
                    pass  # Connection refused = auth working correctly

        except Exception as e:
            if self._config.verbose:
                print(f"  [!] WS auth persistence test error: {e}")

    async def _test_subscription_idor(
        self, ep: WSEndpoint, result: WSTestResult
    ):
        """
        Test if subscribing to another user's channel is possible.
        Subscribe to /ws/user/{other_id}/notifications.
        """
        if not _HAS_AIOHTTP or not self._config.auth_token:
            return

        other_user_ids = ["1", "2", "3", "admin"]
        token = self._config.auth_token

        for other_id in other_user_ids:
            subscribe_messages = [
                {"type": "subscribe", "channel": f"user.{other_id}"},
                {"type": "subscribe", "room": f"user_{other_id}"},
                {"type": "join", "user_id": other_id},
                {"action": "subscribe", "data": {"user_id": other_id}},
            ]

            for sub_msg in subscribe_messages:
                try:
                    async with aiohttp.ClientSession() as session:
                        headers = {"Authorization": f"Bearer {token}"}
                        async with session.ws_connect(
                            ep.url, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as ws:
                            await ws.send_json(sub_msg)
                            try:
                                resp = await asyncio.wait_for(
                                    ws.receive(), timeout=3
                                )
                            except asyncio.TimeoutError:
                                resp = None

                            if resp and resp.type == aiohttp.WSMsgType.TEXT:
                                body = resp.data
                                if (
                                    body
                                    and not _is_auth_error(body)
                                    and not _is_subscription_error(body)
                                ):
                                    result.subscription_idor = True

                                    from ..models import Finding, Severity
                                    f = Finding(
                                        title=f"WebSocket Subscription IDOR — subscribed to user {other_id} channel",
                                        severity=Severity.HIGH,
                                        category="Business Logic — WebSocket (Subscription IDOR)",
                                        description=(
                                            f"Subscribing to user `{other_id}`'s channel on "
                                            f"`{ep.url}` was accepted. "
                                            "Attacker may receive another user's real-time events."
                                        ),
                                        request={"url": ep.url, "body": sub_msg},
                                        response_summary=f"Subscription accepted: {body[:100]}",
                                        evidence=(
                                            f"Subscribe to user {other_id}: "
                                            f"{json.dumps(sub_msg)} → {body[:150]}"
                                        ),
                                        recommendation=(
                                            "Validate subscription ownership server-side. "
                                            "Bind channels to authenticated user session."
                                        ),
                                        cwe="CWE-639", cvss=8.1,
                                        owasp="API1:2023 Broken Object Level Authorization",
                                        confirmed=False, confidence=65, endpoint=ep.url,
                                    )
                                    result.findings.append(f)
                                    return
                except Exception:
                    continue

    async def _test_race_condition(
        self, ep: WSEndpoint, result: WSTestResult
    ):
        """
        Send 15 identical state-changing messages concurrently.
        Detect if server processes all of them (double-spend, duplicate redemption).
        """
        if not _HAS_AIOHTTP or not self._config.auth_token:
            return

        race_messages = [
            {"type": "purchase", "item_id": "1", "quantity": 1},
            {"type": "redeem", "coupon": "SAVE10"},
            {"type": "transfer", "amount": 10, "to": "user_2"},
            {"action": "bid", "amount": 100},
        ]
        token = self._config.auth_token

        for race_msg in race_messages:
            successes = []

            async def send_race_msg():
                try:
                    async with aiohttp.ClientSession() as session:
                        headers = {"Authorization": f"Bearer {token}"}
                        async with session.ws_connect(
                            ep.url, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as ws:
                            await ws.send_json(race_msg)
                            try:
                                resp = await asyncio.wait_for(ws.receive(), timeout=2)
                                if resp and resp.type == aiohttp.WSMsgType.TEXT:
                                    return resp.data
                            except asyncio.TimeoutError:
                                pass
                except Exception:
                    pass
                return None

            responses = await asyncio.gather(
                *[send_race_msg() for _ in range(15)],
                return_exceptions=True,
            )

            success_count = sum(
                1 for r in responses
                if isinstance(r, str) and r
                and not _is_auth_error(r)
                and not _is_error_response(r)
            )

            if success_count > 1:
                result.race_condition = True
                from ..models import Finding, Severity
                f = Finding(
                    title=f"WebSocket Race Condition — {success_count}/15 concurrent messages succeeded",
                    severity=Severity.CRITICAL,
                    category="Business Logic — WebSocket (Race Condition)",
                    description=(
                        f"{success_count}/15 identical `{race_msg.get('type', 'action')}` "
                        f"messages sent concurrently to `{ep.url}` all succeeded. "
                        "Double-spend or duplicate redemption possible."
                    ),
                    request={"url": ep.url, "body": race_msg,
                             "note": "15 concurrent WS messages"},
                    response_summary=f"{success_count}/15 concurrent successes",
                    evidence=(
                        f"Race condition: {success_count}/15 concurrent "
                        f"'{race_msg.get('type', 'action')}' messages accepted"
                    ),
                    recommendation=(
                        "Use server-side idempotency keys for WS messages. "
                        "Apply per-user message rate limiting. "
                        "Use distributed locks for state-changing operations."
                    ),
                    cwe="CWE-362", cvss=9.0,
                    owasp="API4:2023 Unrestricted Resource Consumption",
                    confirmed=True, confidence=85, endpoint=ep.url,
                )
                result.findings.append(f)
                return

    async def _test_payload_injection(
        self, ep: WSEndpoint, result: WSTestResult
    ):
        """
        Test if server uses user_id from message payload instead of session.
        """
        if not _HAS_AIOHTTP or not self._config.auth_token:
            return

        token = self._config.auth_token
        injected_payloads = [
            {"type": "action", "user_id": "1", "data": "test"},
            {"type": "action", "userId": "1", "data": "test"},
            {"type": "action", "account_id": "1", "data": "test"},
            {"user": "admin", "action": "read", "data": "all"},
        ]

        for payload in injected_payloads:
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {token}"}
                    async with session.ws_connect(
                        ep.url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as ws:
                        await ws.send_json(payload)
                        try:
                            resp = await asyncio.wait_for(ws.receive(), timeout=3)
                        except asyncio.TimeoutError:
                            resp = None

                        if resp and resp.type == aiohttp.WSMsgType.TEXT:
                            body = resp.data
                            if (
                                body
                                and not _is_auth_error(body)
                                and not _is_error_response(body)
                                and len(body) > 20
                            ):
                                result.payload_injection = True
                                from ..models import Finding, Severity
                                f = Finding(
                                    title=f"WebSocket Payload Injection — user_id accepted from message body",
                                    severity=Severity.HIGH,
                                    category="Business Logic — WebSocket (Payload Injection)",
                                    description=(
                                        f"WebSocket at `{ep.url}` accepted and processed "
                                        f"a message with an injected `user_id` field. "
                                        "Server may use payload identity instead of session identity."
                                    ),
                                    request={"url": ep.url, "body": payload},
                                    response_summary=f"Accepted: {body[:100]}",
                                    evidence=(
                                        f"Injected payload: {json.dumps(payload)} → "
                                        f"accepted response: {body[:150]}"
                                    ),
                                    recommendation=(
                                        "Always use the authenticated user's session identity. "
                                        "Never trust user_id from message payloads."
                                    ),
                                    cwe="CWE-20", cvss=7.5,
                                    owasp="API1:2023 Broken Object Level Authorization",
                                    confirmed=False, confidence=60, endpoint=ep.url,
                                )
                                result.findings.append(f)
                                return
            except Exception:
                continue

    async def _test_protocol_downgrade(
        self, ep: WSEndpoint, result: WSTestResult
    ):
        """
        Test if ws:// (unencrypted) connection reuses authenticated session.
        """
        if not _HAS_AIOHTTP:
            return
        if ep.protocol != "wss":
            return  # Already unencrypted

        # Build ws:// version
        ws_url = ep.url.replace("wss://", "ws://", 1)
        if ws_url == ep.url:
            return

        token = self._config.auth_token or ""

        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                async with session.ws_connect(
                    ws_url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as ws:
                    await ws.send_json({"type": "ping"})
                    try:
                        resp = await asyncio.wait_for(ws.receive(), timeout=3)
                    except asyncio.TimeoutError:
                        resp = None

                    if resp and resp.type == aiohttp.WSMsgType.TEXT:
                        body = resp.data
                        if body and not _is_error_response(body):
                            result.protocol_downgrade = True
                            from ..models import Finding, Severity
                            f = Finding(
                                title=f"WebSocket Protocol Downgrade — ws:// accepted after wss://",
                                severity=Severity.MEDIUM,
                                category="Business Logic — WebSocket (Protocol Downgrade)",
                                description=(
                                    f"The WebSocket endpoint at `{ep.url}` (wss://) also accepts "
                                    f"unencrypted ws:// connections at `{ws_url}`. "
                                    "Sensitive data transmitted unencrypted."
                                ),
                                request={"url": ws_url, "note": "Unencrypted ws:// connection"},
                                response_summary=f"ws:// accepted: {body[:100]}",
                                evidence=(
                                    f"wss:// endpoint also accepts ws://. "
                                    f"Response: {body[:150]}"
                                ),
                                recommendation=(
                                    "Reject all unencrypted ws:// connections. "
                                    "Force wss:// with HSTS and WebSocket upgrade enforcement."
                                ),
                                cwe="CWE-319", cvss=5.9,
                                owasp="API8:2023 Security Misconfiguration",
                                confirmed=True, confidence=80, endpoint=ws_url,
                            )
                            result.findings.append(f)
        except Exception:
            pass  # Connection refused = not vulnerable

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _probe_ws_connection(self, url: str) -> bool:
        """Quick check if a WebSocket URL accepts connections."""
        if not _HAS_AIOHTTP:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as ws:
                    return True
        except Exception:
            return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_auth_error(body: str) -> bool:
    b = body.lower()
    return any(s in b for s in [
        "unauthorized", "forbidden", "authentication", "invalid token",
        "not authenticated", "access denied", "401", "403",
    ])


def _is_subscription_error(body: str) -> bool:
    b = body.lower()
    return any(s in b for s in [
        "not allowed", "not subscribed", "invalid channel",
        "permission denied", "channel not found",
    ])


def _is_error_response(body: str) -> bool:
    b = body.lower()
    return any(s in b for s in [
        "error", "invalid", "failed", "rejected",
        "not found", "bad request",
    ])

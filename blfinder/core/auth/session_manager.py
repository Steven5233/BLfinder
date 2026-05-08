"""
BLFinder v3.0 — core/auth/session_manager.py
Session Manager — Token Refresh + CSRF Extraction

Keeps scanner sessions alive across long scans by:
  - Detecting 401/403 responses and triggering token refresh
  - Auto-extracting CSRF tokens from HTML meta tags and response headers
  - Maintaining a live cookie jar across all requests
  - Detecting session fixation vulnerabilities
  - Supporting cookie-based and header-based authentication simultaneously

Without this module, BLFinder v2.1 silently fails when tokens expire
mid-scan — producing false negatives for all subsequent endpoints.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Awaitable
from urllib.parse import urlparse


@dataclass
class SessionState:
    """Current state of an authenticated session."""
    token: str = ""
    csrf_token: str = ""
    cookies: dict = field(default_factory=dict)
    token_acquired_at: float = field(default_factory=time.time)
    token_ttl_seconds: float = 3600.0      # Assumed TTL — updated if seen in response
    refresh_count: int = 0
    is_valid: bool = True
    last_refresh_at: float = 0.0

    # CSRF tracking
    csrf_header_name: str = ""             # e.g. "X-CSRF-Token"
    csrf_cookie_name: str = ""             # e.g. "csrf_token"
    csrf_form_field: str = ""              # e.g. "_token"

    # Session fixation tracking
    session_id_before_auth: str = ""
    session_id_after_auth: str = ""
    fixation_detected: bool = False

    def is_expired(self) -> bool:
        age = time.time() - self.token_acquired_at
        return age >= self.token_ttl_seconds

    def seconds_until_expiry(self) -> float:
        age = time.time() - self.token_acquired_at
        return max(0.0, self.token_ttl_seconds - age)


@dataclass
class RefreshConfig:
    """Configuration for automatic token refresh."""
    # The endpoint to call for token refresh
    refresh_url: str = ""
    refresh_method: str = "POST"
    refresh_body: dict = field(default_factory=dict)     # e.g. {"grant_type": "refresh_token"}
    refresh_token_field: str = "refresh_token"           # Field containing the refresh token
    refresh_token_value: str = ""                        # The actual refresh token

    # How to extract the new access token from the refresh response
    access_token_path: str = "access_token"              # JSON path e.g. "data.access_token"
    token_ttl_path: str = "expires_in"                  # JSON path to TTL in response

    # Re-login credentials (fallback if refresh fails)
    login_url: str = ""
    login_method: str = "POST"
    login_body: dict = field(default_factory=dict)       # e.g. {"email": "...", "password": "..."}
    login_token_path: str = "token"                      # JSON path to token in login response


class SessionManager:
    """
    Manages authentication sessions for the scanner.

    Responsibilities:
    1. Injects the current token into every request
    2. Detects 401 responses and refreshes the token automatically
    3. Extracts CSRF tokens from responses and injects them into subsequent requests
    4. Maintains a cookie jar across all requests
    5. Detects session fixation vulnerabilities

    Usage:
        session_mgr = SessionManager(config)
        await session_mgr.initialize(session)   # aiohttp ClientSession

        # Wrap requests through the session manager:
        headers = session_mgr.inject_auth(headers)
        session_mgr.absorb_response(response_headers, response_body, url)

        # Check if token needs refresh before a request:
        await session_mgr.ensure_valid(request_fn)
    """

    # HTTP headers that commonly carry CSRF tokens
    _CSRF_HEADERS = [
        "x-csrf-token", "x-xsrf-token", "x-csrftoken",
        "x-request-token", "csrf-token", "xsrf-token",
    ]

    # Cookie names that commonly carry CSRF tokens
    _CSRF_COOKIES = [
        "csrf_token", "csrftoken", "xsrf-token", "XSRF-TOKEN",
        "_csrf", "_token", "csrf", "anti-csrf",
    ]

    # HTML meta tag patterns for CSRF tokens
    _CSRF_META_PATTERNS = [
        re.compile(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.I),
        re.compile(r'<meta\s+name=["\']_token["\']\s+content=["\']([^"\']+)["\']', re.I),
        re.compile(r'<meta\s+name=["\']X-CSRF-Token["\']\s+content=["\']([^"\']+)["\']', re.I),
        re.compile(r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']', re.I),
    ]

    # JSON body patterns for CSRF tokens
    _CSRF_JSON_PATTERNS = [
        re.compile(r'"csrf_token"\s*:\s*"([^"]+)"'),
        re.compile(r'"csrfToken"\s*:\s*"([^"]+)"'),
        re.compile(r'"_token"\s*:\s*"([^"]+)"'),
        re.compile(r'"xsrf_token"\s*:\s*"([^"]+)"'),
    ]

    # Patterns to extract tokens from responses
    _TOKEN_JSON_PATHS = [
        ["token"], ["access_token"], ["accessToken"],
        ["data", "token"], ["data", "access_token"],
        ["result", "token"], ["auth", "token"],
        ["user", "token"], ["session", "token"],
    ]

    def __init__(self, config, refresh_config: RefreshConfig | None = None):
        self.config = config
        self.refresh_config = refresh_config
        self.state = SessionState(
            token=config.auth_token,
            cookies=dict(config.cookies),
        )
        self._session = None                    # aiohttp.ClientSession
        self._refresh_lock = asyncio.Lock()     # Prevent concurrent refresh calls
        self._401_count = 0
        self._max_refresh_attempts = 3

    def initialize(self, session):
        """Set the aiohttp ClientSession to use for refresh calls."""
        self._session = session

    # ── Public interface ──────────────────────────────────────────────────────

    def inject_auth(self, headers: dict) -> dict:
        """
        Add authentication headers to an outgoing request.
        Injects Bearer token AND CSRF token if known.
        """
        headers = dict(headers)

        # Bearer token
        if self.state.token:
            headers["Authorization"] = f"Bearer {self.state.token}"

        # CSRF token
        if self.state.csrf_token:
            hdr = self.state.csrf_header_name or "X-CSRF-Token"
            headers[hdr] = self.state.csrf_token

        return headers

    def absorb_response(
        self,
        resp_headers: dict,
        resp_body: str,
        url: str,
        status: int = 200,
    ):
        """
        Process a response to extract cookies, CSRF tokens, and session info.
        Call this after every request to keep the session state current.
        """
        # Absorb cookies from Set-Cookie headers
        self._absorb_cookies(resp_headers, url)

        # Extract CSRF token from various locations
        self._extract_csrf_from_headers(resp_headers)
        self._extract_csrf_from_body(resp_body)
        self._extract_csrf_from_cookies()

        # Update token TTL if seen in response
        self._update_ttl_from_response(resp_body)

        # Track 401 count for refresh triggering
        if status == 401:
            self._401_count += 1

    async def ensure_valid(self, request_fn: Callable[[], Awaitable[tuple]]) -> bool:
        """
        Ensure the current token is valid before making a request.
        If token is expired or we've seen repeated 401s, trigger refresh.

        Args:
            request_fn: The async request callable (for re-login if needed)

        Returns:
            True if session is valid (or was successfully refreshed)
            False if refresh failed and session is invalid
        """
        if not self.state.is_expired() and self._401_count < 2:
            return True

        async with self._refresh_lock:
            # Double-check after acquiring lock
            if not self.state.is_expired() and self._401_count < 2:
                return True

            if self.state.refresh_count >= self._max_refresh_attempts:
                self.state.is_valid = False
                return False

            return await self._do_refresh()

    async def handle_401(self, url: str) -> bool:
        """
        Called when a 401 is received. Attempts refresh and returns True if successful.
        Uses a lock so concurrent requests don't all trigger refresh simultaneously.
        """
        async with self._refresh_lock:
            self._401_count += 1
            if self._401_count > self._max_refresh_attempts:
                return False
            return await self._do_refresh()

    def get_cookies(self) -> dict:
        """Get current cookie jar for injection into requests."""
        return dict(self.state.cookies)

    def detect_session_fixation(
        self,
        pre_login_session_id: str,
        post_login_session_id: str,
    ) -> bool:
        """
        Check if the session ID changed after authentication.
        If it didn't change, this is a session fixation vulnerability.
        """
        self.state.session_id_before_auth = pre_login_session_id
        self.state.session_id_after_auth  = post_login_session_id

        if (
            pre_login_session_id
            and post_login_session_id
            and pre_login_session_id == post_login_session_id
        ):
            self.state.fixation_detected = True
            return True
        return False

    def get_session_summary(self) -> dict:
        """Return a summary of the current session state for debugging/reporting."""
        return {
            "token_set":         bool(self.state.token),
            "csrf_token_set":    bool(self.state.csrf_token),
            "csrf_header":       self.state.csrf_header_name,
            "cookie_count":      len(self.state.cookies),
            "token_age_seconds": time.time() - self.state.token_acquired_at,
            "is_expired":        self.state.is_expired(),
            "refresh_count":     self.state.refresh_count,
            "is_valid":          self.state.is_valid,
            "fixation_detected": self.state.fixation_detected,
            "401_count":         self._401_count,
        }

    # ── CSRF extraction ───────────────────────────────────────────────────────

    def _extract_csrf_from_headers(self, headers: dict):
        """Check response headers for CSRF tokens."""
        for hdr_name in self._CSRF_HEADERS:
            # Case-insensitive header lookup
            for key, val in headers.items():
                if key.lower() == hdr_name:
                    if val and val != self.state.csrf_token:
                        self.state.csrf_token = val
                        self.state.csrf_header_name = key
                    break

    def _extract_csrf_from_body(self, body: str):
        """Check response body (HTML or JSON) for embedded CSRF tokens."""
        if not body:
            return

        # HTML meta tags
        for pattern in self._CSRF_META_PATTERNS:
            m = pattern.search(body)
            if m:
                token = m.group(1).strip()
                if token and len(token) >= 8:
                    self.state.csrf_token = token
                    if not self.state.csrf_header_name:
                        self.state.csrf_header_name = "X-CSRF-Token"
                    return

        # JSON body
        for pattern in self._CSRF_JSON_PATTERNS:
            m = pattern.search(body)
            if m:
                token = m.group(1).strip()
                if token and len(token) >= 8:
                    self.state.csrf_token = token
                    if not self.state.csrf_header_name:
                        self.state.csrf_header_name = "X-CSRF-Token"
                    return

    def _extract_csrf_from_cookies(self):
        """Check cookie jar for CSRF tokens."""
        for cookie_name in self._CSRF_COOKIES:
            if cookie_name in self.state.cookies:
                val = self.state.cookies[cookie_name]
                if val and len(val) >= 8:
                    self.state.csrf_token = val
                    self.state.csrf_cookie_name = cookie_name
                    if not self.state.csrf_header_name:
                        self.state.csrf_header_name = "X-XSRF-TOKEN"
                    break

    def _absorb_cookies(self, headers: dict, url: str):
        """Parse Set-Cookie headers and update the cookie jar."""
        domain = urlparse(url).netloc

        for key, val in headers.items():
            if key.lower() != "set-cookie":
                continue
            # Parse cookie: "name=value; Path=/; HttpOnly; Secure"
            parts = [p.strip() for p in val.split(";")]
            if not parts:
                continue
            name_val = parts[0]
            if "=" not in name_val:
                continue
            name, _, value = name_val.partition("=")
            name  = name.strip()
            value = value.strip()
            if name:
                self.state.cookies[name] = value

    def _update_ttl_from_response(self, body: str):
        """If response contains expires_in or token_expiry, update our TTL tracking."""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in ["expires_in", "token_expiry", "expiry", "ttl"]:
                    if key in data and isinstance(data[key], (int, float)):
                        self.state.token_ttl_seconds = float(data[key])
                        break
        except (json.JSONDecodeError, ValueError):
            pass

    # ── Token refresh ─────────────────────────────────────────────────────────

    async def _do_refresh(self) -> bool:
        """Attempt to refresh the token. Returns True on success."""
        if not self.refresh_config:
            return False

        self.state.refresh_count += 1
        self._401_count = 0  # Reset 401 counter on refresh attempt

        # Try refresh_token grant first
        if self.refresh_config.refresh_url and self.refresh_config.refresh_token_value:
            success = await self._refresh_via_refresh_token()
            if success:
                return True

        # Fall back to full re-login
        if self.refresh_config.login_url and self.refresh_config.login_body:
            return await self._refresh_via_login()

        return False

    async def _refresh_via_refresh_token(self) -> bool:
        """Use a refresh token to get a new access token."""
        if not self._session:
            return False

        rc = self.refresh_config
        body = {
            **rc.refresh_body,
            rc.refresh_token_field: rc.refresh_token_value,
        }

        try:
            async with self._session.request(
                rc.refresh_method,
                rc.refresh_url,
                json=body,
                timeout=__import__("aiohttp").ClientTimeout(total=15),
            ) as resp:
                if resp.status not in (200, 201):
                    return False
                text = await resp.text()
                new_token = _extract_json_value(text, rc.access_token_path)
                if new_token:
                    self.state.token = new_token
                    self.state.token_acquired_at = time.time()
                    self.absorb_response(dict(resp.headers), text, rc.refresh_url, resp.status)
                    return True
        except Exception:
            pass
        return False

    async def _refresh_via_login(self) -> bool:
        """Re-authenticate from scratch using login credentials."""
        if not self._session:
            return False

        rc = self.refresh_config

        try:
            async with self._session.request(
                rc.login_method,
                rc.login_url,
                json=rc.login_body,
                timeout=__import__("aiohttp").ClientTimeout(total=15),
            ) as resp:
                if resp.status not in (200, 201):
                    return False
                text = await resp.text()
                new_token = _extract_json_value(text, rc.login_token_path)
                if new_token:
                    self.state.token = new_token
                    self.state.token_acquired_at = time.time()
                    self.absorb_response(dict(resp.headers), text, rc.login_url, resp.status)
                    return True
        except Exception:
            pass
        return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_json_value(body: str, path: str) -> str:
    """
    Extract a value from a JSON body using a dot-notation path.
    e.g. path="data.access_token" extracts body["data"]["access_token"]
    Returns empty string if not found.
    """
    try:
        data = json.loads(body)
        keys = path.split(".")
        current = data
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return ""
            current = current[key]
        return str(current) if current else ""
    except (json.JSONDecodeError, ValueError, AttributeError):
        return ""

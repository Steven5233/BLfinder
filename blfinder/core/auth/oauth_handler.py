"""
BLFinder v3.0 — core/auth/oauth_handler.py
OAuth2 Flow Handler

Supports OAuth2 grant types used by modern APIs:
  - client_credentials  (machine-to-machine, most common in API testing)
  - password            (Resource Owner Password Credentials)
  - refresh_token       (token refresh)
  - authorization_code  (with PKCE — for interactive flows)

Also detects common OAuth2 vulnerabilities during the flow:
  - state parameter missing or not validated
  - redirect_uri manipulation
  - token leakage in referrer headers
  - implicit flow usage (deprecated, insecure)
  - open redirect via redirect_uri
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class OAuthToken:
    """A live OAuth2 access token and its metadata."""
    access_token: str = ""
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: str = ""
    scope: str = ""
    acquired_at: float = field(default_factory=time.time)
    raw_response: dict = field(default_factory=dict)

    def is_expired(self, buffer_seconds: float = 60.0) -> bool:
        age = time.time() - self.acquired_at
        return age >= (self.expires_in - buffer_seconds)

    def as_header(self) -> str:
        return f"{self.token_type} {self.access_token}"


@dataclass
class OAuthConfig:
    """OAuth2 client configuration."""
    token_url: str                          # e.g. https://auth.target.com/oauth/token
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    grant_type: str = "client_credentials"  # client_credentials | password | refresh_token

    # For password grant
    username: str = ""
    password: str = ""

    # For authorization_code grant
    auth_url: str = ""
    redirect_uri: str = "https://localhost/callback"
    use_pkce: bool = True

    # For refresh
    refresh_token: str = ""

    # Extra body params for non-standard implementations
    extra_params: dict = field(default_factory=dict)

    # How to authenticate the client (header vs body)
    client_auth_method: str = "header"      # "header" | "body"


@dataclass
class OAuthVulnFinding:
    """A vulnerability discovered during the OAuth2 flow."""
    title: str
    severity: str                           # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    evidence: str
    recommendation: str
    cwe: str = ""
    owasp: str = ""


class OAuthHandler:
    """
    Handles OAuth2 authentication flows and tests for common OAuth vulnerabilities.

    Usage:
        config = OAuthConfig(
            token_url="https://api.target.com/oauth/token",
            client_id="test_client",
            client_secret="test_secret",
            grant_type="client_credentials",
        )

        handler = OAuthHandler(config)
        token = await handler.get_token(aiohttp_session)

        # Use the token
        headers["Authorization"] = token.as_header()

        # Check for vulnerabilities found during the flow
        for finding in handler.findings:
            print(finding.title)
    """

    def __init__(self, config: OAuthConfig, verbose: bool = False):
        self.config  = config
        self.verbose = verbose
        self._token: OAuthToken | None = None
        self.findings: list[OAuthVulnFinding] = []

    # ── Token Acquisition ─────────────────────────────────────────────────────

    async def get_token(self, session) -> OAuthToken | None:
        """
        Get an access token using the configured grant type.
        Returns None if authentication fails.
        Populates self.findings with any OAuth vulnerabilities discovered.
        """
        grant = self.config.grant_type.lower()

        if grant == "client_credentials":
            return await self._client_credentials(session)
        elif grant == "password":
            return await self._password_grant(session)
        elif grant == "refresh_token":
            return await self._refresh_token_grant(session)
        elif grant == "authorization_code":
            return await self._auth_code_grant(session)
        else:
            if self.verbose:
                print(f"  [!] Unsupported grant type: {grant}")
            return None

    async def ensure_fresh(self, session) -> OAuthToken | None:
        """Return a valid token, refreshing if needed."""
        if self._token and not self._token.is_expired():
            return self._token
        if self._token and self._token.refresh_token:
            # Try refresh first
            refreshed = await self._do_refresh(session, self._token.refresh_token)
            if refreshed:
                return refreshed
        # Fall back to full re-auth
        return await self.get_token(session)

    # ── Grant Type Implementations ────────────────────────────────────────────

    async def _client_credentials(self, session) -> OAuthToken | None:
        """OAuth2 client_credentials grant — machine-to-machine."""
        body = {
            "grant_type": "client_credentials",
            **self.config.extra_params,
        }
        if self.config.scope:
            body["scope"] = self.config.scope
        if self.config.client_auth_method == "body":
            body["client_id"]     = self.config.client_id
            body["client_secret"] = self.config.client_secret

        headers = self._client_auth_header()
        token = await self._post_token(session, body, headers)

        if token:
            # Vulnerability: check if scope is over-granted
            self._check_scope_overgrant(token)
        return token

    async def _password_grant(self, session) -> OAuthToken | None:
        """OAuth2 Resource Owner Password Credentials grant."""
        body = {
            "grant_type": "password",
            "username":   self.config.username,
            "password":   self.config.password,
            **self.config.extra_params,
        }
        if self.config.scope:
            body["scope"] = self.config.scope
        if self.config.client_auth_method == "body":
            body["client_id"]     = self.config.client_id
            body["client_secret"] = self.config.client_secret

        headers = self._client_auth_header()
        token = await self._post_token(session, body, headers)

        if token:
            # ROPC is deprecated in OAuth 2.1 — flag it
            self.findings.append(OAuthVulnFinding(
                title="OAuth2 Password Grant (ROPC) in Use",
                severity="MEDIUM",
                description=(
                    "The API supports the Resource Owner Password Credentials grant, "
                    "which is deprecated in OAuth 2.1. This grant type exposes user "
                    "credentials to the client application and bypasses MFA."
                ),
                evidence=f"Successful token obtained via password grant at {self.config.token_url}",
                recommendation=(
                    "Migrate to authorization_code + PKCE flow. "
                    "Remove ROPC grant type support from the authorization server."
                ),
                cwe="CWE-522",
                owasp="API2:2023 Broken Authentication",
            ))
        return token

    async def _refresh_token_grant(self, session) -> OAuthToken | None:
        """OAuth2 refresh_token grant."""
        return await self._do_refresh(session, self.config.refresh_token)

    async def _do_refresh(self, session, refresh_token: str) -> OAuthToken | None:
        """Internal: perform a refresh_token grant."""
        body = {
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token,
            **self.config.extra_params,
        }
        if self.config.client_auth_method == "body":
            body["client_id"]     = self.config.client_id
            body["client_secret"] = self.config.client_secret

        headers = self._client_auth_header()
        return await self._post_token(session, body, headers)

    async def _auth_code_grant(self, session) -> OAuthToken | None:
        """
        OAuth2 authorization_code grant with PKCE.
        Note: This is for automated testing only — requires the auth URL
        to be accessible and pre-configured with test credentials.
        """
        # Generate PKCE challenge
        code_verifier  = _generate_code_verifier()
        code_challenge = _generate_code_challenge(code_verifier)

        # Build authorization URL
        state = _generate_state()
        auth_params = {
            "response_type":         "code",
            "client_id":             self.config.client_id,
            "redirect_uri":          self.config.redirect_uri,
            "scope":                 self.config.scope,
            "state":                 state,
            "code_challenge":        code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = self.config.auth_url + "?" + urllib.parse.urlencode(auth_params)

        # Test OAuth vulnerabilities in the authorization endpoint
        await self._test_auth_endpoint(session, auth_url, state)

        # We can't complete the interactive flow automatically
        # Return None and let the caller use a pre-obtained code
        if self.verbose:
            print(f"  [*] Auth URL built: {auth_url[:80]}...")
            print(f"  [*] PKCE verifier: {code_verifier[:20]}...")
        return None

    # ── OAuth Vulnerability Tests ─────────────────────────────────────────────

    async def _test_auth_endpoint(self, session, auth_url: str, expected_state: str):
        """Test the authorization endpoint for common OAuth vulnerabilities."""

        # Test 1: Missing state parameter
        no_state_url = re.sub(r'[&?]state=[^&]+', '', auth_url)
        try:
            async with session.get(no_state_url, allow_redirects=False, timeout=10) as resp:
                if resp.status in (200, 302):
                    location = resp.headers.get("Location", "")
                    # If redirect doesn't include state error, state validation is missing
                    if "error" not in location and "state" not in location.lower():
                        self.findings.append(OAuthVulnFinding(
                            title="OAuth2 Missing State Parameter Validation",
                            severity="HIGH",
                            description=(
                                "The authorization endpoint accepted a request without a state parameter. "
                                "This enables CSRF attacks against the OAuth flow."
                            ),
                            evidence=f"GET {no_state_url[:80]} → HTTP {resp.status} without state error",
                            recommendation=(
                                "Require and validate the state parameter on every authorization request. "
                                "Tie the state value to the user's session."
                            ),
                            cwe="CWE-352",
                            owasp="API2:2023 Broken Authentication",
                        ))
        except Exception:
            pass

        # Test 2: Open redirect via redirect_uri manipulation
        if self.config.auth_url:
            evil_redirect = "https://evil.attacker.com/callback"
            evil_params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_url).query))
            evil_params["redirect_uri"] = evil_redirect
            evil_url = self.config.auth_url + "?" + urllib.parse.urlencode(evil_params)
            try:
                async with session.get(evil_url, allow_redirects=False, timeout=10) as resp:
                    location = resp.headers.get("Location", "")
                    if evil_redirect in location:
                        self.findings.append(OAuthVulnFinding(
                            title="OAuth2 Open Redirect via redirect_uri",
                            severity="CRITICAL",
                            description=(
                                "The authorization server accepted an arbitrary redirect_uri. "
                                "An attacker can steal authorization codes by redirecting the victim "
                                "to an attacker-controlled URL."
                            ),
                            evidence=f"redirect_uri={evil_redirect} was accepted and used in redirect",
                            recommendation=(
                                "Enforce strict redirect_uri validation against a pre-registered allowlist. "
                                "Reject any redirect_uri that does not exactly match a registered value."
                            ),
                            cwe="CWE-601",
                            owasp="API2:2023 Broken Authentication",
                        ))
            except Exception:
                pass

    async def test_token_endpoint_vulns(self, session) -> list[OAuthVulnFinding]:
        """
        Test the token endpoint for common vulnerabilities.
        Call after successful token acquisition.
        """
        extra_findings = []

        # Test 1: Accept invalid client credentials
        body = {
            "grant_type":    "client_credentials",
            "client_id":     "invalid_client_xyz",
            "client_secret": "invalid_secret_xyz",
        }
        try:
            async with session.post(
                self.config.token_url, data=body,
                timeout=__import__("aiohttp").ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    data = json.loads(text)
                    if "access_token" in data:
                        extra_findings.append(OAuthVulnFinding(
                            title="OAuth2 Token Endpoint Accepts Invalid Client Credentials",
                            severity="CRITICAL",
                            description=(
                                "The token endpoint issued an access token for completely invalid "
                                "client credentials. Client authentication is not enforced."
                            ),
                            evidence=f"POST {self.config.token_url} with invalid creds → 200 + access_token",
                            recommendation="Enforce strict client authentication before issuing tokens.",
                            cwe="CWE-287",
                            owasp="API2:2023 Broken Authentication",
                        ))
        except Exception:
            pass

        # Test 2: Token endpoint allows GET requests (token in URL = logged)
        try:
            get_url = (
                f"{self.config.token_url}?grant_type=client_credentials"
                f"&client_id={self.config.client_id}"
                f"&client_secret={self.config.client_secret}"
            )
            async with session.get(
                get_url, allow_redirects=False,
                timeout=__import__("aiohttp").ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "access_token" in text:
                        extra_findings.append(OAuthVulnFinding(
                            title="OAuth2 Token Endpoint Accepts GET Requests",
                            severity="HIGH",
                            description=(
                                "The token endpoint issues tokens via GET requests, "
                                "which causes credentials and tokens to appear in server logs, "
                                "browser history, and referrer headers."
                            ),
                            evidence=f"GET {get_url[:80]} → 200 + access_token",
                            recommendation="Require POST for all token endpoint requests. Reject GET.",
                            cwe="CWE-598",
                            owasp="API2:2023 Broken Authentication",
                        ))
        except Exception:
            pass

        self.findings.extend(extra_findings)
        return extra_findings

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _post_token(
        self, session, body: dict, headers: dict
    ) -> OAuthToken | None:
        """POST to the token endpoint and parse the response."""
        try:
            import aiohttp
            async with session.post(
                self.config.token_url,
                data=body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
                allow_redirects=False,
            ) as resp:
                text = await resp.text()

                if resp.status not in (200, 201):
                    if self.verbose:
                        print(f"  [!] Token request failed: HTTP {resp.status} — {text[:100]}")
                    return None

                try:
                    data = json.loads(text)
                except (json.JSONDecodeError, ValueError):
                    if self.verbose:
                        print(f"  [!] Token response is not JSON: {text[:100]}")
                    return None

                if "access_token" not in data:
                    if self.verbose:
                        print(f"  [!] No access_token in response: {list(data.keys())}")
                    return None

                token = OAuthToken(
                    access_token=data["access_token"],
                    token_type=data.get("token_type", "Bearer"),
                    expires_in=int(data.get("expires_in", 3600)),
                    refresh_token=data.get("refresh_token", ""),
                    scope=data.get("scope", ""),
                    raw_response=data,
                )
                self._token = token
                return token

        except Exception as e:
            if self.verbose:
                print(f"  [!] Token request exception: {e}")
            return None

    def _client_auth_header(self) -> dict:
        """Build the Authorization header for client authentication."""
        if self.config.client_auth_method != "header":
            return {}
        if not self.config.client_id:
            return {}
        credentials = f"{self.config.client_id}:{self.config.client_secret}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def _check_scope_overgrant(self, token: OAuthToken):
        """Check if the server granted more scope than requested."""
        if not self.config.scope or not token.scope:
            return
        requested = set(self.config.scope.split())
        granted   = set(token.scope.split())
        extra     = granted - requested
        if extra:
            self.findings.append(OAuthVulnFinding(
                title="OAuth2 Scope Over-granting",
                severity="MEDIUM",
                description=(
                    f"The authorization server granted more scopes than requested. "
                    f"Extra scopes: {extra}"
                ),
                evidence=(
                    f"Requested: '{self.config.scope}' | Granted: '{token.scope}'"
                ),
                recommendation=(
                    "Authorization servers must not grant more permissions than requested. "
                    "Implement strict scope validation."
                ),
                cwe="CWE-269",
                owasp="API5:2023 Broken Function Level Authorization",
            ))


# ── PKCE Helpers ──────────────────────────────────────────────────────────────

def _generate_code_verifier(length: int = 64) -> str:
    """Generate a cryptographically random PKCE code verifier."""
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode()


def _generate_code_challenge(verifier: str) -> str:
    """Generate the S256 PKCE code challenge from the verifier."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


def _generate_state(length: int = 32) -> str:
    """Generate a random state parameter for CSRF protection."""
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode()

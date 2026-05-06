"""
BLFinder - Business Logic Flaw Detection Engine
Core Scanner Module
"""

import asyncio
import aiohttp
import json
import time
import re
import hashlib
import copy
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    title: str
    severity: Severity
    category: str
    description: str
    request: dict
    response_summary: str
    evidence: str
    recommendation: str
    cwe: str = ""
    cvss: float = 0.0


@dataclass
class ScanConfig:
    target_url: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    auth_token: str = ""
    second_user_token: str = ""  # For privilege escalation checks
    timeout: int = 15
    rate_limit: float = 0.5  # seconds between requests
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: str = ""
    wordlist_params: list = field(default_factory=list)
    custom_payloads: dict = field(default_factory=dict)


class BLFScanner:
    """
    Business Logic Flaw Scanner
    Detects flaws that automated scanners miss:
    - Price/quantity manipulation
    - Workflow bypass
    - Privilege escalation via parameter tampering
    - Race conditions
    - IDOR via indirect references
    - State machine abuse
    - Mass assignment
    - Time-based logic flaws
    - Negative value exploits
    - Coupon/discount stacking
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: list[Finding] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_log: list[dict] = []
        self.base_responses: dict = {}

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._build_headers(),
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
        }
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        headers.update(self.config.headers)
        return headers

    async def _request(self, method: str, url: str, **kwargs) -> tuple[int, dict, str, float]:
        """Make a request and return (status, headers, body, elapsed)"""
        start = time.time()
        try:
            async with self.session.request(
                method, url,
                cookies=self.config.cookies,
                allow_redirects=True,
                max_redirects=self.config.max_redirects,
                **kwargs
            ) as resp:
                elapsed = time.time() - start
                body = await resp.text()
                log_entry = {
                    "method": method,
                    "url": url,
                    "status": resp.status,
                    "elapsed": round(elapsed, 3),
                    "kwargs": str(kwargs)[:500]
                }
                self.request_log.append(log_entry)
                await asyncio.sleep(self.config.rate_limit)
                return resp.status, dict(resp.headers), body, elapsed
        except asyncio.TimeoutError:
            return 0, {}, "TIMEOUT", time.time() - start
        except Exception as e:
            return 0, {}, f"ERROR: {str(e)}", time.time() - start

    def _try_parse_json(self, body: str) -> dict:
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _hash_response(self, body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    async def run_all_modules(self, endpoints: list[dict]) -> list[Finding]:
        """
        Run all detection modules against a list of endpoint definitions.
        Each endpoint: {"method": "POST", "url": "/api/checkout", "body": {...}}
        """
        print(f"[*] Starting BLFinder scan against {self.config.target_url}")
        print(f"[*] {len(endpoints)} endpoints loaded\n")

        tasks = []
        for ep in endpoints:
            url = urljoin(self.config.target_url, ep.get("url", ""))
            method = ep.get("method", "GET").upper()
            body = ep.get("body", {})
            params = ep.get("params", {})
            ep_type = ep.get("type", "generic")

            tasks.append(self._run_endpoint_checks(url, method, body, params, ep_type))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                self.findings.extend(r)

        return self.findings

    async def _run_endpoint_checks(self, url, method, body, params, ep_type) -> list[Finding]:
        findings = []

        # Get baseline response
        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body if body else None,
            params=params if params else None
        )
        self.base_responses[url] = {
            "status": status, "body": base_body,
            "hash": self._hash_response(base_body), "elapsed": elapsed
        }

        # Run all detection modules
        checks = [
            self._check_price_manipulation(url, method, body, params, status, base_body),
            self._check_quantity_negative(url, method, body, params, status, base_body),
            self._check_workflow_bypass(url, method, body, params, status, base_body),
            self._check_mass_assignment(url, method, body, params, status, base_body),
            self._check_idor_parameter_pollution(url, method, body, params, status, base_body),
            self._check_privilege_escalation(url, method, body, params, status, base_body),
            self._check_coupon_stacking(url, method, body, params, status, base_body),
            self._check_time_logic_bypass(url, method, body, params, status, base_body),
            self._check_integer_overflow(url, method, body, params, status, base_body),
            self._check_hidden_parameter_disclosure(url, method, body, params, status, base_body),
            self._check_state_machine_abuse(url, method, body, params, status, base_body),
            self._check_concurrent_requests(url, method, body, params, status, base_body),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 1: Price Manipulation
    # ─────────────────────────────────────────────────────────────
    async def _check_price_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        price_keys = ["price", "amount", "total", "cost", "fee", "charge", "unit_price",
                      "subtotal", "discount_amount", "payment_amount", "order_total"]

        for key in price_keys:
            if key in body:
                original = body[key]
                for tampered in [0, 0.01, -1, -100, 0.00001, "0", "0.00", 1]:
                    test_body = {**body, key: tampered}
                    status, headers, resp_body, _ = await self._request(
                        method, url, json=test_body
                    )
                    if status in (200, 201) and self._response_indicates_success(resp_body):
                        findings.append(Finding(
                            title=f"Price Manipulation via `{key}` parameter",
                            severity=Severity.CRITICAL,
                            category="Business Logic - Price Manipulation",
                            description=(
                                f"The `{key}` field accepted tampered value `{tampered}` "
                                f"(original: `{original}`) and the server returned a success response. "
                                "This could allow purchasing items at arbitrary prices."
                            ),
                            request={"method": method, "url": url, "body": test_body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"Original value: {original} → Tampered: {tampered} → Status: {status}",
                            recommendation="Prices must be computed server-side from a trusted product catalog. Never trust client-submitted price values.",
                            cwe="CWE-20",
                            cvss=9.1
                        ))
                        break  # One confirmed finding per key is enough
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 2: Negative Quantity / Value Exploits
    # ─────────────────────────────────────────────────────────────
    async def _check_quantity_negative(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        qty_keys = ["quantity", "qty", "count", "units", "items", "amount", "number"]

        for key in qty_keys:
            if key in body:
                original = body[key]
                for tampered in [-1, -100, -9999, 0, -0.5]:
                    test_body = {**body, key: tampered}
                    status, headers, resp_body, _ = await self._request(
                        method, url, json=test_body
                    )
                    if status in (200, 201) and self._response_indicates_success(resp_body):
                        # Check if balance/credit increased (negative purchase = refund)
                        findings.append(Finding(
                            title=f"Negative Quantity Exploit via `{key}`",
                            severity=Severity.CRITICAL,
                            category="Business Logic - Negative Value",
                            description=(
                                f"Submitting a negative value ({tampered}) for `{key}` was accepted. "
                                "This may allow reversing charges, gaining credits, or withdrawing funds."
                            ),
                            request={"method": method, "url": url, "body": test_body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"qty={tampered} accepted with HTTP {status}",
                            recommendation="Enforce server-side minimum quantity validation (qty >= 1). Reject or sanitize negative/zero values.",
                            cwe="CWE-20",
                            cvss=9.3
                        ))
                        break
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 3: Workflow / Step Bypass
    # ─────────────────────────────────────────────────────────────
    async def _check_workflow_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        """Try to skip workflow steps by accessing later-step endpoints directly."""
        findings = []
        step_patterns = [
            (r"/step[_-]?(\d+)", "step"),
            (r"/stage[_-]?(\d+)", "stage"),
            (r"/page[_-]?(\d+)", "page"),
            (r"/checkout/(\w+)", "checkout"),
        ]

        parsed = urlparse(url)
        path = parsed.path

        for pattern, label in step_patterns:
            match = re.search(pattern, path, re.IGNORECASE)
            if match:
                current_step = match.group(1)
                # Try jumping ahead 2 steps
                try:
                    next_step = str(int(current_step) + 2)
                    new_path = re.sub(pattern, match.group(0).replace(current_step, next_step), path, flags=re.IGNORECASE)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    status, headers, resp_body, _ = await self._request(method, new_url, json=body)

                    if status in (200, 201):
                        findings.append(Finding(
                            title=f"Workflow Step Bypass — jumped from {label} {current_step} to {next_step}",
                            severity=Severity.HIGH,
                            category="Business Logic - Workflow Bypass",
                            description=f"Directly accessing {label} {next_step} without completing {label} {current_step} returned HTTP {status}. Required intermediate steps may be skipped.",
                            request={"method": method, "url": new_url, "body": body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"Skip from {current_step} to {next_step} succeeded",
                            recommendation="Enforce sequential step validation server-side using session state. Each step must verify prior steps completed successfully.",
                            cwe="CWE-284",
                            cvss=7.5
                        ))
                except (ValueError, TypeError):
                    pass

        # Also try removing required step tokens from body
        step_token_keys = ["step", "stage", "workflow_token", "checkout_token", "flow_id", "step_id"]
        for key in step_token_keys:
            if key in body:
                test_body = {k: v for k, v in body.items() if k != key}
                status, headers, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body):
                    findings.append(Finding(
                        title=f"Workflow Token Omission — `{key}` not required",
                        severity=Severity.HIGH,
                        category="Business Logic - Workflow Bypass",
                        description=f"Removing the `{key}` field from the request still returned a success response, suggesting workflow state is not properly validated.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"Missing `{key}` → still HTTP {status}",
                        recommendation="Validate workflow tokens server-side. Tie each token to a session and step sequence.",
                        cwe="CWE-284",
                        cvss=7.2
                    ))
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 4: Mass Assignment
    # ─────────────────────────────────────────────────────────────
    async def _check_mass_assignment(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        privileged_keys = [
            "is_admin", "admin", "role", "roles", "permissions", "is_verified",
            "verified", "is_premium", "premium", "subscription", "plan",
            "credits", "balance", "discount", "is_staff", "group",
            "account_type", "tier", "membership", "vip", "approved",
            "email_verified", "phone_verified", "kyc_verified"
        ]

        for key in privileged_keys:
            test_body = {**body, key: True}
            status, headers, resp_body, _ = await self._request(method, url, json=test_body)

            # Check if the injected field appears in the response
            if status in (200, 201):
                resp_data = self._try_parse_json(resp_body)
                if key in resp_data and resp_data.get(key) in (True, "true", 1, "admin", "premium"):
                    findings.append(Finding(
                        title=f"Mass Assignment — `{key}` accepted and reflected",
                        severity=Severity.CRITICAL,
                        category="Business Logic - Mass Assignment",
                        description=f"Injecting `{key}: true` into the request body was accepted and the value was reflected in the response. This may allow privilege escalation.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}, `{key}` = {resp_data.get(key)}",
                        evidence=f"Injected `{key}=true` → response shows `{key}={resp_data.get(key)}`",
                        recommendation="Use an explicit allowlist of fields that can be set by users. Never pass raw request bodies to ORM update methods.",
                        cwe="CWE-915",
                        cvss=9.8
                    ))

        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 5: IDOR via Parameter Pollution
    # ─────────────────────────────────────────────────────────────
    async def _check_idor_parameter_pollution(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        id_keys = ["id", "user_id", "account_id", "order_id", "invoice_id",
                   "payment_id", "subscription_id", "profile_id", "customer_id"]

        parsed = urlparse(url)
        path_ids = re.findall(r"/(\d+)", parsed.path)

        # Test path-based IDs
        for pid in path_ids:
            alt_id = str(int(pid) - 1) if int(pid) > 1 else str(int(pid) + 1)
            new_url = url.replace(f"/{pid}", f"/{alt_id}", 1)
            status, headers, resp_body, _ = await self._request(method, new_url, json=body)

            if status == 200 and resp_body != base_body:
                findings.append(Finding(
                    title=f"Potential IDOR — path ID {pid} → {alt_id} returned different data",
                    severity=Severity.HIGH,
                    category="Business Logic - IDOR",
                    description=f"Changing the path ID from {pid} to {alt_id} returned a different 200 response, suggesting unauthorized access to another resource.",
                    request={"method": method, "url": new_url, "body": body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"ID {pid} vs ID {alt_id}: different responses",
                    recommendation="Verify object ownership on every request. Check that the authenticated user owns the resource being accessed.",
                    cwe="CWE-639",
                    cvss=8.1
                ))

        # Test body-based IDs with second user context
        if self.config.second_user_token:
            for key in id_keys:
                if key in body:
                    # Try accessing with user2's token but user1's ID
                    headers_u2 = {**self._build_headers(), "Authorization": f"Bearer {self.config.second_user_token}"}
                    status, _, resp_body, _ = await self._request(
                        method, url, json=body, headers=headers_u2
                    )
                    if status == 200:
                        findings.append(Finding(
                            title=f"Cross-User IDOR via `{key}` — User 2 accessing User 1 resource",
                            severity=Severity.CRITICAL,
                            category="Business Logic - IDOR",
                            description=f"User 2's token can access the resource identified by User 1's `{key}`. Full IDOR confirmed.",
                            request={"method": method, "url": url, "body": body},
                            response_summary=f"HTTP {status} with different user token",
                            evidence=f"User 2 token + User 1 {key} → HTTP {status}",
                            recommendation="Enforce ownership checks tied to authenticated session, not just the ID in the request.",
                            cwe="CWE-639",
                            cvss=9.1
                        ))
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 6: Horizontal / Vertical Privilege Escalation
    # ─────────────────────────────────────────────────────────────
    async def _check_privilege_escalation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        admin_paths = [
            "/admin", "/api/admin", "/manage", "/dashboard/admin",
            "/api/users/all", "/api/roles", "/api/permissions",
            "/internal", "/api/internal", "/superuser", "/api/superadmin"
        ]
        parsed = urlparse(url)

        for admin_path in admin_paths:
            test_url = urlunparse(parsed._replace(path=admin_path))
            status, headers, resp_body, _ = await self._request("GET", test_url)
            if status == 200:
                findings.append(Finding(
                    title=f"Unauthorized Admin Endpoint Access: {admin_path}",
                    severity=Severity.CRITICAL,
                    category="Business Logic - Privilege Escalation",
                    description=f"The admin endpoint {admin_path} returned HTTP 200 using the current user's token. This may expose admin functionality.",
                    request={"method": "GET", "url": test_url},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"GET {test_url} → {status}",
                    recommendation="Enforce role-based access control (RBAC) on all admin endpoints. Use middleware that checks role before handler execution.",
                    cwe="CWE-269",
                    cvss=9.8
                ))

        # Try HTTP method override for privilege escalation
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Method-Override": "PUT"},
            {"_method": "PATCH"},
        ]
        for oh in override_headers:
            status, _, resp_body, _ = await self._request("POST", url, json=body, headers=oh)
            if status not in (405, 404, 400):
                findings.append(Finding(
                    title=f"HTTP Method Override Accepted",
                    severity=Severity.MEDIUM,
                    category="Business Logic - Method Override",
                    description=f"The header `{list(oh.keys())[0]}` was accepted by the server, potentially allowing method spoofing.",
                    request={"method": "POST", "url": url, "headers": oh},
                    response_summary=f"HTTP {status}",
                    evidence=f"Override header {oh} → HTTP {status}",
                    recommendation="Disable HTTP method override headers unless explicitly needed. Validate actual HTTP method, not override headers.",
                    cwe="CWE-436",
                    cvss=5.3
                ))
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 7: Coupon / Discount Stacking & Reuse
    # ─────────────────────────────────────────────────────────────
    async def _check_coupon_stacking(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        coupon_keys = ["coupon", "coupon_code", "promo_code", "discount_code",
                       "voucher", "voucher_code", "referral_code", "promo"]

        for key in coupon_keys:
            if key in body:
                original_code = body[key]

                # Test 1: Apply same coupon twice
                test_body = {**body, key: [original_code, original_code]}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body):
                    findings.append(Finding(
                        title=f"Coupon Stacking — duplicate `{key}` in array",
                        severity=Severity.HIGH,
                        category="Business Logic - Coupon Abuse",
                        description=f"Passing the same coupon code twice as an array was accepted. Double discount may be applied.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status} — {resp_body[:200]}",
                        evidence=f"Array with duplicate coupon → HTTP {status}",
                        recommendation="Validate that coupon codes are unique per order. Normalize input to prevent array/string type confusion.",
                        cwe="CWE-20",
                        cvss=6.5
                    ))

                # Test 2: Coupon type confusion (string → array)
                test_body2 = {**body, key: [original_code]}
                status2, _, resp_body2, _ = await self._request(method, url, json=test_body2)
                base_discount = self._extract_discount(base_body)
                new_discount = self._extract_discount(resp_body2)
                if status2 == 200 and new_discount and base_discount and new_discount > base_discount:
                    findings.append(Finding(
                        title=f"Coupon Type Confusion — `{key}` array yields larger discount",
                        severity=Severity.HIGH,
                        category="Business Logic - Coupon Abuse",
                        description=f"Passing coupon as an array instead of string resulted in a larger discount ({new_discount} vs {base_discount}).",
                        request={"method": method, "url": url, "body": test_body2},
                        response_summary=f"HTTP {status2}",
                        evidence=f"String discount: {base_discount} → Array discount: {new_discount}",
                        recommendation="Strictly type-validate coupon inputs. Reject arrays where a string is expected.",
                        cwe="CWE-843",
                        cvss=7.2
                    ))
        return findings

    def _extract_discount(self, body: str) -> float:
        try:
            data = json.loads(body)
            for key in ["discount", "discount_amount", "savings", "promo_discount"]:
                if key in data:
                    return float(data[key])
        except Exception:
            pass
        return 0.0

    # ─────────────────────────────────────────────────────────────
    # MODULE 8: Time-based Logic Bypass
    # ─────────────────────────────────────────────────────────────
    async def _check_time_logic_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        time_keys = ["date", "expiry", "expiry_date", "expires_at", "valid_until",
                     "timestamp", "created_at", "booking_date", "start_date", "end_date"]

        for key in time_keys:
            if key in body:
                # Try far-future date
                test_body = {**body, key: "2099-12-31T23:59:59Z"}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body):
                    findings.append(Finding(
                        title=f"Time-based Logic Bypass — `{key}` accepts arbitrary future dates",
                        severity=Severity.HIGH,
                        category="Business Logic - Time Bypass",
                        description=f"Setting `{key}` to a far-future value was accepted, potentially bypassing expiry or time-gated functionality.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"`{key}` = 2099-12-31 accepted",
                        recommendation="Validate all date/time fields server-side. Do not trust client-supplied timestamps for security decisions.",
                        cwe="CWE-20",
                        cvss=7.3
                    ))

        # Check header-based time manipulation
        time_headers = {"X-Custom-Date": "Mon, 01 Jan 2099 00:00:00 GMT", "X-Forwarded-Date": "2099-01-01"}
        status, _, resp_body, _ = await self._request(method, url, json=body, headers=time_headers)
        if status in (200, 201) and resp_body != base_body:
            findings.append(Finding(
                title="Time Manipulation via Custom Date Headers",
                severity=Severity.MEDIUM,
                category="Business Logic - Time Bypass",
                description="Custom date headers altered the response, suggesting the server trusts client-supplied time headers for logic decisions.",
                request={"method": method, "url": url, "headers": time_headers},
                response_summary=f"HTTP {status}",
                evidence="Response differed with X-Custom-Date header",
                recommendation="Never use client-supplied time headers for business logic. Use server-side time.",
                cwe="CWE-807",
                cvss=5.5
            ))
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 9: Integer Overflow / Extreme Values
    # ─────────────────────────────────────────────────────────────
    async def _check_integer_overflow(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        numeric_keys = [k for k, v in body.items() if isinstance(v, (int, float))]
        extreme_values = [2**31 - 1, 2**31, 2**32, 2**63 - 1, -2**31, 9999999999, 1e308]

        for key in numeric_keys:
            for val in extreme_values:
                test_body = {**body, key: val}
                try:
                    status, _, resp_body, _ = await self._request(method, url, json=test_body)
                    if status in (200, 201):
                        data = self._try_parse_json(resp_body)
                        # Check for negative values in response (overflow symptom)
                        for rkey, rval in data.items():
                            if isinstance(rval, (int, float)) and rval < 0:
                                findings.append(Finding(
                                    title=f"Integer Overflow — `{key}` = {val} caused negative `{rkey}` in response",
                                    severity=Severity.HIGH,
                                    category="Business Logic - Integer Overflow",
                                    description=f"Setting `{key}` to {val} caused `{rkey}` to become negative ({rval}) in the response, indicating an integer overflow.",
                                    request={"method": method, "url": url, "body": test_body},
                                    response_summary=f"HTTP {status}, {rkey}={rval}",
                                    evidence=f"Input {key}={val} → response {rkey}={rval}",
                                    recommendation="Use safe integer libraries. Validate numeric ranges on input. Use 64-bit integers where large numbers are expected.",
                                    cwe="CWE-190",
                                    cvss=7.8
                                ))
                except Exception:
                    pass
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 10: Hidden Parameter Disclosure
    # ─────────────────────────────────────────────────────────────
    async def _check_hidden_parameter_disclosure(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        # Try common hidden debug/internal params
        probe_params = [
            "debug", "test", "admin", "internal", "verbose", "dev",
            "trace", "showsql", "sql", "dump", "export", "raw",
            "format=json", "format=xml", "callback=test", "jsonp=test",
            "pretty=1", "full=1", "include_deleted=1", "show_all=1",
            "_debug=1", "XDEBUG_SESSION_START=1"
        ]

        for param in probe_params:
            if "=" in param:
                k, v = param.split("=", 1)
                test_params = {**params, k: v}
            else:
                test_params = {**params, param: "1"}

            status, headers, resp_body, elapsed = await self._request(
                "GET", url, params=test_params
            )

            if status == 200 and len(resp_body) > len(base_body) * 1.2:
                findings.append(Finding(
                    title=f"Hidden Parameter `{param}` Discloses Extra Data",
                    severity=Severity.MEDIUM,
                    category="Business Logic - Information Disclosure",
                    description=f"Adding `{param}` to the request returned a significantly larger response, suggesting hidden debug or verbose mode was activated.",
                    request={"method": "GET", "url": url, "params": test_params},
                    response_summary=f"HTTP {status}, len={len(resp_body)} vs baseline {len(base_body)}",
                    evidence=f"Response size: baseline={len(base_body)} → with param={len(resp_body)}",
                    recommendation="Remove debug/verbose parameters from production. Use environment flags server-side, not request parameters.",
                    cwe="CWE-200",
                    cvss=5.3
                ))
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 11: State Machine Abuse
    # ─────────────────────────────────────────────────────────────
    async def _check_state_machine_abuse(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        state_keys = ["status", "state", "order_status", "payment_status",
                      "verification_status", "kyc_status", "approval_status"]
        valid_states = {
            "status": ["completed", "approved", "verified", "active", "paid", "shipped"],
            "state": ["completed", "approved", "verified", "active"],
            "order_status": ["completed", "shipped", "delivered"],
            "payment_status": ["paid", "completed", "cleared"],
            "verification_status": ["verified", "approved"],
        }

        for key in state_keys:
            if key in body:
                target_states = valid_states.get(key, ["completed", "approved", "verified"])
                for state in target_states:
                    test_body = {**body, key: state}
                    status, _, resp_body, _ = await self._request(method, url, json=test_body)
                    if status in (200, 201) and self._response_indicates_success(resp_body):
                        data = self._try_parse_json(resp_body)
                        if data.get(key) == state:
                            findings.append(Finding(
                                title=f"State Machine Abuse — `{key}` forced to `{state}`",
                                severity=Severity.CRITICAL,
                                category="Business Logic - State Machine Abuse",
                                description=f"Forcing `{key}` to `{state}` was accepted and reflected. An attacker could bypass required approval/payment workflows.",
                                request={"method": method, "url": url, "body": test_body},
                                response_summary=f"HTTP {status}, {key}={data.get(key)}",
                                evidence=f"Forced state {key}={state} → confirmed in response",
                                recommendation="Never trust client-submitted state values. Compute state transitions server-side based on verified conditions.",
                                cwe="CWE-284",
                                cvss=9.5
                            ))
                            break
        return findings

    # ─────────────────────────────────────────────────────────────
    # MODULE 12: Race Condition Detection
    # ─────────────────────────────────────────────────────────────
    async def _check_concurrent_requests(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        """Send 10 concurrent identical requests to detect race conditions."""
        findings = []
        if method not in ("POST", "PUT", "PATCH"):
            return findings

        # Only run on endpoints that look like state-changing operations
        race_indicators = ["redeem", "transfer", "withdraw", "claim", "apply", "checkout",
                           "purchase", "buy", "order", "submit", "confirm"]
        if not any(ind in url.lower() for ind in race_indicators):
            return findings

        tasks = [self._request(method, url, json=body) for _ in range(10)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(
            1 for r in responses
            if isinstance(r, tuple) and r[0] in (200, 201)
            and self._response_indicates_success(r[2])
        )

        if success_count > 1:
            findings.append(Finding(
                title=f"Race Condition — {success_count}/10 concurrent requests succeeded",
                severity=Severity.CRITICAL,
                category="Business Logic - Race Condition",
                description=(
                    f"{success_count} out of 10 simultaneous identical requests returned success. "
                    "This may allow redeeming a coupon/credit multiple times, double-spending, or bypassing one-time-use restrictions."
                ),
                request={"method": method, "url": url, "body": body, "note": "10 concurrent requests"},
                response_summary=f"{success_count} successes out of 10 concurrent requests",
                evidence=f"Concurrent success rate: {success_count}/10",
                recommendation="Use database-level locks (SELECT FOR UPDATE), atomic operations, or distributed locks (Redis SETNX) to prevent race conditions on critical operations.",
                cwe="CWE-362",
                cvss=9.0
            ))
        return findings

    def _response_indicates_success(self, body: str) -> bool:
        """Heuristically determine if a response body indicates a successful operation."""
        if not body or body in ("TIMEOUT", ) or body.startswith("ERROR"):
            return False
        body_lower = body.lower()
        failure_signals = ["error", "invalid", "failed", "unauthorized", "forbidden",
                           "not found", "rejected", "denied", "exception", "bad request"]
        success_signals = ["success", "true", "created", "updated", "confirmed",
                           "processed", "completed", "accepted", "ok", "order_id",
                           "transaction_id", "payment_id"]

        has_failure = any(s in body_lower for s in failure_signals)
        has_success = any(s in body_lower for s in success_signals)
        return has_success and not has_failure

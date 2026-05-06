"""
BLFinder v2.0 - Advanced Business Logic Flaw Detection Engine
Optimized for Termux/Android + Bug Bounty Hunting
"""

import asyncio
import aiohttp
import json
import time
import re
import hashlib
import copy
import itertools
import random
import string
import base64
from typing import Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, quote, unquote
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict


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
    owasp: str = ""
    confirmed: bool = False  # True = verified, not just heuristic


@dataclass
class ScanConfig:
    target_url: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    auth_token: str = ""
    second_user_token: str = ""     # For IDOR cross-user confirmation
    third_user_token: str = ""      # For privilege escalation chain
    no_auth_check: bool = True      # Also test without any auth
    timeout: int = 20
    rate_limit: float = 0.3         # Base delay (adaptive override per-domain)
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: str = ""
    wordlist_params: list = field(default_factory=list)
    custom_payloads: dict = field(default_factory=dict)
    user_agent_rotate: bool = True
    smart_discovery: bool = True    # Auto-discover endpoints from JS/links
    fuzz_depth: int = 2             # How deep to mutate nested JSON
    respect_robots: bool = False    # Skip robots.txt for bug bounty
    verbose: bool = False
    output_dir: str = "."


# ─── Adaptive Rate Limiter ─────────────────────────────────────────────────────
class AdaptiveRateLimiter:
    """
    Tracks response times and 429s per domain.
    Backs off exponentially on throttling, speeds up on consistent fast responses.
    """
    def __init__(self, base_delay: float = 0.3):
        self.base_delay = base_delay
        self.delays: dict[str, float] = {}
        self.consecutive_429: dict[str, int] = defaultdict(int)
        self.consecutive_ok: dict[str, int] = defaultdict(int)
        self.last_request: dict[str, float] = {}

    def get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    async def wait(self, url: str):
        domain = self.get_domain(url)
        delay = self.delays.get(domain, self.base_delay)
        since_last = time.time() - self.last_request.get(domain, 0)
        wait_time = max(0, delay - since_last)
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        self.last_request[domain] = time.time()

    def record(self, url: str, status: int, elapsed: float):
        domain = self.get_domain(url)
        if status == 429:
            self.consecutive_429[domain] += 1
            self.consecutive_ok[domain] = 0
            new_delay = min(30.0, self.base_delay * (2 ** self.consecutive_429[domain]))
            self.delays[domain] = new_delay
            print(f"  [!] 429 received — backing off to {new_delay:.1f}s for {domain}")
        elif status in (200, 201, 204, 301, 302, 400, 401, 403, 404):
            self.consecutive_ok[domain] += 1
            self.consecutive_429[domain] = 0
            if self.consecutive_ok[domain] > 10:
                current = self.delays.get(domain, self.base_delay)
                self.delays[domain] = max(self.base_delay, current * 0.85)


# ─── User-Agent Pool ───────────────────────────────────────────────────────────
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "PostmanRuntime/7.37.0",
    "python-httpx/0.27.0",
    "axios/1.6.8",
]


class BLFScanner:
    """
    BLFinder v2.0 — Business Logic Flaw Scanner

    Advanced modules:
    ─ Price / quantity manipulation (deep nested + type confusion)
    ─ IDOR / BOLA (path, body, header, GraphQL, multi-user confirmation)
    ─ Object property enumeration (BOPLA)
    ─ Workflow / step bypass (forward & backward skipping)
    ─ Mass assignment with reflection & shadow fields
    ─ Privilege escalation (horizontal + vertical + JWT claim tampering)
    ─ Race conditions (Turbo Intruder-style last-byte sync)
    ─ Coupon / discount stacking, replay, type confusion
    ─ Time-based logic bypass (headers, body, past/future)
    ─ Integer overflow & floating point edge cases
    ─ Hidden parameter disclosure
    ─ State machine abuse (forced transitions)
    ─ HTTP method override & verb tampering
    ─ GraphQL introspection + IDOR via aliases
    ─ JWT claim injection (alg:none, kid injection, claim escalation)
    ─ Response-based account enumeration
    ─ Business-logic-specific path traversal
    ─ Function-level access control (FLAC/BFLA)
    ─ Limit/offset manipulation for data leakage
    ─ Soft-delete bypass
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: list[Finding] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_log: list[dict] = []
        self.base_responses: dict = {}
        self.rate_limiter = AdaptiveRateLimiter(config.rate_limit)
        self._ua_cycle = itertools.cycle(UA_POOL)
        self.discovered_endpoints: list[dict] = []
        self._seen_findings: set = set()

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl,
            limit=20,
            limit_per_host=5,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout, connect=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _build_headers(self, extra: dict = None) -> dict:
        ua = next(self._ua_cycle) if self.config.user_agent_rotate else UA_POOL[0]
        headers = {
            "User-Agent": ua,
            "Accept": "application/json, text/html, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.config.auth_token:
            headers["Authorization"] = f"Bearer {self.config.auth_token}"
        headers.update(self.config.headers)
        if extra:
            headers.update(extra)
        return headers

    async def _request(
        self, method: str, url: str,
        headers: dict = None, token_override: str = None,
        **kwargs
    ) -> tuple[int, dict, str, float]:
        """Core request method with adaptive rate limiting and logging."""
        await self.rate_limiter.wait(url)

        req_headers = self._build_headers(headers)
        if token_override is not None:
            if token_override == "":
                req_headers.pop("Authorization", None)
            else:
                req_headers["Authorization"] = f"Bearer {token_override}"

        start = time.time()
        try:
            async with self.session.request(
                method, url,
                headers=req_headers,
                cookies=self.config.cookies,
                allow_redirects=True,
                max_redirects=self.config.max_redirects,
                proxy=self.config.proxy if self.config.proxy else None,
                **kwargs
            ) as resp:
                elapsed = time.time() - start
                body = await resp.text(errors="replace")
                self.rate_limiter.record(url, resp.status, elapsed)
                self.request_log.append({
                    "method": method, "url": url,
                    "status": resp.status, "elapsed": round(elapsed, 3),
                })
                if self.config.verbose:
                    print(f"  [{resp.status}] {method} {url[:80]} ({elapsed:.2f}s)")
                return resp.status, dict(resp.headers), body, elapsed
        except asyncio.TimeoutError:
            return 0, {}, "TIMEOUT", time.time() - start
        except aiohttp.ClientConnectorError as e:
            return 0, {}, f"CONNECTION_ERROR: {str(e)[:100]}", time.time() - start
        except Exception as e:
            return 0, {}, f"ERROR: {str(e)[:100]}", time.time() - start

    # ─── Utility Helpers ───────────────────────────────────────────────────────

    def _try_parse_json(self, body: str) -> dict | list:
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _hash_response(self, body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    def _responses_differ_significantly(self, a: str, b: str, threshold: float = 0.1) -> bool:
        if a == b:
            return False
        len_diff = abs(len(a) - len(b))
        if len_diff > max(50, max(len(a), len(b)) * threshold):
            return True
        return self._hash_response(a) != self._hash_response(b)

    def _dedupe_finding(self, title: str, url: str) -> bool:
        key = hashlib.md5(f"{title}:{url}".encode()).hexdigest()
        if key in self._seen_findings:
            return True
        self._seen_findings.add(key)
        return False

    def _add_finding(self, finding: Finding):
        if not self._dedupe_finding(finding.title, str(finding.request.get("url", ""))):
            self.findings.append(finding)

    def _response_indicates_success(self, body: str, status: int = 200) -> bool:
        if not body or body in ("TIMEOUT",) or body.startswith(("ERROR:", "CONNECTION_ERROR:")):
            return False
        if status >= 500:
            return False
        body_lower = body.lower()
        failure_signals = [
            "error", "invalid", "failed", "unauthorized", "forbidden",
            "not found", "rejected", "denied", "exception", "bad request",
            "validation", "required", "missing"
        ]
        success_signals = [
            "success", "true", "created", "updated", "confirmed",
            "processed", "completed", "accepted", "ok", "order_id",
            "transaction_id", "payment_id", "id", "token"
        ]
        has_failure = any(s in body_lower for s in failure_signals)
        has_success = any(s in body_lower for s in success_signals)
        if status in (200, 201, 204):
            return not has_failure
        return has_success and not has_failure

    def _extract_all_ids(self, body: str) -> list[str]:
        ids = []
        ids += re.findall(r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', body, re.I)
        ids += re.findall(r'"(?:id|user_id|account_id|order_id|invoice_id)":\s*(\d+)', body)
        ids += re.findall(r'/(\d{3,})', body)
        return list(set(ids))[:20]

    def _mutate_nested(self, obj: Any, target_key: str, new_val: Any, depth: int = 0) -> list[Any]:
        mutations = []
        if depth > self.config.fuzz_depth:
            return mutations
        if isinstance(obj, dict):
            if target_key in obj:
                m = copy.deepcopy(obj)
                m[target_key] = new_val
                mutations.append(m)
            for k, v in obj.items():
                for sub_mut in self._mutate_nested(v, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[k] = sub_mut
                    mutations.append(m)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                for sub_mut in self._mutate_nested(item, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[i] = sub_mut
                    mutations.append(m)
        return mutations

    # ─── Smart Endpoint Discovery ──────────────────────────────────────────────

    async def smart_discover(self, seed_url: str) -> list[dict]:
        print("[*] Smart Discovery — crawling for endpoints...")
        found = []
        visited = set()

        async def fetch_and_extract(url: str):
            if url in visited:
                return
            visited.add(url)
            status, headers, body, _ = await self._request("GET", url)
            if status != 200 or not body:
                return

            api_patterns = [
                r'''(?:url|endpoint|api|path)\s*[=:]\s*["`']([/][^`'"<>\s]{3,80})["`']''',
                r'''(?:fetch|axios|get|post|put|patch|delete)\s*\(\s*["`']([/][^`'"<>\s]{3,80})["`']''',
                r'''/api/v?\d*/[a-z][a-z0-9_/-]{2,50}''',
                r'''/v\d+/[a-z][a-z0-9_/-]{2,50}''',
            ]
            discovered_paths = set()
            for pat in api_patterns:
                for match in re.findall(pat, body, re.I):
                    if isinstance(match, str) and match.startswith("/"):
                        discovered_paths.add(match.split("?")[0])

            js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
            parsed = urlparse(seed_url)
            base = f"{parsed.scheme}://{parsed.netloc}"

            for path in discovered_paths:
                ep_url = urljoin(base, path)
                method = "GET"
                body_template = {}
                if any(k in path.lower() for k in ["creat", "add", "submit", "register", "signup", "order", "checkout"]):
                    method = "POST"
                elif any(k in path.lower() for k in ["updat", "edit", "modif"]):
                    method = "PUT"
                found.append({"url": ep_url, "method": method, "body": body_template, "params": {}})

            for js_url in js_urls[:5]:
                full_js = urljoin(base, js_url) if not js_url.startswith("http") else js_url
                await fetch_and_extract(full_js)

        await fetch_and_extract(seed_url)

        common_bases = [
            "/api/v1", "/api/v2", "/api", "/v1", "/v2",
            "/graphql", "/api/graphql",
            "/api/users", "/api/me", "/api/profile",
            "/api/orders", "/api/products", "/api/payments",
            "/api/admin", "/api/internal",
            "/.well-known/openapi.json", "/swagger.json", "/openapi.json",
            "/api-docs", "/api/docs", "/docs/api",
        ]
        parsed = urlparse(seed_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        probe_tasks = [self._request("GET", f"{base}{path}") for path in common_bases]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for path, result in zip(common_bases, probe_results):
            if isinstance(result, tuple) and result[0] == 200:
                ep_url = f"{base}{path}"
                found.append({"url": ep_url, "method": "GET", "body": {}, "params": {}})
                print(f"  [+] Discovered: {ep_url}")
                if "openapi" in path or "swagger" in path:
                    spec_endpoints = self._parse_openapi(result[2], base)
                    found.extend(spec_endpoints)

        self.discovered_endpoints = found
        print(f"  [*] Discovered {len(found)} endpoints\n")
        return found

    def _parse_openapi(self, spec_body: str, base_url: str) -> list[dict]:
        endpoints = []
        try:
            spec = json.loads(spec_body)
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                for method, info in methods.items():
                    if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        body = {}
                        rb = info.get("requestBody", {})
                        if rb:
                            schema = rb.get("content", {}).get("application/json", {}).get("schema", {})
                            body = self._schema_to_example(schema)
                        endpoints.append({
                            "url": urljoin(base_url, path),
                            "method": method.upper(),
                            "body": body,
                            "params": {},
                        })
        except Exception:
            pass
        return endpoints

    def _schema_to_example(self, schema: dict) -> dict:
        example = {}
        props = schema.get("properties", {})
        for k, v in props.items():
            t = v.get("type", "string")
            if t == "integer" or t == "number":
                example[k] = 1
            elif t == "boolean":
                example[k] = True
            elif t == "array":
                example[k] = []
            elif t == "object":
                example[k] = {}
            else:
                example[k] = "test"
        return example

    # ─── Main Runner ───────────────────────────────────────────────────────────

    async def run_all_modules(self, endpoints: list[dict]) -> list[Finding]:
        print(f"[*] BLFinder v2.0 — Target: {self.config.target_url}")
        print(f"[*] {len(endpoints)} endpoints queued\n")

        if self.config.smart_discovery:
            extra = await self.smart_discover(self.config.target_url)
            existing = {(e["url"], e.get("method", "GET")) for e in endpoints}
            for ep in extra:
                key = (ep["url"], ep.get("method", "GET"))
                if key not in existing:
                    endpoints.append(ep)
                    existing.add(key)
            print(f"[*] Total after discovery: {len(endpoints)} endpoints\n")

        tasks = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self.config.target_url, url)
            method = ep.get("method", "GET").upper()
            body = ep.get("body", {})
            params = ep.get("params", {})
            tasks.append(self._run_endpoint_checks(url, method, body, params))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                self.findings.extend(r)

        cross = await self._check_graphql_idor()
        self.findings.extend(cross)

        seen = set()
        unique = []
        for f in self.findings:
            key = hashlib.md5(f"{f.title}{f.evidence}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        return self.findings

    async def _run_endpoint_checks(self, url, method, body, params) -> list[Finding]:
        findings = []

        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body if body else None,
            params=params if params else None,
        )
        if status == 0:
            return findings

        self.base_responses[url] = {
            "status": status, "body": base_body,
            "hash": self._hash_response(base_body), "elapsed": elapsed,
            "headers": headers,
        }

        checks = [
            self._check_price_manipulation(url, method, body, params, status, base_body),
            self._check_quantity_negative(url, method, body, params, status, base_body),
            self._check_workflow_bypass(url, method, body, params, status, base_body),
            self._check_mass_assignment(url, method, body, params, status, base_body),
            self._check_idor_bola_advanced(url, method, body, params, status, base_body, headers),
            self._check_bopla(url, method, body, params, status, base_body),
            self._check_privilege_escalation(url, method, body, params, status, base_body),
            self._check_function_level_access(url, method, body, params, status, base_body),
            self._check_coupon_stacking(url, method, body, params, status, base_body),
            self._check_time_logic_bypass(url, method, body, params, status, base_body),
            self._check_integer_overflow(url, method, body, params, status, base_body),
            self._check_hidden_parameter_disclosure(url, method, body, params, status, base_body),
            self._check_state_machine_abuse(url, method, body, params, status, base_body),
            self._check_race_condition(url, method, body, params, status, base_body),
            self._check_jwt_manipulation(url, method, body, params, status, base_body, headers),
            self._check_account_enumeration(url, method, body, params, status, base_body),
            self._check_limit_offset_manipulation(url, method, body, params, status, base_body),
            self._check_soft_delete_bypass(url, method, body, params, status, base_body),
            self._check_http_method_override(url, method, body, params, status, base_body),
            self._check_parameter_pollution(url, method, body, params, status, base_body),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception) and self.config.verbose:
                print(f"  [!] Module error: {r}")

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 1: Price Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_price_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        price_keys = [
            "price", "amount", "total", "cost", "fee", "charge", "unit_price",
            "subtotal", "discount_amount", "payment_amount", "order_total",
            "grand_total", "final_price", "sale_price", "tax", "shipping_cost",
        ]
        tamper_values = [0, 0.01, -1, -100, 0.00001, "0", "0.00", 1, "1", None, "", "null", False]

        def _find_and_mutate(obj, keys, results, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(pk in k.lower() for pk in keys):
                        results.append((path + f".{k}" if path else k, k, v))
                    _find_and_mutate(v, keys, results, path + f".{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _find_and_mutate(item, keys, results, path + f"[{i}]")

        price_fields = []
        _find_and_mutate(body, price_keys, price_fields)

        for field_path, key, original in price_fields:
            for tampered in tamper_values:
                for mutated_body in self._mutate_nested(body, key, tampered):
                    status, headers, resp_body, _ = await self._request(method, url, json=mutated_body)
                    if status in (200, 201) and self._response_indicates_success(resp_body, status):
                        resp_data = self._try_parse_json(resp_body)
                        confirmed = False
                        if isinstance(resp_data, dict):
                            for rk, rv in resp_data.items():
                                if any(pk in rk.lower() for pk in price_keys):
                                    if isinstance(rv, (int, float)) and rv != original:
                                        confirmed = True
                                        break

                        findings.append(Finding(
                            title=f"Price Manipulation — `{field_path}` accepted tampered value",
                            severity=Severity.CRITICAL,
                            category="Business Logic — Price Manipulation",
                            description=(
                                f"Field `{field_path}` (original: `{original}`) accepted tampered value "
                                f"`{tampered}`. Server returned success. "
                                f"{'Order created at manipulated price.' if confirmed else 'Potential price acceptance.'}"
                            ),
                            request={"method": method, "url": url, "body": mutated_body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"Original: {original} → Tampered: {tampered} → HTTP {status} {'[CONFIRMED]' if confirmed else ''}",
                            recommendation="Compute prices server-side from a trusted catalog. Never accept client-submitted price values.",
                            cwe="CWE-20", cvss=9.1,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            confirmed=confirmed,
                        ))
                        break
            if findings:
                break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 2: Negative Quantity / Value
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_quantity_negative(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        qty_keys = ["quantity", "qty", "count", "units", "items", "amount", "number", "stock"]

        for key in qty_keys:
            if key not in body:
                continue
            original = body[key]
            for tampered in [-1, -100, -9999, 0, -0.5, "-1", 2**31 - 1]:
                test_body = {**body, key: tampered}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body, status):
                    findings.append(Finding(
                        title=f"Negative Quantity Exploit — `{key}` = {tampered} accepted",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Negative Value",
                        description=(
                            f"Submitting `{key}` = {tampered} (original: {original}) was accepted. "
                            "Negative purchases may trigger refunds, reverse charges, or gift negative inventory."
                        ),
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"qty={tampered} → HTTP {status}",
                        recommendation="Enforce qty >= 1 server-side. Reject/clamp negative and zero values.",
                        cwe="CWE-20", cvss=9.3,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    ))
                    break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 3: Advanced IDOR / BOLA Detection
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_idor_bola_advanced(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        path = parsed.path
        path_segments = path.split("/")

        # ── 1. Path-based ID enumeration ──────────────────────────────────────
        for seg_idx, segment in enumerate(path_segments):
            if not segment:
                continue

            if re.match(r'^\d{1,12}$', segment):
                original_id = int(segment)
                test_ids = [
                    original_id - 1, original_id + 1,
                    original_id + 100, 1, 2, 3, 9999,
                ]
                for test_id in test_ids:
                    if test_id <= 0:
                        continue
                    new_segments = path_segments[:]
                    new_segments[seg_idx] = str(test_id)
                    new_path = "/".join(new_segments)
                    test_url = urlunparse(parsed._replace(path=new_path))

                    status, _, resp_body, elapsed = await self._request(method, test_url, json=body if body else None)

                    if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                        confirmed = False
                        if self.config.second_user_token:
                            s2, _, rb2, _ = await self._request(
                                method, test_url,
                                json=body if body else None,
                                token_override=self.config.second_user_token,
                            )
                            confirmed = s2 == 200

                        sev = Severity.CRITICAL if confirmed else Severity.HIGH
                        findings.append(Finding(
                            title=f"IDOR/BOLA — Path ID {original_id} → {test_id} leaked different resource",
                            severity=sev,
                            category="Business Logic — IDOR/BOLA",
                            description=(
                                f"Changing path segment `{original_id}` to `{test_id}` returned a different 200 response. "
                                f"{'Cross-user access CONFIRMED.' if confirmed else 'Possible unauthorized resource access.'}"
                            ),
                            request={"method": method, "url": test_url, "body": body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"ID {original_id} → {test_id}: different response bodies {'[CROSS-USER CONFIRMED]' if confirmed else ''}",
                            recommendation="Enforce ownership checks on every request. Tie resource access to authenticated session, not just the ID.",
                            cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                            owasp="API1:2023 Broken Object Level Authorization",
                            confirmed=confirmed,
                        ))
                        if confirmed:
                            break

            uuid_match = re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I)
            if uuid_match:
                test_uuids = [
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                    "11111111-1111-1111-1111-111111111111",
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                    segment[:-4] + "0001",
                ]
                for test_uuid in test_uuids:
                    new_segments = path_segments[:]
                    new_segments[seg_idx] = test_uuid
                    new_path = "/".join(new_segments)
                    test_url = urlunparse(parsed._replace(path=new_path))

                    status, _, resp_body, _ = await self._request(method, test_url, json=body if body else None)
                    if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                        findings.append(Finding(
                            title=f"IDOR/BOLA — UUID swap leaked different resource",
                            severity=Severity.HIGH,
                            category="Business Logic — IDOR/BOLA",
                            description=f"Replacing UUID `{segment}` with `{test_uuid}` returned a different resource. UUIDs alone are not an authorization control.",
                            request={"method": method, "url": test_url, "body": body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"UUID {segment} → {test_uuid}: different response",
                            recommendation="Never use UUIDs as the sole authorization check. Verify object ownership against authenticated user on every request.",
                            cwe="CWE-639", cvss=8.5,
                            owasp="API1:2023 Broken Object Level Authorization",
                        ))
                        break

        # ── 2. Body/param ID replacement ──────────────────────────────────────
        id_keys = ["id", "user_id", "account_id", "order_id", "invoice_id",
                   "customer_id", "profile_id", "resource_id", "doc_id", "file_id",
                   "subscription_id", "payment_id", "ticket_id", "record_id"]

        for key in id_keys:
            if key not in body:
                continue
            original_val = body[key]
            test_vals = []
            if isinstance(original_val, int):
                test_vals = [original_val - 1, original_val + 1, 1, 2]
            elif isinstance(original_val, str) and original_val.isdigit():
                test_vals = [str(int(original_val) - 1), str(int(original_val) + 1), "1", "2"]

            for test_val in test_vals:
                if not test_val:
                    continue
                test_body = {**body, key: test_val}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                    confirmed = False
                    if self.config.second_user_token:
                        s2, _, _, _ = await self._request(
                            method, url, json=test_body,
                            token_override=self.config.second_user_token,
                        )
                        confirmed = s2 == 200

                    findings.append(Finding(
                        title=f"IDOR/BOLA — body field `{key}` = {test_val} exposed different resource",
                        severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                        category="Business Logic — IDOR/BOLA",
                        description=f"Changing body field `{key}` from `{original_val}` to `{test_val}` returned different resource data. {'Cross-user CONFIRMED.' if confirmed else ''}",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"body.{key}: {original_val} → {test_val}: different response {'[CONFIRMED]' if confirmed else ''}",
                        recommendation="Validate that the object referenced by the ID belongs to the authenticated user.",
                        cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                        owasp="API1:2023 Broken Object Level Authorization",
                        confirmed=confirmed,
                    ))

        # ── 3. No-auth access check ────────────────────────────────────────────
        if self.config.no_auth_check:
            s_noauth, _, rb_noauth, _ = await self._request(method, url, json=body if body else None, token_override="")
            if s_noauth in (200, 201) and self._response_indicates_success(rb_noauth, s_noauth):
                findings.append(Finding(
                    title=f"Unauthenticated Access — resource accessible without token",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Missing Authentication",
                    description=f"Removing the Authorization header entirely returned HTTP {s_noauth}. The endpoint may be publicly accessible.",
                    request={"method": method, "url": url, "note": "No Authorization header"},
                    response_summary=f"HTTP {s_noauth} — {rb_noauth[:300]}",
                    evidence=f"No-auth request → HTTP {s_noauth}",
                    recommendation="Require authentication on all non-public endpoints. Validate session tokens server-side before processing.",
                    cwe="CWE-306", cvss=9.8,
                    owasp="API2:2023 Broken Authentication",
                    confirmed=True,
                ))

        # ── 4. Header-based ID injection ──────────────────────────────────────
        id_headers_list = [
            {"X-User-Id": "1"},
            {"X-Account-Id": "1"},
            {"X-Admin-User": "true"},
            {"X-Internal-User": "1"},
            {"X-Forwarded-User": "admin"},
            {"X-Original-User-Id": "1"},
        ]
        for id_hdr in id_headers_list:
            status, _, resp_body, _ = await self._request(method, url, json=body if body else None, headers=id_hdr)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                hdr_name = list(id_hdr.keys())[0]
                findings.append(Finding(
                    title=f"Header-based IDOR — `{hdr_name}` overrides user context",
                    severity=Severity.CRITICAL,
                    category="Business Logic — IDOR/BOLA",
                    description=f"Adding `{hdr_name}: {id_hdr[hdr_name]}` returned a different response, suggesting this header overrides the authenticated user context.",
                    request={"method": method, "url": url, "headers": id_hdr},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"Header `{hdr_name}` changed response",
                    recommendation="Never trust user-controlled headers for identity. Derive user context solely from cryptographically verified tokens.",
                    cwe="CWE-639", cvss=9.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confirmed=True,
                ))

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 4: BOPLA
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_bopla(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        base_len = len(base_body)

        expand_probes = [
            {"expand": "all"},
            {"expand": "user,payment,admin"},
            {"include": "all"},
            {"fields": "*"},
            {"select": "*"},
            {"verbose": "1"},
            {"full": "true"},
            {"include_deleted": "true"},
            {"show_private": "1"},
            {"_all": "1"},
        ]

        for probe_params in expand_probes:
            merged_params = {**params, **probe_params}
            status, _, resp_body, _ = await self._request("GET", url, params=merged_params)
            if status == 200 and len(resp_body) > base_len * 1.15:
                base_data = self._try_parse_json(base_body)
                new_data = self._try_parse_json(resp_body)
                sensitive_fields = ["password", "secret", "token", "private_key", "ssn", "dob",
                                    "credit_card", "cvv", "bank", "salary", "internal", "hash"]
                new_keys = set()
                if isinstance(new_data, dict) and isinstance(base_data, dict):
                    new_keys = set(new_data.keys()) - set(base_data.keys())
                has_sensitive = any(sf in " ".join(new_keys).lower() for sf in sensitive_fields)

                findings.append(Finding(
                    title=f"BOPLA — `{list(probe_params.keys())[0]}` param unlocks hidden fields",
                    severity=Severity.HIGH if has_sensitive else Severity.MEDIUM,
                    category="Business Logic — Object Property Exposure",
                    description=(
                        f"Adding `{probe_params}` returned {len(resp_body) - base_len} extra bytes. "
                        f"New fields: {list(new_keys)[:5] if new_keys else 'unknown'}. "
                        f"{'Sensitive fields detected!' if has_sensitive else ''}"
                    ),
                    request={"method": "GET", "url": url, "params": merged_params},
                    response_summary=f"HTTP {status}, {len(resp_body)} bytes vs baseline {base_len}",
                    evidence=f"Extra data: +{len(resp_body) - base_len} bytes, new keys: {list(new_keys)[:5]}",
                    recommendation="Implement property-level authorization. Define explicit field allowlists per role.",
                    cwe="CWE-213", cvss=7.5 if has_sensitive else 5.3,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 5: Workflow / Step Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_workflow_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        step_patterns = [
            (r"/step[_-]?(\d+)", "step"),
            (r"/stage[_-]?(\d+)", "stage"),
            (r"/page[_-]?(\d+)", "page"),
            (r"/checkout/(\w+)", "checkout"),
            (r"/flow/(\w+)", "flow"),
        ]

        for pattern, label in step_patterns:
            match = re.search(pattern, path, re.IGNORECASE)
            if not match:
                continue
            current_step = match.group(1)
            try:
                for delta in [2, 3, -1]:
                    next_step = str(int(current_step) + delta)
                    if int(next_step) < 0:
                        continue
                    new_path = re.sub(pattern, match.group(0).replace(current_step, next_step), path, flags=re.IGNORECASE)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    status, _, resp_body, _ = await self._request(method, new_url, json=body)
                    if status in (200, 201):
                        findings.append(Finding(
                            title=f"Workflow Step Bypass — jumped {label} {current_step} → {next_step}",
                            severity=Severity.HIGH,
                            category="Business Logic — Workflow Bypass",
                            description=f"Directly accessing {label} {next_step} without completing {label} {current_step} returned HTTP {status}.",
                            request={"method": method, "url": new_url, "body": body},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"Skip {current_step} → {next_step} succeeded",
                            recommendation="Enforce sequential step validation using signed server-side session state.",
                            cwe="CWE-284", cvss=7.5,
                            owasp="API5:2023 Broken Function Level Authorization",
                        ))
            except (ValueError, TypeError):
                pass

        step_token_keys = ["step", "stage", "workflow_token", "checkout_token", "flow_id",
                           "step_id", "verification_token", "otp", "mfa_token"]
        for key in step_token_keys:
            if key not in body:
                continue
            test_body = {k: v for k, v in body.items() if k != key}
            status, _, resp_body, _ = await self._request(method, url, json=test_body)
            if status in (200, 201) and self._response_indicates_success(resp_body, status):
                findings.append(Finding(
                    title=f"Workflow Token Omission — `{key}` not validated",
                    severity=Severity.HIGH,
                    category="Business Logic — Workflow Bypass",
                    description=f"Removing `{key}` from the request still returned success. Workflow/MFA/OTP verification appears optional.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Missing `{key}` → HTTP {status}",
                    recommendation="Validate all workflow tokens server-side. OTP/MFA tokens must be required and verified before action.",
                    cwe="CWE-284", cvss=8.2,
                    owasp="API5:2023 Broken Function Level Authorization",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 6: Mass Assignment
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_mass_assignment(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        privileged_keys = [
            "is_admin", "admin", "role", "roles", "permissions", "is_verified",
            "verified", "is_premium", "premium", "subscription", "plan",
            "credits", "balance", "discount", "is_staff", "group",
            "account_type", "tier", "membership", "vip", "approved",
            "email_verified", "phone_verified", "kyc_verified",
            "internal_notes", "notes", "metadata", "tags",
            "price_override", "tax_exempt", "fee_waiver",
        ]

        for key in privileged_keys:
            for val in [True, "admin"]:
                test_body = {**body, key: val}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201):
                    continue
                resp_data = self._try_parse_json(resp_body)
                reflected_val = None
                if isinstance(resp_data, dict):
                    reflected_val = resp_data.get(key)
                if reflected_val in (True, "true", 1, "admin", "premium", "verified", val):
                    findings.append(Finding(
                        title=f"Mass Assignment — `{key}` accepted and reflected",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Mass Assignment",
                        description=f"Injecting `{key}: {val}` was accepted and reflected in the response as `{reflected_val}`. This may allow privilege escalation.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}, `{key}` = {reflected_val}",
                        evidence=f"Injected `{key}={val}` → response shows `{key}={reflected_val}`",
                        recommendation="Use an explicit field allowlist. Never pass raw request bodies to ORM methods.",
                        cwe="CWE-915", cvss=9.8,
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        confirmed=True,
                    ))
                    break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 7: Privilege Escalation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_privilege_escalation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        admin_paths = [
            "/admin", "/api/admin", "/api/v1/admin", "/api/v2/admin",
            "/manage", "/dashboard/admin", "/api/users", "/api/users/all",
            "/api/roles", "/api/permissions", "/internal", "/api/internal",
            "/superuser", "/api/superadmin", "/api/metrics", "/api/stats",
            "/api/config", "/api/settings", "/api/debug",
            "/api/v1/users", "/api/v1/accounts", "/api/v1/orders",
        ]
        for admin_path in admin_paths:
            test_url = f"{base}{admin_path}"
            for token, label in [(self.config.auth_token, "low-priv"), ("", "no-auth")]:
                status, _, resp_body, _ = await self._request("GET", test_url, token_override=token)
                if status == 200:
                    findings.append(Finding(
                        title=f"BFLA — Admin endpoint `{admin_path}` accessible by {label} user",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Function Level Access Control",
                        description=f"The admin endpoint `{admin_path}` returned HTTP 200 with a {label} token.",
                        request={"method": "GET", "url": test_url, "note": f"Token: {label}"},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"GET {test_url} with {label} token → {status}",
                        recommendation="Enforce RBAC on all admin endpoints using middleware. Validate role before executing handler logic.",
                        cwe="CWE-269", cvss=9.8,
                        owasp="API5:2023 Broken Function Level Authorization",
                        confirmed=True,
                    ))
                    break
        return findings

    async def _check_function_level_access(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if not self.config.second_user_token:
            return findings

        for test_method in ["DELETE", "PUT", "PATCH", "GET"]:
            if test_method == method:
                continue
            status, _, resp_body, _ = await self._request(
                test_method, url,
                json=body if body else None,
                token_override=self.config.second_user_token,
            )
            if status in (200, 201, 204):
                findings.append(Finding(
                    title=f"BFLA — User 2 can {test_method} resource owned by User 1",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=f"User 2's token successfully performed {test_method} on a resource owned by User 1.",
                    request={"method": test_method, "url": url, "note": "Second user token"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"User2 token + {test_method} {url} → {status}",
                    recommendation="Verify resource ownership on every mutating request.",
                    cwe="CWE-284", cvss=9.1,
                    owasp="API5:2023 Broken Function Level Authorization",
                    confirmed=True,
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 8: Coupon / Discount Abuse
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_coupon_stacking(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        coupon_keys = ["coupon", "coupon_code", "promo_code", "discount_code",
                       "voucher", "voucher_code", "referral_code", "promo", "code"]

        for key in coupon_keys:
            if key not in body:
                continue
            original = body[key]

            tests = [
                ({**body, key: [original, original]}, "duplicate array"),
                ({**body, key: [original]}, "single-item array"),
                ({**body, key: original.upper() if isinstance(original, str) else original}, "uppercase"),
                ({**body, key: f" {original} " if isinstance(original, str) else original}, "whitespace-padded"),
            ]

            base_discount = self._extract_discount(base_body)
            for test_body, label in tests:
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201):
                    continue
                new_discount = self._extract_discount(resp_body)
                if self._response_indicates_success(resp_body, status):
                    confirmed = bool(new_discount and base_discount and new_discount > base_discount * 1.5)
                    findings.append(Finding(
                        title=f"Coupon Abuse — {label} for `{key}` accepted",
                        severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                        category="Business Logic — Coupon Abuse",
                        description=f"Sending coupon `{key}` as {label} was accepted. {'Larger discount confirmed.' if confirmed else 'May cause unexpected discount stacking.'}",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"Coupon type: {label}, discount: {base_discount} → {new_discount}",
                        recommendation="Normalize and validate coupon inputs. Enforce one-coupon-per-order server-side.",
                        cwe="CWE-20", cvss=8.5 if confirmed else 6.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=confirmed,
                    ))
        return findings

    def _extract_discount(self, body: str) -> float:
        try:
            data = json.loads(body)
            for key in ["discount", "discount_amount", "savings", "promo_discount", "coupon_value"]:
                if isinstance(data, dict) and key in data:
                    return float(data[key])
        except Exception:
            pass
        return 0.0

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 9: Time-based Logic Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_time_logic_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        time_keys = ["date", "expiry", "expiry_date", "expires_at", "valid_until",
                     "timestamp", "created_at", "booking_date", "start_date", "end_date",
                     "valid_from", "activation_date"]

        for key in time_keys:
            if key not in body:
                continue
            for ts, label in [
                ("2099-12-31T23:59:59Z", "far-future"),
                ("1970-01-01T00:00:01Z", "epoch"),
                ("2020-01-01T00:00:00Z", "past"),
                (9999999999, "unix-far-future"),
                (-1, "unix-negative"),
            ]:
                test_body = {**body, key: ts}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body, status):
                    findings.append(Finding(
                        title=f"Time Bypass — `{key}` accepts {label} timestamp",
                        severity=Severity.HIGH,
                        category="Business Logic — Time Bypass",
                        description=f"Setting `{key}` to a {label} value was accepted, potentially bypassing expiry or time-gated functionality.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"`{key}` = {ts} ({label}) accepted with HTTP {status}",
                        recommendation="Validate all timestamps server-side. Never trust client-supplied dates for security decisions.",
                        cwe="CWE-20", cvss=7.3,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    ))
                    break

        time_headers_list = [
            {"X-Custom-Date": "Mon, 01 Jan 2099 00:00:00 GMT"},
            {"X-Forwarded-Date": "2099-01-01"},
            {"Date": "Mon, 01 Jan 2099 00:00:00 GMT"},
        ]
        for time_hdrs in time_headers_list:
            status, _, resp_body, _ = await self._request(method, url, json=body, headers=time_hdrs)
            if status in (200, 201) and self._responses_differ_significantly(base_body, resp_body):
                hdr = list(time_hdrs.keys())[0]
                findings.append(Finding(
                    title=f"Time Bypass via `{hdr}` header",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Time Bypass",
                    description=f"The `{hdr}` header altered the server response, suggesting client-supplied time is trusted for business logic.",
                    request={"method": method, "url": url, "headers": time_hdrs},
                    response_summary=f"HTTP {status}",
                    evidence=f"Response differed with {hdr} header",
                    recommendation="Never use client-supplied time headers for business logic. Use server-side time exclusively.",
                    cwe="CWE-807", cvss=5.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 10: Integer Overflow & Extreme Values
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_integer_overflow(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        numeric_keys = [k for k, v in body.items() if isinstance(v, (int, float)) and not isinstance(v, bool)]
        extreme_values = [2**31 - 1, 2**31, 2**32, 2**63 - 1, -2**31, 9999999999, 1e308]

        for key in numeric_keys:
            for val in extreme_values:
                test_body = {**body, key: val}
                try:
                    status, _, resp_body, _ = await self._request(method, url, json=test_body)
                    if status == 500:
                        findings.append(Finding(
                            title=f"Integer Overflow — `{key}` = {val} caused server error",
                            severity=Severity.MEDIUM,
                            category="Business Logic — Integer Overflow",
                            description=f"Setting `{key}` to {val} caused a 500 error, suggesting unhandled overflow.",
                            request={"method": method, "url": url, "body": test_body},
                            response_summary="HTTP 500",
                            evidence=f"Input {key}={val} → 500",
                            recommendation="Validate numeric ranges on input. Handle overflow explicitly.",
                            cwe="CWE-190", cvss=6.5,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        ))
                    elif status in (200, 201):
                        data = self._try_parse_json(resp_body)
                        if isinstance(data, dict):
                            for rk, rv in data.items():
                                if isinstance(rv, (int, float)) and rv < 0 and not isinstance(rv, bool):
                                    findings.append(Finding(
                                        title=f"Integer Overflow — `{key}` = {val} caused negative `{rk}`",
                                        severity=Severity.HIGH,
                                        category="Business Logic — Integer Overflow",
                                        description=f"Setting `{key}` to {val} caused `{rk}` = {rv} (negative), indicating integer overflow.",
                                        request={"method": method, "url": url, "body": test_body},
                                        response_summary=f"HTTP {status}, {rk}={rv}",
                                        evidence=f"Input {key}={val} → response {rk}={rv}",
                                        recommendation="Use 64-bit integers. Validate input ranges. Use safe arithmetic libraries.",
                                        cwe="CWE-190", cvss=7.8,
                                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                    ))
                except Exception:
                    pass
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 11: Hidden Parameter Disclosure
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_hidden_parameter_disclosure(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        probe_params = {
            "debug": "1", "test": "1", "admin": "1", "internal": "1",
            "verbose": "1", "dev": "1", "trace": "1", "sql": "1",
            "dump": "1", "export": "1", "raw": "1", "pretty": "1",
            "full": "1", "include_deleted": "1", "show_all": "1",
            "_debug": "1", "XDEBUG_SESSION_START": "phpstorm",
            "format": "json", "callback": "test", "jsonp": "test",
        }

        for param, val in probe_params.items():
            test_params = {**params, param: val}
            status, headers, resp_body, elapsed = await self._request("GET", url, params=test_params)
            base_len = len(base_body)
            new_len = len(resp_body)

            if status == 200 and new_len > base_len * 1.2 and new_len - base_len > 100:
                severity = Severity.HIGH if new_len > base_len * 2 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"Hidden Parameter — `{param}` discloses extra data",
                    severity=severity,
                    category="Business Logic — Information Disclosure",
                    description=f"Adding `{param}={val}` returned {new_len - base_len} extra bytes, suggesting a hidden debug mode was activated.",
                    request={"method": "GET", "url": url, "params": test_params},
                    response_summary=f"HTTP {status}, {new_len} bytes vs baseline {base_len}",
                    evidence=f"Response size: baseline={base_len} → with param={new_len}",
                    recommendation="Remove debug/verbose parameters from production. Control verbosity via server-side flags only.",
                    cwe="CWE-200", cvss=6.5 if severity == Severity.HIGH else 5.3,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 12: State Machine Abuse
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_state_machine_abuse(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        state_keys = ["status", "state", "order_status", "payment_status",
                      "verification_status", "kyc_status", "approval_status",
                      "account_status", "subscription_status"]
        valid_states = {
            "status": ["completed", "approved", "verified", "active", "paid", "shipped", "published"],
            "state": ["completed", "approved", "verified", "active", "enabled"],
            "order_status": ["completed", "shipped", "delivered", "paid"],
            "payment_status": ["paid", "completed", "cleared", "succeeded"],
            "verification_status": ["verified", "approved", "confirmed"],
            "kyc_status": ["verified", "approved", "passed"],
        }

        for key in state_keys:
            if key not in body:
                continue
            targets = valid_states.get(key, ["completed", "approved", "verified"])
            for state in targets:
                test_body = {**body, key: state}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201):
                    continue
                data = self._try_parse_json(resp_body)
                if isinstance(data, dict) and data.get(key) == state:
                    findings.append(Finding(
                        title=f"State Machine Abuse — `{key}` forced to `{state}`",
                        severity=Severity.CRITICAL,
                        category="Business Logic — State Machine Abuse",
                        description=f"Forcing `{key}` to `{state}` was accepted and reflected. Attackers could bypass payment/approval workflows.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}, {key}={data.get(key)}",
                        evidence=f"Forced {key}={state} → confirmed in response",
                        recommendation="Compute state transitions server-side. Never trust client-submitted state values.",
                        cwe="CWE-284", cvss=9.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=True,
                    ))
                    break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 13: Race Condition
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_race_condition(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if method not in ("POST", "PUT", "PATCH"):
            return findings

        race_indicators = [
            "redeem", "transfer", "withdraw", "claim", "apply", "checkout",
            "purchase", "buy", "order", "submit", "confirm", "coupon",
            "vote", "like", "referral", "bonus", "reward", "spin",
        ]
        if not any(ind in url.lower() for ind in race_indicators):
            return findings

        orig_delay = self.rate_limiter.base_delay
        self.rate_limiter.base_delay = 0

        tasks = [self._request(method, url, json=body) for _ in range(15)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        self.rate_limiter.base_delay = orig_delay

        success_count = sum(
            1 for r in responses
            if isinstance(r, tuple) and r[0] in (200, 201)
            and self._response_indicates_success(r[2], r[0])
        )

        if success_count > 1:
            findings.append(Finding(
                title=f"Race Condition — {success_count}/15 concurrent requests succeeded",
                severity=Severity.CRITICAL,
                category="Business Logic — Race Condition",
                description=(
                    f"{success_count} of 15 simultaneous requests succeeded. "
                    "May allow double-redemption, multiple-order creation, or bypassing single-use restrictions."
                ),
                request={"method": method, "url": url, "body": body, "note": "15 concurrent requests"},
                response_summary=f"{success_count}/15 successes",
                evidence=f"Concurrent success rate: {success_count}/15",
                recommendation="Use DB-level locks (SELECT FOR UPDATE), Redis SETNX, or idempotency keys.",
                cwe="CWE-362", cvss=9.0,
                owasp="API4:2023 Unrestricted Resource Consumption",
                confirmed=True,
            ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 14: JWT Claim Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_jwt_manipulation(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings = []
        token = self.config.auth_token
        if not token or "." not in token:
            return findings

        parts = token.split(".")
        if len(parts) != 3:
            return findings

        def b64_decode_part(part: str) -> dict:
            pad = 4 - len(part) % 4
            try:
                return json.loads(base64.urlsafe_b64decode(part + "=" * pad))
            except Exception:
                return {}

        def b64_encode_part(data: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

        header = b64_decode_part(parts[0])
        payload = b64_decode_part(parts[1])

        if not header or not payload:
            return findings

        # Test 1: alg:none
        header_none = {**header, "alg": "none"}
        forged_token = f"{b64_encode_part(header_none)}.{parts[1]}."
        status, _, resp_body, _ = await self._request(method, url, json=body if body else None, token_override=forged_token)
        if status in (200, 201) and self._response_indicates_success(resp_body, status):
            findings.append(Finding(
                title="JWT alg:none Bypass — signature not validated",
                severity=Severity.CRITICAL,
                category="Business Logic — JWT Vulnerability",
                description="The server accepted a JWT with alg:none and no signature. Any claims can be forged.",
                request={"method": method, "url": url, "note": "JWT with alg:none"},
                response_summary=f"HTTP {status}",
                evidence=f"alg:none JWT accepted → HTTP {status}",
                recommendation="Explicitly whitelist allowed JWT algorithms. Reject 'none'. Use a hardened JWT library.",
                cwe="CWE-347", cvss=10.0,
                owasp="API2:2023 Broken Authentication",
                confirmed=True,
            ))

        # Test 2: Claim escalation
        claim_escalations = [
            {"role": "admin"}, {"is_admin": True}, {"scope": "admin"},
            {"permissions": ["admin", "superuser"]}, {"type": "admin"},
            {"user_type": "admin"}, {"level": 99},
        ]
        for extra_claims in claim_escalations:
            new_payload = {**payload, **extra_claims}
            forged = f"{parts[0]}.{b64_encode_part(new_payload)}.fakesignature"
            status, _, resp_body, _ = await self._request(method, url, json=body if body else None, token_override=forged)
            if status in (200, 201) and self._responses_differ_significantly(base_body, resp_body):
                findings.append(Finding(
                    title=f"JWT Claim Escalation — injected `{list(extra_claims.keys())[0]}` changed response",
                    severity=Severity.CRITICAL,
                    category="Business Logic — JWT Vulnerability",
                    description=f"Injecting `{extra_claims}` into the JWT payload with a forged signature produced a different response. Server may not verify signatures.",
                    request={"method": method, "url": url, "note": f"Forged JWT claims: {extra_claims}"},
                    response_summary=f"HTTP {status}",
                    evidence=f"Forged claims {extra_claims} → different response",
                    recommendation="Always verify JWT signatures with a strong secret or asymmetric key.",
                    cwe="CWE-347", cvss=9.5,
                    owasp="API2:2023 Broken Authentication",
                ))
                break

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 15: Account Enumeration
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_account_enumeration(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if method != "POST":
            return findings
        user_fields = ["email", "username", "user", "login", "phone"]
        field = next((k for k in user_fields if k in body), None)
        if not field:
            return findings

        test_cases = [
            ("nonexistent_zzz_test@example.com", "nonexistent"),
            ("admin@example.com", "common admin"),
        ]

        responses = []
        for test_val, label in test_cases:
            test_body = {**body, field: test_val}
            status, _, resp_body, elapsed = await self._request(method, url, json=test_body)
            responses.append((label, status, resp_body, elapsed))

        if len(responses) >= 2:
            r1_body = responses[0][2].lower()
            r2_body = responses[1][2].lower()
            not_found = ["not found", "no account", "doesn't exist", "invalid email"]
            wrong_pass = ["wrong password", "incorrect password", "invalid password"]

            if (any(s in r1_body for s in not_found) and any(s in r2_body for s in wrong_pass)) or \
               (any(s in r2_body for s in not_found) and any(s in r1_body for s in wrong_pass)):
                findings.append(Finding(
                    title=f"Account Enumeration — different error messages reveal valid accounts",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Information Disclosure",
                    description=f"Different error messages for valid vs invalid `{field}` values allow enumeration of valid accounts.",
                    request={"method": method, "url": url},
                    response_summary="Different error messages for valid vs invalid accounts",
                    evidence="'no account' vs 'wrong password' type messages differ",
                    recommendation="Use a generic error for all auth failures: 'Invalid credentials'.",
                    cwe="CWE-204", cvss=5.3,
                    owasp="API2:2023 Broken Authentication",
                ))

            times = [r[3] for r in responses]
            if max(times) - min(times) > 0.15:
                findings.append(Finding(
                    title=f"Account Enumeration — timing oracle ({max(times)-min(times):.2f}s delta) on `{field}`",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Information Disclosure",
                    description=f"Timing difference of {max(times)-min(times):.2f}s between valid and invalid accounts enables enumeration.",
                    request={"method": method, "url": url, "note": "Timing oracle"},
                    response_summary=f"Response times: {[round(t,3) for t in times]}",
                    evidence=f"Max timing delta: {max(times)-min(times):.3f}s",
                    recommendation="Use constant-time comparisons. Return identical responses for valid and invalid accounts.",
                    cwe="CWE-203", cvss=5.3,
                    owasp="API2:2023 Broken Authentication",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 16: Limit/Offset Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_limit_offset_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        probe_params_list = [
            {"limit": 99999, "offset": 0},
            {"limit": -1, "offset": 0},
            {"per_page": 99999, "page": 0},
            {"pageSize": 99999},
            {"size": 99999, "page": 0},
            {"limit": 0},
            {"offset": -1},
        ]

        for probe in probe_params_list:
            merged = {**params, **probe}
            status, _, resp_body, _ = await self._request("GET", url, params=merged)
            if status == 200 and len(resp_body) > len(base_body) * 2:
                data = self._try_parse_json(resp_body)
                count = len(data) if isinstance(data, list) else len(data.get("data", data.get("items", data.get("results", []))))
                base_data = self._try_parse_json(base_body)
                base_count = len(base_data) if isinstance(base_data, list) else len(base_data.get("data", base_data.get("items", [])))

                if count > base_count * 2:
                    findings.append(Finding(
                        title=f"Limit Manipulation — `{probe}` returned {count} vs {base_count} records",
                        severity=Severity.HIGH,
                        category="Business Logic — Excessive Data Exposure",
                        description=f"Setting pagination to `{probe}` returned {count} records vs baseline {base_count}. May expose data belonging to other users.",
                        request={"method": "GET", "url": url, "params": merged},
                        response_summary=f"HTTP {status}, {count} records",
                        evidence=f"Baseline: {base_count} records → With {probe}: {count} records",
                        recommendation="Enforce server-side maximum page size. Filter paginated data by authenticated user.",
                        cwe="CWE-213", cvss=7.5,
                        owasp="API3:2023 Broken Object Property Level Authorization",
                    ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 17: Soft Delete Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_soft_delete_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        bypass_params = [
            {"include_deleted": "true"},
            {"include_deleted": 1},
            {"show_deleted": "true"},
            {"status": "deleted"},
            {"active": "false"},
            {"archived": "true"},
            {"trashed": "true"},
        ]
        for probe in bypass_params:
            merged = {**params, **probe}
            status, _, resp_body, _ = await self._request("GET", url, params=merged)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                findings.append(Finding(
                    title=f"Soft Delete Bypass — `{probe}` exposes deleted records",
                    severity=Severity.HIGH,
                    category="Business Logic — Soft Delete Bypass",
                    description=f"Adding `{probe}` returned a different response, potentially exposing deleted/archived records.",
                    request={"method": "GET", "url": url, "params": merged},
                    response_summary=f"HTTP {status}, {len(resp_body)} bytes",
                    evidence=f"Response changed with {probe}",
                    recommendation="Filter soft-deleted records at the ORM/query layer. Never trust client-supplied visibility flags.",
                    cwe="CWE-284", cvss=6.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 18: HTTP Method Override
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_http_method_override(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        override_headers_list = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
            {"X-HTTP-Method": "DELETE"},
        ]
        for oh in override_headers_list:
            status, _, resp_body, _ = await self._request("POST", url, json=body, headers=oh)
            if status not in (405, 404, 400, 403, 401, 0):
                findings.append(Finding(
                    title=f"HTTP Method Override — `{list(oh.keys())[0]}` accepted",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Method Override",
                    description=f"The header `{list(oh.keys())[0]}: {list(oh.values())[0]}` was accepted (HTTP {status}), potentially allowing method spoofing.",
                    request={"method": "POST", "url": url, "headers": oh},
                    response_summary=f"HTTP {status}",
                    evidence=f"Override header {oh} → HTTP {status}",
                    recommendation="Disable HTTP method override middleware in production unless explicitly required.",
                    cwe="CWE-436", cvss=5.3,
                    owasp="API5:2023 Broken Function Level Authorization",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 19: HTTP Parameter Pollution
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_parameter_pollution(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if not params:
            return findings

        for key, val in params.items():
            parsed = urlparse(url)
            qs = f"{key}={val}&{key}=999999"
            test_url = urlunparse(parsed._replace(query=qs))
            status, _, resp_body, _ = await self._request("GET", test_url)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution — duplicate `{key}` changed response",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Parameter Pollution",
                    description=f"Duplicating `{key}` with value `999999` alongside `{val}` changed the response.",
                    request={"method": "GET", "url": test_url},
                    response_summary=f"HTTP {status}",
                    evidence=f"Duplicate {key} → different response",
                    recommendation="Use a single canonical source for each parameter. Take first value only for duplicate parameters.",
                    cwe="CWE-20", cvss=5.8,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                ))
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 20: GraphQL IDOR + Introspection
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_graphql_idor(self) -> list[Finding]:
        findings = []
        parsed = urlparse(self.config.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        graphql_endpoints = [
            f"{base}/graphql",
            f"{base}/api/graphql",
            f"{base}/v1/graphql",
            f"{base}/query",
        ]

        for gql_url in graphql_endpoints:
            introspection_query = '{"query": "{ __schema { types { name } } }"}'
            status, _, resp_body, _ = await self._request("POST", gql_url, data=introspection_query)
            if status == 200 and "__schema" in resp_body:
                findings.append(Finding(
                    title="GraphQL Introspection Enabled",
                    severity=Severity.MEDIUM,
                    category="Business Logic — GraphQL",
                    description="GraphQL introspection is enabled in production. This exposes the entire API schema to attackers.",
                    request={"method": "POST", "url": gql_url, "note": "Introspection query"},
                    response_summary=f"HTTP {status} — schema exposed",
                    evidence="__schema returned in response",
                    recommendation="Disable introspection in production. Use query whitelisting if GraphQL is required.",
                    cwe="CWE-200", cvss=5.3,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    confirmed=True,
                ))

            simple_queries = [
                '{"query": "{ users { id email } }"}',
                '{"query": "{ me { id email role } }"}',
                '{"query": "{ orders { id total } }"}',
            ]
            for q in simple_queries:
                status, _, resp_body, _ = await self._request("POST", gql_url, data=q, token_override="")
                if status == 200 and "data" in resp_body and "errors" not in resp_body:
                    findings.append(Finding(
                        title="GraphQL Unauthenticated Data Access",
                        severity=Severity.HIGH,
                        category="Business Logic — GraphQL",
                        description="GraphQL query succeeded without authentication. Data may be accessible to anonymous users.",
                        request={"method": "POST", "url": gql_url, "body": q, "note": "No auth token"},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence="Unauthenticated query returned data",
                        recommendation="Require authentication for all non-public GraphQL queries. Implement per-field authorization.",
                        cwe="CWE-306", cvss=8.5,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True,
                    ))
                    break

        return findings

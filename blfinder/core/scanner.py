"""
BLFinder v2.1 — Business Logic Flaw Scanner
Optimized for bug bounty hunting on Termux/Android

Changes in v2.1:
  - Integrated PoC generation for every finding
  - Confidence scoring on every finding
  - FindingVerifier re-tests before reporting
  - Improved false positive reduction throughout
  - Semantic response analysis (not just status codes)
  - Better IDOR baseline comparison
"""

import asyncio
import aiohttp
import json
import time
import re
import hashlib
import copy
import itertools
import base64
import difflib
from typing import Optional, Any
from urllib.parse import urlparse, urljoin, urlunparse
from dataclasses import field
from enum import Enum
from collections import defaultdict

from .models import Finding, ScanConfig, Severity, ProofOfConcept
from .confidence import ConfidenceEngine, severity_from_confidence
from .poc import PoCGenerator
from .verifier import FindingVerifier


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "PostmanRuntime/7.37.0",
    "python-httpx/0.27.0",
]


class AdaptiveRateLimiter:
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
            print(f"  [!] 429 — backing off to {new_delay:.1f}s for {domain}")
        elif status in (200, 201, 204, 301, 302, 400, 401, 403, 404):
            self.consecutive_ok[domain] += 1
            self.consecutive_429[domain] = 0
            if self.consecutive_ok[domain] > 10:
                current = self.delays.get(domain, self.base_delay)
                self.delays[domain] = max(self.base_delay, current * 0.85)


class BLFScanner:

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
        self.confidence_engine = ConfidenceEngine()
        self.poc_generator = PoCGenerator(config)
        self._verifier: Optional[FindingVerifier] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl, limit=20, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout, connect=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        self._verifier = FindingVerifier(self, self.config)
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _build_headers(self, extra: dict = None, token: str = None) -> dict:
        ua = next(self._ua_cycle) if self.config.user_agent_rotate else UA_POOL[0]
        headers = {
            "User-Agent": ua,
            "Accept": "application/json, text/html, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        t = token if token is not None else self.config.auth_token
        if t:
            headers["Authorization"] = f"Bearer {t}"
        headers.update(self.config.headers)
        if extra:
            headers.update(extra)
        return headers

    async def _request(
        self, method: str, url: str,
        headers: dict = None, token_override: str = None,
        **kwargs
    ) -> tuple[int, dict, str, float]:
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
                method, url, headers=req_headers,
                cookies=self.config.cookies,
                allow_redirects=True, max_redirects=self.config.max_redirects,
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

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _try_parse_json(self, body: str):
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _hash_response(self, body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    def _responses_differ_significantly(self, a: str, b: str) -> bool:
        if a == b:
            return False
        sim = difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()
        return sim < (1.0 - self.config.similarity_threshold)

    def _response_indicates_success(self, body: str, status: int = 200) -> bool:
        if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
            return False
        if status >= 500:
            return False
        body_lower = body.lower()
        failure = ["error", "invalid", "failed", "unauthorized", "forbidden",
                   "not found", "rejected", "denied", "exception", "bad request",
                   "validation", "required", "missing", "stack trace"]
        success = ["success", "true", "created", "updated", "confirmed",
                   "processed", "completed", "accepted", "ok", "order_id",
                   "transaction_id", "payment_id", "id", "token"]
        has_failure = any(s in body_lower for s in failure)
        has_success = any(s in body_lower for s in success)
        if status in (200, 201, 204):
            return not has_failure
        return has_success and not has_failure

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
                for sub in self._mutate_nested(v, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[k] = sub
                    mutations.append(m)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                for sub in self._mutate_nested(item, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[i] = sub
                    mutations.append(m)
        return mutations

    def _finalize_finding(self, finding: Finding, base_body: str, tampered_body: str,
                           base_status: int, tampered_status: int) -> Finding:
        """Apply confidence scoring, PoC generation, and severity calibration."""
        # Score confidence
        finding = self.confidence_engine.score(
            finding, base_body, tampered_body, base_status, tampered_status
        )
        # Calibrate severity
        finding = severity_from_confidence(finding)
        # Generate PoC
        finding.poc = self.poc_generator.generate(finding)
        return finding

    # ── Discovery ─────────────────────────────────────────────────────────────

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
            discovered = set()
            for pat in api_patterns:
                for m in re.findall(pat, body, re.I):
                    if isinstance(m, str) and m.startswith("/"):
                        discovered.add(m.split("?")[0])

            js_urls = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
            parsed = urlparse(seed_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in discovered:
                method = "POST" if any(k in path.lower() for k in ["creat", "add", "submit", "order", "checkout"]) else "GET"
                found.append({"url": urljoin(base, path), "method": method, "body": {}, "params": {}})
            for js_url in js_urls[:5]:
                full = urljoin(base, js_url) if not js_url.startswith("http") else js_url
                await fetch_and_extract(full)

        await fetch_and_extract(seed_url)

        common = [
            "/api/v1", "/api/v2", "/api", "/v1", "/v2",
            "/graphql", "/api/graphql", "/api/users", "/api/me",
            "/api/orders", "/api/payments", "/api/admin",
            "/swagger.json", "/openapi.json", "/api-docs",
        ]
        parsed = urlparse(seed_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        probes = await asyncio.gather(*[self._request("GET", f"{base}{p}") for p in common], return_exceptions=True)
        for path, result in zip(common, probes):
            if isinstance(result, tuple) and result[0] == 200:
                ep_url = f"{base}{path}"
                found.append({"url": ep_url, "method": "GET", "body": {}, "params": {}})
                print(f"  [+] Discovered: {ep_url}")
                if "openapi" in path or "swagger" in path:
                    found.extend(self._parse_openapi(result[2], base))

        self.discovered_endpoints = found
        print(f"  [*] Discovered {len(found)} endpoints\n")
        return found

    def _parse_openapi(self, spec_body: str, base_url: str) -> list[dict]:
        endpoints = []
        try:
            spec = json.loads(spec_body)
            for path, methods in spec.get("paths", {}).items():
                for method, info in methods.items():
                    if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        body = {}
                        rb = info.get("requestBody", {})
                        if rb:
                            schema = rb.get("content", {}).get("application/json", {}).get("schema", {})
                            for k, v in schema.get("properties", {}).items():
                                t = v.get("type", "string")
                                body[k] = 1 if t in ("integer", "number") else (True if t == "boolean" else "test")
                        endpoints.append({"url": urljoin(base_url, path), "method": method.upper(), "body": body, "params": {}})
        except Exception:
            pass
        return endpoints

    # ── Main Runner ───────────────────────────────────────────────────────────

    async def run_all_modules(self, endpoints: list[dict]) -> list[Finding]:
        print(f"[*] BLFinder v2.1 — Target: {self.config.target_url}")
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
            tasks.append(self._run_endpoint_checks(url, ep.get("method", "GET").upper(), ep.get("body", {}), ep.get("params", {})))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_findings = []
        for r in results:
            if isinstance(r, list):
                raw_findings.extend(r)

        raw_findings.extend(await self._check_graphql_idor())

        # Filter by minimum confidence
        above_threshold = [f for f in raw_findings if f.confidence >= self.config.min_confidence]
        below = len(raw_findings) - len(above_threshold)
        if below > 0:
            print(f"  [*] Dropped {below} low-confidence findings (below {self.config.min_confidence}%)")

        # Re-verify remaining findings
        print(f"[*] Verifying {len(above_threshold)} findings...")
        verified = await self._verifier.verify_all(above_threshold, self.base_responses)

        # Deduplicate
        seen = set()
        unique = []
        for f in verified:
            key = hashlib.md5(f"{f.title}{f.evidence}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique
        print(f"[*] Final: {len(self.findings)} verified findings\n")
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
            "hash": self._hash_response(base_body), "elapsed": elapsed, "headers": headers,
        }

        checks = [
            self._check_price_manipulation(url, method, body, params, status, base_body),
            self._check_quantity_negative(url, method, body, params, status, base_body),
            self._check_workflow_bypass(url, method, body, params, status, base_body),
            self._check_mass_assignment(url, method, body, params, status, base_body),
            self._check_idor_bola(url, method, body, params, status, base_body, headers),
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
        price_keys = ["price", "amount", "total", "cost", "fee", "charge", "unit_price",
                      "subtotal", "payment_amount", "order_total", "grand_total", "final_price", "shipping_cost"]
        tamper_values = [0, 0.01, -1, -100, 0.00001, "0", "0.00", 1, None, False]

        def find_price_fields(obj, keys, results, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(pk in k.lower() for pk in keys):
                        results.append((path + f".{k}" if path else k, k, v))
                    find_price_fields(v, keys, results, path + f".{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_price_fields(item, keys, results, path + f"[{i}]")

        price_fields = []
        find_price_fields(body, price_keys, price_fields)

        for field_path, key, original in price_fields:
            for tampered in tamper_values:
                for mutated_body in self._mutate_nested(body, key, tampered):
                    status, _, resp_body, _ = await self._request(method, url, json=mutated_body)
                    if status not in (200, 201):
                        continue

                    # FP check: confirm order was actually created
                    resp_data = self._try_parse_json(resp_body)
                    confirmed = False
                    evidence_detail = ""
                    if isinstance(resp_data, dict):
                        for rk, rv in resp_data.items():
                            if any(pk in rk.lower() for pk in price_keys):
                                if isinstance(rv, (int, float)) and rv != original:
                                    confirmed = True
                                    evidence_detail = f" → server returned {rk}={rv}"
                                    break

                    # Must actually indicate success (not just 200)
                    if not self._response_indicates_success(resp_body, status):
                        continue

                    f = Finding(
                        title=f"Price Manipulation — `{field_path}` accepted tampered value `{tampered}`",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Price Manipulation",
                        description=(
                            f"Field `{field_path}` (original: `{original}`) accepted tampered value `{tampered}`. "
                            f"{'Order likely created at manipulated price.' if confirmed else 'Server returned success.'}"
                        ),
                        request={"method": method, "url": url, "body": mutated_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"Original={original} → Tampered={tampered} → HTTP {status}{evidence_detail}",
                        recommendation="Compute all prices server-side from a trusted catalog. Never accept client-submitted price values.",
                        cwe="CWE-20", cvss=9.1,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=confirmed, endpoint=url, parameter=field_path,
                    )
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    break
            if findings:
                break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 2: Negative Quantity
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_quantity_negative(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        qty_keys = ["quantity", "qty", "count", "units", "items", "amount", "number", "stock"]

        for key in qty_keys:
            if key not in body:
                continue
            original = body[key]
            for tampered in [-1, -100, -9999, 0, -0.5]:
                test_body = {**body, key: tampered}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201) or not self._response_indicates_success(resp_body, status):
                    continue

                # FP check: make sure this isn't a generic 200 for everything
                # Re-test with an obviously invalid value to see if anything is rejected
                canary_body = {**body, key: "INVALID_STRING_VALUE"}
                cs, _, _, _ = await self._request(method, url, json=canary_body)
                if cs in (200, 201):
                    # Server accepts everything — not a real vuln, skip
                    continue

                f = Finding(
                    title=f"Negative Quantity Exploit — `{key}` = {tampered} accepted",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Negative Value",
                    description=f"`{key}` = {tampered} (original: {original}) was accepted. May trigger refunds or reverse charges.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"qty={tampered} → HTTP {status} (canary 'INVALID_STRING_VALUE' → HTTP {cs} ✓)",
                    recommendation="Enforce qty >= 1 server-side. Reject negative and zero values explicitly.",
                    cwe="CWE-20", cvss=9.3,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 3: Advanced IDOR / BOLA
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_idor_bola(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        path_segments = parsed.path.split("/")

        # ── Path-based ID enumeration ──────────────────────────────────────────
        for seg_idx, segment in enumerate(path_segments):
            if not segment:
                continue

            if re.match(r'^\d{1,12}$', segment):
                original_id = int(segment)
                for test_id in [original_id - 1, original_id + 1, 1, 2, 3]:
                    if test_id <= 0:
                        continue
                    new_segs = path_segments[:]
                    new_segs[seg_idx] = str(test_id)
                    test_url = urlunparse(parsed._replace(path="/".join(new_segs)))

                    status, _, resp_body, _ = await self._request(method, test_url, json=body if body else None)

                    # FP checks:
                    # 1. Must return different data (not just same 200)
                    if status != 200:
                        continue
                    if not self._responses_differ_significantly(base_body, resp_body):
                        continue
                    # 2. Must not be a generic "not found" body with 200 status
                    if any(t in resp_body.lower() for t in ["not found", "no resource", "does not exist"]):
                        continue
                    # 3. Cross-user confirmation (strongest signal)
                    confirmed = False
                    if self.config.second_user_token:
                        s2, _, rb2, _ = await self._request(method, test_url, json=body if body else None, token_override=self.config.second_user_token)
                        confirmed = s2 == 200 and self._responses_differ_significantly(base_body, rb2)

                    f = Finding(
                        title=f"IDOR/BOLA — Path ID {original_id} → {test_id} returns different resource",
                        severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                        category="Business Logic — IDOR/BOLA",
                        description=f"Changing path ID from {original_id} to {test_id} returned a different 200 response with {len(resp_body)} bytes. {'Cross-user access CONFIRMED.' if confirmed else ''}",
                        request={"method": method, "url": test_url},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"ID {original_id} → {test_id}: responses differ (sim < {self.config.similarity_threshold:.0%}) {'[CROSS-USER CONFIRMED]' if confirmed else ''}",
                        recommendation="Enforce ownership checks on every request. Tie resource access to authenticated session, not just the ID.",
                        cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                        owasp="API1:2023 Broken Object Level Authorization",
                        confirmed=confirmed, endpoint=url, parameter=f"path[{seg_idx}]",
                    )
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    if confirmed:
                        break

            # UUID swap
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I):
                for test_uuid in ["00000000-0000-0000-0000-000000000001", "11111111-1111-1111-1111-111111111111"]:
                    new_segs = path_segments[:]
                    new_segs[seg_idx] = test_uuid
                    test_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                    status, _, resp_body, _ = await self._request(method, test_url, json=body if body else None)
                    if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                        if any(t in resp_body.lower() for t in ["not found", "no resource"]):
                            continue
                        f = Finding(
                            title=f"IDOR/BOLA — UUID swap in path returned different resource",
                            severity=Severity.HIGH,
                            category="Business Logic — IDOR/BOLA",
                            description=f"Replacing UUID `{segment}` with `{test_uuid}` returned different data. UUIDs are not an access control mechanism.",
                            request={"method": method, "url": test_url},
                            response_summary=f"HTTP {status} — {resp_body[:300]}",
                            evidence=f"UUID {segment} → {test_uuid}: different response",
                            recommendation="Verify object ownership against authenticated user on every request.",
                            cwe="CWE-639", cvss=8.5,
                            owasp="API1:2023 Broken Object Level Authorization",
                            endpoint=url,
                        )
                        f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                        if f.confidence >= self.config.min_confidence:
                            findings.append(f)
                        break

        # ── Body ID replacement ────────────────────────────────────────────────
        id_keys = ["id", "user_id", "account_id", "order_id", "customer_id",
                   "profile_id", "subscription_id", "payment_id"]
        for key in id_keys:
            if key not in body:
                continue
            original_val = body[key]
            test_vals = []
            if isinstance(original_val, int):
                test_vals = [original_val - 1, original_val + 1, 1, 2]
            elif isinstance(original_val, str) and original_val.isdigit():
                test_vals = [str(int(original_val) + 1), "1", "2"]

            for test_val in test_vals:
                if not test_val or test_val == original_val:
                    continue
                test_body = {**body, key: test_val}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status != 200 or not self._responses_differ_significantly(base_body, resp_body):
                    continue
                if any(t in resp_body.lower() for t in ["not found", "no resource", "does not exist"]):
                    continue

                confirmed = False
                if self.config.second_user_token:
                    s2, _, _, _ = await self._request(method, url, json=test_body, token_override=self.config.second_user_token)
                    confirmed = s2 == 200

                f = Finding(
                    title=f"IDOR/BOLA — body field `{key}` = {test_val} exposed different resource",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    category="Business Logic — IDOR/BOLA",
                    description=f"Changing `{key}` from `{original_val}` to `{test_val}` returned different data. {'Cross-user CONFIRMED.' if confirmed else ''}",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"body.{key}: {original_val} → {test_val}: responses differ {'[CONFIRMED]' if confirmed else ''}",
                    recommendation="Validate that the referenced object belongs to the authenticated user.",
                    cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confirmed=confirmed, endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)

        # ── No-auth access ────────────────────────────────────────────────────
        if self.config.no_auth_check:
            s_noauth, _, rb_noauth, _ = await self._request(method, url, json=body if body else None, token_override="")
            # FP: check that authenticated response and unauthenticated are similar (otherwise it's a generic public endpoint)
            if s_noauth in (200, 201) and self._response_indicates_success(rb_noauth, s_noauth):
                sim = difflib.SequenceMatcher(None, base_body[:2000], rb_noauth[:2000]).ratio()
                if sim > 0.7:  # Returns same data as when authenticated → real leak
                    f = Finding(
                        title="Unauthenticated Access — authenticated resource accessible without token",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Missing Authentication",
                        description=f"Removing the Authorization header returned HTTP {s_noauth} with similar data to the authenticated response (similarity={sim:.0%}).",
                        request={"method": method, "url": url, "note": "No Authorization header"},
                        response_summary=f"HTTP {s_noauth} — {rb_noauth[:300]}",
                        evidence=f"No-auth → HTTP {s_noauth}, response similarity to authed={sim:.0%}",
                        recommendation="Require authentication on all non-public endpoints.",
                        cwe="CWE-306", cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True, endpoint=url,
                    )
                    f = self._finalize_finding(f, base_body, rb_noauth, base_status, s_noauth)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)

        # ── Header-based ID injection ─────────────────────────────────────────
        id_headers_list = [
            {"X-User-Id": "1"}, {"X-Account-Id": "1"},
            {"X-Admin-User": "true"}, {"X-Internal-User": "1"},
        ]
        for id_hdr in id_headers_list:
            status, _, resp_body, _ = await self._request(method, url, json=body if body else None, headers=id_hdr)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                hdr_name = list(id_hdr.keys())[0]
                f = Finding(
                    title=f"Header-based IDOR — `{hdr_name}` overrides user context",
                    severity=Severity.CRITICAL,
                    category="Business Logic — IDOR/BOLA",
                    description=f"Adding `{hdr_name}: {id_hdr[hdr_name]}` returned a different response, suggesting this header overrides the authenticated user context.",
                    request={"method": method, "url": url, "headers": id_hdr},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"Header `{hdr_name}` changed response significantly",
                    recommendation="Never trust user-controlled headers for identity.",
                    cwe="CWE-639", cvss=9.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confirmed=True, endpoint=url,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 4: BOPLA
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_bopla(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        base_len = len(base_body)

        for probe in [
            {"expand": "all"}, {"fields": "*"}, {"include": "all"},
            {"verbose": "1"}, {"full": "true"}, {"show_private": "1"},
        ]:
            status, _, resp_body, _ = await self._request("GET", url, params={**params, **probe})
            if status != 200 or len(resp_body) <= base_len * 1.15:
                continue

            base_data = self._try_parse_json(base_body)
            new_data = self._try_parse_json(resp_body)
            new_keys = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())

            sensitive = ["password", "secret", "token", "private_key", "ssn", "dob",
                         "credit_card", "cvv", "bank", "salary", "internal", "hash", "salt"]
            has_sensitive = any(sf in " ".join(new_keys).lower() for sf in sensitive)

            f = Finding(
                title=f"BOPLA — `{list(probe.keys())[0]}` param exposes hidden fields",
                severity=Severity.HIGH if has_sensitive else Severity.MEDIUM,
                category="Business Logic — Object Property Exposure",
                description=f"Adding `{probe}` returned {len(resp_body) - base_len} extra bytes. New fields: {list(new_keys)[:5]}. {'Sensitive fields present!' if has_sensitive else ''}",
                request={"method": "GET", "url": url, "params": {**params, **probe}},
                response_summary=f"HTTP {status}, {len(resp_body)} vs {base_len} bytes",
                evidence=f"+{len(resp_body) - base_len} bytes, new keys: {list(new_keys)[:5]}",
                recommendation="Implement property-level authorization. Define explicit field allowlists per role.",
                cwe="CWE-213", cvss=7.5 if has_sensitive else 5.3,
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=url,
            )
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 5: Workflow Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_workflow_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        for pattern, label in [(r"/step[_-]?(\d+)", "step"), (r"/stage[_-]?(\d+)", "stage")]:
            match = re.search(pattern, path, re.IGNORECASE)
            if not match:
                continue
            current_step = match.group(1)
            try:
                for delta in [2, 3]:
                    next_step = str(int(current_step) + delta)
                    new_path = re.sub(pattern, match.group(0).replace(current_step, next_step), path, flags=re.IGNORECASE)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    status, _, resp_body, _ = await self._request(method, new_url, json=body)
                    if status in (200, 201):
                        # FP: confirm baseline step URL doesn't also return 200 for any step number
                        canary_url = urlunparse(parsed._replace(path=re.sub(pattern, match.group(0).replace(current_step, "999"), path, flags=re.IGNORECASE)))
                        cs, _, _, _ = await self._request(method, canary_url, json=body)
                        if cs == 200:
                            continue  # Server returns 200 for any step — no bypass

                        f = Finding(
                            title=f"Workflow Step Bypass — jumped {label} {current_step} → {next_step}",
                            severity=Severity.HIGH,
                            category="Business Logic — Workflow Bypass",
                            description=f"Directly accessing {label} {next_step} without completing {label} {current_step} returned HTTP {status}.",
                            request={"method": method, "url": new_url, "body": body},
                            response_summary=f"HTTP {status}",
                            evidence=f"Skip {current_step} → {next_step} succeeded (canary step 999 → {cs} ✓)",
                            recommendation="Enforce sequential step validation using signed server-side session state.",
                            cwe="CWE-284", cvss=7.5,
                            owasp="API5:2023 Broken Function Level Authorization",
                            endpoint=url,
                        )
                        f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                        if f.confidence >= self.config.min_confidence:
                            findings.append(f)
            except (ValueError, TypeError):
                pass

        # OTP/MFA token omission
        for key in ["otp", "mfa_token", "verification_token", "step_token"]:
            if key not in body:
                continue
            test_body = {k: v for k, v in body.items() if k != key}
            status, _, resp_body, _ = await self._request(method, url, json=test_body)
            if status in (200, 201) and self._response_indicates_success(resp_body, status):
                f = Finding(
                    title=f"MFA/OTP Token Omission — `{key}` not validated server-side",
                    severity=Severity.HIGH,
                    category="Business Logic — Workflow Bypass",
                    description=f"Removing `{key}` from the request still returned success, indicating the MFA/OTP step is not enforced server-side.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Missing `{key}` → HTTP {status}",
                    recommendation="Validate OTP/MFA tokens server-side. Require and verify before any action.",
                    cwe="CWE-284", cvss=8.5,
                    owasp="API5:2023 Broken Function Level Authorization",
                    endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 6: Mass Assignment
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_mass_assignment(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        privileged_keys = [
            "is_admin", "admin", "role", "roles", "permissions",
            "is_premium", "premium", "subscription", "plan",
            "credits", "balance", "is_staff", "approved",
            "email_verified", "kyc_verified", "price_override", "tax_exempt",
        ]

        for key in privileged_keys:
            test_body = {**body, key: True}
            status, _, resp_body, _ = await self._request(method, url, json=test_body)
            if status not in (200, 201):
                continue

            resp_data = self._try_parse_json(resp_body)
            if not isinstance(resp_data, dict):
                continue

            # FP: field must actually be reflected with the injected value
            reflected = resp_data.get(key)
            if reflected not in (True, "true", 1, "admin", "premium", "verified"):
                continue

            # FP: confirm baseline response does NOT have this field set to True
            base_data = self._try_parse_json(base_body)
            if isinstance(base_data, dict) and base_data.get(key) == reflected:
                continue  # Already set — no injection occurred

            f = Finding(
                title=f"Mass Assignment — `{key}` injected and reflected as `{reflected}`",
                severity=Severity.CRITICAL,
                category="Business Logic — Mass Assignment",
                description=f"Injecting `{key}: true` was accepted and reflected as `{reflected}` in the response. Privilege escalation confirmed.",
                request={"method": method, "url": url, "body": test_body},
                response_summary=f"HTTP {status}, `{key}` = {reflected}",
                evidence=f"Injected `{key}=True` → response shows `{key}={reflected}` (was not present in baseline)",
                recommendation="Use an explicit field allowlist. Never pass raw request bodies to ORM methods.",
                cwe="CWE-915", cvss=9.8,
                owasp="API3:2023 Broken Object Property Level Authorization",
                confirmed=True, endpoint=url, parameter=key,
            )
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 7: Privilege Escalation / BFLA
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_privilege_escalation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        admin_paths = [
            "/admin", "/api/admin", "/api/v1/admin",
            "/manage", "/api/users/all", "/api/roles", "/api/permissions",
            "/internal", "/api/internal", "/api/metrics", "/api/config",
        ]
        for admin_path in admin_paths:
            test_url = f"{base}{admin_path}"
            for token, label in [(self.config.auth_token, "low-priv"), ("", "no-auth")]:
                status, _, resp_body, _ = await self._request("GET", test_url, token_override=token)
                if status != 200:
                    continue
                # FP: Check response has actual content, not a generic landing page
                if len(resp_body) < 50 or not self._response_indicates_success(resp_body, status):
                    continue
                f = Finding(
                    title=f"BFLA — `{admin_path}` accessible by {label} user",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=f"Admin endpoint `{admin_path}` returned HTTP 200 with content ({len(resp_body)} bytes) using a {label} token.",
                    request={"method": "GET", "url": test_url, "note": f"Token: {label}"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"GET {test_url} with {label} → 200 + {len(resp_body)} bytes",
                    recommendation="Enforce RBAC on all admin endpoints using middleware.",
                    cwe="CWE-269", cvss=9.8,
                    owasp="API5:2023 Broken Function Level Authorization",
                    confirmed=True, endpoint=test_url,
                )
                f = self._finalize_finding(f, "", resp_body, 403, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings

    async def _check_function_level_access(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if not self.config.second_user_token:
            return findings
        for test_method in ["DELETE", "PUT", "PATCH"]:
            if test_method == method:
                continue
            status, _, resp_body, _ = await self._request(test_method, url, json=body if body else None, token_override=self.config.second_user_token)
            if status in (200, 201, 204):
                f = Finding(
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
                    confirmed=True, endpoint=url,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 8: Coupon Abuse
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_coupon_stacking(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        coupon_keys = ["coupon", "coupon_code", "promo_code", "discount_code", "voucher", "promo"]

        for key in coupon_keys:
            if key not in body:
                continue
            original = body[key]
            base_discount = self._extract_discount(base_body)

            for test_body, label in [
                ({**body, key: [original, original]}, "duplicate array"),
                ({**body, key: [original]}, "single-item array"),
            ]:
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201) or not self._response_indicates_success(resp_body, status):
                    continue
                new_discount = self._extract_discount(resp_body)
                confirmed = bool(new_discount and base_discount and new_discount > base_discount * 1.4)
                f = Finding(
                    title=f"Coupon Abuse — {label} accepted for `{key}`",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    category="Business Logic — Coupon Abuse",
                    description=f"Sending `{key}` as {label} was accepted. {'Discount increased: ' + str(base_discount) + ' → ' + str(new_discount) + '.' if confirmed else 'Possible stacking.'}",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Coupon as {label}: discount {base_discount} → {new_discount}",
                    recommendation="Normalize coupon inputs. Enforce one-coupon-per-order server-side. Reject arrays for string fields.",
                    cwe="CWE-20", cvss=8.5 if confirmed else 6.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confirmed=confirmed, endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    def _extract_discount(self, body: str) -> float:
        try:
            data = json.loads(body)
            for key in ["discount", "discount_amount", "savings", "coupon_value"]:
                if isinstance(data, dict) and key in data:
                    return float(data[key])
        except Exception:
            pass
        return 0.0

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 9: Time Logic Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_time_logic_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        time_keys = ["date", "expiry", "expiry_date", "expires_at", "valid_until",
                     "timestamp", "start_date", "end_date", "valid_from"]

        for key in time_keys:
            if key not in body:
                continue
            for ts, label in [("2099-12-31T23:59:59Z", "far-future"), (-1, "unix-negative")]:
                test_body = {**body, key: ts}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status in (200, 201) and self._response_indicates_success(resp_body, status):
                    # FP: confirm baseline with original value also succeeds differently
                    if self._hash_response(resp_body) != self._hash_response(base_body):
                        f = Finding(
                            title=f"Time Bypass — `{key}` accepts {label} timestamp",
                            severity=Severity.HIGH,
                            category="Business Logic — Time Bypass",
                            description=f"Setting `{key}` to {ts} ({label}) was accepted and produced a different response.",
                            request={"method": method, "url": url, "body": test_body},
                            response_summary=f"HTTP {status}",
                            evidence=f"`{key}` = {ts} → different response",
                            recommendation="Validate all timestamps server-side using server time only.",
                            cwe="CWE-20", cvss=7.3,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            endpoint=url, parameter=key,
                        )
                        f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                        if f.confidence >= self.config.min_confidence:
                            findings.append(f)
                        break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 10: Integer Overflow
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_integer_overflow(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        numeric_keys = [k for k, v in body.items() if isinstance(v, (int, float)) and not isinstance(v, bool)]

        for key in numeric_keys:
            for val in [2**31 - 1, 2**63 - 1, -2**31, 9999999999]:
                test_body = {**body, key: val}
                try:
                    status, _, resp_body, _ = await self._request(method, url, json=test_body)
                    if status == 500:
                        f = Finding(
                            title=f"Integer Overflow — `{key}` = {val} caused server error",
                            severity=Severity.MEDIUM,
                            category="Business Logic — Integer Overflow",
                            description=f"Setting `{key}` to {val} caused HTTP 500.",
                            request={"method": method, "url": url, "body": test_body},
                            response_summary="HTTP 500",
                            evidence=f"Input {key}={val} → 500",
                            recommendation="Validate numeric ranges. Handle overflow explicitly.",
                            cwe="CWE-190", cvss=6.5,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            endpoint=url, parameter=key,
                        )
                        f = self._finalize_finding(f, base_body, resp_body, base_status, 500)
                        if f.confidence >= self.config.min_confidence:
                            findings.append(f)
                    elif status in (200, 201):
                        data = self._try_parse_json(resp_body)
                        if isinstance(data, dict):
                            for rk, rv in data.items():
                                if isinstance(rv, (int, float)) and not isinstance(rv, bool) and rv < 0:
                                    f = Finding(
                                        title=f"Integer Overflow — `{key}` = {val} caused negative `{rk}`",
                                        severity=Severity.HIGH,
                                        category="Business Logic — Integer Overflow",
                                        description=f"Setting `{key}` to {val} caused `{rk}` = {rv} (negative), indicating overflow.",
                                        request={"method": method, "url": url, "body": test_body},
                                        response_summary=f"HTTP {status}, {rk}={rv}",
                                        evidence=f"Input {key}={val} → response {rk}={rv}",
                                        recommendation="Use 64-bit integers. Validate input ranges.",
                                        cwe="CWE-190", cvss=7.8,
                                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                        confirmed=True, endpoint=url, parameter=key,
                                    )
                                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                                    if f.confidence >= self.config.min_confidence:
                                        findings.append(f)
                except Exception:
                    pass
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 11: Hidden Parameter Disclosure
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_hidden_parameter_disclosure(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        probes = {"debug": "1", "verbose": "1", "admin": "1", "internal": "1",
                  "full": "1", "include_deleted": "1", "show_all": "1", "_debug": "1"}

        for param, val in probes.items():
            status, _, resp_body, _ = await self._request("GET", url, params={**params, param: val})
            base_len = len(base_body)
            new_len = len(resp_body)
            if status != 200 or new_len <= base_len * 1.2 or new_len - base_len < 100:
                continue

            # FP: Check that baseline and probed responses are genuinely different structurally
            base_data = self._try_parse_json(base_body)
            new_data = self._try_parse_json(resp_body)
            new_keys = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())

            if not new_keys and new_len < base_len * 1.5:
                continue  # Just whitespace/formatting difference

            f = Finding(
                title=f"Hidden Parameter — `{param}` discloses extra data",
                severity=Severity.HIGH if new_len > base_len * 2 else Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=f"Adding `{param}={val}` returned {new_len - base_len} extra bytes. New fields: {list(new_keys)[:5]}.",
                request={"method": "GET", "url": url, "params": {**params, param: val}},
                response_summary=f"HTTP {status}, {new_len} vs {base_len} bytes",
                evidence=f"baseline={base_len}B → with param={new_len}B, new keys: {list(new_keys)[:5]}",
                recommendation="Remove debug params from production. Control verbosity server-side.",
                cwe="CWE-200", cvss=6.5,
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=url, parameter=param,
            )
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 12: State Machine Abuse
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_state_machine_abuse(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        state_map = {
            "status": ["completed", "approved", "paid", "shipped"],
            "order_status": ["completed", "delivered", "paid"],
            "payment_status": ["paid", "completed", "cleared"],
            "verification_status": ["verified", "approved"],
            "kyc_status": ["verified", "approved"],
        }

        for key, targets in state_map.items():
            if key not in body:
                continue
            for state in targets:
                if body.get(key) == state:
                    continue  # Already in this state

                test_body = {**body, key: state}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201):
                    continue

                data = self._try_parse_json(resp_body)
                # FP: state must actually be reflected in the response
                if not isinstance(data, dict) or data.get(key) != state:
                    continue

                f = Finding(
                    title=f"State Machine Abuse — `{key}` forced to `{state}`",
                    severity=Severity.CRITICAL,
                    category="Business Logic — State Machine Abuse",
                    description=f"Forcing `{key}` to `{state}` was accepted and confirmed in the response. Workflow conditions were bypassed.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}, {key}={state}",
                    evidence=f"Forced {key}={state} → confirmed in response (was: {body.get(key)})",
                    recommendation="Compute state transitions server-side. Never trust client state values.",
                    cwe="CWE-284", cvss=9.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confirmed=True, endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 13: Race Condition
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_race_condition(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if method not in ("POST", "PUT", "PATCH"):
            return findings
        race_indicators = ["redeem", "transfer", "withdraw", "claim", "checkout",
                           "purchase", "buy", "confirm", "coupon", "reward", "spin", "vote"]
        if not any(ind in url.lower() for ind in race_indicators):
            return findings

        orig_delay = self.rate_limiter.base_delay
        self.rate_limiter.base_delay = 0
        responses = await asyncio.gather(*[self._request(method, url, json=body) for _ in range(15)], return_exceptions=True)
        self.rate_limiter.base_delay = orig_delay

        success_count = sum(1 for r in responses if isinstance(r, tuple) and r[0] in (200, 201) and self._response_indicates_success(r[2], r[0]))

        if success_count > 1:
            # Verify: re-run single request to confirm it's still individually accessible
            single_status, _, _, _ = await self._request(method, url, json=body)
            f = Finding(
                title=f"Race Condition — {success_count}/15 concurrent requests succeeded",
                severity=Severity.CRITICAL,
                category="Business Logic — Race Condition",
                description=f"{success_count} of 15 simultaneous requests succeeded. Single-use or one-time operations may be exploitable for double-spending.",
                request={"method": method, "url": url, "body": body, "note": "15 concurrent requests"},
                response_summary=f"{success_count}/15 successes",
                evidence=f"Concurrent: {success_count}/15 succeeded. Single re-test: {single_status}",
                recommendation="Use DB-level locks (SELECT FOR UPDATE), Redis SETNX, or idempotency keys.",
                cwe="CWE-362", cvss=9.0,
                owasp="API4:2023 Unrestricted Resource Consumption",
                confirmed=True, endpoint=url,
            )
            f = self._finalize_finding(f, base_body, "", base_status, 200)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 14: JWT Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_jwt_manipulation(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings = []
        token = self.config.auth_token
        if not token or token.count(".") != 2:
            return findings

        parts = token.split(".")

        def b64d(part):
            pad = 4 - len(part) % 4
            try:
                return json.loads(base64.urlsafe_b64decode(part + "=" * pad))
            except Exception:
                return {}

        def b64e(data):
            return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

        header = b64d(parts[0])
        payload = b64d(parts[1])
        if not header or not payload:
            return findings

        # alg:none
        forged = f"{b64e({**header, 'alg': 'none'})}.{parts[1]}."
        status, _, resp_body, _ = await self._request(method, url, json=body if body else None, token_override=forged)
        if status in (200, 201) and self._response_indicates_success(resp_body, status):
            # FP: Confirm that a completely invalid token is NOT accepted
            totally_invalid = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZmFrZSJ9."
            ts2, _, _, _ = await self._request(method, url, json=body if body else None, token_override=totally_invalid)
            if ts2 in (200, 201):
                pass  # Server accepts anything — skip
            else:
                f = Finding(
                    title="JWT alg:none Bypass — original token accepted without signature",
                    severity=Severity.CRITICAL,
                    category="Business Logic — JWT Vulnerability",
                    description="Server accepted original payload with alg:none (no signature). Signatures are not verified.",
                    request={"method": method, "url": url, "note": "JWT with alg:none, original payload"},
                    response_summary=f"HTTP {status}",
                    evidence=f"alg:none with original payload → {status} (fully random token → {ts2})",
                    recommendation="Whitelist allowed algorithms. Reject 'none'. Use a hardened JWT library.",
                    cwe="CWE-347", cvss=10.0,
                    owasp="API2:2023 Broken Authentication",
                    confirmed=True, endpoint=url,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 15: Account Enumeration
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_account_enumeration(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if method != "POST":
            return findings
        field = next((k for k in ["email", "username", "login"] if k in body), None)
        if not field:
            return findings

        results = []
        for test_val in ["nonexistent_zzzz_test_9999@nowhere.invalid", "admin@example.com"]:
            test_body = {**body, field: test_val}
            s, _, rb, elapsed = await self._request(method, url, json=test_body)
            results.append((test_val, s, rb.lower(), elapsed))

        if len(results) < 2:
            return findings

        r1_body, r2_body = results[0][2], results[1][2]
        not_found = ["not found", "no account", "doesn't exist", "no user"]
        wrong_pass = ["wrong password", "incorrect password", "invalid password", "invalid credentials"]

        enum_by_message = (
            (any(s in r1_body for s in not_found) and any(s in r2_body for s in wrong_pass)) or
            (any(s in r2_body for s in not_found) and any(s in r1_body for s in wrong_pass))
        )

        times = [r[3] for r in results]
        timing_delta = max(times) - min(times)
        enum_by_timing = timing_delta > 0.20

        if enum_by_message:
            f = Finding(
                title="Account Enumeration — different error messages for valid vs invalid accounts",
                severity=Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=f"Different error messages for valid vs invalid `{field}` values enable user enumeration.",
                request={"method": method, "url": url},
                response_summary="Different messages: 'no account' vs 'wrong password'",
                evidence=f"'{results[0][0]}' message vs '{results[1][0]}' message differ",
                recommendation="Use a single generic error: 'Invalid credentials'.",
                cwe="CWE-204", cvss=5.3,
                owasp="API2:2023 Broken Authentication",
                confirmed=True, endpoint=url, parameter=field,
            )
            f = self._finalize_finding(f, base_body, results[0][2], base_status, results[0][1])
            if f.confidence >= self.config.min_confidence:
                findings.append(f)

        if enum_by_timing:
            f = Finding(
                title=f"Account Enumeration — timing oracle ({timing_delta:.2f}s delta) on `{field}`",
                severity=Severity.LOW,
                category="Business Logic — Information Disclosure",
                description=f"Timing difference of {timing_delta:.2f}s between valid and invalid accounts enables enumeration.",
                request={"method": method, "url": url, "note": "Timing oracle"},
                response_summary=f"Times: {[round(r[3], 3) for r in results]}",
                evidence=f"Delta: {timing_delta:.3f}s",
                recommendation="Use constant-time comparisons. Return identical responses for valid and invalid accounts.",
                cwe="CWE-203", cvss=3.7,
                owasp="API2:2023 Broken Authentication",
                endpoint=url, parameter=field,
            )
            f = self._finalize_finding(f, base_body, results[0][2], base_status, results[0][1])
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 16: Limit/Offset Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_limit_offset_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        for probe in [{"limit": 99999, "offset": 0}, {"per_page": 99999}, {"size": 99999}]:
            merged = {**params, **probe}
            status, _, resp_body, _ = await self._request("GET", url, params=merged)
            if status != 200 or len(resp_body) <= len(base_body) * 2:
                continue
            data = self._try_parse_json(resp_body)
            count = len(data) if isinstance(data, list) else len(data.get("data", data.get("items", []))) if isinstance(data, dict) else 0
            base_data = self._try_parse_json(base_body)
            base_count = len(base_data) if isinstance(base_data, list) else len(base_data.get("data", base_data.get("items", []))) if isinstance(base_data, dict) else 0

            if count > base_count * 2:
                f = Finding(
                    title=f"Limit Manipulation — `{probe}` returned {count} vs {base_count} records",
                    severity=Severity.HIGH,
                    category="Business Logic — Excessive Data Exposure",
                    description=f"Setting pagination to `{probe}` returned {count} records vs baseline {base_count}.",
                    request={"method": "GET", "url": url, "params": merged},
                    response_summary=f"HTTP {status}, {count} records",
                    evidence=f"Baseline: {base_count} records → probe: {count} records",
                    recommendation="Enforce server-side maximum page size. Filter by authenticated user.",
                    cwe="CWE-213", cvss=7.5,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    endpoint=url,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 17: Soft Delete Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_soft_delete_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        for probe in [{"include_deleted": "true"}, {"show_deleted": "true"}, {"archived": "true"}]:
            merged = {**params, **probe}
            status, _, resp_body, _ = await self._request("GET", url, params=merged)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                f = Finding(
                    title=f"Soft Delete Bypass — `{probe}` exposes deleted records",
                    severity=Severity.HIGH,
                    category="Business Logic — Soft Delete Bypass",
                    description=f"Adding `{probe}` returned a significantly different response, potentially exposing deleted/archived records.",
                    request={"method": "GET", "url": url, "params": merged},
                    response_summary=f"HTTP {status}, {len(resp_body)} bytes",
                    evidence=f"Response changed with {probe}",
                    recommendation="Filter soft-deleted records at the ORM layer. Never trust client-supplied visibility flags.",
                    cwe="CWE-284", cvss=6.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    endpoint=url,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 18: HTTP Method Override
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_http_method_override(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        for oh in [{"X-HTTP-Method-Override": "DELETE"}, {"X-Method-Override": "DELETE"}, {"_method": "DELETE"}]:
            status, _, resp_body, _ = await self._request("POST", url, json=body, headers=oh)
            if status not in (405, 404, 400, 403, 401, 0):
                # FP: confirm actual impact — not just a 200 for any POST
                if status in (200, 201) and self._responses_differ_significantly(base_body, resp_body):
                    f = Finding(
                        title=f"HTTP Method Override — `{list(oh.keys())[0]}` caused different response",
                        severity=Severity.MEDIUM,
                        category="Business Logic — Method Override",
                        description=f"Method override header `{oh}` was accepted and produced a different response than baseline POST.",
                        request={"method": "POST", "url": url, "headers": oh},
                        response_summary=f"HTTP {status}",
                        evidence=f"Override {oh} → {status} + different body",
                        recommendation="Disable HTTP method override middleware in production.",
                        cwe="CWE-436", cvss=5.3,
                        owasp="API5:2023 Broken Function Level Authorization",
                        endpoint=url,
                    )
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 19: Parameter Pollution
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_parameter_pollution(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        if not params:
            return findings
        for key, val in list(params.items())[:3]:  # Limit to 3 params
            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=f"{key}={val}&{key}=999999"))
            status, _, resp_body, _ = await self._request("GET", test_url)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                f = Finding(
                    title=f"HTTP Parameter Pollution — duplicate `{key}` changed response",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Parameter Pollution",
                    description=f"Duplicating `{key}` with an injected value changed the response significantly.",
                    request={"method": "GET", "url": test_url},
                    response_summary=f"HTTP {status}",
                    evidence=f"Duplicate {key} → significantly different response",
                    recommendation="Take only the first value for duplicate parameters. Reject or normalize duplicates.",
                    cwe="CWE-20", cvss=5.8,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 20: GraphQL
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_graphql_idor(self) -> list[Finding]:
        findings = []
        parsed = urlparse(self.config.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for gql_url in [f"{base}/graphql", f"{base}/api/graphql", f"{base}/query"]:
            status, _, resp_body, _ = await self._request("POST", gql_url, data='{"query": "{ __schema { types { name } } }"}')
            if status == 200 and "__schema" in resp_body:
                f = Finding(
                    title="GraphQL Introspection Enabled in Production",
                    severity=Severity.MEDIUM,
                    category="Business Logic — GraphQL",
                    description="GraphQL introspection is enabled, exposing the full API schema.",
                    request={"method": "POST", "url": gql_url, "note": "Introspection"},
                    response_summary=f"HTTP {status}",
                    evidence="__schema returned",
                    recommendation="Disable introspection in production.",
                    cwe="CWE-200", cvss=5.3,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    confirmed=True, endpoint=gql_url,
                )
                f = self._finalize_finding(f, "", resp_body, 403, 200)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)

            for q in ['{"query": "{ users { id email } }"}', '{"query": "{ me { id email role } }"}']:
                status, _, resp_body, _ = await self._request("POST", gql_url, data=q, token_override="")
                if status == 200 and "data" in resp_body and "errors" not in resp_body:
                    f = Finding(
                        title="GraphQL Unauthenticated Data Access",
                        severity=Severity.HIGH,
                        category="Business Logic — GraphQL",
                        description="GraphQL query returned data without any authentication token.",
                        request={"method": "POST", "url": gql_url, "body": q, "note": "No auth"},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence="Unauthenticated query returned data",
                        recommendation="Require authentication for all non-public GraphQL queries.",
                        cwe="CWE-306", cvss=8.5,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True, endpoint=gql_url,
                    )
                    f = self._finalize_finding(f, "", resp_body, 401, 200)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    break
        return findings

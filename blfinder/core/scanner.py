"""
BLFinder v3.0 — core/scanner.py
Main Scanner — Integrated with all Phase 1 modules

New in v3.0 vs v2.1:
  - BlindIDORScanner integrated into IDOR module (5 oracle channels)
  - SessionManager keeps tokens alive across long scans
  - FlowReplayer + FlowTemplates run multi-step business flow attacks
  - SemanticDiff replaces naive difflib string comparison
  - VolatileFieldExtractor learns per-endpoint volatile fields
  - TimingOracle with statistical significance replaces single-measurement timing
  - OAuthHandler acquires tokens automatically
  - All modules feed through confidence engine + verifier before reporting
"""

from __future__ import annotations

import asyncio
import aiohttp
import base64
import copy
import difflib
import hashlib
import itertools
import json
import re
import time
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, urlunparse

from .models import Finding, ScanConfig, Severity, ProofOfConcept
from .confidence import ConfidenceEngine, severity_from_confidence
from .poc import PoCGenerator
from .verifier import FindingVerifier

# Phase 1 imports — graceful fallback if a module isn't present yet
try:
    from .analysis.semantic_diff import SemanticDiff, ResponseFingerprint
    from .analysis.field_extractor import VolatileFieldExtractor, build_volatile_map
    _HAS_SEMANTIC = True
except ImportError:
    _HAS_SEMANTIC = False

try:
    from .oracles.blind_idor import BlindIDORScanner
    _HAS_BLIND_IDOR = True
except ImportError:
    _HAS_BLIND_IDOR = False

try:
    from .oracles.timing_oracle import TimingOracle
    _HAS_TIMING = True
except ImportError:
    _HAS_TIMING = False

try:
    from .auth.session_manager import SessionManager, RefreshConfig
    _HAS_SESSION = True
except ImportError:
    _HAS_SESSION = False

try:
    from .auth.oauth_handler import OAuthHandler, OAuthConfig
    _HAS_OAUTH = True
except ImportError:
    _HAS_OAUTH = False

try:
    from .flows.flow_replayer import FlowReplayer
    from .flows.flow_templates import FlowTemplates
    _HAS_FLOWS = True
except ImportError:
    _HAS_FLOWS = False


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "PostmanRuntime/7.37.0",
    "python-httpx/0.27.0",
    "axios/1.6.8",
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
    """
    BLFinder v3.0 — Business Logic Flaw Scanner
    Full Phase 1 integration.
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
        self.confidence_engine = ConfidenceEngine()
        self.poc_generator = PoCGenerator(config)
        self._verifier: Optional[FindingVerifier] = None

        # Phase 1 components
        self._session_mgr: Optional[SessionManager] = None
        self._blind_idor: Optional[BlindIDORScanner] = None
        self._timing_oracle: Optional[TimingOracle] = None
        self._flow_replayer: Optional[FlowReplayer] = None
        self._volatile_extractors: dict[str, VolatileFieldExtractor] = {}

        # Per-endpoint baseline sample store (for volatile field learning)
        self._baseline_samples: dict[str, list[str]] = defaultdict(list)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl, limit=20, limit_per_host=5
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout, connect=10)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        self._verifier = FindingVerifier(self, self.config)

        # Initialise Phase 1 components
        if _HAS_BLIND_IDOR:
            self._blind_idor = BlindIDORScanner(self)
        if _HAS_TIMING:
            self._timing_oracle = TimingOracle(self)
        if _HAS_FLOWS:
            self._flow_replayer = FlowReplayer(self)
        if _HAS_SESSION and self.config.refresh_config:
            self._session_mgr = SessionManager(self.config, self.config.refresh_config)
            self._session_mgr.initialize(self.session)

        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    # ── Core Request ──────────────────────────────────────────────────────────

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

        # Inject CSRF token if session manager has one
        if self._session_mgr and self._session_mgr.state.csrf_token:
            csrf_hdr = self._session_mgr.state.csrf_header_name or "X-CSRF-Token"
            headers[csrf_hdr] = self._session_mgr.state.csrf_token

        headers.update(self.config.headers)
        if extra:
            headers.update(extra)
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        token_override: str = None,
        _retry_on_401: bool = True,
        **kwargs,
    ) -> tuple[int, dict, str, float]:
        """
        Core request method — adaptive rate limiting, session management,
        CSRF injection, and automatic 401 refresh.
        """
        # Session manager: ensure token is still valid
        if self._session_mgr and _retry_on_401:
            await self._session_mgr.ensure_valid(
                lambda: self._request(method, url, headers=headers,
                                      token_override=token_override,
                                      _retry_on_401=False, **kwargs)
            )

        await self.rate_limiter.wait(url)

        req_headers = self._build_headers(headers)
        if token_override is not None:
            if token_override == "":
                req_headers.pop("Authorization", None)
            else:
                req_headers["Authorization"] = f"Bearer {token_override}"

        # Session manager: inject live cookies
        cookies = dict(self.config.cookies)
        if self._session_mgr:
            cookies.update(self._session_mgr.get_cookies())

        start = time.time()
        try:
            async with self.session.request(
                method, url,
                headers=req_headers,
                cookies=cookies,
                allow_redirects=True,
                max_redirects=self.config.max_redirects,
                proxy=self.config.proxy if self.config.proxy else None,
                **kwargs,
            ) as resp:
                elapsed = time.time() - start
                body = await resp.text(errors="replace")
                self.rate_limiter.record(url, resp.status, elapsed)
                self.request_log.append({
                    "method": method, "url": url,
                    "status": resp.status, "elapsed": round(elapsed, 3),
                })

                # Session manager: absorb cookies and CSRF tokens
                if self._session_mgr:
                    self._session_mgr.absorb_response(
                        dict(resp.headers), body, url, resp.status
                    )

                # Auto-refresh on 401
                if (
                    resp.status == 401
                    and _retry_on_401
                    and self._session_mgr
                ):
                    refreshed = await self._session_mgr.handle_401(url)
                    if refreshed:
                        return await self._request(
                            method, url, headers=headers,
                            token_override=token_override,
                            _retry_on_401=False, **kwargs
                        )

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

    def _try_parse_json(self, body: str) -> dict | list:
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _hash_response(self, body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    def _responses_differ_significantly(self, a: str, b: str) -> bool:
        """
        Compare two responses using SemanticDiff if available,
        otherwise fall back to difflib with threshold.
        """
        if a == b:
            return False

        if _HAS_SEMANTIC:
            diff = SemanticDiff.compare(a, b, threshold=self.config.similarity_threshold)
            # FP guard: only flag if no FP signals override
            if diff.fp_signals and not diff.confirmed if hasattr(diff, 'confirmed') else False:
                return False
            return diff.is_different

        # v2.1 fallback
        sim = difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()
        return sim < (1.0 - self.config.similarity_threshold)

    def _response_indicates_success(self, body: str, status: int = 200) -> bool:
        if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
            return False
        if status >= 500:
            return False
        body_lower = body.lower()
        failure = [
            "error", "invalid", "failed", "unauthorized", "forbidden",
            "not found", "rejected", "denied", "exception", "bad request",
            "validation", "required", "missing", "stack trace",
        ]
        has_failure = any(s in body_lower for s in failure)
        if status in (200, 201, 204):
            return not has_failure
        success = [
            "success", "true", "created", "updated", "confirmed",
            "processed", "completed", "accepted", "ok",
            "order_id", "transaction_id", "payment_id", "id", "token",
        ]
        return any(s in body_lower for s in success) and not has_failure

    def _extract_discount(self, body: str) -> float:
        try:
            data = json.loads(body)
            for key in ["discount", "discount_amount", "savings", "coupon_value"]:
                if isinstance(data, dict) and key in data:
                    return float(data[key])
        except Exception:
            pass
        return 0.0

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

    def _finalize_finding(
        self, finding: Finding, base_body: str,
        tampered_body: str, base_status: int, tampered_status: int,
    ) -> Finding:
        finding = self.confidence_engine.score(
            finding, base_body, tampered_body, base_status, tampered_status
        )
        finding = severity_from_confidence(finding)
        finding.poc = self.poc_generator.generate(finding)
        return finding

    def _record_baseline_sample(self, url: str, body: str):
        """Record a baseline response sample for volatile field learning."""
        if _HAS_SEMANTIC and body and not body.startswith(("TIMEOUT", "ERROR:")):
            self._baseline_samples[url].append(body)
            # After 3 samples, build volatile field map
            if len(self._baseline_samples[url]) == 3:
                self._volatile_extractors[url] = build_volatile_map(
                    self._baseline_samples[url], endpoint=url
                )

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
                method = "POST" if any(
                    k in path.lower() for k in ["creat", "add", "submit", "order", "checkout"]
                ) else "GET"
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
        probes = await asyncio.gather(
            *[self._request("GET", f"{base}{p}") for p in common],
            return_exceptions=True,
        )
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
                            schema = (
                                rb.get("content", {})
                                .get("application/json", {})
                                .get("schema", {})
                            )
                            for k, v in schema.get("properties", {}).items():
                                t = v.get("type", "string")
                                body[k] = (
                                    1 if t in ("integer", "number")
                                    else True if t == "boolean"
                                    else "test"
                                )
                        endpoints.append({
                            "url": urljoin(base_url, path),
                            "method": method.upper(),
                            "body": body,
                            "params": {},
                        })
        except Exception:
            pass
        return endpoints

    # ── Main Runner ───────────────────────────────────────────────────────────

    async def run_all_modules(self, endpoints: list[dict]) -> list[Finding]:
        print(f"[*] BLFinder v3.0 — Target: {self.config.target_url}")
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

        # ── Phase 1: Multi-step flow attacks ──────────────────────────────────
        flow_findings = []
        if _HAS_FLOWS and self._flow_replayer and getattr(self.config, "run_flows", False):
            flow_findings = await self._run_flow_attacks()
            print(f"  [*] Flow attacks: {len(flow_findings)} findings\n")

        # ── Phase 1: OAuth vulnerability tests ────────────────────────────────
        oauth_findings = []
        if _HAS_OAUTH and getattr(self.config, "oauth_config", None):
            oauth_findings = await self._run_oauth_tests()

        # ── Standard endpoint scanning ────────────────────────────────────────
        tasks = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self.config.target_url, url)
            tasks.append(
                self._run_endpoint_checks(
                    url, ep.get("method", "GET").upper(),
                    ep.get("body", {}), ep.get("params", {}),
                )
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw_findings = list(flow_findings) + list(oauth_findings)
        for r in results:
            if isinstance(r, list):
                raw_findings.extend(r)

        raw_findings.extend(await self._check_graphql_idor())

        # Filter by confidence
        above = [f for f in raw_findings if f.confidence >= self.config.min_confidence]
        dropped = len(raw_findings) - len(above)
        if dropped > 0:
            print(f"  [*] Dropped {dropped} low-confidence findings (< {self.config.min_confidence}%)")

        # Re-verify
        print(f"[*] Verifying {len(above)} findings...")
        verified = await self._verifier.verify_all(above, self.base_responses)

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
            "hash": self._hash_response(base_body),
            "elapsed": elapsed, "headers": headers,
        }

        # Record sample for volatile field learning
        self._record_baseline_sample(url, base_body)

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
            self._check_blind_idor(url, method, body, params, status, base_body),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception) and self.config.verbose:
                print(f"  [!] Module error: {r}")
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE: Blind IDOR (Phase 1 — new)
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_blind_idor(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        if not _HAS_BLIND_IDOR or not self._blind_idor:
            return []

        findings = []
        all_results = []

        # Path-based blind IDOR
        path_results = await self._blind_idor.scan_path(
            url=url, method=method, body=body if body else None,
            token_owned=self.config.auth_token,
            token_other=self.config.second_user_token,
            samples=3,
        )
        all_results.extend(path_results)

        # Body-based blind IDOR
        if body:
            body_results = await self._blind_idor.scan_body(
                url=url, method=method, body=body,
                token_owned=self.config.auth_token,
                token_other=self.config.second_user_token,
                samples=3,
            )
            all_results.extend(body_results)

        # Header injection
        header_results = await self._blind_idor.scan_header_injection(
            url=url, method=method, body=body if body else None,
            token_owned=self.config.auth_token,
        )
        all_results.extend(header_results)

        for r in all_results:
            if not r.is_idor:
                continue
            f = Finding(
                title=r.title or f"Blind IDOR — {r.parameter}: {r.owned_id}→{r.tested_id}",
                severity=Severity.CRITICAL if r.confirmed else Severity.HIGH,
                category="Business Logic — IDOR/BOLA (Blind)",
                description=(
                    f"Blind IDOR detected on `{r.parameter}`. "
                    f"{len(r.oracles_triggered)} oracle(s) triggered: "
                    f"{', '.join(r.oracles_triggered[:2])}. "
                    f"{'Cross-user CONFIRMED.' if r.confirmed else 'Heuristic detection.'}"
                ),
                request={"method": method, "url": r.tested_url or url},
                response_summary=(
                    f"Status: {r.status_owned}→{r.status_tested} | "
                    f"Size delta: {r.size_delta_bytes:+d}B | "
                    f"Timing delta: {r.timing_delta_ms:+.0f}ms"
                ),
                evidence=r.evidence,
                recommendation=r.recommendation,
                cwe="CWE-639",
                cvss=9.1 if r.confirmed else 8.1,
                owasp="API1:2023 Broken Object Level Authorization",
                confirmed=r.confirmed,
                confidence=r.confidence,
                false_positive_checks=r.fp_signals,
                endpoint=url,
                parameter=r.parameter,
            )
            f.poc = self.poc_generator.generate(f)
            findings.append(f)

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE: Multi-step Flow Attacks (Phase 1 — new)
    # ═══════════════════════════════════════════════════════════════════════════
    async def _run_flow_attacks(self) -> list[Finding]:
        if not _HAS_FLOWS or not self._flow_replayer:
            return []

        findings = []
        base_url = self.config.target_url
        flow_configs = getattr(self.config, "flow_configs", [])

        # Run user-specified flows
        for fc in flow_configs:
            try:
                if isinstance(fc, dict):
                    steps = FlowTemplates.from_json(fc)
                    flow_name = fc.get("name", "custom")
                else:
                    steps = fc

                print(f"  [*] Running flow attacks...")

                # Standard attack
                flow_findings = await self._flow_replayer.attack(steps, base_url=base_url)
                findings.extend(flow_findings)

                # Workflow bypass attack
                bypass_findings = await self._flow_replayer.attack_workflow_bypass(
                    steps, base_url=base_url
                )
                findings.extend(bypass_findings)

                # Race condition on final step
                final_steps = [s for s in steps if s.attack_here]
                if final_steps:
                    race_findings = await self._flow_replayer.attack_race_condition(
                        final_steps[-1], base_url=base_url
                    )
                    findings.extend(race_findings)

            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Flow attack error: {e}")

        # Auto-detect e-commerce patterns and run checkout flow
        if getattr(self.config, "auto_detect_flows", False):
            await self._auto_run_ecommerce_flow(findings, base_url)

        # Finalize all flow findings
        finalized = []
        for f in findings:
            if not hasattr(f, "confidence") or f.confidence == 0:
                f.confidence = 55
            if not f.poc:
                f.poc = self.poc_generator.generate(f)
            finalized.append(f)

        return finalized

    async def _auto_run_ecommerce_flow(self, findings: list, base_url: str):
        """Auto-detect e-commerce endpoints and run the checkout flow template."""
        checkout_indicators = ["/cart", "/checkout", "/order", "/payment"]
        discovered_urls = [ep.get("url", "") for ep in self.discovered_endpoints]

        has_ecommerce = any(
            any(ind in url.lower() for ind in checkout_indicators)
            for url in discovered_urls
        )
        if not has_ecommerce:
            return

        print("  [*] E-commerce endpoints detected — running checkout flow template...")
        steps = FlowTemplates.ecommerce_checkout(
            product_id=getattr(self.config, "product_id", 1),
            quantity=1,
            price=getattr(self.config, "product_price", 99.99),
        )
        try:
            flow_findings = await self._flow_replayer.attack(steps, base_url=base_url)
            findings.extend(flow_findings)
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Auto e-commerce flow error: {e}")

    async def _run_oauth_tests(self) -> list[Finding]:
        """Run OAuth2 vulnerability tests if oauth_config is provided."""
        if not _HAS_OAUTH:
            return []

        oauth_cfg = getattr(self.config, "oauth_config", None)
        if not oauth_cfg:
            return []

        findings = []
        try:
            handler = OAuthHandler(oauth_cfg, verbose=self.config.verbose)
            token = await handler.get_token(self.session)

            if token:
                print(f"  [+] OAuth2 token acquired (expires in {token.expires_in}s)")
                # Use the token for subsequent requests
                self.config.auth_token = token.access_token
                await handler.test_token_endpoint_vulns(self.session)

            # Convert OAuth findings to Finding objects
            from .models import Severity as Sev
            sev_map = {"CRITICAL": Sev.CRITICAL, "HIGH": Sev.HIGH,
                       "MEDIUM": Sev.MEDIUM, "LOW": Sev.LOW}
            for vuln in handler.findings:
                f = Finding(
                    title=vuln.title,
                    severity=sev_map.get(vuln.severity.upper(), Sev.MEDIUM),
                    category="Business Logic — OAuth2 Vulnerability",
                    description=vuln.description,
                    request={"note": "OAuth2 flow test"},
                    response_summary=vuln.evidence,
                    evidence=vuln.evidence,
                    recommendation=vuln.recommendation,
                    cwe=vuln.cwe,
                    owasp=vuln.owasp,
                    confirmed=True,
                    confidence=80,
                    endpoint=oauth_cfg.token_url,
                )
                f.poc = self.poc_generator.generate(f)
                findings.append(f)

        except Exception as e:
            if self.config.verbose:
                print(f"  [!] OAuth test error: {e}")

        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 1: Price Manipulation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_price_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        price_keys = [
            "price", "amount", "total", "cost", "fee", "charge", "unit_price",
            "subtotal", "payment_amount", "order_total", "grand_total",
            "final_price", "shipping_cost", "discount_amount",
        ]
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
                    status, headers, resp_body, _ = await self._request(method, url, json=mutated_body)
                    if status not in (200, 201):
                        continue
                    if not self._response_indicates_success(resp_body, status):
                        continue

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

                    f = Finding(
                        title=f"Price Manipulation — `{field_path}` accepted {tampered}",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Price Manipulation",
                        description=(
                            f"Field `{field_path}` (original: `{original}`) accepted tampered "
                            f"value `{tampered}`. Server returned success."
                        ),
                        request={"method": method, "url": url, "body": mutated_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"Original={original} → Tampered={tampered} → HTTP {status}{evidence_detail}",
                        recommendation="Compute all prices server-side. Never trust client-submitted values.",
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
                # FP: canary test
                canary_body = {**body, key: "INVALID_STRING_CANARY"}
                cs, _, _, _ = await self._request(method, url, json=canary_body)
                if cs in (200, 201):
                    continue
                f = Finding(
                    title=f"Negative Quantity Exploit — `{key}` = {tampered} accepted",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Negative Value",
                    description=f"`{key}` = {tampered} (original: {original}) was accepted.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"qty={tampered} → HTTP {status} (canary rejected → {cs})",
                    recommendation="Enforce qty >= 1 server-side.",
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
    # MODULE 3: IDOR / BOLA
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_idor_bola(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        path_segments = parsed.path.split("/")

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
                    if status != 200:
                        continue
                    if not self._responses_differ_significantly(base_body, resp_body):
                        continue
                    if any(t in resp_body.lower() for t in ["not found", "no resource", "does not exist"]):
                        continue
                    confirmed = False
                    if self.config.second_user_token:
                        s2, _, _, _ = await self._request(
                            method, test_url, json=body if body else None,
                            token_override=self.config.second_user_token,
                        )
                        confirmed = s2 == 200
                    f = Finding(
                        title=f"IDOR/BOLA — Path ID {original_id}→{test_id} returned different resource",
                        severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                        category="Business Logic — IDOR/BOLA",
                        description=(
                            f"Changing path ID {original_id}→{test_id} returned different data. "
                            f"{'Cross-user CONFIRMED.' if confirmed else ''}"
                        ),
                        request={"method": method, "url": test_url},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"ID {original_id}→{test_id}: different response {'[CONFIRMED]' if confirmed else ''}",
                        recommendation="Enforce ownership checks on every request.",
                        cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                        owasp="API1:2023 Broken Object Level Authorization",
                        confirmed=confirmed, endpoint=url, parameter=f"path[{seg_idx}]",
                    )
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    if confirmed:
                        break

        # No-auth access
        if self.config.no_auth_check:
            import difflib as _dl
            s_na, _, rb_na, _ = await self._request(method, url, json=body if body else None, token_override="")
            if s_na in (200, 201) and self._response_indicates_success(rb_na, s_na):
                sim = _dl.SequenceMatcher(None, base_body[:2000], rb_na[:2000]).ratio()
                if sim > 0.7:
                    f = Finding(
                        title="Unauthenticated Access — resource accessible without token",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Missing Authentication",
                        description=f"No auth header → HTTP {s_na} with {sim:.0%} similarity to authenticated response.",
                        request={"method": method, "url": url, "note": "No Authorization header"},
                        response_summary=f"HTTP {s_na} — {rb_na[:300]}",
                        evidence=f"No-auth → HTTP {s_na}, similarity={sim:.0%}",
                        recommendation="Require authentication on all non-public endpoints.",
                        cwe="CWE-306", cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True, endpoint=url,
                    )
                    f = self._finalize_finding(f, base_body, rb_na, base_status, s_na)
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
            new_data  = self._try_parse_json(resp_body)
            new_keys  = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())
            sensitive = ["password", "secret", "token", "private_key", "ssn", "dob",
                         "credit_card", "cvv", "salary", "internal", "hash"]
            has_sensitive = any(sf in " ".join(new_keys).lower() for sf in sensitive)
            f = Finding(
                title=f"BOPLA — `{list(probe.keys())[0]}` exposes hidden fields",
                severity=Severity.HIGH if has_sensitive else Severity.MEDIUM,
                category="Business Logic — Object Property Exposure",
                description=f"Adding `{probe}` returned {len(resp_body)-base_len} extra bytes. New fields: {list(new_keys)[:5]}.",
                request={"method": "GET", "url": url, "params": {**params, **probe}},
                response_summary=f"HTTP {status}, {len(resp_body)} vs {base_len} bytes",
                evidence=f"+{len(resp_body)-base_len} bytes, new keys: {list(new_keys)[:5]}",
                recommendation="Define explicit field allowlists per role.",
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
            current = match.group(1)
            try:
                for delta in [2, 3]:
                    next_step = str(int(current) + delta)
                    new_path = re.sub(pattern, match.group(0).replace(current, next_step), path, flags=re.IGNORECASE)
                    new_url = urlunparse(parsed._replace(path=new_path))
                    status, _, resp_body, _ = await self._request(method, new_url, json=body)
                    if status not in (200, 201):
                        continue
                    # FP: canary
                    canary_url = urlunparse(parsed._replace(path=re.sub(pattern, match.group(0).replace(current, "999"), path, flags=re.IGNORECASE)))
                    cs, _, _, _ = await self._request(method, canary_url, json=body)
                    if cs == 200:
                        continue
                    f = Finding(
                        title=f"Workflow Step Bypass — {label} {current}→{next_step}",
                        severity=Severity.HIGH,
                        category="Business Logic — Workflow Bypass",
                        description=f"Step {next_step} accessible without completing step {current}.",
                        request={"method": method, "url": new_url, "body": body},
                        response_summary=f"HTTP {status}",
                        evidence=f"Skip {current}→{next_step}: HTTP {status} (canary 999→{cs})",
                        recommendation="Enforce sequential step validation server-side.",
                        cwe="CWE-284", cvss=7.5,
                        owasp="API5:2023 Broken Function Level Authorization",
                        endpoint=url,
                    )
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
            except (ValueError, TypeError):
                pass

        for key in ["otp", "mfa_token", "verification_token"]:
            if key not in body:
                continue
            test_body = {k: v for k, v in body.items() if k != key}
            status, _, resp_body, _ = await self._request(method, url, json=test_body)
            if status in (200, 201) and self._response_indicates_success(resp_body, status):
                f = Finding(
                    title=f"MFA/OTP Omission — `{key}` not validated server-side",
                    severity=Severity.HIGH,
                    category="Business Logic — Workflow Bypass",
                    description=f"Removing `{key}` returned success — MFA/OTP step is not enforced.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Missing `{key}` → HTTP {status}",
                    recommendation="Validate OTP/MFA tokens server-side before any action.",
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
            "is_admin", "admin", "role", "is_premium", "premium", "subscription",
            "plan", "credits", "balance", "is_staff", "approved", "email_verified",
            "kyc_verified", "price_override", "tax_exempt", "fee_waiver",
        ]
        for key in privileged_keys:
            test_body = {**body, key: True}
            status, _, resp_body, _ = await self._request(method, url, json=test_body)
            if status not in (200, 201):
                continue
            resp_data = self._try_parse_json(resp_body)
            if not isinstance(resp_data, dict):
                continue
            reflected = resp_data.get(key)
            if reflected not in (True, "true", 1, "admin", "premium", "verified"):
                continue
            base_data = self._try_parse_json(base_body)
            if isinstance(base_data, dict) and base_data.get(key) == reflected:
                continue
            f = Finding(
                title=f"Mass Assignment — `{key}` reflected as `{reflected}`",
                severity=Severity.CRITICAL,
                category="Business Logic — Mass Assignment",
                description=f"Injecting `{key}: true` reflected as `{reflected}` — privilege escalation confirmed.",
                request={"method": method, "url": url, "body": test_body},
                response_summary=f"HTTP {status}, `{key}`={reflected}",
                evidence=f"Injected {key}=True → response {key}={reflected} (absent in baseline)",
                recommendation="Use explicit field allowlists. Never pass raw bodies to ORM methods.",
                cwe="CWE-915", cvss=9.8,
                owasp="API3:2023 Broken Object Property Level Authorization",
                confirmed=True, endpoint=url, parameter=key,
            )
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE 7: Privilege Escalation
    # ═══════════════════════════════════════════════════════════════════════════
    async def _check_privilege_escalation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        admin_paths = [
            "/admin", "/api/admin", "/api/v1/admin", "/manage",
            "/api/users/all", "/api/roles", "/api/permissions",
            "/internal", "/api/internal", "/api/metrics", "/api/config",
        ]
        for admin_path in admin_paths:
            test_url = f"{base}{admin_path}"
            for token, label in [(self.config.auth_token, "low-priv"), ("", "no-auth")]:
                status, _, resp_body, _ = await self._request("GET", test_url, token_override=token)
                if status != 200 or len(resp_body) < 50:
                    continue
                if not self._response_indicates_success(resp_body, status):
                    continue
                f = Finding(
                    title=f"BFLA — `{admin_path}` accessible by {label} user",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=f"Admin endpoint `{admin_path}` returned HTTP 200 + {len(resp_body)}B with {label} token.",
                    request={"method": "GET", "url": test_url, "note": f"Token: {label}"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"GET {test_url} with {label} → {status} + {len(resp_body)}B",
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
            status, _, resp_body, _ = await self._request(
                test_method, url,
                json=body if body else None,
                token_override=self.config.second_user_token,
            )
            if status in (200, 201, 204):
                f = Finding(
                    title=f"BFLA — User 2 can {test_method} User 1's resource",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=f"User 2 performed {test_method} on User 1's resource → HTTP {status}.",
                    request={"method": test_method, "url": url, "note": "Second user token"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"User2 + {test_method} {url} → {status}",
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
                ({**body, key: [original]},           "single-item array"),
            ]:
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201) or not self._response_indicates_success(resp_body, status):
                    continue
                new_discount = self._extract_discount(resp_body)
                confirmed = bool(new_discount and base_discount and new_discount > base_discount * 1.4)
                f = Finding(
                    title=f"Coupon Abuse — {label} for `{key}`",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    category="Business Logic — Coupon Abuse",
                    description=f"Coupon as {label} accepted. {'Discount increased: ' + str(base_discount) + '→' + str(new_discount) if confirmed else 'Possible stacking.'}",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Coupon as {label}: {base_discount}→{new_discount}",
                    recommendation="Normalize coupon inputs. Enforce one-coupon-per-order server-side.",
                    cwe="CWE-20", cvss=8.5 if confirmed else 6.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confirmed=confirmed, endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings

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
                if (
                    status in (200, 201)
                    and self._response_indicates_success(resp_body, status)
                    and self._hash_response(resp_body) != self._hash_response(base_body)
                ):
                    f = Finding(
                        title=f"Time Bypass — `{key}` accepts {label} timestamp",
                        severity=Severity.HIGH,
                        category="Business Logic — Time Bypass",
                        description=f"`{key}` = {ts} ({label}) accepted with different response.",
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"`{key}` = {ts} → different response from baseline",
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
                            title=f"Integer Overflow — `{key}` = {val} caused 500",
                            severity=Severity.MEDIUM,
                            category="Business Logic — Integer Overflow",
                            description=f"`{key}` = {val} caused HTTP 500.",
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
                                        title=f"Integer Overflow — `{key}`={val} caused negative `{rk}`",
                                        severity=Severity.HIGH,
                                        category="Business Logic — Integer Overflow",
                                        description=f"`{key}`={val} → `{rk}`={rv} (negative).",
                                        request={"method": method, "url": url, "body": test_body},
                                        response_summary=f"HTTP {status}, {rk}={rv}",
                                        evidence=f"Input {key}={val} → {rk}={rv}",
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
        probes = {
            "debug": "1", "verbose": "1", "admin": "1", "internal": "1",
            "full": "1", "include_deleted": "1", "show_all": "1", "_debug": "1",
        }
        for param, val in probes.items():
            status, _, resp_body, _ = await self._request("GET", url, params={**params, param: val})
            base_len = len(base_body)
            new_len  = len(resp_body)
            if status != 200 or new_len <= base_len * 1.2 or new_len - base_len < 100:
                continue
            base_data = self._try_parse_json(base_body)
            new_data  = self._try_parse_json(resp_body)
            new_keys  = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())
            if not new_keys and new_len < base_len * 1.5:
                continue
            f = Finding(
                title=f"Hidden Parameter — `{param}` discloses extra data",
                severity=Severity.HIGH if new_len > base_len * 2 else Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=f"`{param}={val}` returned {new_len-base_len} extra bytes. New keys: {list(new_keys)[:5]}.",
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
                    continue
                test_body = {**body, key: state}
                status, _, resp_body, _ = await self._request(method, url, json=test_body)
                if status not in (200, 201):
                    continue
                data = self._try_parse_json(resp_body)
                if not isinstance(data, dict) or data.get(key) != state:
                    continue
                f = Finding(
                    title=f"State Machine Abuse — `{key}` forced to `{state}`",
                    severity=Severity.CRITICAL,
                    category="Business Logic — State Machine Abuse",
                    description=f"Forcing `{key}`→`{state}` accepted and confirmed in response.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}, {key}={state}",
                    evidence=f"Forced {key}={state} → confirmed (was: {body.get(key)})",
                    recommendation="Compute state transitions server-side. Never trust client state.",
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
                           "purchase", "buy", "confirm", "coupon", "reward", "spin"]
        if not any(ind in url.lower() for ind in race_indicators):
            return findings

        orig_delay = self.rate_limiter.base_delay
        self.rate_limiter.base_delay = 0
        responses = await asyncio.gather(
            *[self._request(method, url, json=body) for _ in range(15)],
            return_exceptions=True,
        )
        self.rate_limiter.base_delay = orig_delay

        success_count = sum(
            1 for r in responses
            if isinstance(r, tuple)
            and r[0] in (200, 201)
            and self._response_indicates_success(r[2], r[0])
        )
        if success_count > 1:
            single_status, _, _, _ = await self._request(method, url, json=body)
            f = Finding(
                title=f"Race Condition — {success_count}/15 concurrent requests succeeded",
                severity=Severity.CRITICAL,
                category="Business Logic — Race Condition",
                description=f"{success_count}/15 simultaneous requests succeeded. Double-spending possible.",
                request={"method": method, "url": url, "body": body, "note": "15 concurrent"},
                response_summary=f"{success_count}/15 successes",
                evidence=f"Concurrent: {success_count}/15. Single re-test: {single_status}",
                recommendation="Use SELECT FOR UPDATE, Redis SETNX, or idempotency keys.",
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

        def b64d(p):
            pad = 4 - len(p) % 4
            try:
                return json.loads(base64.urlsafe_b64decode(p + "=" * pad))
            except Exception:
                return {}

        def b64e(d):
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        header  = b64d(parts[0])
        payload = b64d(parts[1])
        if not header or not payload:
            return findings

        # alg:none
        forged = f"{b64e({**header, 'alg': 'none'})}.{parts[1]}."
        status, _, resp_body, _ = await self._request(method, url, json=body if body else None, token_override=forged)
        if status in (200, 201) and self._response_indicates_success(resp_body, status):
            totally_invalid = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZmFrZSJ9."
            ts2, _, _, _ = await self._request(method, url, json=body if body else None, token_override=totally_invalid)
            if ts2 not in (200, 201):
                f = Finding(
                    title="JWT alg:none Bypass — signature not validated",
                    severity=Severity.CRITICAL,
                    category="Business Logic — JWT Vulnerability",
                    description="Server accepted JWT with alg:none (no signature). Claims can be forged.",
                    request={"method": method, "url": url, "note": "JWT with alg:none"},
                    response_summary=f"HTTP {status}",
                    evidence=f"alg:none → {status} (random invalid → {ts2})",
                    recommendation="Whitelist allowed algorithms. Reject 'none'.",
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
        for test_val in ["nonexistent_zzz_9999@nowhere.invalid", "admin@example.com"]:
            test_body = {**body, field: test_val}
            s, _, rb, elapsed = await self._request(method, url, json=test_body)
            results.append((test_val, s, rb.lower(), elapsed))

        if len(results) < 2:
            return findings

        r1_body, r2_body = results[0][2], results[1][2]
        not_found = ["not found", "no account", "doesn't exist", "no user"]
        wrong_pass = ["wrong password", "incorrect password", "invalid password"]

        if (
            (any(s in r1_body for s in not_found) and any(s in r2_body for s in wrong_pass)) or
            (any(s in r2_body for s in not_found) and any(s in r1_body for s in wrong_pass))
        ):
            f = Finding(
                title="Account Enumeration — different error messages for valid vs invalid accounts",
                severity=Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=f"Different error messages for `{field}` enable user enumeration.",
                request={"method": method, "url": url},
                response_summary="Different messages for valid vs invalid accounts",
                evidence="'no account' vs 'wrong password' messages differ",
                recommendation="Use generic 'Invalid credentials' for all auth failures.",
                cwe="CWE-204", cvss=5.3,
                owasp="API2:2023 Broken Authentication",
                confirmed=True, endpoint=url, parameter=field,
            )
            f = self._finalize_finding(f, base_body, results[0][2], base_status, results[0][1])
            if f.confidence >= self.config.min_confidence:
                findings.append(f)

        times = [r[3] for r in results]
        timing_delta = max(times) - min(times)
        if timing_delta > 0.20:
            f = Finding(
                title=f"Account Enumeration — timing oracle ({timing_delta:.2f}s delta)",
                severity=Severity.LOW,
                category="Business Logic — Information Disclosure",
                description=f"Timing delta of {timing_delta:.2f}s between valid/invalid accounts.",
                request={"method": method, "url": url, "note": "Timing oracle"},
                response_summary=f"Times: {[round(r[3], 3) for r in results]}",
                evidence=f"Delta: {timing_delta:.3f}s",
                recommendation="Use constant-time comparisons.",
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
            count = (
                len(data) if isinstance(data, list)
                else len(data.get("data", data.get("items", []))) if isinstance(data, dict)
                else 0
            )
            base_data = self._try_parse_json(base_body)
            base_count = (
                len(base_data) if isinstance(base_data, list)
                else len(base_data.get("data", base_data.get("items", []))) if isinstance(base_data, dict)
                else 0
            )
            if count > base_count * 2:
                f = Finding(
                    title=f"Limit Manipulation — {probe} returned {count} vs {base_count} records",
                    severity=Severity.HIGH,
                    category="Business Logic — Excessive Data Exposure",
                    description=f"Pagination `{probe}` → {count} records vs baseline {base_count}.",
                    request={"method": "GET", "url": url, "params": merged},
                    response_summary=f"HTTP {status}, {count} records",
                    evidence=f"Baseline: {base_count} → probe: {count} records",
                    recommendation="Enforce server-side max page size. Filter by authenticated user.",
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
                    description=f"`{probe}` returned a different response — deleted records possibly exposed.",
                    request={"method": "GET", "url": url, "params": merged},
                    response_summary=f"HTTP {status}, {len(resp_body)} bytes",
                    evidence=f"Response changed with {probe}",
                    recommendation="Filter soft-deleted records at the ORM layer.",
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
        for oh in [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Method-Override": "DELETE"},
            {"_method": "DELETE"},
        ]:
            status, _, resp_body, _ = await self._request("POST", url, json=body, headers=oh)
            if status not in (405, 404, 400, 403, 401, 0):
                if status in (200, 201) and self._responses_differ_significantly(base_body, resp_body):
                    f = Finding(
                        title=f"HTTP Method Override — `{list(oh.keys())[0]}` caused different response",
                        severity=Severity.MEDIUM,
                        category="Business Logic — Method Override",
                        description=f"Override header `{oh}` produced different response from baseline POST.",
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
        for key, val in list(params.items())[:3]:
            parsed = urlparse(url)
            test_url = urlunparse(parsed._replace(query=f"{key}={val}&{key}=999999"))
            status, _, resp_body, _ = await self._request("GET", test_url)
            if status == 200 and self._responses_differ_significantly(base_body, resp_body):
                f = Finding(
                    title=f"HTTP Parameter Pollution — duplicate `{key}` changed response",
                    severity=Severity.MEDIUM,
                    category="Business Logic — Parameter Pollution",
                    description=f"Duplicating `{key}` with injected value changed the response significantly.",
                    request={"method": "GET", "url": test_url},
                    response_summary=f"HTTP {status}",
                    evidence=f"Duplicate {key} → significantly different response",
                    recommendation="Take only the first value for duplicate parameters.",
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
            status, _, resp_body, _ = await self._request(
                "POST", gql_url,
                data='{"query": "{ __schema { types { name } } }"}',
            )
            if status == 200 and "__schema" in resp_body:
                f = Finding(
                    title="GraphQL Introspection Enabled in Production",
                    severity=Severity.MEDIUM,
                    category="Business Logic — GraphQL",
                    description="GraphQL introspection exposes the full API schema.",
                    request={"method": "POST", "url": gql_url},
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
                        description="GraphQL query returned data without authentication.",
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

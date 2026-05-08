"""
BLFinder v3.0 — core/oracles/blind_idor.py
Blind IDOR Detection via Multi-Oracle Analysis

Detects IDOR vulnerabilities even when the server returns identical-looking
responses for owned vs non-owned resources. Uses five oracle channels:

  1. STATUS  — HTTP status code differences
  2. SIZE    — response body size differences
  3. ERROR   — "forbidden" vs "not found" message analysis
  4. TIMING  — server response time differences (corroborated only)
  5. CROSS   — cross-user token confirmation (strongest signal)

Confirmed IDORs require signal from >=2 oracles OR 1 cross-user confirmation.
All findings include FP analysis before being returned.
"""

from __future__ import annotations

import asyncio
import json
import re
import statistics
import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse


@dataclass
class OracleSignal:
    name: str
    triggered: bool = False
    detail: str = ""
    confidence_contribution: int = 0


@dataclass
class BlindIDORResult:
    is_idor: bool = False
    confidence: int = 0
    confirmed: bool = False
    signals: list[OracleSignal] = field(default_factory=list)
    oracles_triggered: list[str] = field(default_factory=list)
    timing_delta_ms: float = 0.0
    size_delta_bytes: int = 0
    status_owned: int = 0
    status_tested: int = 0
    error_diff: str = ""
    owned_id: str = ""
    tested_id: str = ""
    owned_url: str = ""
    tested_url: str = ""
    method: str = "GET"
    parameter: str = ""
    fp_signals: list[str] = field(default_factory=list)
    fp_risk: str = "LOW"
    evidence: str = ""
    title: str = ""
    recommendation: str = (
        "Enforce server-side ownership checks. Verify the authenticated user owns "
        "the resource before returning any data, timing information, or error details. "
        "Use consistent error messages for 'not found' and 'forbidden' to prevent oracle leakage."
    )


_TIMING_THRESHOLD = 0.080
_SIZE_THRESHOLD = 25

_RESOURCE_EXISTS_PATTERNS = [
    re.compile(r'\baccess\s+denied\b', re.I),
    re.compile(r'\bforbidden\b', re.I),
    re.compile(r'\bnot\s+authorized\b', re.I),
    re.compile(r'\bunauthorized\b', re.I),
    re.compile(r'\bpermission\s+denied\b', re.I),
    re.compile(r'\byou\s+don.t\s+have\s+access\b', re.I),
    re.compile(r'\binsufficien\w+\s+permissions?\b', re.I),
]

_RESOURCE_NOTFOUND_PATTERNS = [
    re.compile(r'\bnot\s+found\b', re.I),
    re.compile(r'\bdoes\s+not\s+exist\b', re.I),
    re.compile(r'\bno\s+such\b', re.I),
    re.compile(r'\binvalid\s+id\b', re.I),
    re.compile(r'\bresource\s+unavailable\b', re.I),
    re.compile(r'\bcould\s+not\s+find\b', re.I),
]


class BlindIDORScanner:
    """
    Detects blind IDOR vulnerabilities using multiple oracle channels.
    Works even when server returns HTTP 200 for all requests.
    """

    def __init__(self, scanner):
        self._r = scanner._request
        self._config = scanner.config

    async def scan_path(
        self,
        url: str,
        method: str = "GET",
        body: dict | None = None,
        token_owned: str = "",
        token_other: str = "",
        samples: int = 4,
    ) -> list[BlindIDORResult]:
        results = []
        parsed = urlparse(url)
        segments = parsed.path.split("/")

        for idx, seg in enumerate(segments):
            if not seg:
                continue

            if re.match(r'^\d{1,15}$', seg):
                original_id = int(seg)
                for test_id in _adjacent_ids(original_id)[:3]:
                    new_segs = segments[:]
                    new_segs[idx] = str(test_id)
                    test_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                    r = await self._run_all_oracles(
                        owned_url=url, test_url=test_url,
                        method=method, owned_body=body, test_body=body,
                        token_owned=token_owned, token_other=token_other,
                        owned_id=str(original_id), tested_id=str(test_id),
                        parameter=f"path[{idx}]", samples=samples,
                    )
                    if r.is_idor:
                        results.append(r)
                        break

            elif re.match(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                seg, re.I
            ):
                for test_uuid in _test_uuids(seg):
                    new_segs = segments[:]
                    new_segs[idx] = test_uuid
                    test_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                    r = await self._run_all_oracles(
                        owned_url=url, test_url=test_url,
                        method=method, owned_body=body, test_body=body,
                        token_owned=token_owned, token_other=token_other,
                        owned_id=seg, tested_id=test_uuid,
                        parameter=f"path[{idx}]", samples=samples,
                    )
                    if r.is_idor:
                        results.append(r)
                        break

        return results

    async def scan_body(
        self,
        url: str,
        method: str,
        body: dict,
        token_owned: str = "",
        token_other: str = "",
        samples: int = 4,
    ) -> list[BlindIDORResult]:
        results = []
        id_keys = [
            "id", "user_id", "account_id", "order_id", "customer_id",
            "profile_id", "subscription_id", "resource_id", "doc_id",
            "file_id", "payment_id", "ticket_id", "invoice_id",
        ]
        for key in id_keys:
            if key not in body:
                continue
            original_val = body[key]
            for test_val in _body_test_values(original_val)[:2]:
                test_body = {**body, key: test_val}
                r = await self._run_all_oracles(
                    owned_url=url, test_url=url,
                    method=method, owned_body=body, test_body=test_body,
                    token_owned=token_owned, token_other=token_other,
                    owned_id=str(original_val), tested_id=str(test_val),
                    parameter=f"body.{key}", samples=samples,
                )
                if r.is_idor:
                    results.append(r)
                    break
        return results

    async def scan_header_injection(
        self,
        url: str,
        method: str = "GET",
        body: dict | None = None,
        token_owned: str = "",
    ) -> list[BlindIDORResult]:
        results = []
        baseline_status, _, baseline_body, _ = await self._r(
            method, url,
            json=body if body else None,
            token_override=token_owned or None,
        )

        injection_headers = [
            {"X-User-Id": "1"},
            {"X-Account-Id": "1"},
            {"X-Admin-User": "true"},
            {"X-Internal-User": "1"},
            {"X-Forwarded-User": "admin"},
            {"X-Original-User-Id": "1"},
            {"X-Impersonate-User": "1"},
            {"X-Sudo": "true"},
        ]

        for hdr in injection_headers:
            s, _, resp_body, _ = await self._r(
                method, url,
                json=body if body else None,
                headers=hdr,
                token_override=token_owned or None,
            )
            hdr_name = list(hdr.keys())[0]
            hdr_val  = list(hdr.values())[0]

            if s == baseline_status and not _responses_differ(baseline_body, resp_body):
                continue
            if _is_waf_block(resp_body):
                continue

            r = BlindIDORResult()
            r.owned_url      = url
            r.tested_url     = url
            r.method         = method
            r.owned_id       = "current_user"
            r.tested_id      = f"{hdr_name}: {hdr_val}"
            r.parameter      = f"header:{hdr_name}"
            r.status_owned   = baseline_status
            r.status_tested  = s
            r.size_delta_bytes = len(resp_body) - len(baseline_body)
            r.confirmed      = True
            sig = OracleSignal(
                name="HEADER_INJECTION",
                triggered=True,
                detail=(
                    f"`{hdr_name}: {hdr_val}` changed response "
                    f"(status {baseline_status}→{s}, size delta {r.size_delta_bytes:+d}B)"
                ),
                confidence_contribution=60,
            )
            r.signals.append(sig)
            r.oracles_triggered.append(sig.detail)
            r.confidence = 75
            r.is_idor    = True
            r.fp_risk    = "LOW"
            r.title      = f"Header-based IDOR — `{hdr_name}` overrides user context"
            r.evidence   = (
                f"Adding `{hdr_name}: {hdr_val}` changed the response. "
                f"Status: {baseline_status}→{s}, Size delta: {r.size_delta_bytes:+d}B"
            )
            results.append(r)

        return results

    async def _run_all_oracles(
        self,
        owned_url: str,
        test_url: str,
        method: str,
        owned_body: dict | None,
        test_body: dict | None,
        token_owned: str,
        token_other: str,
        owned_id: str,
        tested_id: str,
        parameter: str,
        samples: int,
    ) -> BlindIDORResult:

        result = BlindIDORResult()
        result.owned_url  = owned_url
        result.tested_url = test_url
        result.method     = method
        result.owned_id   = owned_id
        result.tested_id  = tested_id
        result.parameter  = parameter

        owned_resp = []
        test_resp  = []

        for _ in range(max(2, samples)):
            s, _, b, t = await self._r(
                method, owned_url,
                json=owned_body if owned_body else None,
                token_override=token_owned or None,
            )
            owned_resp.append((s, b, t))
            await asyncio.sleep(0.05)

            s, _, b, t = await self._r(
                method, test_url,
                json=test_body if test_body else None,
                token_override=token_owned or None,
            )
            test_resp.append((s, b, t))
            await asyncio.sleep(0.05)

        if not owned_resp or not test_resp:
            result.fp_signals.append("Could not collect response samples")
            return result

        if all(r[0] == 0 for r in owned_resp) or all(r[0] == 0 for r in test_resp):
            result.fp_signals.append("All requests timed out — endpoint unreachable")
            return result

        owned_statuses = [r[0] for r in owned_resp]
        test_statuses  = [r[0] for r in test_resp]
        dom_owned = _dominant(owned_statuses)
        dom_test  = _dominant(test_statuses)

        result.status_owned  = dom_owned
        result.status_tested = dom_test

        if dom_owned == 404 and dom_test == 404:
            result.fp_signals.append("Both owned and tested return 404 — endpoint may not exist")
            return result

        # Oracle 1: Status
        sig_status = OracleSignal(name="STATUS")
        if dom_owned != dom_test:
            sig_status.triggered = True
            sig_status.detail = f"Status changed {dom_owned}→{dom_test} when ID changed"
            sig_status.confidence_contribution = 25
            if dom_test == 200 and dom_owned in (401, 403):
                sig_status.confidence_contribution = 45
                sig_status.detail = f"Access gained: baseline {dom_owned} → tested ID returns {dom_test}"
        result.signals.append(sig_status)

        # Oracle 2: Size
        owned_sizes = [len(r[1]) for r in owned_resp]
        test_sizes  = [len(r[1]) for r in test_resp]
        avg_owned_sz = statistics.mean(owned_sizes)
        avg_test_sz  = statistics.mean(test_sizes)
        result.size_delta_bytes = int(avg_test_sz - avg_owned_sz)

        sig_size = OracleSignal(name="SIZE")
        if abs(result.size_delta_bytes) >= _SIZE_THRESHOLD:
            sig_size.triggered = True
            sig_size.detail = (
                f"Size changed by {result.size_delta_bytes:+d}B "
                f"(owned={avg_owned_sz:.0f}B, tested={avg_test_sz:.0f}B)"
            )
            sig_size.confidence_contribution = 20 if abs(result.size_delta_bytes) < 100 else 30
        result.signals.append(sig_size)

        # Oracle 3: Error message
        owned_body_str = owned_resp[0][1]
        test_body_str  = test_resp[0][1]

        sig_error = OracleSignal(name="ERROR_MSG")
        owned_exists   = any(p.search(owned_body_str) for p in _RESOURCE_EXISTS_PATTERNS)
        owned_notfound = any(p.search(owned_body_str) for p in _RESOURCE_NOTFOUND_PATTERNS)
        test_exists    = any(p.search(test_body_str)  for p in _RESOURCE_EXISTS_PATTERNS)
        test_notfound  = any(p.search(test_body_str)  for p in _RESOURCE_NOTFOUND_PATTERNS)

        if owned_exists and test_notfound:
            sig_error.triggered = True
            sig_error.detail = (
                "Server reveals resource existence: "
                "owned='access denied' vs tested='not found'"
            )
            sig_error.confidence_contribution = 40
            result.error_diff = sig_error.detail
        elif test_exists and owned_notfound:
            sig_error.triggered = True
            sig_error.detail = "Inverse: tested ID exists but owned does not"
            sig_error.confidence_contribution = 30
            result.error_diff = sig_error.detail
        else:
            owned_msg = _extract_message(owned_body_str)
            test_msg  = _extract_message(test_body_str)
            if owned_msg and test_msg and owned_msg != test_msg:
                sig_error.triggered = True
                sig_error.detail = (
                    f"Different messages: owned='{owned_msg[:40]}' vs tested='{test_msg[:40]}'"
                )
                sig_error.confidence_contribution = 15
                result.error_diff = sig_error.detail
        result.signals.append(sig_error)

        # Oracle 4: Timing (corroborated only)
        sig_timing = OracleSignal(name="TIMING")
        owned_times = [r[2] for r in owned_resp]
        test_times  = [r[2] for r in test_resp]

        if len(owned_times) >= 2 and len(test_times) >= 2:
            clean_owned = _trim_outliers(owned_times)
            clean_test  = _trim_outliers(test_times)
            if clean_owned and clean_test:
                mean_owned = statistics.mean(clean_owned)
                mean_test  = statistics.mean(clean_test)
                result.timing_delta_ms = (mean_test - mean_owned) * 1000

                if abs(result.timing_delta_ms) >= (_TIMING_THRESHOLD * 1000):
                    other_triggered = any(
                        s.triggered for s in result.signals if s.name != "TIMING"
                    )
                    if other_triggered:
                        sig_timing.triggered = True
                        sig_timing.detail = (
                            f"Response {abs(result.timing_delta_ms):.0f}ms "
                            f"{'slower' if result.timing_delta_ms > 0 else 'faster'} "
                            f"for tested ID (corroborated)"
                        )
                        sig_timing.confidence_contribution = 15
                    else:
                        result.fp_signals.append(
                            f"Timing delta {result.timing_delta_ms:.0f}ms but no corroborating oracle — "
                            "skipped to avoid false positive on mobile networks"
                        )
        result.signals.append(sig_timing)

        # Oracle 5: Cross-user
        sig_cross = OracleSignal(name="CROSS_USER")
        if token_other and token_other != token_owned:
            s_cross, _, b_cross, _ = await self._r(
                method, test_url,
                json=test_body if test_body else None,
                token_override=token_other,
            )
            if s_cross == 200 and not _is_waf_block(b_cross) and _response_has_data(b_cross):
                sig_cross.triggered = True
                sig_cross.detail = (
                    f"User 2 accessed ID {tested_id} → HTTP {s_cross} ({len(b_cross)}B)"
                )
                sig_cross.confidence_contribution = 50
                result.confirmed = True
        result.signals.append(sig_cross)

        # Aggregate
        triggered = [s for s in result.signals if s.triggered]
        result.oracles_triggered = [s.detail for s in triggered]
        result.confidence = min(100, sum(s.confidence_contribution for s in triggered))

        non_cross = [s for s in triggered if s.name != "CROSS_USER"]
        result.is_idor = result.confirmed or len(non_cross) >= 2

        if result.is_idor:
            if _is_waf_block(test_body_str):
                result.is_idor = False
                result.fp_signals.append("WAF block pattern in response — likely blocked")
                result.fp_risk = "HIGH"
            elif _is_empty_response(test_body_str) and not result.confirmed:
                result.fp_signals.append("Tested ID returned empty response — may be valid 'not found'")
                result.fp_risk = "MEDIUM"
            else:
                result.fp_risk = "LOW"

        if result.is_idor:
            result.title = (
                f"Blind IDOR — {parameter}: ID {owned_id}→{tested_id} "
                f"({len(triggered)} oracle{'s' if len(triggered) != 1 else ''} triggered)"
            )
            result.evidence = (
                f"Oracles: {' | '.join(result.oracles_triggered)} | "
                f"Confidence: {result.confidence}% | "
                f"{'CROSS-USER CONFIRMED' if result.confirmed else 'Heuristic'}"
            )

        return result


def _adjacent_ids(original: int) -> list[int]:
    candidates = []
    for delta in [-1, 1, -2, 2, 10, -10, 100]:
        c = original + delta
        if c > 0:
            candidates.append(c)
    for low in [1, 2, 3]:
        if low != original and low not in candidates:
            candidates.append(low)
    return candidates[:6]


def _test_uuids(original: str) -> list[str]:
    return [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "11111111-1111-1111-1111-111111111111",
        original[:-4] + "0001",
    ]


def _body_test_values(original) -> list:
    if isinstance(original, int):
        return [v for v in [original - 1, original + 1, 1, 2, 3] if v > 0 and v != original]
    if isinstance(original, str) and original.isdigit():
        v = int(original)
        return [str(x) for x in [v - 1, v + 1, 1, 2] if x > 0 and x != v]
    return []


def _dominant(statuses: list[int]) -> int:
    if not statuses:
        return 0
    return max(set(statuses), key=statuses.count)


def _trim_outliers(samples: list[float]) -> list[float]:
    if len(samples) <= 2:
        return samples[:]
    s = sorted(samples)
    return s[1:-1]


def _responses_differ(body_a: str, body_b: str, threshold: float = 0.15) -> bool:
    if body_a == body_b:
        return False
    size_delta = abs(len(body_a) - len(body_b))
    if size_delta > max(25, max(len(body_a), len(body_b)) * threshold):
        return True
    return (
        hashlib.md5(body_a.encode()).hexdigest() !=
        hashlib.md5(body_b.encode()).hexdigest()
    )


def _is_waf_block(body: str) -> bool:
    waf_signals = [
        "access denied", "request blocked", "security violation",
        "cloudflare", "akamai security", "imperva", "sucuri",
        "mod_security", "your request has been blocked",
        "ddos protection", "attention required",
    ]
    body_lower = body.lower()
    return any(sig in body_lower for sig in waf_signals)


def _is_empty_response(body: str) -> bool:
    stripped = body.strip()
    if not stripped or stripped in ("{}", "[]", "null", '{"data":null}', '{"result":null}'):
        return True
    try:
        data = json.loads(stripped)
        if isinstance(data, dict) and not data:
            return True
        if isinstance(data, list) and not data:
            return True
    except (json.JSONDecodeError, ValueError):
        pass
    return len(stripped) < 10


def _response_has_data(body: str) -> bool:
    if len(body) < 20:
        return False
    try:
        data = json.loads(body.strip())
        if isinstance(data, dict):
            return len(data) > 0 and any(v not in (None, "", [], {}) for v in data.values())
        if isinstance(data, list):
            return len(data) > 0
    except (json.JSONDecodeError, ValueError):
        pass
    return len(body) > 50


def _extract_message(body: str) -> str:
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key in ["message", "error", "detail", "msg", "description", "reason"]:
                if key in data and isinstance(data[key], str):
                    return data[key].strip()[:80]
    except (json.JSONDecodeError, ValueError):
        pass
    return ""

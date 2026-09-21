from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin


class ValidationResult(str, Enum):
    VALID          = "VALID"
    SOFT_404       = "SOFT_404"
    GENERIC        = "GENERIC"
    WAF_BLOCKED    = "WAF_BLOCKED"
    AUTH_REQUIRED  = "AUTH_REQUIRED"
    NOT_GRAPHQL    = "NOT_GRAPHQL"
    UNKNOWN        = "UNKNOWN"
    SKIP           = "SKIP"


@dataclass
class ValidationReport:
    url:                str
    result:             ValidationResult = ValidationResult.UNKNOWN
    confidence:         int = 100
    should_skip:        bool = False
    confidence_penalty: int = 0

    content_type_ok:    bool = True
    content_type_found: str = ""
    json_parseable:     bool = False
    canary_passed:      bool = True
    soft404_passed:     bool = True
    graphql_confirmed:  bool = False

    original_status:    int = 0
    original_body_len:  int = 0
    canary_status:      int = 0
    probe_404_status:   int = 0
    probe_similarity:   float = 0.0

    reasons:            list[str] = field(default_factory=list)
    warnings:           list[str] = field(default_factory=list)

    def add_reason(self, reason: str):
        self.reasons.append(reason)

    def add_warning(self, warning: str):
        self.warnings.append(warning)

    @property
    def summary(self) -> str:
        status = self.result.value
        if self.reasons:
            return f"{status}: {'; '.join(self.reasons[:2])}"
        return status


@dataclass
class ValidationConfig:
    require_json_content_type: bool = True
    allowed_content_types: list[str] = field(default_factory=lambda: [
        "application/json", "application/graphql", "text/plain",
        "application/ld+json", "application/vnd.api+json",
    ])

    soft_404_threshold:           float = 0.85
    soft404_similarity_threshold: float = 0.85
    min_meaningful_body_bytes:    int = 20

    run_canary_test:             bool = True
    canary_similarity_threshold: float = 0.90

    strict_graphql_validation: bool = True

    always_valid_statuses: list[int] = field(
        default_factory=lambda: [401, 403]
    )
    error_statuses_are_valid: bool = True
    html_skip_enabled:        bool = True


_WAF_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"cloudflare",
        r"access denied",
        r"request blocked",
        r"security violation",
        r"akamai",
        r"imperva",
        r"sucuri",
        r"mod_security",
        r"your request has been blocked",
        r"ddos protection",
        r"attention required.*cloudflare",
        r"<title>.*blocked.*</title>",
        r"<title>.*security.*</title>",
    ]
]

_HTML_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"<!doctype\s+html",
        r"<html[\s>]",
        r"<head[\s>]",
        r"<title>",
        r"<body[\s>]",
        r"<meta\s+",
        r"<link\s+",
        r"<script\s+",
        r"<div[\s>]",
    ]
]

_GENERIC_404_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'"error"\s*:\s*"not found"',
        r'"message"\s*:\s*"not found"',
        r'"status"\s*:\s*404',
        r'"code"\s*:\s*"404"',
        r"page not found",
        r"404 not found",
        r"resource not found",
        r"endpoint not found",
    ]
]


class EndpointValidator:

    def __init__(self, scanner, config: ValidationConfig | None = None, **kwargs):
        self._scanner = scanner
        self._config  = config or ValidationConfig()

        for k, v in kwargs.items():
            if hasattr(self._config, k):
                setattr(self._config, k, v)
            else:
                setattr(self, k, v)
        self._cache: dict[str, ValidationReport] = {}

    async def validate(
        self,
        url: str,
        method: str = "GET",
        body: dict | None = None,
        is_graphql: bool = False,
    ) -> ValidationReport:
        cache_key = f"{method}:{url}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        report = ValidationReport(url=url)

        status, headers, body_text, elapsed = await self._scanner._request(
            method, url,
            json=body if body else None,
        )
        report.original_status   = status
        report.original_body_len = len(body_text)

        if status == 0:
            report.result = ValidationResult.UNKNOWN
            report.add_warning("Endpoint unreachable — skipping validation")
            self._cache[cache_key] = report
            return report

        if status in self._config.always_valid_statuses:
            report.result         = ValidationResult.AUTH_REQUIRED
            report.json_parseable = _is_json(body_text)
            report.add_reason(f"HTTP {status} — endpoint requires authentication (real endpoint)")
            report.should_skip    = False
            self._cache[cache_key] = report
            return report

        if status >= 500 and self._config.error_statuses_are_valid:
            report.result      = ValidationResult.VALID
            report.add_reason(f"HTTP {status} — server error indicates real endpoint")
            report.should_skip = False
            self._cache[cache_key] = report
            return report

        if _is_waf_block(body_text):
            report.result             = ValidationResult.WAF_BLOCKED
            report.should_skip        = True
            report.confidence         = 20
            report.confidence_penalty = 40
            report.add_reason("WAF block page detected in response")
            self._cache[cache_key] = report
            return report

        content_type         = _get_content_type(headers)
        report.content_type_found = content_type
        is_html_content      = _is_html_content_type(content_type)
        body_looks_like_html = _body_is_html(body_text)

        if is_html_content or body_looks_like_html:
            report.content_type_ok = False
            if self._config.html_skip_enabled:
                report.result      = ValidationResult.SOFT_404
                report.should_skip = True
                report.confidence  = 95
                report.add_reason(
                    f"Response is HTML (Content-Type: {content_type or 'unknown'}) "
                    "— not an API endpoint."
                )
                self._cache[cache_key] = report
                return report
            else:
                report.add_warning(f"HTML response detected (Content-Type: {content_type})")
                report.confidence_penalty += 20

        if len(body_text.strip()) < self._config.min_meaningful_body_bytes:
            report.add_warning(
                f"Response body very short ({len(body_text)}B) — may be a stub endpoint"
            )
            report.confidence_penalty += 10

        report.json_parseable = _is_json(body_text)
        if not report.json_parseable and status == 200:
            report.add_warning("Response body is not valid JSON — may not be a real API endpoint")
            report.confidence_penalty += 15

        parsed      = urlparse(url)
        nonexistent = urljoin(
            f"{parsed.scheme}://{parsed.netloc}",
            f"{parsed.path}/__blfinder_nonexistent_probe_xyz__"
        )
        probe_status, _, probe_body, _ = await self._scanner._request("GET", nonexistent)
        report.probe_404_status = probe_status
        report.soft404_passed   = True

        threshold = max(
            self._config.soft_404_threshold,
            self._config.soft404_similarity_threshold,
        )
        if probe_status == 200 and body_text and probe_body:
            similarity = _body_similarity(body_text, probe_body)
            report.probe_similarity = similarity
            if similarity > threshold:
                report.soft404_passed = False
                report.result         = ValidationResult.SOFT_404
                report.should_skip    = True
                report.confidence     = 90
                report.add_reason(
                    f"Soft-404 detected: response is {similarity:.0%} similar to a "
                    "request for a nonexistent path."
                )
                self._cache[cache_key] = report
                return report

        if self._config.run_canary_test and method in ("POST", "PUT", "PATCH"):
            canary_body = {"__blfinder_canary__": True, "__invalid_field_xyz__": 12345}
            canary_status, _, canary_body_text, _ = await self._scanner._request(
                method, url, json=canary_body
            )
            report.canary_status = canary_status

            if canary_status == status and body_text and canary_body_text:
                canary_sim = _body_similarity(body_text, canary_body_text)
                if canary_sim > self._config.canary_similarity_threshold:
                    report.canary_passed       = False
                    report.result              = ValidationResult.GENERIC
                    report.should_skip         = False
                    report.confidence_penalty += 30
                    report.add_warning(
                        f"Canary test failed: server returned {canary_sim:.0%} similar "
                        "response to a nonsense request. Finding confidence will be reduced."
                    )

        if is_graphql or _url_looks_like_graphql(url):
            gql_valid = await self._validate_graphql(url)
            report.graphql_confirmed = gql_valid
            if not gql_valid and self._config.strict_graphql_validation:
                report.result      = ValidationResult.NOT_GRAPHQL
                report.should_skip = True
                report.confidence  = 85
                report.add_reason(
                    "URL looks like a GraphQL endpoint but did not return "
                    '{"data":...} or {"errors":[...]}.'
                )
                self._cache[cache_key] = report
                return report

        if report.result == ValidationResult.UNKNOWN:
            if report.json_parseable or status in (200, 201, 204):
                report.result = ValidationResult.VALID
            else:
                report.result = ValidationResult.UNKNOWN

        report.should_skip = report.result in (
            ValidationResult.SOFT_404,
            ValidationResult.NOT_GRAPHQL,
            ValidationResult.WAF_BLOCKED,
        )
        report.confidence = max(0, 100 - report.confidence_penalty)

        self._cache[cache_key] = report
        return report

    async def _validate_graphql(self, url: str) -> bool:
        for query in ['{"query": "{ __typename }"}', '{"query": "query { __typename }"}']:
            status, headers, body, _ = await self._scanner._request("POST", url, data=query)
            if status == 200:
                ct = _get_content_type(headers)
                if "json" in ct.lower():
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            return True
                    except (json.JSONDecodeError, ValueError):
                        pass
        return False

    def clear_cache(self):
        self._cache.clear()

    def get_stats(self) -> dict:
        stats = {
            "total": len(self._cache), "valid": 0, "skipped": 0,
            "auth": 0, "soft_404": 0, "waf": 0, "generic": 0, "not_graphql": 0,
        }
        for r in self._cache.values():
            if r.result == ValidationResult.VALID:           stats["valid"] += 1
            elif r.result == ValidationResult.AUTH_REQUIRED: stats["auth"] += 1
            elif r.result == ValidationResult.SOFT_404:      stats["soft_404"] += 1
            elif r.result == ValidationResult.WAF_BLOCKED:   stats["waf"] += 1
            elif r.result == ValidationResult.GENERIC:       stats["generic"] += 1
            elif r.result == ValidationResult.NOT_GRAPHQL:   stats["not_graphql"] += 1
            if r.should_skip:                                 stats["skipped"] += 1
        return stats


def _get_content_type(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def _is_html_content_type(ct: str) -> bool:
    return "text/html" in ct or "application/xhtml" in ct


def _body_is_html(body: str) -> bool:
    if not body:
        return False
    sample  = body.strip()[:500].lower()
    matches = sum(1 for p in _HTML_PATTERNS if p.search(sample))
    return matches >= 2


def _is_json(body: str) -> bool:
    if not body:
        return False
    body = body.strip()
    if not (body.startswith("{") or body.startswith("[")):
        return False
    try:
        json.loads(body)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _is_waf_block(body: str) -> bool:
    if not body:
        return False
    body_lower = body.lower()
    return sum(1 for p in _WAF_PATTERNS if p.search(body_lower)) >= 1


def _body_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if max(la, lb) > 0:
        if min(la, lb) / max(la, lb) < 0.5:
            return 0.0
    tokens_a = set(re.findall(r'\w+', a[:3000]))
    tokens_b = set(re.findall(r'\w+', b[:3000]))
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union        = tokens_a | tokens_b
    return len(intersection) / len(union)


def _url_looks_like_graphql(url: str) -> bool:
    url_lower = url.lower()
    return any(
        seg in url_lower
        for seg in ["/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query"]
    )

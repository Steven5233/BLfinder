"""
BLFinder Phase 3 — core/validation/endpoint_validator.py
5-Step Endpoint Validation Pipeline

Runs BEFORE any attack module to confirm an endpoint is a real API endpoint.
Prevents false positives like the Twilio case where a marketing homepage was
mistaken for a GraphQL endpoint.

The 5 steps:
  1. Content-Type enforcement  — response must be JSON, not HTML
  2. Structural response check — response must parse as valid JSON
  3. Canary request test       — server must not accept everything equally
  4. Soft-404 detection        — response must differ from a 404 probe
  5. GraphQL confirmation      — GraphQL endpoints must return data/errors

FP-reduction design decisions:
  - Auth-required endpoints (401/403) are NEVER suppressed — they are real
  - 500 errors are flagged as real endpoints (they have business logic)
  - Partial validation failures reduce confidence rather than hard-suppressing
  - Each step is independently configurable via ValidationConfig
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin


class ValidationResult(str, Enum):
    VALID          = "VALID"           # Confirmed real API endpoint
    SOFT_404       = "SOFT_404"        # Returns HTML or generic page
    GENERIC        = "GENERIC"         # Accepts any request equally
    WAF_BLOCKED    = "WAF_BLOCKED"     # Request is blocked by WAF
    AUTH_REQUIRED  = "AUTH_REQUIRED"   # Real endpoint, needs auth
    NOT_GRAPHQL    = "NOT_GRAPHQL"     # URL looks like GraphQL but isn't
    UNKNOWN        = "UNKNOWN"         # Could not determine (treat as valid)
    SKIP           = "SKIP"            # Definitively not an API endpoint


@dataclass
class ValidationReport:
    """Full result of running the 5-step validation pipeline."""
    url:                str
    result:             ValidationResult = ValidationResult.UNKNOWN
    confidence:         int = 100            # 0–100, how confident in result
    should_skip:        bool = False         # True = do not test this endpoint
    confidence_penalty: int = 0             # Applied to all findings on this endpoint

    # Step results
    content_type_ok:    bool = True
    content_type_found: str = ""
    json_parseable:     bool = False
    canary_passed:      bool = True          # True = canary was different (good)
    soft404_passed:     bool = True          # True = not a soft-404 (good)
    graphql_confirmed:  bool = False

    # Raw data
    original_status:    int = 0
    original_body_len:  int = 0
    canary_status:      int = 0
    probe_404_status:   int = 0
    probe_similarity:   float = 0.0

    # Explanation
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
    """Controls how strictly the validator operates."""
    # Content-Type enforcement
    require_json_content_type: bool = True
    allowed_content_types: list[str] = field(default_factory=lambda: [
        "application/json", "application/graphql", "text/plain",
        "application/ld+json", "application/vnd.api+json",
    ])

    # Soft-404 detection
    soft404_similarity_threshold: float = 0.85   # >85% similar to 404 = skip
    min_meaningful_body_bytes:    int = 20        # Body shorter than this = skip

    # Canary test
    run_canary_test:          bool = True
    canary_similarity_threshold: float = 0.90    # >90% same as canary = generic

    # GraphQL-specific
    strict_graphql_validation: bool = True       # Require JSON with data/errors

    # Auth endpoints — NEVER suppress (critical FP prevention)
    always_valid_statuses: list[int] = field(
        default_factory=lambda: [401, 403]
    )
    # Error responses are real endpoints worth testing
    error_statuses_are_valid: bool = True

    # Skip HTML content entirely
    html_skip_enabled: bool = True


# ── WAF fingerprints ──────────────────────────────────────────────────────────
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

# ── HTML detection ────────────────────────────────────────────────────────────
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

# ── Generic soft-404 body patterns ────────────────────────────────────────────
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
    """
    5-step validation pipeline for API endpoints.

    Usage:
        validator = EndpointValidator(scanner, config=ValidationConfig())
        report = await validator.validate(url, method="POST", body={})

        if report.should_skip:
            return []  # Skip this endpoint entirely
        if report.confidence_penalty > 0:
            # Apply penalty to all findings from this endpoint
    """

    def __init__(self, scanner, config: ValidationConfig | None = None):
        self._scanner = scanner
        self._config  = config or ValidationConfig()
        self._cache: dict[str, ValidationReport] = {}

    async def validate(
        self,
        url: str,
        method: str = "GET",
        body: dict | None = None,
        is_graphql: bool = False,
    ) -> ValidationReport:
        """
        Run the full 5-step validation pipeline.

        Returns a ValidationReport. Check report.should_skip before testing.
        """
        # Cache results — don't re-validate the same URL repeatedly
        cache_key = f"{method}:{url}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        report = ValidationReport(url=url)

        # Make the initial request
        status, headers, body_text, elapsed = await self._scanner._request(
            method, url,
            json=body if body else None,
        )
        report.original_status  = status
        report.original_body_len = len(body_text)

        # ── STEP 0: Connection failure check ──────────────────────────────────
        if status == 0:
            report.result  = ValidationResult.UNKNOWN
            report.add_warning("Endpoint unreachable — skipping validation")
            self._cache[cache_key] = report
            return report

        # ── CRITICAL: Auth-required = ALWAYS VALID ────────────────────────────
        # 401/403 means the endpoint EXISTS and has access control
        # Never suppress these — they are exactly what we want to test
        if status in self._config.always_valid_statuses:
            report.result = ValidationResult.AUTH_REQUIRED
            report.json_parseable = _is_json(body_text)
            report.add_reason(
                f"HTTP {status} — endpoint requires authentication (real endpoint)"
            )
            report.should_skip = False
            self._cache[cache_key] = report
            return report

        # ── CRITICAL: 500 errors are real endpoints ───────────────────────────
        if status >= 500 and self._config.error_statuses_are_valid:
            report.result = ValidationResult.VALID
            report.add_reason(f"HTTP {status} — server error indicates real endpoint")
            report.should_skip = False
            self._cache[cache_key] = report
            return report

        # ── STEP 1: WAF detection ──────────────────────────────────────────────
        if _is_waf_block(body_text):
            report.result        = ValidationResult.WAF_BLOCKED
            report.should_skip   = True
            report.confidence    = 20
            report.confidence_penalty = 40
            report.add_reason("WAF block page detected in response")
            self._cache[cache_key] = report
            return report

        # ── STEP 2: Content-Type enforcement ──────────────────────────────────
        content_type = _get_content_type(headers)
        report.content_type_found = content_type
        is_html_content = _is_html_content_type(content_type)
        body_looks_like_html = _body_is_html(body_text)

        if is_html_content or body_looks_like_html:
            report.content_type_ok = False
            if self._config.html_skip_enabled:
                report.result      = ValidationResult.SOFT_404
                report.should_skip = True
                report.confidence  = 95
                report.add_reason(
                    f"Response is HTML (Content-Type: {content_type or 'unknown'}) "
                    "— not an API endpoint. Likely a soft-404 or marketing page."
                )
                self._cache[cache_key] = report
                return report
            else:
                report.add_warning(
                    f"HTML response detected (Content-Type: {content_type})"
                )
                report.confidence_penalty += 20

        # ── STEP 3: Body size check ────────────────────────────────────────────
        if len(body_text.strip()) < self._config.min_meaningful_body_bytes:
            report.add_warning(
                f"Response body very short ({len(body_text)}B) — "
                "may be an empty or stub endpoint"
            )
            report.confidence_penalty += 10

        # ── STEP 4: JSON parseability ──────────────────────────────────────────
        report.json_parseable = _is_json(body_text)
        if not report.json_parseable and status == 200:
            # Non-JSON 200 is suspicious for an API endpoint
            report.add_warning(
                "Response body is not valid JSON — may not be a real API endpoint"
            )
            report.confidence_penalty += 15

        # ── STEP 5: Soft-404 probe ─────────────────────────────────────────────
        parsed      = urlparse(url)
        nonexistent = urljoin(
            f"{parsed.scheme}://{parsed.netloc}",
            f"{parsed.path}/__blfinder_nonexistent_probe_xyz__"
        )
        probe_status, _, probe_body, _ = await self._scanner._request(
            "GET", nonexistent
        )
        report.probe_404_status = probe_status
        report.soft404_passed   = True

        if probe_status == 200 and body_text and probe_body:
            similarity = _body_similarity(body_text, probe_body)
            report.probe_similarity = similarity
            if similarity > self._config.soft404_similarity_threshold:
                report.soft404_passed    = False
                report.result            = ValidationResult.SOFT_404
                report.should_skip       = True
                report.confidence        = 90
                report.add_reason(
                    f"Soft-404 detected: response is {similarity:.0%} similar to a "
                    "request for a nonexistent path. Server returns same page for "
                    "any URL."
                )
                self._cache[cache_key] = report
                return report

        # ── STEP 6: Canary request test ────────────────────────────────────────
        if self._config.run_canary_test and method in ("POST", "PUT", "PATCH"):
            canary_body = {"__blfinder_canary__": True, "__invalid_field_xyz__": 12345}
            canary_status, _, canary_body_text, _ = await self._scanner._request(
                method, url, json=canary_body
            )
            report.canary_status = canary_status

            if canary_status == status and body_text and canary_body_text:
                canary_sim = _body_similarity(body_text, canary_body_text)
                if canary_sim > self._config.canary_similarity_threshold:
                    report.canary_passed    = False
                    report.result           = ValidationResult.GENERIC
                    report.should_skip      = False  # Still test but reduce confidence
                    report.confidence_penalty += 30
                    report.add_warning(
                        f"Canary test failed: server returned {canary_sim:.0%} similar "
                        "response to a nonsense request. Endpoint may accept any input. "
                        "Finding confidence will be reduced."
                    )

        # ── STEP 7: GraphQL-specific validation ────────────────────────────────
        if is_graphql or _url_looks_like_graphql(url):
            gql_valid = await self._validate_graphql(url)
            report.graphql_confirmed = gql_valid
            if not gql_valid and self._config.strict_graphql_validation:
                report.result      = ValidationResult.NOT_GRAPHQL
                report.should_skip = True
                report.confidence  = 85
                report.add_reason(
                    "URL looks like a GraphQL endpoint but did not return "
                    '{"data":...} or {"errors":[...]} — likely not a real '
                    "GraphQL endpoint."
                )
                self._cache[cache_key] = report
                return report

        # ── Final verdict ──────────────────────────────────────────────────────
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
        """Confirm a GraphQL endpoint by sending a minimal valid query."""
        test_queries = [
            '{"query": "{ __typename }"}',
            '{"query": "query { __typename }"}',
        ]
        for query in test_queries:
            status, headers, body, _ = await self._scanner._request(
                "POST", url,
                data=query,
            )
            if status == 200:
                ct = _get_content_type(headers)
                if "json" in ct.lower():
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and (
                            "data" in data or "errors" in data
                        ):
                            return True
                    except (json.JSONDecodeError, ValueError):
                        pass
        return False

    def clear_cache(self):
        """Clear validation cache — call between targets."""
        self._cache.clear()

    def get_stats(self) -> dict:
        """Return validation statistics for the current scan."""
        stats = {
            "total":       len(self._cache),
            "valid":       0,
            "skipped":     0,
            "auth":        0,
            "soft_404":    0,
            "waf":         0,
            "generic":     0,
            "not_graphql": 0,
        }
        for r in self._cache.values():
            if r.result == ValidationResult.VALID:
                stats["valid"] += 1
            elif r.result == ValidationResult.AUTH_REQUIRED:
                stats["auth"] += 1
            elif r.result == ValidationResult.SOFT_404:
                stats["soft_404"] += 1
            elif r.result == ValidationResult.WAF_BLOCKED:
                stats["waf"] += 1
            elif r.result == ValidationResult.GENERIC:
                stats["generic"] += 1
            elif r.result == ValidationResult.NOT_GRAPHQL:
                stats["not_graphql"] += 1
            if r.should_skip:
                stats["skipped"] += 1
        return stats


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    sample = body.strip()[:500].lower()
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
    """Fast approximate similarity between two response bodies."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    # Length-based pre-check
    la, lb = len(a), len(b)
    if max(la, lb) > 0:
        len_ratio = min(la, lb) / max(la, lb)
        if len_ratio < 0.5:
            return 0.0

    # Token-based similarity (faster than difflib for large bodies)
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

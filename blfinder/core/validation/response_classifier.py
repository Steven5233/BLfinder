"""
BLFinder Phase 3 — core/validation/response_classifier.py
Response Classifier

Classifies every HTTP response into one of 9 categories before any
attack module processes it. The classification is attached to
base_responses[url] so every downstream module can check it.

Classifications:
  REAL_API_JSON      → JSON response, parses cleanly, has meaningful data
  GRAPHQL_ENDPOINT   → Returns {"data":...} or {"errors":[...]}
  AUTH_REQUIRED      → 401/403, real endpoint, needs token
  SOFT_404_HTML      → HTML returned for API request (homepage / CMS redirect)
  SOFT_404_JSON      → JSON "not found" returned for everything
  GENERIC_RESPONDER  → Same response regardless of input
  WAF_BLOCK          → Security tool block page
  RATE_LIMITED       → 429 with retry headers
  REAL_ERROR         → 500 with stack trace or error detail
  EMPTY_RESPONSE     → No meaningful body
  UNKNOWN            → Cannot determine

Finding suppression rules:
  SOFT_404_HTML      → ALL findings suppressed (skip)
  GENERIC_RESPONDER  → Confidence capped at 40% (still report but warn)
  WAF_BLOCK          → ALL findings suppressed
  EMPTY_RESPONSE     → Confidence capped at 30%
  AUTH_REQUIRED      → Findings promoted (real endpoint, auth bypass is high value)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResponseClass(str, Enum):
    REAL_API_JSON     = "REAL_API_JSON"
    GRAPHQL_ENDPOINT  = "GRAPHQL_ENDPOINT"
    AUTH_REQUIRED     = "AUTH_REQUIRED"
    SOFT_404_HTML     = "SOFT_404_HTML"
    SOFT_404_JSON     = "SOFT_404_JSON"
    GENERIC_RESPONDER = "GENERIC_RESPONDER"
    WAF_BLOCK         = "WAF_BLOCK"
    RATE_LIMITED      = "RATE_LIMITED"
    REAL_ERROR        = "REAL_ERROR"
    EMPTY_RESPONSE    = "EMPTY_RESPONSE"
    UNKNOWN           = "UNKNOWN"



SUPPRESSION_RULES: dict[ResponseClass, dict] = {
    ResponseClass.SOFT_404_HTML:     {"suppress": True,  "confidence_cap": 0,   "note": "Soft-404 HTML — marketing/homepage response"},
    ResponseClass.WAF_BLOCK:         {"suppress": True,  "confidence_cap": 0,   "note": "WAF block page — request was blocked"},
    ResponseClass.SOFT_404_JSON:     {"suppress": True,  "confidence_cap": 0,   "note": "Soft-404 JSON — returns not-found for everything"},
    ResponseClass.GENERIC_RESPONDER: {"suppress": False, "confidence_cap": 40,  "note": "Generic responder — accepts any input equally"},
    ResponseClass.EMPTY_RESPONSE:    {"suppress": False, "confidence_cap": 30,  "note": "Empty response — body has no meaningful data"},
    ResponseClass.RATE_LIMITED:      {"suppress": False, "confidence_cap": 50,  "note": "Rate limited — results may be incomplete"},
    ResponseClass.AUTH_REQUIRED:     {"suppress": False, "confidence_cap": 100, "note": "Auth required — real endpoint (high value target)"},
    ResponseClass.REAL_API_JSON:     {"suppress": False, "confidence_cap": 100, "note": "Confirmed real API endpoint"},
    ResponseClass.GRAPHQL_ENDPOINT:  {"suppress": False, "confidence_cap": 100, "note": "Confirmed GraphQL endpoint"},
    ResponseClass.REAL_ERROR:        {"suppress": False, "confidence_cap": 100, "note": "Server error — real endpoint (check for info leakage)"},
    ResponseClass.UNKNOWN:           {"suppress": False, "confidence_cap": 70,  "note": "Unknown — treat with caution"},
}


@dataclass
class ClassifiedResponse:
    """A classified HTTP response with suppression guidance."""
    url:            str
    status:         int
    body:           str
    headers:        dict
    elapsed_ms:     float
    response_class: ResponseClass = ResponseClass.UNKNOWN


    suppress_findings:  bool = False
    confidence_cap:     int  = 100
    classification_note: str = ""


    body_parsed:    Any = None
    is_json:        bool = False
    is_html:        bool = False
    has_data_field: bool = False     


    has_graphql_data:   bool = False
    has_graphql_errors: bool = False


    has_stack_trace: bool = False
    error_message:   str  = ""


    signals: list[str] = field(default_factory=list)

    def apply_suppression(self, finding_confidence: int) -> int:
        """
        Apply suppression rules to a finding's confidence score.
        Returns the adjusted confidence (0 = suppressed).
        """
        if self.suppress_findings:
            return 0
        return min(finding_confidence, self.confidence_cap)

    @property
    def is_real_endpoint(self) -> bool:
        return self.response_class in (
            ResponseClass.REAL_API_JSON,
            ResponseClass.GRAPHQL_ENDPOINT,
            ResponseClass.AUTH_REQUIRED,
            ResponseClass.REAL_ERROR,
        )

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v.lower()
        return ""


class ResponseClassifier:
    """
    Classifies HTTP responses and provides suppression guidance.

    Usage:
        classifier = ResponseClassifier()

        # Classify a response
        classified = classifier.classify(url, status, headers, body, elapsed)

        # Check before running attack modules
        if classified.suppress_findings:
            return []  # Skip this endpoint

        # Apply confidence cap to findings
        adjusted_confidence = classified.apply_suppression(finding.confidence)
    """



    def classify(
        self,
        url:      str,
        status:   int,
        headers:  dict,
        body:     str,
        elapsed:  float = 0.0,
    ) -> ClassifiedResponse:
        """
        Classify a response and return guidance for attack modules.
        """
        cr = ClassifiedResponse(
            url=url, status=status, body=body,
            headers=headers, elapsed_ms=elapsed * 1000,
        )


        cr.is_json = _is_json(body)
        cr.is_html = _is_html(body, headers)
        if cr.is_json:
            try:
                cr.body_parsed = json.loads(body.strip())
            except (json.JSONDecodeError, ValueError):
                pass


        rc = self._classify_ordered(cr, status, body, headers)
        cr.response_class = rc


        rule = SUPPRESSION_RULES.get(rc, SUPPRESSION_RULES[ResponseClass.UNKNOWN])
        cr.suppress_findings  = rule["suppress"]
        cr.confidence_cap     = rule["confidence_cap"]
        cr.classification_note = rule["note"]

        return cr

    def _classify_ordered(
        self,
        cr: ClassifiedResponse,
        status: int,
        body: str,
        headers: dict,
    ) -> ResponseClass:
        """Run classifiers in priority order."""


        if _is_waf_block(body):
            cr.signals.append("WAF block patterns detected")
            return ResponseClass.WAF_BLOCK


        if status == 429:
            cr.signals.append("HTTP 429 Too Many Requests")
            return ResponseClass.RATE_LIMITED


        if status in (401, 403):
            cr.signals.append(f"HTTP {status} — authentication/authorization required")

            if cr.is_html:
                cr.signals.append("Auth response is HTML — may be a redirect to login")
            return ResponseClass.AUTH_REQUIRED


        if status >= 500:
            cr.signals.append(f"HTTP {status} — server error")
            cr.has_stack_trace = _has_stack_trace(body)
            if cr.has_stack_trace:
                cr.signals.append("Stack trace detected in error response")
            cr.error_message = _extract_error_message(body)
            return ResponseClass.REAL_ERROR


        if cr.is_html:
            cr.signals.append("Response body is HTML — not an API endpoint")
            cr.signals.append(
                "Likely a soft-404, CMS redirect, or marketing homepage"
            )
            return ResponseClass.SOFT_404_HTML


        if not body or len(body.strip()) < 10:
            cr.signals.append("Response body is empty or nearly empty")
            return ResponseClass.EMPTY_RESPONSE


        if cr.is_json and isinstance(cr.body_parsed, dict):
            cr.has_graphql_data   = "data"   in cr.body_parsed
            cr.has_graphql_errors = "errors" in cr.body_parsed
            if cr.has_graphql_data or cr.has_graphql_errors:
                cr.signals.append("GraphQL response structure detected")
                cr.has_data_field = True
                return ResponseClass.GRAPHQL_ENDPOINT


        if cr.is_json and _is_generic_404_json(body, status):
            cr.signals.append(
                "JSON not-found pattern — endpoint returns generic error for everything"
            )
            return ResponseClass.SOFT_404_JSON


        if cr.is_json and status in (200, 201, 204):
            cr.has_data_field = _has_meaningful_data(cr.body_parsed)
            if cr.has_data_field:
                cr.signals.append("Valid JSON with meaningful data fields")
            else:
                cr.signals.append("Valid JSON but minimal data")
            return ResponseClass.REAL_API_JSON


        cr.signals.append(
            f"Could not classify: status={status}, "
            f"is_json={cr.is_json}, is_html={cr.is_html}, "
            f"body_len={len(body)}"
        )
        return ResponseClass.UNKNOWN



    def classify_many(
        self,
        responses: list[tuple[str, int, dict, str, float]],
    ) -> list[ClassifiedResponse]:
        """Classify a list of (url, status, headers, body, elapsed) tuples."""
        return [self.classify(*r) for r in responses]

    def should_suppress(self, url: str, classified: ClassifiedResponse) -> bool:
        """Quick check: should all findings for this URL be suppressed?"""
        return classified.suppress_findings

    def get_confidence_cap(self, classified: ClassifiedResponse) -> int:
        """Get the maximum confidence allowed for findings on this endpoint."""
        return classified.confidence_cap




_WAF_SIGNALS = [
    re.compile(p, re.I) for p in [
        r"cloudflare", r"akamai", r"imperva", r"sucuri", r"barracuda",
        r"access denied", r"request blocked", r"security violation",
        r"mod_security", r"your request has been blocked",
        r"ddos protection", r"<title>.*blocked.*</title>",
        r"<title>.*attention required",
        r"ray id:", r"cf-ray",
    ]
]

_HTML_SIGNALS = [
    re.compile(p, re.I) for p in [
        r"<!doctype\s+html", r"<html[\s>]", r"<head[\s>]",
        r"<title>", r"<body[\s>]", r"<meta\s+", r"<div[\s>]",
    ]
]

_STACK_TRACE_SIGNALS = [
    re.compile(p, re.I) for p in [
        r"at\s+\w+\.\w+\(.*\.py:\d+\)",   
        r"at\s+\w+\.\w+\(.*\.java:\d+\)", 
        r"at\s+\w+\.\w+\(.*\.js:\d+\)",   
        r"stack trace:", r"traceback",
        r"exception in thread", r"caused by:",
        r"at\s+\w[\w.]+\s+\(.*:\d+:\d+\)",  
    ]
]

_GENERIC_404_JSON = [
    re.compile(p, re.I) for p in [
        r'"status"\s*:\s*"?404"?',
        r'"error"\s*:\s*"not found"',
        r'"message"\s*:\s*"not found"',
        r'"message"\s*:\s*"resource not found"',
        r'"message"\s*:\s*"endpoint not found"',
        r'"code"\s*:\s*"not_found"',
        r'"type"\s*:\s*"not_found"',
    ]
]


def _is_json(body: str) -> bool:
    if not body:
        return False
    b = body.strip()
    if not (b.startswith("{") or b.startswith("[")):
        return False
    try:
        json.loads(b)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _is_html(body: str, headers: dict) -> bool:
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    if not body:
        return False
    sample = body.strip()[:300].lower()
    return sum(1 for p in _HTML_SIGNALS if p.search(sample)) >= 2


def _is_waf_block(body: str) -> bool:
    if not body:
        return False
    bl = body.lower()
    return sum(1 for p in _WAF_SIGNALS if p.search(bl)) >= 1


def _is_generic_404_json(body: str, status: int) -> bool:
    """Return True if the JSON body looks like a generic not-found response."""
    if status == 404:
        return True
    return sum(1 for p in _GENERIC_404_JSON if p.search(body)) >= 1


def _has_stack_trace(body: str) -> bool:
    body_lower = body.lower()
    return any(p.search(body_lower) for p in _STACK_TRACE_SIGNALS)


def _has_meaningful_data(parsed: Any) -> bool:
    """True if the parsed JSON body contains substantive data."""
    if parsed is None:
        return False
    if isinstance(parsed, list):
        return len(parsed) > 0
    if isinstance(parsed, dict):
        if not parsed:
            return False

        if set(parsed.keys()) <= {"status", "ok", "success", "message", "code"}:
            return len(parsed) > 1
        return True
    return False


def _extract_error_message(body: str) -> str:
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            for key in ["message", "error", "detail", "msg"]:
                if key in data and isinstance(data[key], str):
                    return data[key][:100]
    except (json.JSONDecodeError, ValueError):
        pass
    return ""

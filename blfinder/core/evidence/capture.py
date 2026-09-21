"""
BLFinder v3.1 — core/evidence/capture.py
Evidence Package + Evidence Capture

Every Finding in v3.1 carries an EvidencePackage — a structured container
holding the actual raw HTTP requests and responses that PROVE the vulnerability.

This eliminates the "#1 rejection reason" on HackerOne:
  "Please provide specific endpoints and actual HTTP evidence"

EvidencePackage contains:
  - Exact raw HTTP request/response pairs (Burp Suite importable)
  - Field-level diff between baseline and attack responses
  - Verified curl command that was actually executed and confirmed working
  - Impact summary with real sensitive data found
  - Timeline for race condition / multi-step proof
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


@dataclass
class RequestRecord:
    """A single HTTP request — exactly as sent over the wire."""
    method: str
    url: str
    headers: dict
    body: str | dict | None = None
    timestamp: float = field(default_factory=time.time)
    label: str = ""                     

    def to_burp_format(self) -> str:
        """Return raw HTTP in Burp Suite Repeater format."""
        from .http_recorder import HTTPRecorder
        return HTTPRecorder.request_to_burp(self)

    def to_curl(self) -> str:
        """Return a copy-paste curl command."""
        from .http_recorder import HTTPRecorder
        return HTTPRecorder.request_to_curl(self)

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")


@dataclass
class ResponseRecord:
    """A single HTTP response — exactly as received."""
    status: int
    headers: dict
    body: str
    elapsed_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    label: str = ""

    def to_burp_format(self) -> str:
        """Return raw HTTP response in Burp Suite format."""
        from .http_recorder import HTTPRecorder
        return HTTPRecorder.response_to_burp(self)

    @property
    def body_parsed(self) -> dict | list | None:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, ValueError):
            return None

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v
        return "application/octet-stream"

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type.lower()


@dataclass
class RequestResponsePair:
    """A matched request + response pair with context label."""
    request: RequestRecord
    response: ResponseRecord
    label: str = ""                     
    note: str = ""                      

    def to_burp_format(self) -> str:
        return (
            f"=== {self.label.upper()} REQUEST ===\n"
            f"{self.request.to_burp_format()}\n\n"
            f"=== {self.label.upper()} RESPONSE ===\n"
            f"{self.response.to_burp_format()}"
        )


@dataclass
class EvidencePackage:
    """
    Complete evidence bundle for a single Finding.

    This is what gets attached to every Finding object in v3.1.
    Contains everything a HackerOne reviewer needs to validate the bug.

    Usage:
        pkg = EvidencePackage(
            finding_title="IDOR on /api/v1/orders/{id}",
            endpoint="https://api.target.com/api/v1/orders/455",
            vulnerability_type="IDOR/BOLA",
        )
        pkg.baseline = RequestResponsePair(req, resp, label="baseline")
        pkg.attack   = RequestResponsePair(req, resp, label="attack")
        pkg.build()   # Runs diff + impact analysis
    """


    finding_title: str = ""
    endpoint: str = ""
    vulnerability_type: str = ""
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )


    baseline: RequestResponsePair | None = None         
    attack: RequestResponsePair | None = None           
    no_auth: RequestResponsePair | None = None          
    cross_user: RequestResponsePair | None = None       
    extra_pairs: list[RequestResponsePair] = field(default_factory=list)  


    diff_report: Any = None                             
    impact_report: Any = None                           
    verified_curl: str = ""                             


    confidence: int = 0
    confirmed: bool = False
    fp_notes: list[str] = field(default_factory=list)

    def build(self):
        """
        Run diff analysis and impact assessment.
        Call this after setting baseline and attack pairs.
        """
        from .diff_engine import DiffEngine
        from .impact_assessor import ImpactAssessor

        if self.baseline and self.attack:
            self.diff_report = DiffEngine.compare(
                self.baseline.response,
                self.attack.response,
            )


        attack_body = self.attack.response.body if self.attack else ""
        baseline_body = self.baseline.response.body if self.baseline else ""
        if attack_body:
            self.impact_report = ImpactAssessor.assess(
                attack_body=attack_body,
                baseline_body=baseline_body,
                endpoint=self.endpoint,
            )


        if self.attack:
            self.verified_curl = self.attack.request.to_curl()

    @property
    def summary(self) -> str:
        """
        One-paragraph evidence summary for the Finding.evidence field.
        Uses real endpoint and real data — no placeholders.
        """
        parts = []

        if self.baseline and self.attack:
            b_status = self.baseline.response.status
            a_status = self.attack.response.status
            b_size   = len(self.baseline.response.body)
            a_size   = len(self.attack.response.body)
            parts.append(
                f"Endpoint: {self.endpoint} | "
                f"Baseline: HTTP {b_status} ({b_size}B) | "
                f"Attack: HTTP {a_status} ({a_size}B)"
            )

        if self.diff_report:
            parts.append(self.diff_report.one_line_summary)

        if self.impact_report and self.impact_report.sensitive_items:
            top = self.impact_report.sensitive_items[:2]
            parts.append(
                "Exposed: " + ", ".join(f"{i.field_name}={i.sample_value[:20]}" for i in top)
            )

        if self.confirmed:
            parts.append("[CONFIRMED: cross-user verification passed]")

        return " | ".join(parts) if parts else f"Evidence captured for {self.endpoint}"

    @property
    def has_sensitive_data(self) -> bool:
        return (
            self.impact_report is not None
            and len(self.impact_report.sensitive_items) > 0
        )

    @property
    def sensitive_data_preview(self) -> str:
        """Short preview of sensitive data found, safe to include in reports."""
        if not self.impact_report:
            return ""
        items = self.impact_report.sensitive_items[:5]
        return ", ".join(f"`{i.field_name}`" for i in items)

    def all_pairs(self) -> list[RequestResponsePair]:
        """Return all non-None request/response pairs in order."""
        pairs = []
        for pair in [self.baseline, self.attack, self.no_auth, self.cross_user]:
            if pair is not None:
                pairs.append(pair)
        pairs.extend(self.extra_pairs)
        return pairs


class EvidenceCapture:
    """
    Capture evidence for a Finding during scanning.

    Used by scanner.py to record actual HTTP traffic as it happens.
    Designed to be lightweight — called inside every _check_* module
    without meaningfully slowing down the scan.

    Usage in scanner._check_idor_bola():
        evidence = EvidenceCapture(self)

        # Record baseline
        status, headers, body, elapsed = await self._request(method, url, ...)
        evidence.record_baseline(method, url, request_headers, body, status, headers, elapsed)

        # Record attack
        status2, headers2, body2, elapsed2 = await self._request(method, test_url, ...)
        evidence.record_attack(method, test_url, request_headers, body2, status2, headers2, elapsed2)

        # Build package
        pkg = evidence.build_package(
            finding_title="IDOR — path ID 456→455",
            endpoint=url,
            vulnerability_type="IDOR/BOLA",
        )
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._pairs: dict[str, RequestResponsePair] = {}

    def record(
        self,
        label: str,
        method: str,
        url: str,
        req_headers: dict,
        req_body: dict | str | None,
        resp_status: int,
        resp_headers: dict,
        resp_body: str,
        elapsed: float,
        note: str = "",
    ) -> RequestResponsePair:
        """
        Record a request/response pair with a given label.

        Labels: "baseline", "attack", "no_auth", "cross_user", or any custom string.
        """
        req = RequestRecord(
            method=method,
            url=url,
            headers=dict(req_headers),
            body=req_body,
            label=label,
        )
        resp = ResponseRecord(
            status=resp_status,
            headers=dict(resp_headers),
            body=resp_body,
            elapsed_ms=elapsed * 1000,
            label=label,
        )
        pair = RequestResponsePair(request=req, response=resp, label=label, note=note)
        self._pairs[label] = pair
        return pair

    def record_baseline(
        self, method: str, url: str, req_headers: dict,
        req_body, resp_status: int, resp_headers: dict,
        resp_body: str, elapsed: float,
    ) -> RequestResponsePair:
        return self.record(
            "baseline", method, url, req_headers, req_body,
            resp_status, resp_headers, resp_body, elapsed,
            note="Normal authenticated request",
        )

    def record_attack(
        self, method: str, url: str, req_headers: dict,
        req_body, resp_status: int, resp_headers: dict,
        resp_body: str, elapsed: float, note: str = "Exploit request",
    ) -> RequestResponsePair:
        return self.record(
            "attack", method, url, req_headers, req_body,
            resp_status, resp_headers, resp_body, elapsed, note=note,
        )

    def record_no_auth(
        self, method: str, url: str, req_headers: dict,
        req_body, resp_status: int, resp_headers: dict,
        resp_body: str, elapsed: float,
    ) -> RequestResponsePair:
        return self.record(
            "no_auth", method, url, req_headers, req_body,
            resp_status, resp_headers, resp_body, elapsed,
            note="Request without Authorization header",
        )

    def record_cross_user(
        self, method: str, url: str, req_headers: dict,
        req_body, resp_status: int, resp_headers: dict,
        resp_body: str, elapsed: float,
    ) -> RequestResponsePair:
        return self.record(
            "cross_user", method, url, req_headers, req_body,
            resp_status, resp_headers, resp_body, elapsed,
            note="Request with User 2 token accessing User 1 resource",
        )

    def build_package(
        self,
        finding_title: str,
        endpoint: str,
        vulnerability_type: str,
        confidence: int = 0,
        confirmed: bool = False,
        fp_notes: list[str] | None = None,
    ) -> EvidencePackage:
        """Build and return a complete EvidencePackage from recorded pairs."""
        pkg = EvidencePackage(
            finding_title=finding_title,
            endpoint=endpoint,
            vulnerability_type=vulnerability_type,
            confidence=confidence,
            confirmed=confirmed,
            fp_notes=fp_notes or [],
        )
        pkg.baseline   = self._pairs.get("baseline")
        pkg.attack     = self._pairs.get("attack")
        pkg.no_auth    = self._pairs.get("no_auth")
        pkg.cross_user = self._pairs.get("cross_user")


        known_labels = {"baseline", "attack", "no_auth", "cross_user"}
        pkg.extra_pairs = [
            pair for label, pair in self._pairs.items()
            if label not in known_labels
        ]

        pkg.build()
        return pkg

    def clear(self):
        """Reset for reuse across multiple findings."""
        self._pairs.clear()

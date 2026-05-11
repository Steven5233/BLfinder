"""
BLFinder Phase 4 — core/modules/idor_mass_enum.py
Systematic IDOR/BOLA Mass Enumeration Engine

Goes beyond ±1 testing. Systematically enumerates a configurable ID range,
maps which resources exist and who owns them, and confirms cross-user access
with a second token.

Key capabilities:
  - Async batch enumeration (configurable range, default 100)
  - ResourceStatus oracle: OWNED | EXISTS | FORBIDDEN | NOT_FOUND
  - Cross-endpoint ID reuse (BOLA): IDs from /orders also tested on /invoices
  - ID harvesting: collects IDs seen anywhere in scan responses
  - Cross-user confirmation: User 2 token accesses User 1 resources

FP reduction:
  - Ownership confirmation: baseline response compared to enumerate response
  - Cross-user double-check: confirmed with second token before CRITICAL rating
  - NOT_FOUND vs EXISTS: response oracle distinguishes real 404 from soft-404
  - Canary ID test: nonsense ID must be rejected before flagging any finding
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse, urlunparse


class ResourceStatusType(str, Enum):
    OWNED     = "OWNED"       # Resource belongs to authenticated user
    EXISTS    = "EXISTS"      # Resource exists, different owner (potential IDOR)
    FORBIDDEN = "FORBIDDEN"   # 403 — resource exists but access denied (good)
    NOT_FOUND = "NOT_FOUND"   # Resource does not exist
    ERROR     = "ERROR"       # Server error during probe
    UNKNOWN   = "UNKNOWN"     # Cannot determine


@dataclass
class ResourceStatus:
    """Status of a single ID probe."""
    id:             str
    url:            str
    status_type:    ResourceStatusType
    http_status:    int
    response_size:  int
    response_hash:  str
    confirmed_idor: bool = False
    owner_match:    bool = False
    cross_user_status: int = 0


@dataclass
class IDOREnumResult:
    """Full result of mass IDOR enumeration on one endpoint."""
    endpoint:          str
    id_field:          str          # "path[2]", "body.user_id", etc.
    id_type:           str          # "numeric", "uuid", "harvested"
    total_tested:      int = 0
    existing_ids:      list[str] = field(default_factory=list)
    accessible_ids:    list[str] = field(default_factory=list)  # Not owned
    forbidden_ids:     list[str] = field(default_factory=list)  # 403 access
    confirmed_idors:   list[str] = field(default_factory=list)  # Cross-user verified
    resource_map:      dict[str, ResourceStatus] = field(default_factory=dict)
    findings:          list = field(default_factory=list)  # list[Finding]
    owned_id:          str = ""     # The ID that belongs to the current user
    owned_response:    str = ""     # Baseline response for owned resource
    owned_hash:        str = ""


class IDORMassEnumerator:
    """
    Systematic IDOR/BOLA enumeration engine.

    Usage:
        enumerator = IDORMassEnumerator(scanner)
        result = await enumerator.enumerate_path(
            url="https://api.target.com/api/v1/orders/456",
            method="GET",
            max_range=200,
        )
        for finding in result.findings:
            scanner.findings.append(finding)
    """

    # Common test UUIDs used across many test suites
    _TEST_UUIDS = [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "11111111-1111-1111-1111-111111111111",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]

    def __init__(self, scanner):
        self._scanner    = scanner
        self._config     = scanner.config
        self._request    = scanner._request
        self._req_ev     = scanner._req_ev
        self._build_pkg  = scanner._build_pkg
        self._new_ev     = scanner._new_evidence
        self._attach     = scanner._attach
        self._finalize   = scanner._finalize_finding
        self._harvested_ids: set[str] = set()

    # ── Public API ────────────────────────────────────────────────────────────

    async def enumerate_path(
        self,
        url:       str,
        method:    str = "GET",
        body:      dict | None = None,
        max_range: int = 100,
    ) -> IDOREnumResult:
        """
        Enumerate IDs in the URL path segment.
        e.g. /api/orders/456 → probe /api/orders/1 through /api/orders/max_range
        """
        parsed        = urlparse(url)
        path_segments = parsed.path.split("/")
        results: list[IDOREnumResult] = []

        for seg_idx, segment in enumerate(path_segments):
            if not segment:
                continue
            id_type = _detect_id_type(segment)
            if id_type == "none":
                continue

            result = IDOREnumResult(
                endpoint=url,
                id_field=f"path[{seg_idx}]",
                id_type=id_type,
                owned_id=segment,
            )

            # Get baseline (owned resource)
            _, _, baseline_body, _ = await self._request(
                method, url, json=body if body else None
            )
            result.owned_response = baseline_body
            result.owned_hash     = _hash(baseline_body)

            # Canary FP guard — nonsense ID must be rejected
            canary_segs    = path_segments[:]
            canary_segs[seg_idx] = "__blfinder_canary_xyz__"
            canary_url     = urlunparse(parsed._replace(path="/".join(canary_segs)))
            canary_status, _, _, _ = await self._request("GET", canary_url)
            if canary_status in (200, 201):
                # Server accepts anything — skip this segment
                continue

            # Build candidate IDs
            if id_type == "numeric":
                original_id = int(segment)
                candidates  = _build_numeric_range(original_id, max_range)
            elif id_type == "uuid":
                candidates = self._TEST_UUIDS + list(self._harvested_ids)
            else:
                candidates = list(self._harvested_ids)

            # Batch probe
            result = await self._probe_batch(
                result, parsed, path_segments, seg_idx,
                candidates, method, body, max_range,
            )
            results.append(result)

        return results[0] if results else IDOREnumResult(
            endpoint=url, id_field="", id_type="none"
        )

    async def enumerate_body(
        self,
        url:       str,
        method:    str,
        body:      dict,
        max_range: int = 100,
    ) -> IDOREnumResult:
        """
        Enumerate IDs in the request body.
        e.g. {"user_id": 456} → probe with user_id=1..max_range
        """
        id_fields = _find_id_fields(body)
        if not id_fields:
            return IDOREnumResult(endpoint=url, id_field="", id_type="none")

        field_name, original_value = id_fields[0]
        id_type = _detect_id_type(str(original_value))

        result = IDOREnumResult(
            endpoint=url,
            id_field=f"body.{field_name}",
            id_type=id_type,
            owned_id=str(original_value),
        )

        # Baseline
        _, _, baseline_body, _ = await self._request(method, url, json=body)
        result.owned_response = baseline_body
        result.owned_hash     = _hash(baseline_body)

        # Canary guard
        canary_body = {**body, field_name: "__blfinder_canary__"}
        cs, _, _, _ = await self._request(method, url, json=canary_body)
        if cs in (200, 201):
            return result

        # Candidates
        if id_type == "numeric":
            candidates = _build_numeric_range(int(original_value), max_range)
        else:
            candidates = self._TEST_UUIDS + list(self._harvested_ids)

        # Probe
        sem = asyncio.Semaphore(20)

        async def probe_one(cand_id: str) -> ResourceStatus:
            async with sem:
                test_body    = {**body, field_name: _cast(cand_id, original_value)}
                status, _, resp_body, _ = await self._request(
                    method, url, json=test_body
                )
                status_type = _classify_status(
                    status, resp_body, result.owned_hash, result.owned_response
                )
                return ResourceStatus(
                    id=cand_id, url=url,
                    status_type=status_type,
                    http_status=status,
                    response_size=len(resp_body),
                    response_hash=_hash(resp_body),
                )

        statuses = await asyncio.gather(
            *[probe_one(c) for c in candidates[:max_range]],
            return_exceptions=True,
        )

        for rs in statuses:
            if not isinstance(rs, ResourceStatus):
                continue
            result.resource_map[rs.id] = rs
            result.total_tested += 1
            if rs.status_type in (ResourceStatusType.EXISTS,):
                result.accessible_ids.append(rs.id)
            elif rs.status_type == ResourceStatusType.FORBIDDEN:
                result.forbidden_ids.append(rs.id)

        await self._confirm_and_generate(result, url, method)
        return result

    async def enumerate_cross_endpoint(
        self,
        id_value:   str,
        endpoints:  list[dict],
        method:     str = "GET",
    ) -> list:
        """
        Test a harvested ID against all endpoints that accept IDs.
        Implements BOLA: IDs from /orders also tested on /invoices, etc.
        """
        findings = []
        for ep in endpoints:
            ep_url = ep.get("url", "")
            if id_value in ep_url:
                continue  # Same endpoint, skip

            parsed   = urlparse(ep_url)
            segments = parsed.path.split("/")
            for i, seg in enumerate(segments):
                if _detect_id_type(seg) == "none":
                    continue
                new_segs    = segments[:]
                new_segs[i] = id_value
                test_url    = urlunparse(parsed._replace(path="/".join(new_segs)))

                status, _, resp_body, _ = await self._request(
                    method, test_url
                )
                if status == 200 and len(resp_body) > 50:
                    # FP guard: verify it's not a generic 200
                    if not _body_is_error(resp_body):
                        ev  = self._new_ev()
                        pkg = self._build_pkg(
                            ev,
                            title=f"BOLA Cross-Endpoint — ID {id_value} on {ep_url}",
                            endpoint=test_url,
                            vuln_type="BOLA",
                            confidence=65,
                        )
                        from ..models import Finding, Severity
                        f = Finding(
                            title=(
                                f"BOLA — Harvested ID `{id_value}` "
                                f"accessible on {ep_url}"
                            ),
                            severity=Severity.HIGH,
                            category="Business Logic — IDOR/BOLA (Cross-Endpoint)",
                            description=(
                                f"ID `{id_value}` discovered on one endpoint was "
                                f"also accessible on `{test_url}` — "
                                "same ID namespace reuse across object types."
                            ),
                            request={"method": method, "url": test_url},
                            response_summary=f"HTTP {status} — {resp_body[:200]}",
                            evidence=(
                                f"Harvested ID {id_value} → "
                                f"HTTP {status} on {test_url}"
                            ),
                            recommendation=(
                                "Validate that IDs are scoped to the correct "
                                "object type. Do not share ID namespaces."
                            ),
                            cwe="CWE-639", cvss=8.1,
                            owasp="API1:2023 Broken Object Level Authorization",
                            endpoint=test_url, parameter=f"path[{i}]",
                            confidence=65,
                        )
                        self._attach(f, pkg)
                        findings.append(f)
        return findings

    def harvest_ids(self, response_body: str):
        """
        Extract all IDs from a response body for later cross-endpoint testing.
        Call this after every baseline response.
        """
        if not response_body:
            return
        # Numeric IDs (>= 3 digits to avoid noise)
        for m in re.finditer(r'\b(\d{3,12})\b', response_body):
            self._harvested_ids.add(m.group(1))
        # UUIDs
        for m in re.finditer(
            r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b',
            response_body, re.I,
        ):
            self._harvested_ids.add(m.group(1))

    @property
    def harvested_ids(self) -> set[str]:
        return self._harvested_ids

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _probe_batch(
        self,
        result:        IDOREnumResult,
        parsed,
        path_segments: list[str],
        seg_idx:       int,
        candidates:    list[str],
        method:        str,
        body:          dict | None,
        max_range:     int,
    ) -> IDOREnumResult:
        sem = asyncio.Semaphore(20)

        async def probe_one(cand_id: str) -> ResourceStatus:
            async with sem:
                new_segs      = path_segments[:]
                new_segs[seg_idx] = cand_id
                test_url      = urlunparse(
                    parsed._replace(path="/".join(new_segs))
                )
                status, _, rb, _ = await self._request(
                    method, test_url,
                    json=body if body else None,
                )
                st = _classify_status(
                    status, rb,
                    result.owned_hash, result.owned_response,
                )
                return ResourceStatus(
                    id=cand_id, url=test_url,
                    status_type=st,
                    http_status=status,
                    response_size=len(rb),
                    response_hash=_hash(rb),
                )

        statuses = await asyncio.gather(
            *[probe_one(c) for c in candidates[:max_range]],
            return_exceptions=True,
        )

        for rs in statuses:
            if not isinstance(rs, ResourceStatus):
                continue
            result.resource_map[rs.id] = rs
            result.total_tested += 1
            if rs.status_type == ResourceStatusType.OWNED:
                result.existing_ids.append(rs.id)
                result.owner_match = True
            elif rs.status_type == ResourceStatusType.EXISTS:
                result.accessible_ids.append(rs.id)
                result.existing_ids.append(rs.id)
            elif rs.status_type == ResourceStatusType.FORBIDDEN:
                result.forbidden_ids.append(rs.id)
                result.existing_ids.append(rs.id)

        await self._confirm_and_generate(result, result.endpoint, method)
        return result

    async def _confirm_and_generate(
        self,
        result: IDOREnumResult,
        url:    str,
        method: str,
    ):
        """Confirm accessible IDs with second token and generate findings."""
        if not result.accessible_ids:
            return

        from ..models import Finding, Severity

        for acc_id in result.accessible_ids[:5]:  # Cap at 5 confirmations
            rs        = result.resource_map.get(acc_id)
            confirmed = False

            if self._config.second_user_token and rs:
                parsed   = urlparse(rs.url)
                s2, _, rb2, _ = await self._request(
                    method, rs.url,
                    token_override=self._config.second_user_token,
                )
                confirmed = s2 == 200 and not _body_is_error(rb2)
                if rs:
                    rs.confirmed_idor      = confirmed
                    rs.cross_user_status   = s2

            if confirmed:
                result.confirmed_idors.append(acc_id)

            ev  = self._new_ev()
            pkg = self._build_pkg(
                ev,
                title=f"IDOR Mass Enum — ID {acc_id} accessible",
                endpoint=rs.url if rs else url,
                vuln_type="IDOR/BOLA",
                confidence=91 if confirmed else 72,
                confirmed=confirmed,
            )

            f = Finding(
                title=(
                    f"IDOR — ID `{acc_id}` accessible on "
                    f"`{result.id_field}` "
                    f"({'CONFIRMED' if confirmed else 'potential'})"
                ),
                severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                category="Business Logic — IDOR/BOLA (Mass Enumeration)",
                description=(
                    f"Systematic enumeration of `{result.id_field}` on "
                    f"`{url}` found ID `{acc_id}` returning different "
                    f"data from the owned resource. "
                    f"{'Cross-user confirmed.' if confirmed else ''}"
                ),
                request={"method": method, "url": rs.url if rs else url},
                response_summary=(
                    f"HTTP {rs.http_status if rs else '?'}, "
                    f"{rs.response_size if rs else '?'}B"
                ),
                evidence=(
                    f"Owned ID: {result.owned_id} | "
                    f"Accessible ID: {acc_id} | "
                    f"Total probed: {result.total_tested} | "
                    f"{'CROSS-USER CONFIRMED' if confirmed else 'unconfirmed'}"
                ),
                recommendation=(
                    "Enforce ownership checks on every request. "
                    "Tie resource access to authenticated session."
                ),
                cwe="CWE-639",
                cvss=9.1 if confirmed else 8.1,
                owasp="API1:2023 Broken Object Level Authorization",
                confirmed=confirmed,
                confidence=91 if confirmed else 72,
                endpoint=rs.url if rs else url,
                parameter=result.id_field,
            )
            self._attach(f, pkg)
            result.findings.append(f)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_id_type(segment: str) -> str:
    if re.match(r'^\d{1,12}$', segment):
        return "numeric"
    if re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        segment, re.I,
    ):
        return "uuid"
    if re.match(r'^[a-f0-9]{24}$', segment, re.I):
        return "mongo_id"
    return "none"


def _build_numeric_range(original: int, max_range: int) -> list[str]:
    """Build a list of candidate IDs around the original."""
    start  = max(1, original - max_range // 2)
    end    = start + max_range
    ids    = [str(i) for i in range(start, end) if i != original]
    # Prioritise nearby IDs
    nearby = [str(original - 1), str(original + 1),
              str(original - 2), str(original + 2)]
    ordered = [x for x in nearby if x in ids]
    rest    = [x for x in ids if x not in ordered]
    return ordered + rest


def _classify_status(
    status: int,
    body:   str,
    owned_hash: str,
    owned_body: str,
) -> ResourceStatusType:
    if status == 403:
        return ResourceStatusType.FORBIDDEN
    if status in (404, 410):
        return ResourceStatusType.NOT_FOUND
    if status >= 500:
        return ResourceStatusType.ERROR
    if status not in (200, 201):
        return ResourceStatusType.UNKNOWN
    if _body_is_error(body):
        return ResourceStatusType.NOT_FOUND
    body_hash = _hash(body)
    if body_hash == owned_hash:
        return ResourceStatusType.OWNED
    if len(body) > 20:
        return ResourceStatusType.EXISTS
    return ResourceStatusType.UNKNOWN


def _find_id_fields(body: dict) -> list[tuple[str, Any]]:
    """Find fields in a body that look like IDs."""
    id_keywords = ["id", "user_id", "account_id", "order_id", "item_id",
                   "resource_id", "object_id", "entity_id"]
    results = []
    for k, v in body.items():
        if any(kw in k.lower() for kw in id_keywords):
            if isinstance(v, (int, str)) and _detect_id_type(str(v)) != "none":
                results.append((k, v))
    return results


def _body_is_error(body: str) -> bool:
    if not body:
        return True
    b = body.lower()
    return any(s in b for s in [
        "not found", "does not exist", "no resource",
        "invalid id", "not authorized", "access denied",
    ])


def _hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _cast(value: str, original: Any) -> Any:
    """Cast a string ID to the same type as the original."""
    if isinstance(original, int):
        try:
            return int(value)
        except ValueError:
            return value
    return value

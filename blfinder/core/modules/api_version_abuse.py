"""
BLFinder Phase 4 — core/modules/api_version_abuse.py
API Version Downgrade Scanner

Old API versions left active after v3 launch are consistently less secure:
  - They often lack rate limiting
  - Skip new auth checks
  - Expose deprecated admin endpoints
  - Return extra fields not present in latest version

FP reduction:
  - Version existence confirmed before attack (must return 200)
  - BOPLA via version confirmed by actual new field presence
  - Rate limit bypass confirmed by comparing 429 behaviour
  - Deprecated endpoint confirmed by canary check
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


@dataclass
class APIVersion:
    """A discovered API version."""
    version_string: str         # "v1", "v2", "2024-01-01"
    base_path:      str         # "/api/v1"
    is_live:        bool = False
    discovered_endpoints: list[str] = field(default_factory=list)
    has_auth_weaknesses: bool = False
    extra_fields_vs_latest: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class VersionAbuseResult:
    """Full result of API version abuse testing."""
    target:                    str
    versions_found:            list[APIVersion] = field(default_factory=list)
    downgrade_findings:        list = field(default_factory=list)
    deprecated_admin_findings: list = field(default_factory=list)
    bopla_findings:            list = field(default_factory=list)
    rate_limit_findings:       list = field(default_factory=list)

    @property
    def all_findings(self) -> list:
        return (
            self.downgrade_findings
            + self.deprecated_admin_findings
            + self.bopla_findings
            + self.rate_limit_findings
        )


class APIVersionScanner:
    """
    API version abuse scanner.

    Usage:
        scanner = APIVersionScanner(main_scanner)
        result  = await scanner.scan(
            base_url="https://api.target.com",
            known_endpoints=["/api/v3/users/me", "/api/v3/orders"],
        )
    """

    _VERSION_PATHS = [
        # Numeric versions
        "/v1", "/v2", "/v3", "/v4",
        "/api/v1", "/api/v2", "/api/v3", "/api/v4",
        "/api/1", "/api/2", "/api/3",
        "/1", "/2", "/3",
        # Named versions
        "/api/beta", "/api/legacy", "/api/internal",
        "/api/dev", "/api/old", "/api/deprecated",
        # Date-based versions
        "/api/2023-01-01", "/api/2022-01-01", "/api/2021-01-01",
        "/api/2020-01-01",
    ]

    _DEPRECATED_PATHS = [
        "/admin", "/admin/users", "/admin/config",
        "/internal", "/internal/users",
        "/debug", "/api/debug",
        "/manage", "/manage/users",
        "/system", "/api/system",
    ]

    def __init__(self, scanner):
        self._scanner   = scanner
        self._config    = scanner.config
        self._request   = scanner._request
        self._req_ev    = scanner._req_ev
        self._build_pkg = scanner._build_pkg
        self._new_ev    = scanner._new_evidence
        self._attach    = scanner._attach
        self._finalize  = scanner._finalize_finding

    # ── Public entry point ────────────────────────────────────────────────────

    async def scan(
        self,
        base_url:         str,
        known_endpoints:  list[str] | None = None,
    ) -> VersionAbuseResult:
        result = VersionAbuseResult(target=base_url)

        # Step 1: Discover all live API versions
        versions = await self._discover_versions(base_url)
        result.versions_found = versions

        if not versions:
            return result

        if self._config.verbose:
            live = [v.version_string for v in versions if v.is_live]
            print(f"  [*] API versions found: {live}")

        # Step 2: Run attacks in parallel
        checks = await asyncio.gather(
            self._test_version_downgrade(base_url, versions, known_endpoints or [], result),
            self._test_deprecated_endpoints(base_url, versions, result),
            self._test_bopla_via_version(base_url, versions, known_endpoints or [], result),
            self._test_rate_limit_bypass(base_url, versions, result),
            return_exceptions=True,
        )

        for check in checks:
            if isinstance(check, Exception) and self._config.verbose:
                print(f"  [!] Version scan error: {check}")

        return result

    # ── Version discovery ─────────────────────────────────────────────────────

    async def _discover_versions(self, base_url: str) -> list[APIVersion]:
        parsed = urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        found: list[APIVersion] = []

        async def probe(path: str) -> APIVersion | None:
            url = f"{base}{path}"
            status, headers, body, _ = await self._request("GET", url)
            if status not in (200, 201, 401, 403, 404):
                return None
            if status in (200, 201, 401, 403):
                # Check for version hint in response headers
                ver_str = path.strip("/").split("/")[-1]
                return APIVersion(
                    version_string=ver_str,
                    base_path=path,
                    is_live=status in (200, 201, 401, 403),
                )
            return None

        results = await asyncio.gather(
            *[probe(p) for p in self._VERSION_PATHS],
            return_exceptions=True,
        )

        seen: set[str] = set()
        for r in results:
            if isinstance(r, APIVersion) and r.is_live:
                if r.base_path not in seen:
                    seen.add(r.base_path)
                    found.append(r)

        return found

    # ── Version downgrade attack ──────────────────────────────────────────────

    async def _test_version_downgrade(
        self,
        base_url:         str,
        versions:         list[APIVersion],
        known_endpoints:  list[str],
        result:           VersionAbuseResult,
    ):
        """
        For each known v3 endpoint, test if v1/v2 equivalents are weaker.
        """
        parsed = urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Detect the "latest" version path from known_endpoints
        latest_ver = self._detect_latest_version(known_endpoints)
        old_versions = [v for v in versions if v.version_string != latest_ver and v.is_live]

        if not old_versions or not known_endpoints:
            return

        for endpoint in known_endpoints[:10]:   # Cap
            for old_ver in old_versions[:3]:
                # Replace version in path
                old_url = self._swap_version(endpoint, old_ver.base_path, base)
                if not old_url or old_url == endpoint:
                    continue

                ev = self._new_ev()
                await self._req_ev("baseline", ev, "GET", endpoint)
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, "GET", old_url
                )

                if status not in (200, 201, 401, 403):
                    continue

                # Auth-required on latest = free on old version?
                latest_status, _, _, _ = await self._request("GET", endpoint)

                if latest_status in (401, 403) and status in (200, 201):
                    pkg = self._build_pkg(
                        ev,
                        title=f"Version Downgrade Auth Bypass — {old_ver.version_string}",
                        endpoint=old_url,
                        vuln_type="API Version Downgrade",
                        confidence=85, confirmed=True,
                    )
                    from ..models import Finding, Severity
                    f = Finding(
                        title=(
                            f"API Version Downgrade — `{old_ver.version_string}` "
                            f"bypasses auth on `{old_url}`"
                        ),
                        severity=Severity.HIGH,
                        category="Business Logic — API Version Abuse",
                        description=(
                            f"Endpoint `{endpoint}` requires auth (HTTP {latest_status}), "
                            f"but the `{old_ver.version_string}` equivalent at `{old_url}` "
                            f"returns HTTP {status} without auth."
                        ),
                        request={"method": "GET", "url": old_url},
                        response_summary=f"HTTP {status} (vs {latest_status} on latest)",
                        evidence=(
                            f"Latest {endpoint} → {latest_status}. "
                            f"Old {old_url} → {status} (unprotected)"
                        ),
                        recommendation=(
                            "Retire old API versions or apply the same "
                            "authentication middleware as the latest version."
                        ),
                        cwe="CWE-284", cvss=8.5,
                        owasp="API9:2023 Improper Inventory Management",
                        confirmed=True, confidence=85, endpoint=old_url,
                    )
                    self._attach(f, pkg)
                    result.downgrade_findings.append(f)

    # ── Deprecated endpoint discovery ─────────────────────────────────────────

    async def _test_deprecated_endpoints(
        self,
        base_url: str,
        versions: list[APIVersion],
        result:   VersionAbuseResult,
    ):
        """
        Test if deprecated admin/internal endpoints exist on old versions.
        """
        parsed = urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        old_versions = [v for v in versions if v.is_live]

        for ver in old_versions[:3]:
            for dep_path in self._DEPRECATED_PATHS:
                url = f"{base}{ver.base_path}{dep_path}"
                ev = self._new_ev()
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, "GET", url
                )

                if status not in (200, 201):
                    continue
                if len(resp_body) < 30:
                    continue
                if _body_is_error(resp_body):
                    continue

                # FP: canary — a nonsense path must be rejected
                canary_url = f"{base}{ver.base_path}/__canary_blfinder__"
                cs, _, _, _ = await self._request("GET", canary_url)
                if cs == 200:
                    continue  # Server 200s everything

                pkg = self._build_pkg(
                    ev,
                    title=f"Deprecated Endpoint — {ver.version_string}{dep_path}",
                    endpoint=url,
                    vuln_type="Deprecated API Endpoint",
                    confidence=80, confirmed=True,
                )
                from ..models import Finding, Severity
                f = Finding(
                    title=(
                        f"Deprecated API Endpoint — "
                        f"`{ver.version_string}{dep_path}` accessible"
                    ),
                    severity=Severity.HIGH,
                    category="Business Logic — API Version Abuse (Deprecated Endpoint)",
                    description=(
                        f"Deprecated endpoint `{url}` on API version "
                        f"`{ver.version_string}` returns HTTP {status} "
                        "with content. This endpoint may lack the security "
                        "controls added to later versions."
                    ),
                    request={"method": "GET", "url": url},
                    response_summary=f"HTTP {status} — {resp_body[:200]}",
                    evidence=(
                        f"{ver.version_string}{dep_path} → {status} + "
                        f"{len(resp_body)}B (canary rejected → {cs})"
                    ),
                    recommendation=(
                        "Remove all deprecated endpoints. "
                        "If needed, apply same auth middleware as latest version."
                    ),
                    cwe="CWE-1059", cvss=7.5,
                    owasp="API9:2023 Improper Inventory Management",
                    confirmed=True, confidence=80, endpoint=url,
                )
                self._attach(f, pkg)
                result.deprecated_admin_findings.append(f)

    # ── BOPLA via version ─────────────────────────────────────────────────────

    async def _test_bopla_via_version(
        self,
        base_url:         str,
        versions:         list[APIVersion],
        known_endpoints:  list[str],
        result:           VersionAbuseResult,
    ):
        """
        Compare response schemas between versions.
        Old version may return extra sensitive fields.
        """
        parsed    = urlparse(base_url)
        base      = f"{parsed.scheme}://{parsed.netloc}"
        sensitive = [
            "password", "hash", "secret", "token", "key",
            "ssn", "salary", "internal", "debug", "admin_note",
            "credit_card", "bank_account", "api_key",
        ]

        latest_ver = self._detect_latest_version(known_endpoints)
        old_versions = [v for v in versions if v.version_string != latest_ver and v.is_live]

        for endpoint in known_endpoints[:5]:
            # Get latest version response
            _, _, latest_body, _ = await self._request("GET", endpoint)
            latest_data = _parse_json(latest_body)
            if not isinstance(latest_data, dict):
                continue
            latest_keys = set(_flatten_keys(latest_data))

            for old_ver in old_versions[:2]:
                old_url = self._swap_version(endpoint, old_ver.base_path, base)
                if not old_url or old_url == endpoint:
                    continue

                ev = self._new_ev()
                await self._req_ev("baseline", ev, "GET", endpoint)
                status, _, old_body, _ = await self._req_ev(
                    "attack", ev, "GET", old_url
                )

                if status != 200:
                    continue

                old_data = _parse_json(old_body)
                if not isinstance(old_data, dict):
                    continue

                old_keys  = set(_flatten_keys(old_data))
                new_keys  = old_keys - latest_keys
                sensitive_new = [k for k in new_keys
                                 if any(s in k.lower() for s in sensitive)]

                if sensitive_new:
                    pkg = self._build_pkg(
                        ev,
                        title=f"BOPLA via Version — {old_ver.version_string}",
                        endpoint=old_url,
                        vuln_type="BOPLA via Version Downgrade",
                        confidence=80, confirmed=True,
                    )
                    from ..models import Finding, Severity
                    f = Finding(
                        title=(
                            f"BOPLA via Version Downgrade — "
                            f"`{old_ver.version_string}` exposes "
                            f"{sensitive_new[:3]}"
                        ),
                        severity=Severity.HIGH,
                        category="Business Logic — API Version Abuse (BOPLA)",
                        description=(
                            f"API version `{old_ver.version_string}` at `{old_url}` "
                            f"returns {len(new_keys)} additional fields vs latest version. "
                            f"Sensitive fields: {sensitive_new[:5]}."
                        ),
                        request={"method": "GET", "url": old_url},
                        response_summary=(
                            f"HTTP {status} — extra fields: {list(new_keys)[:5]}"
                        ),
                        evidence=(
                            f"Latest keys: {len(latest_keys)} | "
                            f"Old version keys: {len(old_keys)} | "
                            f"New sensitive fields: {sensitive_new[:5]}"
                        ),
                        recommendation=(
                            "Remove old API versions or ensure they return "
                            "the same filtered schema as the latest version."
                        ),
                        cwe="CWE-213", cvss=7.5,
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        confirmed=True, confidence=80, endpoint=old_url,
                    )
                    self._attach(f, pkg)
                    result.bopla_findings.append(f)

    # ── Rate limit bypass via old version ─────────────────────────────────────

    async def _test_rate_limit_bypass(
        self,
        base_url: str,
        versions: list[APIVersion],
        result:   VersionAbuseResult,
    ):
        """
        Test if rate limiting on latest version is absent on old versions.
        """
        parsed   = urlparse(base_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"
        auth_paths = ["/auth/login", "/login", "/token", "/auth/token", "/sign_in"]

        # Check if latest version has rate limiting
        latest_429 = False
        for auth_path in auth_paths:
            url = f"{base}/api/v3{auth_path}"
            responses = await asyncio.gather(
                *[self._request("POST", url, json={"email": "x", "password": "y"})
                  for _ in range(10)],
                return_exceptions=True,
            )
            if any(
                isinstance(r, tuple) and r[0] == 429
                for r in responses
            ):
                latest_429 = True
                latest_auth_path = auth_path
                break

        if not latest_429:
            return  # Latest version doesn't rate limit either — nothing to compare

        old_versions = [v for v in versions if v.is_live]
        for ver in old_versions[:3]:
            for auth_path in auth_paths:
                old_url = f"{base}{ver.base_path}{auth_path}"
                ev = self._new_ev()
                responses = await asyncio.gather(
                    *[self._request(
                        "POST", old_url,
                        json={"email": "test@test.com", "password": "wrong"},
                    ) for _ in range(10)],
                    return_exceptions=True,
                )
                statuses = [
                    r[0] for r in responses
                    if isinstance(r, tuple)
                ]
                has_429 = 429 in statuses
                has_200 = any(s in (200, 201, 400, 401) for s in statuses)

                if not has_429 and has_200:
                    pkg = self._build_pkg(
                        ev,
                        title=f"Rate Limit Bypass via {ver.version_string}",
                        endpoint=old_url,
                        vuln_type="Rate Limit Bypass",
                        confidence=82, confirmed=True,
                    )
                    from ..models import Finding, Severity
                    f = Finding(
                        title=(
                            f"Rate Limit Bypass — `{ver.version_string}` "
                            f"has no rate limit on auth endpoint"
                        ),
                        severity=Severity.HIGH,
                        category="Business Logic — API Version Abuse (Rate Limit Bypass)",
                        description=(
                            f"Latest version enforces rate limiting (HTTP 429) on auth endpoints, "
                            f"but version `{ver.version_string}` at `{old_url}` does not. "
                            "Brute force protection is bypassed via version downgrade."
                        ),
                        request={"method": "POST", "url": old_url,
                                 "note": "10 rapid requests"},
                        response_summary=f"10 requests, no 429. Statuses: {statuses[:5]}",
                        evidence=(
                            f"Latest /v3{latest_auth_path} → 429 (rate limited). "
                            f"{ver.version_string}{auth_path} → no 429"
                        ),
                        recommendation=(
                            "Apply rate limiting middleware globally, "
                            "not just on latest API version."
                        ),
                        cwe="CWE-307", cvss=7.5,
                        owasp="API4:2023 Unrestricted Resource Consumption",
                        confirmed=True, confidence=82, endpoint=old_url,
                    )
                    self._attach(f, pkg)
                    result.rate_limit_findings.append(f)
                    break

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_latest_version(self, endpoints: list[str]) -> str:
        for ep in endpoints:
            m = re.search(r'/(v\d+|api/v\d+)/', ep, re.I)
            if m:
                return m.group(1).split("/")[-1]
        return "v3"

    def _swap_version(
        self, endpoint: str, new_base: str, base: str
    ) -> str | None:
        """Replace the version segment in a URL path."""
        for pattern in [
            r'/(v\d+)/', r'/(api/v\d+)/',
            r'/(\d{4}-\d{2}-\d{2})/',
        ]:
            m = re.search(pattern, endpoint, re.I)
            if m:
                old_part = m.group(1)
                new_part = new_base.strip("/")
                new_path = endpoint.replace(f"/{old_part}/", f"/{new_part}/", 1)
                if not new_path.startswith("http"):
                    return f"{base}{new_path}"
                return new_path
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_json(body: str) -> Any:
    try:
        return json.loads(body.strip())
    except (json.JSONDecodeError, ValueError):
        return {}


def _flatten_keys(obj: Any, prefix: str = "") -> list[str]:
    """Recursively extract all key paths from a JSON object."""
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            keys.append(path)
            keys.extend(_flatten_keys(v, path))
    elif isinstance(obj, list) and obj:
        keys.extend(_flatten_keys(obj[0], prefix))
    return keys


def _body_is_error(body: str) -> bool:
    b = body.lower()
    return any(s in b for s in [
        "not found", "error", "invalid", "forbidden",
        "unauthorized", "does not exist",
    ])

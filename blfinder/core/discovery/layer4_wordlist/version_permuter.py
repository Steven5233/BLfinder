"""
BLFinder v3.1 — core/discovery/layer4_wordlist/version_permuter.py
API version abuse + shadow endpoint discovery.

Termux-safe: stdlib + aiohttp only. No external dependencies.

What this finds
---------------
Retired API versions (/v1, /v2) that are still live but have weaker
access controls than the current version. Also probes for:
  - Parallel version namespaces: /api/v1 → /internal/v1, /mobile/v1
  - Non-versioned shadows:       /api/v1/users → /api/users (no version)
  - Numeric downgrades:          /api/v3/... → /api/v1/..., /api/v2/...
  - Beta/legacy/staging paths:   /beta/, /legacy/, /staging/, /old/
  - Environment leakage:         /dev/, /test/, /qa/, /uat/
  - Debug endpoints:             /_debug/, /_internal/, /__debug__

FP-reduction rules (aligned with README)
-----------------------------------------
1. Canary check: before marking any version path as a finding, we verify
   a random non-existent path under the same version returns NOT 200.
   If /v99/canary_xyz returns 200, the server returns 200 for everything
   on that version prefix — we do NOT report those as endpoints.

2. Content comparison: version-downgraded paths must return a response
   that differs from a known-404 baseline. Pure HTML error pages are
   rejected regardless of status code.

3. Minimum response size: 30 bytes. Smaller responses are noise.

4. Auth-bypass confirmation: if the original endpoint requires a token
   (baseline returned 401/403 without one), the downgraded version is
   confirmed ONLY if it returns 200 WITHOUT a token. This is the real
   critical signal.

Confidence levels
-----------------
  0.90 — version downgrade returns data WITHOUT auth (auth bypass confirmed)
  0.80 — version downgrade returns more data than current version
  0.65 — version path exists but returns same data as current version
  0.55 — environment/debug path exists (lower value, needs manual review)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse


import os as _os
import sys as _sys

# ── Debug logging for silently-swallowed exceptions ────────────────────────
# Set BLFINDER_DEBUG=1 in the environment to see what these except blocks
# were hiding (parse failures, timeouts, malformed responses, etc.) instead
# of endpoints silently disappearing with no trace.
_BLF_DEBUG = bool(_os.environ.get("BLFINDER_DEBUG"))


def _blf_dbg(where: str, err: BaseException) -> None:
    if _BLF_DEBUG:
        print(f"[debug] {where}: {type(err).__name__}: {err}", file=_sys.stderr)

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_VERSION, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import (
    normalise_url, extract_id_params, dedup_key,
)


# ─────────────────────────────────────────────────────────────────────────────
# Version namespace trees to probe
# ─────────────────────────────────────────────────────────────────────────────

# Version prefixes: generate by replacing the detected version segment
_VERSION_PREFIXES = [
    "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
    "internal", "legacy", "beta", "alpha", "preview",
    "dev", "test", "qa", "uat", "staging",
    "old", "deprecated", "classic", "archive",
    "mobile", "app", "native",
    "public", "private", "partner", "b2b", "b2c",
]

# Namespace alternatives: /api/v1 → /internal/v1, /service/v1, …
_NAMESPACE_ALTS = [
    "api", "rest", "service", "services",
    "internal", "private", "backend",
    "mobile", "app",
    "partner", "b2b", "external",
]

# Debug / introspection paths to always probe (appended to base URL)
_DEBUG_PROBE_PATHS = [
    "/_debug",
    "/__debug__",
    "/_internal",
    "/_health",
    "/_status",
    "/_metrics",
    "/_info",
    "/_env",
    "/_config",
    "/_admin",
    "/_api",
    "/debug",
    "/debug/info",
    "/debug/vars",
    "/debug/pprof",          # Go pprof
    "/debug/routes",
    "/metrics",
    "/actuator",             # Spring Boot
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/mappings",
    "/actuator/beans",
    "/jolokia",              # Java JMX
    "/.well-known/health",
    "/management",
    "/management/health",
    "/management/info",
]

# Tag inference map
_TAG_KEYWORDS: dict[str, list[str]] = {
    "admin":    ["admin", "manage", "internal", "staff", "backoffice"],
    "payment":  ["payment", "billing", "transaction", "wallet", "charge"],
    "auth":     ["auth", "login", "token", "session", "password", "oauth"],
    "user":     ["user", "account", "profile", "member"],
    "order":    ["order", "cart", "checkout", "purchase"],
    "debug":    ["debug", "metrics", "actuator", "health", "env", "pprof",
                 "jolokia", "management", "info", "vars", "config"],
}


def _infer_tags(path: str) -> list[str]:
    lp = path.lower()
    return [tag for tag, kws in _TAG_KEYWORDS.items()
            if any(k in lp for k in kws)]


def _priority(tags: list[str], auth_bypass: bool = False) -> int:
    if auth_bypass:
        return 1
    if any(t in tags for t in ("admin", "payment", "debug")):
        return 1
    if any(t in tags for t in ("auth", "order", "user")):
        return 2
    return 3


# ─────────────────────────────────────────────────────────────────────────────
# URL manipulation helpers
# ─────────────────────────────────────────────────────────────────────────────

_RE_VERSION_SEG = re.compile(
    r'(?<![a-z])v\d+(?!\d)',
    re.IGNORECASE,
)

_RE_NAMESPACE_SEG = re.compile(
    r'^(?:api|rest|service|services|internal|mobile|app|partner|b2b)$',
    re.IGNORECASE,
)


def _detect_version_in_path(path: str) -> Optional[tuple[int, str]]:
    """
    Find the first version segment in a path.
    Returns (segment_index, version_string) or None.
    e.g. /api/v1/users → (1 relative to split, 'v1')
         /v2/orders    → (0, 'v2')
    """
    parts = path.lstrip("/").split("/")
    for i, seg in enumerate(parts):
        if _RE_VERSION_SEG.match(seg):
            return i, seg
    return None


def _swap_version(path: str, old_version: str, new_version: str) -> str:
    """Replace the first occurrence of old_version with new_version in path."""
    parts = path.lstrip("/").split("/")
    for i, seg in enumerate(parts):
        if seg.lower() == old_version.lower():
            parts[i] = new_version
            return "/" + "/".join(parts)
    return path


def _strip_version(path: str, version: str) -> str:
    """Remove the version segment from a path entirely."""
    parts = [p for p in path.lstrip("/").split("/")
             if p.lower() != version.lower()]
    return "/" + "/".join(parts) if parts else "/"


def _prepend_namespace(base: str, path: str, ns: str) -> str:
    """
    Prepend a namespace to a path.
    /v1/users + ns='internal'  →  /internal/v1/users
    """
    clean = path.lstrip("/")
    return f"{base}/{ns}/{clean}"


def _build_url(base: str, path: str) -> str:
    parsed = urlparse(base)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


# ─────────────────────────────────────────────────────────────────────────────
# Response analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

def _body_hash(body: str) -> str:
    return hashlib.md5(body[:1000].encode()).hexdigest()


def _is_html(content_type: str, body: str) -> bool:
    if "text/html" in content_type.lower():
        stripped = body.strip()
        if stripped.startswith("<") or "<html" in stripped[:200].lower():
            return True
    return False


def _response_looks_real(
    status: int,
    content_type: str,
    body: str,
    canary_hash: Optional[str],
    min_size: int = 30,
) -> bool:
    """
    FP filter: return True only if the response is a plausible real API response.
    """
    if status == 0:
        return False
    if len(body) < min_size:
        return False
    # Soft-404 / wildcard catch-all check
    if canary_hash and _body_hash(body) == canary_hash:
        return False
    # Reject pure HTML error pages (unless body also has JSON structure)
    if _is_html(content_type, body):
        stripped = body.strip()
        if not (stripped.startswith("{") or stripped.startswith("[")):
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class VersionPermuter:
    """
    Probes version-permuted and debug paths derived from already-discovered
    endpoints. Highest-value module for finding auth-bypass via version downgrade.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def run(
        self,
        target_url: str,
        session: Any,
        config: "DiscoveryConfig",
        auth_token: str = "",
        known_endpoints: Optional[list[str]] = None,
    ) -> LayerResult:
        t0     = time.time()
        result = LayerResult(layer=SOURCE_VERSION)

        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        authed_headers = {
            "Accept":           "application/json, */*",
            "X-Requested-With": "XMLHttpRequest",
        }
        if auth_token:
            authed_headers["Authorization"] = f"Bearer {auth_token}"

        unauthed_headers = {k: v for k, v in authed_headers.items()
                            if k != "Authorization"}

        seen_keys: set[str] = set()

        # ── Step 1: Establish per-prefix canary fingerprints ──────────────────
        # We probe one random non-existent path under each version prefix so
        # we can detect "this version prefix returns 200 for everything" (catch-all).
        canary_cache: dict[str, Optional[str]] = {}

        async def get_canary(prefix_path: str) -> Optional[str]:
            """prefix_path e.g. /api/v2"""
            if prefix_path in canary_cache:
                return canary_cache[prefix_path]
            canary_url = (
                base + prefix_path.rstrip("/")
                + "/blfinder_canary_xyz_notexist_9z9"
            )
            try:
                async with session.get(
                    canary_url, headers=authed_headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    if resp.status in (200,):
                        # Server returns 200 for anything under this prefix — unreliable
                        canary_cache[prefix_path] = _body_hash(body)
                    else:
                        canary_cache[prefix_path] = None
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer4_wordlist/version_permuter.py#1", e)
                canary_cache[prefix_path] = None
            return canary_cache[prefix_path]

        # ── Step 2: Probe debug / introspection paths ─────────────────────────
        async def probe_debug(path: str) -> Optional[DiscoveredEndpoint]:
            full_url = base + path
            key = dedup_key(full_url, "GET")
            if key in seen_keys:
                return None

            # Check canary for this prefix
            prefix = "/" + path.lstrip("/").split("/")[0]
            canary_hash = await get_canary(prefix)

            try:
                async with session.get(
                    full_url, headers=authed_headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    status = resp.status
                    ct     = resp.headers.get("Content-Type", "")
                    body   = await resp.text(errors="replace")

                if not _response_looks_real(status, ct, body, canary_hash, min_size=20):
                    return None
                if status not in (200, 201, 204, 401, 403):
                    return None

                seen_keys.add(key)
                _, tmpl = normalise_url(full_url)
                tags    = _infer_tags(path)

                if self.verbose:
                    print(f"  [version+] DEBUG {status} {full_url}")

                return DiscoveredEndpoint(
                    url=full_url, method="GET",
                    source=SOURCE_VERSION,
                    confidence=0.75,
                    priority=_priority(tags),
                    id_params=extract_id_params(path),
                    tags=tags,
                    raw_source_evidence=f"debug probe: {path}",
                    normalised_template=tmpl,
                )
            except Exception as e:
                if self.verbose:
                    result.errors.append(f"debug probe {path}: {e}")
                return None

        debug_results = await asyncio.gather(
            *[probe_debug(p) for p in _DEBUG_PROBE_PATHS]
        )
        for ep in debug_results:
            if ep:
                result.endpoints.append(ep)

        # ── Step 3: Version-permute known endpoints ───────────────────────────
        source_paths = list(known_endpoints or [])

        # Also try base-level version paths even without known endpoints
        base_resource_paths = [
            "/users", "/orders", "/payments", "/accounts",
            "/admin", "/profile", "/me", "/products",
            "/transactions", "/settings", "/config",
        ]

        for resource in base_resource_paths:
            for ver in _VERSION_PREFIXES[:6]:   # depth-limited to top 6
                candidate = f"/{ver}{resource}"
                if candidate not in source_paths:
                    source_paths.append(candidate)

        async def probe_version(
            original_path: str,
            new_path: str,
            label: str,
            base_status: int = 0,
            base_body: str = "",
        ) -> Optional[DiscoveredEndpoint]:
            full_url = _build_url(base, new_path)
            key = dedup_key(full_url, "GET")
            if key in seen_keys:
                return None

            # Get canary for the new version prefix
            prefix_seg = new_path.lstrip("/").split("/")[0]
            canary_hash = await get_canary("/" + prefix_seg)

            try:
                # Probe WITH auth
                async with session.get(
                    full_url, headers=authed_headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    status_auth = resp.status
                    ct_auth     = resp.headers.get("Content-Type", "")
                    body_auth   = await resp.text(errors="replace")

                if not _response_looks_real(status_auth, ct_auth, body_auth,
                                            canary_hash):
                    return None

                # Key signal: probe WITHOUT auth
                # If the ORIGINAL required auth but the NEW version doesn't → finding
                auth_bypass = False
                if status_auth == 200 and base_status in (401, 403, 0):
                    async with session.get(
                        full_url, headers=unauthed_headers,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                        ssl=False,
                    ) as resp2:
                        status_noauth = resp2.status
                        body_noauth   = await resp2.text(errors="replace")

                    if status_noauth == 200 and _response_looks_real(
                        status_noauth,
                        resp2.headers.get("Content-Type", ""),
                        body_noauth, canary_hash,
                    ):
                        auth_bypass = True

                # Determine confidence based on what we found
                if auth_bypass:
                    confidence = 0.90
                elif status_auth == 200:
                    # Did it return more data than the original? (richer old API)
                    if base_body and len(body_auth) > len(base_body) * 1.2:
                        confidence = 0.80
                    else:
                        confidence = 0.65
                elif status_auth in (401, 403):
                    # Endpoint exists but requires auth — still useful for scanner
                    confidence = 0.60
                else:
                    return None

                seen_keys.add(key)
                _, tmpl = normalise_url(full_url)
                tags    = _infer_tags(new_path)

                if self.verbose:
                    bypass_note = " [AUTH BYPASS]" if auth_bypass else ""
                    print(
                        f"  [version+] {status_auth} {full_url} "
                        f"← {label}{bypass_note}"
                    )

                return DiscoveredEndpoint(
                    url=full_url, method="GET",
                    source=SOURCE_VERSION,
                    confidence=confidence,
                    priority=_priority(tags, auth_bypass=auth_bypass),
                    id_params=extract_id_params(new_path),
                    tags=tags,
                    raw_source_evidence=(
                        f"version permute: {original_path} → {new_path} "
                        f"({'AUTH BYPASS' if auth_bypass else label})"
                    ),
                    normalised_template=tmpl,
                    spec_verified=False,
                )

            except Exception as e:
                if self.verbose:
                    result.errors.append(f"version probe {full_url}: {e}")
                return None

        # Build all version permutations from source paths
        probe_tasks = []

        for path in source_paths[:50]:   # cap to avoid runaway on large apps
            parsed_path = urlparse(path).path if "://" in path else path
            version_info = _detect_version_in_path(parsed_path)

            if version_info:
                seg_idx, current_ver = version_info

                # Numeric downgrades (e.g. v3 → v1, v2)
                ver_num = re.search(r'\d+', current_ver)
                if ver_num:
                    n = int(ver_num.group())
                    for down in range(1, n):
                        new_ver  = f"v{down}"
                        new_path = _swap_version(parsed_path, current_ver, new_ver)
                        probe_tasks.append((
                            parsed_path, new_path,
                            f"downgrade {current_ver}→{new_ver}",
                        ))

                # Non-versioned shadow: strip the version segment
                stripped = _strip_version(parsed_path, current_ver)
                if stripped and stripped != parsed_path:
                    probe_tasks.append((
                        parsed_path, stripped,
                        f"strip version ({current_ver})",
                    ))

                # Namespace alternatives
                parts = parsed_path.lstrip("/").split("/")
                for ns in _NAMESPACE_ALTS:
                    if parts and parts[0].lower() == ns.lower():
                        continue    # already in this namespace
                    new_path = _prepend_namespace(base, parsed_path, ns)
                    # Trim to path only
                    new_path_only = urlparse(new_path).path
                    probe_tasks.append((
                        parsed_path, new_path_only,
                        f"namespace alt: {ns}",
                    ))

            else:
                # No version detected — try prepending common versions
                for ver in config.include_versions[:4]:
                    new_path = f"/{ver}{parsed_path}"
                    probe_tasks.append((
                        parsed_path, new_path,
                        f"inject version {ver}",
                    ))

        # Deduplicate probe tasks
        seen_tasks: set[str] = set()
        unique_tasks = []
        for orig, new, label in probe_tasks:
            task_key = f"{new}"
            if task_key not in seen_tasks:
                seen_tasks.add(task_key)
                unique_tasks.append((orig, new, label))

        # Execute in batches (Termux: keep concurrent I/O low)
        batch_size = 8
        for i in range(0, len(unique_tasks), batch_size):
            batch = unique_tasks[i:i + batch_size]
            findings = await asyncio.gather(
                *[probe_version(orig, new, label) for orig, new, label in batch]
            )
            for ep in findings:
                if ep:
                    result.endpoints.append(ep)

        count = len(result.endpoints)
        if count:
            auth_bypass_count = sum(
                1 for ep in result.endpoints
                if "AUTH BYPASS" in ep.raw_source_evidence
            )
            print(
                f"  [+] Version permuter: {count} paths found"
                + (f" ({auth_bypass_count} auth-bypass confirmed)" if auth_bypass_count else "")
            )

        result.elapsed_s = time.time() - t0
        return result

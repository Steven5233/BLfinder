"""
BLFinder v3.1 — core/discovery/layer5_dedup/soft404_filter.py
Statistical soft-404 detector.

Termux-safe: stdlib + aiohttp only. No C extensions.

Problem
-------
Many production servers return HTTP 200 for every request regardless of whether
the resource exists. A scanner that trusts HTTP status codes alone will report
thousands of false positives — every wordlist hit looks real.

Solution: multi-signal soft-404 detection using 4 independent oracles.

Oracle 1 — Body hash canary
  Fetch a known-nonexistent random path (blfinder_canary_<random>).
  Hash the first 800 bytes of the response body. Any future response
  whose hash matches this fingerprint is a soft-404.

Oracle 2 — Size-variance canary
  Fetch 3 different known-bad paths. If they all return the same body
  size (±5%), the server uses a fixed-size error page — any response
  within that size band is a soft-404.

Oracle 3 — Title/content anchor
  If the canary response contains a recognisable error phrase
  ("page not found", "404", "doesn't exist", "no resource"), any
  response containing the same phrase is a soft-404.

Oracle 4 — Structural JSON anchor
  If the canary returns JSON with an error key ("error", "message",
  "code", "status") and a fixed value, match future responses by
  that structure.

A response is classified as soft-404 if ANY oracle fires.

FP-reduction design
-------------------
- 3 distinct canary paths are used (not 1) to avoid false positives
  from the canary itself being a real endpoint.
- If all 3 canaries return DIFFERENT bodies, the server is probably
  not a catch-all — we lower the sensitivity threshold.
- The filter is per-domain, not global. Different subdomains of the
  same target may behave differently.
- Minimum body length: 10 bytes. Zero-byte and tiny responses are
  always soft-404s regardless of status.

Confidence impact
-----------------
When an endpoint passes the soft-404 filter AND the status is 200/201,
its confidence is boosted by +0.10 (it's more likely real).
When the filter fires, the endpoint is dropped entirely.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Any, Optional


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

from ..models import DiscoveredEndpoint, DiscoveryConfig


# ─────────────────────────────────────────────────────────────────────────────
# Canary path generator
# ─────────────────────────────────────────────────────────────────────────────

def _random_token(length: int = 18) -> str:
    chars = string.ascii_lowercase + string.digits
    return "blfinder_" + "".join(random.choices(chars, k=length))


# Recognisable error phrases for Oracle 3
_ERROR_PHRASES = [
    "page not found", "404", "not found", "doesn't exist",
    "does not exist", "no resource", "resource not found",
    "cannot find", "could not find", "nothing here",
    "unknown route", "invalid path", "route not found",
    "endpoint not found", "no such", "unavailable",
]

# JSON error keys for Oracle 4
_JSON_ERROR_KEYS = {
    "error", "errors", "message", "msg", "detail",
    "details", "code", "status", "reason", "description",
}


def _body_hash(body: str) -> str:
    """Hash first 800 bytes — enough to fingerprint a fixed error page."""
    return hashlib.md5(body[:800].encode(errors="replace")).hexdigest()


def _extract_json_error_signature(body: str) -> Optional[str]:
    """
    If body is JSON with a single dominant error key, return a signature
    string we can match against future responses.
    Returns None if body is not JSON or has no error keys.
    """
    try:
        data = json.loads(body)
        if not isinstance(data, dict):
            return None
        for key in _JSON_ERROR_KEYS:
            if key in data and isinstance(data[key], (str, int, bool)):
                val = str(data[key])[:80]
                return f"{key}:{val}"
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer5_dedup/soft404_filter.py#1", e)
        pass
    return None


def _extract_error_phrase(body: str) -> Optional[str]:
    """Return the first matching error phrase found in body (lowercased)."""
    lower = body.lower()
    for phrase in _ERROR_PHRASES:
        if phrase in lower:
            return phrase
    return None


def _body_size_band(size: int, tolerance: float = 0.05) -> tuple[int, int]:
    """Return the ±tolerance size band for a given body size."""
    delta = max(10, int(size * tolerance))
    return size - delta, size + delta


# ─────────────────────────────────────────────────────────────────────────────
# Per-domain soft-404 profile
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Soft404Profile:
    """
    Soft-404 detection profile for a single domain.
    Built by probing 3 canary paths before the main scan.
    """
    domain:               str
    canary_hashes:        set[str]           = field(default_factory=set)
    canary_size_band:     Optional[tuple]    = None   # (min, max) bytes
    canary_error_phrase:  Optional[str]      = None
    canary_json_sig:      Optional[str]      = None
    all_canaries_same:    bool               = False  # if True, high confidence
    is_catch_all:         bool               = False  # returns 200 for everything
    built:                bool               = False


@dataclass
class FilterResult:
    is_soft_404:      bool
    oracle_fired:     str   = ""   # which oracle triggered
    confidence_boost: float = 0.0  # +0.10 if passed all oracles on 200


# ─────────────────────────────────────────────────────────────────────────────
# Main filter class
# ─────────────────────────────────────────────────────────────────────────────

class Soft404Filter:
    """
    Builds per-domain soft-404 profiles and filters DiscoveredEndpoints.

    Usage:
        f = Soft404Filter(verbose=True)
        await f.build_profile("https://api.target.com", session, config)
        result = f.check("https://api.target.com/api/users", 200, body)
        if not result.is_soft_404:
            keep(endpoint)
    """

    def __init__(self, verbose: bool = False):
        self.verbose  = verbose
        self._profiles: dict[str, Soft404Profile] = {}

    async def build_profile(
        self,
        base_url: str,
        session:  Any,
        config:   "DiscoveryConfig",
    ) -> Soft404Profile:
        """
        Probe 3 canary paths on the target domain and build a Soft404Profile.
        Safe to call multiple times — returns cached profile if already built.
        """
        from urllib.parse import urlparse
        domain = urlparse(base_url).netloc
        if domain in self._profiles and self._profiles[domain].built:
            return self._profiles[domain]

        profile = Soft404Profile(domain=domain)
        self._profiles[domain] = profile

        headers = {
            "Accept":           "application/json, */*",
            "X-Requested-With": "XMLHttpRequest",
        }
        if config.auth_token:
            headers["Authorization"] = f"Bearer {config.auth_token}"

        # 3 distinct canary paths across different depth levels
        canary_paths = [
            f"/{_random_token()}",
            f"/api/{_random_token()}",
            f"/api/v1/{_random_token()}/{_random_token()}",
        ]

        canary_bodies: list[str] = []
        canary_sizes:  list[int] = []

        async def fetch_canary(path: str) -> Optional[str]:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(
                    url, headers=headers, allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    # Only fingerprint if status is 200 (the tricky catch-all case)
                    if resp.status == 200:
                        return body
            except Exception as e:
                if self.verbose:
                    print(f"  [soft404] canary error {path}: {e}")
            return None

        results = await asyncio.gather(*[fetch_canary(p) for p in canary_paths])

        # Collect canary fingerprints
        hashes_seen: list[str] = []
        for body in results:
            if body is None:
                continue
            canary_bodies.append(body)
            canary_sizes.append(len(body))
            h = _body_hash(body)
            hashes_seen.append(h)
            profile.canary_hashes.add(h)

            # Oracle 3: error phrase anchor
            phrase = _extract_error_phrase(body)
            if phrase and not profile.canary_error_phrase:
                profile.canary_error_phrase = phrase

            # Oracle 4: JSON error signature
            sig = _extract_json_error_signature(body)
            if sig and not profile.canary_json_sig:
                profile.canary_json_sig = sig

        # Oracle 2: size-variance band
        if len(canary_sizes) >= 2:
            avg = sum(canary_sizes) / len(canary_sizes)
            all_close = all(
                abs(s - avg) / max(avg, 1) < 0.05
                for s in canary_sizes
            )
            if all_close:
                mn, mx = min(canary_sizes), max(canary_sizes)
                profile.canary_size_band = (
                    mn - max(10, int(mn * 0.05)),
                    mx + max(10, int(mx * 0.05)),
                )

        # Did all 3 canaries return the same hash? → strong catch-all signal
        if len(hashes_seen) >= 2 and len(set(hashes_seen)) == 1:
            profile.all_canaries_same = True
            profile.is_catch_all      = True

        profile.built = True

        if self.verbose:
            print(
                f"  [soft404] profile for {domain}: "
                f"catch_all={profile.is_catch_all}, "
                f"hashes={len(profile.canary_hashes)}, "
                f"phrase={profile.canary_error_phrase!r}, "
                f"json_sig={profile.canary_json_sig!r}"
            )

        return profile

    def check(
        self,
        url:          str,
        status:       int,
        body:         str,
        content_type: str = "",
    ) -> FilterResult:
        """
        Check whether a response is a soft-404.
        Returns FilterResult with is_soft_404 and the oracle that fired.
        Call build_profile() first for best accuracy.
        """
        from urllib.parse import urlparse
        domain  = urlparse(url).netloc
        profile = self._profiles.get(domain)

        # Always-fail conditions
        if status == 0 or not body:
            return FilterResult(is_soft_404=True, oracle_fired="zero_body")
        if len(body) < 10:
            return FilterResult(is_soft_404=True, oracle_fired="too_small")

        # Status codes that are clearly not real content
        if status in (404, 410):
            return FilterResult(is_soft_404=True, oracle_fired="404_status")

        if profile is None or not profile.built:
            # No profile — only apply basic heuristics
            return FilterResult(is_soft_404=False, confidence_boost=0.0)

        # Oracle 1 — body hash match
        bh = _body_hash(body)
        if bh in profile.canary_hashes:
            return FilterResult(is_soft_404=True, oracle_fired="oracle1_hash")

        # Oracle 2 — size band match (only when all canaries had same size)
        if profile.canary_size_band:
            lo, hi = profile.canary_size_band
            if lo <= len(body) <= hi:
                return FilterResult(
                    is_soft_404=True, oracle_fired="oracle2_size_band"
                )

        # Oracle 3 — error phrase anchor
        if profile.canary_error_phrase:
            if profile.canary_error_phrase in body.lower():
                return FilterResult(
                    is_soft_404=True, oracle_fired="oracle3_phrase"
                )

        # Oracle 4 — JSON error signature
        if profile.canary_json_sig:
            sig = _extract_json_error_signature(body)
            if sig == profile.canary_json_sig:
                return FilterResult(
                    is_soft_404=True, oracle_fired="oracle4_json_sig"
                )

        # Passed all oracles — boost confidence if status is good
        boost = 0.10 if status in (200, 201, 204) else 0.0
        return FilterResult(is_soft_404=False, confidence_boost=boost)

    async def filter_endpoints(
        self,
        endpoints: list[DiscoveredEndpoint],
        session:   Any,
        config:    "DiscoveryConfig",
    ) -> tuple[list[DiscoveredEndpoint], list[DiscoveredEndpoint]]:
        """
        Filter a list of DiscoveredEndpoints using soft-404 profiles.
        Builds profiles for all unique domains first.

        Returns (kept, dropped).
        """
        # Build profiles for all unique domains
        from urllib.parse import urlparse
        domains = {urlparse(ep.url).netloc for ep in endpoints}
        await asyncio.gather(*[
            self.build_profile(
                f"https://{d}" if "://" not in d else d,
                session, config,
            )
            for d in domains
        ])

        kept:    list[DiscoveredEndpoint] = []
        dropped: list[DiscoveredEndpoint] = []

        for ep in endpoints:
            # We don't have a live response here — use structural signals only
            # (live probing happens in the wordlist/version modules)
            # For spec/headless-verified endpoints, skip soft-404 filtering
            if ep.spec_verified or ep.live_verified:
                kept.append(ep)
                continue

            domain  = urlparse(ep.url).netloc
            profile = self._profiles.get(domain)

            if profile and profile.is_catch_all and not ep.spec_verified:
                # Catch-all server: only keep endpoints from authoritative sources
                if ep.confidence < 0.80:
                    dropped.append(ep)
                    continue

            kept.append(ep)

        if self.verbose and dropped:
            print(f"  [soft404] filtered {len(dropped)} catch-all endpoints")

        return kept, dropped

"""
core/intelligence/platform_scanner.py

Orchestrates platform detection and domain-specific attack modules.
Integrates with BLFScanner through scanner_integration.py.

Flow:
  1. PlatformProfiler identifies the target platform
  2. PlatformScanner selects the right module classes
  3. Each module runs against relevant endpoints
  4. Findings flow into the same pipeline as existing modules
  5. DomainChainEngine adds platform-specific exploit chains

FIX CHANGELOG:
  BUG-4  : PLATFORM_BANKING and PLATFORM_ECOMMERCE were silently dropped in
            run() — both branches of the if/elif returned [] with no message.
            Now a visible "[platform] no domain modules configured" log line
            is emitted for those types so the user knows detection fired but
            no attack followed.  This prevents the confusing situation where
            platform confidence is printed but nothing happens.

  BUG-19 : Removed the dead imports of PLATFORM_BANKING and
            PLATFORM_ECOMMERCE from the top-level import statement.  Both
            constants appeared in the import but were never referenced in the
            file body, signalling unfinished platform support.  Keeping them
            as deliberate TODO stubs (commented) to signal intent without
            triggering linters.

  BUG-20 : _endpoint_matches_module() previously had a silent catch-all
            `routes.get(module_name, False)` that returned False for any
            unrecognised module name — so a newly added module that was
            missing from the routes dict would silently never match any
            endpoint and never run.  Now an unknown module name emits a
            warning in verbose mode so the gap is caught during development.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.intelligence.platform_profiler import (
    PlatformProfiler, PlatformProfile,
    PLATFORM_FINTECH, PLATFORM_STREAMING,
    # PLATFORM_BANKING and PLATFORM_ECOMMERCE are intentionally NOT imported
    # here because no attack modules are implemented for those types yet.
    # When banking/ecommerce modules are added, re-add those imports and
    # wire them into run() below.
    PLATFORM_UNKNOWN,
    KNOWN_SPOTIFY, KNOWN_STRIPE, KNOWN_PAYPAL,
    KNOWN_WISE, KNOWN_REVOLUT, KNOWN_FLUTTERWAVE, KNOWN_PAYSTACK,
)
from core.intelligence.platform_attack_modules import (
    FintechAttackModules,
    SpotifyAttackModules,
    _make_finding,
    _try_json,
    _get,
)
from core.intelligence.domain_chains import (
    DomainChainEngine,
    extend_capability_classifier,
)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint relevance router
# ─────────────────────────────────────────────────────────────────────────────

# The full set of module names that have routing entries.  Used to detect
# missing entries when a new module is added to fintech_modules / spotify_modules
# but its route is not added to the dict in _endpoint_matches_module().
_KNOWN_MODULE_NAMES = frozenset({
    "amount_sign_flip",
    "currency_confusion",
    "idempotency_abuse",
    "refund_overflow",
    "webhook_forgery",
    "fee_bypass",
    "kyc_sca_bypass",
    "transfer_idor",
    "subscription_scope",
    "stream_count_manipulation",
    "download_token_replay",
    "device_limit_bypass",
    "playlist_idor",
})


def _endpoint_matches_module(
    url: str,
    method: str,
    body: dict,
    module_name: str,
    verbose: bool = False,
) -> bool:
    """
    Return True if the given endpoint (url, method, body) is relevant for
    the named attack module.

    FIX (BUG-20): unknown module_name now emits a warning in verbose mode
    instead of silently returning False.  This catches the case where a new
    module is added to the fintech_modules / spotify_modules list but its
    routing entry is not added to the routes dict below.
    """
    url_l  = url.lower()
    body_k = " ".join(body.keys()).lower() if body else ""

    routes = {
        "amount_sign_flip": (
            any(k in body_k for k in [
                "amount", "value", "sourceamount", "targetamount",
                "sum", "total", "price", "cost",
            ])
        ),
        "currency_confusion": (
            any(k in body_k for k in [
                "currency", "currencycode", "sourcecurrency", "targetcurrency",
            ])
        ),
        "idempotency_abuse": (
            method.upper() in ("POST", "PUT") and
            any(w in url_l for w in [
                "transfer", "payment", "charge", "pay", "send",
                "payout", "order", "transaction",
            ])
        ),
        "refund_overflow": (
            any(w in url_l for w in ["refund", "return", "reversal", "chargeback"])
        ),
        "webhook_forgery": (
            any(w in url_l for w in ["webhook", "callback", "notify", "ipn", "hook"])
            and method.upper() == "POST"
        ),
        "fee_bypass": (
            any(k in body_k for k in [
                "fee", "platform_fee", "commission", "markup",
                "is_fee_exempt", "fee_exempt", "waive_fee",
            ]) or
            any(w in url_l for w in ["fee", "commission", "charge"])
        ),
        "kyc_sca_bypass": (
            any(w in url_l for w in [
                "kyc", "verify", "verification", "identity",
                "2fa", "otp", "mfa", "sca", "challenge",
            ])
        ),
        "transfer_idor": (
            any(w in url_l for w in [
                "transfer", "payment", "payout", "send", "wire",
            ])
        ),
        "subscription_scope": (
            any(w in url_l for w in [
                "premium", "subscription", "pro", "paid", "plus",
                "download", "offline", "hq", "lossless",
            ])
        ),
        "stream_count_manipulation": (
            any(w in url_l for w in [
                "play", "stream", "listen", "log", "event",
                "heartbeat", "progress", "played",
            ]) and method.upper() in ("POST", "PUT")
        ),
        "download_token_replay": (
            any(w in url_l for w in [
                "download", "offline", "license", "audio", "stream_url",
            ])
        ),
        "device_limit_bypass": (
            any(w in url_l for w in [
                "device", "player", "active", "session", "connect",
            ])
        ),
        "playlist_idor": (
            any(w in url_l for w in [
                "playlist", "track", "album", "artist",
                "user", "profile", "library",
            ])
        ),
    }

    # FIX (BUG-20): warn on unknown module names so gaps are visible during
    # development rather than silently returning False.
    if module_name not in routes:
        if verbose:
            print(
                f"  [platform] WARNING: no routing entry for module "
                f"'{module_name}' — it will never match any endpoint. "
                f"Add an entry to _endpoint_matches_module()."
            )
        return False

    return routes[module_name]


# ─────────────────────────────────────────────────────────────────────────────
# PlatformScanner
# ─────────────────────────────────────────────────────────────────────────────

class PlatformScanner:
    """
    Runs platform-specific attack modules against discovered endpoints.
    Called from scanner_integration.py after the main 21-module sweep.
    """

    def __init__(self, scanner, config):
        self._scanner  = scanner
        self._config   = config
        self._profiler = PlatformProfiler()
        self._fintech  = FintechAttackModules()
        self._spotify  = SpotifyAttackModules()
        self._profile: Optional[PlatformProfile] = None

    async def detect_platform(
        self,
        target_url:       str,
        response_headers: dict,
        response_body:    str,
        discovered_paths: list[str],
    ) -> PlatformProfile:
        self._profile = self._profiler.profile(
            target_url, response_headers, response_body, discovered_paths
        )
        known = self._profile.known_platform or self._profile.platform_type
        print(
            f"  [platform] detected: {known} "
            f"(confidence={self._profile.confidence}%)"
        )
        if self._profile.indicators:
            print(f"  [platform] signals: {', '.join(self._profile.indicators[:4])}")
        return self._profile

    async def run(
        self,
        endpoints:   list[dict],
        concurrency: int = 4,
    ) -> list[dict]:
        if self._profile is None:
            return []

        ptype  = self._profile.platform_type
        known  = self._profile.known_platform
        verbose = getattr(self._config, "verbose", False)

        # FIX (BUG-4): the previous code had two branches that BOTH returned
        # [] silently — PLATFORM_BANKING and PLATFORM_ECOMMERCE fell through
        # without any message.  Now platforms that have no modules configured
        # emit a clear log line so the user knows detection fired but no
        # domain-specific attack ran.  PLATFORM_UNKNOWN is the only case that
        # should be truly silent.
        if ptype == PLATFORM_UNKNOWN:
            return []

        if ptype not in (PLATFORM_FINTECH, PLATFORM_STREAMING):
            # Known platform type but no attack modules implemented yet.
            # This covers PLATFORM_BANKING, PLATFORM_ECOMMERCE, and any
            # future platform types added to platform_profiler.py before
            # their module sets are built here.
            print(
                f"  [platform] no domain modules configured for "
                f"'{ptype}' — skipped (detection only)"
            )
            return []

        sem      = asyncio.Semaphore(concurrency)
        findings: list[dict] = []

        fintech_modules = [
            "amount_sign_flip",
            "currency_confusion",
            "idempotency_abuse",
            "refund_overflow",
            "webhook_forgery",
            "fee_bypass",
            "kyc_sca_bypass",
            "transfer_idor",
        ]
        spotify_modules = [
            "subscription_scope",
            "stream_count_manipulation",
            "download_token_replay",
            "device_limit_bypass",
            "playlist_idor",
        ]

        skip = set(self._profile.skip_modules)

        tasks = []
        for ep in endpoints:
            url    = ep.get("url", "")
            method = ep.get("method", "GET")
            body   = ep.get("body") or {}

            if not url.startswith("http"):
                continue

            if ptype == PLATFORM_FINTECH or known in (
                KNOWN_STRIPE, KNOWN_PAYPAL, KNOWN_WISE,
                KNOWN_REVOLUT, KNOWN_FLUTTERWAVE, KNOWN_PAYSTACK,
            ):
                for mod in fintech_modules:
                    if mod in skip:
                        continue
                    if not _endpoint_matches_module(url, method, body, mod, verbose):
                        continue
                    tasks.append(
                        self._run_module_bounded(
                            sem, mod, url, method, body
                        )
                    )

            if ptype == PLATFORM_STREAMING or known == KNOWN_SPOTIFY:
                for mod in spotify_modules:
                    if mod in skip:
                        continue
                    if not _endpoint_matches_module(url, method, body, mod, verbose):
                        continue
                    tasks.append(
                        self._run_module_bounded(
                            sem, mod, url, method, body
                        )
                    )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception) and verbose:
                print(f"  [platform] module error: {r}")

        if findings:
            print(
                f"  [platform] {len(findings)} domain-specific findings "
                f"({ptype})"
            )

        return findings

    async def _run_module_bounded(
        self,
        sem:    asyncio.Semaphore,
        module: str,
        url:    str,
        method: str,
        body:   dict,
    ) -> list[dict]:
        async with sem:
            base_entry  = self._scanner.base_responses.get(url, {})
            base_status = base_entry.get("status", 0)
            base_body   = base_entry.get("body",   "")

            try:
                fn = self._module_fn(module)
                if fn is None:
                    return []
                return await fn(
                    self._scanner, url, method, body,
                    base_status, base_body,
                )
            except Exception as e:
                if getattr(self._config, "verbose", False):
                    print(f"  [platform] {module} error on {url[:55]}: {e}")
                return []

    def _module_fn(self, module: str):
        fintech_map = {
            "amount_sign_flip":    self._fintech.check_amount_sign_flip,
            "currency_confusion":  self._fintech.check_currency_confusion,
            "idempotency_abuse":   self._fintech.check_idempotency_abuse,
            "refund_overflow":     self._fintech.check_refund_overflow,
            "webhook_forgery":     self._fintech.check_webhook_forgery,
            "fee_bypass":          self._fintech.check_fee_bypass,
            "kyc_sca_bypass":      self._fintech.check_kyc_sca_bypass,
            "transfer_idor":       self._fintech.check_transfer_idor,
        }
        spotify_map = {
            "subscription_scope":          self._spotify.check_subscription_scope,
            "stream_count_manipulation":   self._spotify.check_stream_count_manipulation,
            "download_token_replay":       self._spotify.check_download_token_replay,
            "device_limit_bypass":         self._spotify.check_device_limit_bypass,
            "playlist_idor":               self._spotify.check_playlist_idor,
        }
        return fintech_map.get(module) or spotify_map.get(module)

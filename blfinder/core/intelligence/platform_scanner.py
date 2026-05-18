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
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.intelligence.platform_profiler import (
    PlatformProfiler, PlatformProfile,
    PLATFORM_FINTECH, PLATFORM_STREAMING,
    PLATFORM_BANKING, PLATFORM_ECOMMERCE, PLATFORM_UNKNOWN,
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

def _endpoint_matches_module(url: str, method: str, body: dict,
                              module_name: str) -> bool:
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
    return routes.get(module_name, False)


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
        endpoints:  list[dict],
        concurrency: int = 4,
    ) -> list[dict]:
        if self._profile is None:
            return []

        ptype  = self._profile.platform_type
        known  = self._profile.known_platform

        if ptype not in (PLATFORM_FINTECH, PLATFORM_STREAMING):
            if ptype == PLATFORM_UNKNOWN:
                return []
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
                    if not _endpoint_matches_module(url, method, body, mod):
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
                    if not _endpoint_matches_module(url, method, body, mod):
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
            elif isinstance(r, Exception) and self._config.verbose:
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
            base_entry = self._scanner.base_responses.get(url, {})
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
                if self._config.verbose:
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

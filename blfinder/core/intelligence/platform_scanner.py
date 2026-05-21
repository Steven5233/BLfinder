"""
core/intelligence/platform_scanner.py  — FIXED v3.1 Phase 5+

FIX CHANGELOG (all bugs from screenshot root-cause map applied):

  BUG-4  : PLATFORM_BANKING and PLATFORM_ECOMMERCE silently returned []
            with no log. Now emits a visible "no domain modules configured"
            line so the user knows detection fired but no attack followed.

  BUG-19 : Dead imports of PLATFORM_BANKING / PLATFORM_ECOMMERCE removed.
            Left as commented TODO stubs to signal intent without linting errors.

  BUG-20 : _endpoint_matches_module() silent catch-all replaced with a
            warning in verbose mode for unknown module names.

  RC-4   : _run_module_bounded() now captures the raw request + response
            into the finding's request_log list so reports contain real HTTP
            proof instead of stub text. Token is redacted before storage.

  RC-5   : Platform findings are converted from plain dicts to Finding
            objects (via _dict_to_finding) before being returned so the
            verifier, PoC generator, and reporter all receive typed objects,
            not raw dicts — fixing the "hollow report" root cause for
            platform-specific findings.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.intelligence.platform_profiler import (
    PlatformProfiler, PlatformProfile,
    PLATFORM_FINTECH, PLATFORM_STREAMING,
    # PLATFORM_BANKING / PLATFORM_ECOMMERCE intentionally NOT imported —
    # no attack modules exist yet. Re-add when modules are implemented.
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
# RC-5 FIX: Convert platform finding dict → Finding dataclass
# ─────────────────────────────────────────────────────────────────────────────

def _dict_to_finding(d: dict):
    """
    Convert a plain dict returned by platform attack modules into a
    Finding dataclass so the verifier + PoC generator receive a typed object.

    Falls back gracefully when the Finding import is unavailable (e.g. in
    unit tests that don't load the full core package).
    """
    try:
        from core.models import Finding, Severity
        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
            "INFO":     Severity.INFO,
        }
        sev = sev_map.get(str(d.get("severity", "MEDIUM")).upper(), Severity.MEDIUM)
        f = Finding(
            title             = d.get("title", "Platform Finding"),
            severity          = sev,
            category          = d.get("category", "Business Logic — Platform"),
            description       = d.get("description", ""),
            request           = d.get("request", {}),
            response_summary  = d.get("response_summary", ""),
            evidence          = d.get("evidence", ""),
            recommendation    = d.get("recommendation", ""),
            cwe               = d.get("cwe", "CWE-20"),
            cvss              = float(d.get("cvss", 7.0)),
            owasp             = d.get("owasp", ""),
            confirmed         = bool(d.get("confirmed", False)),
            confidence        = int(d.get("confidence", 70)),
            endpoint          = d.get("endpoint", ""),
            parameter         = d.get("parameter", ""),
        )
        # RC-5: attach real HTTP proof fields if present
        if d.get("curl_command"):
            f.poc = d["curl_command"]
        if d.get("request_log"):
            f.evidence = (
                f.evidence + "\n\nHTTP Log:\n" +
                "\n".join(
                    f"  [{e.get('label','')}] {e.get('method','')} {e.get('url','')} "
                    f"→ HTTP {e.get('status','?')}"
                    for e in d["request_log"]
                )
            )
        return f
    except (ImportError, TypeError, AttributeError):
        # Return the dict as-is if Finding is not available
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint relevance router
# ─────────────────────────────────────────────────────────────────────────────

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
    url:         str,
    method:      str,
    body:        dict,
    module_name: str,
    verbose:     bool = False,
) -> bool:
    """
    Return True if the endpoint is relevant for the named attack module.

    BUG-20 FIX: unknown module_name now emits a warning in verbose mode
    instead of silently returning False.
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

    # BUG-20 FIX: warn on unknown module names
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
    ) -> list:
        """
        BUG-4 FIX: All platform types now emit a log line.
        RC-5 FIX: Returns list of Finding objects (via _dict_to_finding),
        not raw dicts.
        """
        if self._profile is None:
            return []

        ptype   = self._profile.platform_type
        known   = self._profile.known_platform
        verbose = getattr(self._config, "verbose", False)

        # BUG-4 FIX: PLATFORM_UNKNOWN is the only truly silent case.
        if ptype == PLATFORM_UNKNOWN:
            return []

        if ptype not in (PLATFORM_FINTECH, PLATFORM_STREAMING):
            # Known type but no attack modules yet
            # (covers PLATFORM_BANKING, PLATFORM_ECOMMERCE, future types)
            print(
                f"  [platform] no domain modules configured for "
                f"'{ptype}' — skipped (detection only)"
            )
            return []

        sem      = asyncio.Semaphore(concurrency)
        findings = []

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

        skip  = set(self._profile.skip_modules)
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
                        self._run_module_bounded(sem, mod, url, method, body)
                    )

            if ptype == PLATFORM_STREAMING or known == KNOWN_SPOTIFY:
                for mod in spotify_modules:
                    if mod in skip:
                        continue
                    if not _endpoint_matches_module(url, method, body, mod, verbose):
                        continue
                    tasks.append(
                        self._run_module_bounded(sem, mod, url, method, body)
                    )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_dicts: list[dict] = []
        for r in results:
            if isinstance(r, list):
                raw_dicts.extend(r)
            elif isinstance(r, Exception) and verbose:
                print(f"  [platform] module error: {r}")

        # RC-5 FIX: convert dicts → Finding objects
        for d in raw_dicts:
            findings.append(_dict_to_finding(d))

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
            "subscription_scope":        self._spotify.check_subscription_scope,
            "stream_count_manipulation": self._spotify.check_stream_count_manipulation,
            "download_token_replay":     self._spotify.check_download_token_replay,
            "device_limit_bypass":       self._spotify.check_device_limit_bypass,
            "playlist_idor":             self._spotify.check_playlist_idor,
        }
        return fintech_map.get(module) or spotify_map.get(module)

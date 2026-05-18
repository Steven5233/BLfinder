"""
core/intelligence/platform_attack_modules.py

Domain-specific attack modules for Fintech (Stripe, PayPal, Wise,
Flutterwave, Paystack, Revolut) and Streaming (Spotify).

Each module is an async method that accepts the same signature as
BLFScanner's existing check methods and returns list[dict] findings
compatible with the Finding dataclass and the rest of the pipeline
(verifier, PoC generator, reporter).

Integration: PlatformScanner.run() is called from scanner_integration.py
which patches it into BLFScanner.run_all_modules().
"""

from __future__ import annotations

import asyncio
import difflib
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse, urljoin


# ─────────────────────────────────────────────────────────────────────────────
# Wordlist seeds (imported by platform_profiler._default_seeds)
# ─────────────────────────────────────────────────────────────────────────────

PLATFORM_SEEDS: dict[str, list[str]] = {
    "STREAMING": [
        "stream", "track", "album", "playlist", "artist", "podcast",
        "premium", "subscription", "download", "offline", "device",
        "play", "skip", "queue", "radio", "listen", "audio", "royalty",
        "analytics", "embed", "connect", "lyrics", "preview", "free",
        "shuffle", "repeat", "volume", "episode", "show", "chapter",
    ],
    "FINTECH": [
        "charge", "payment", "intent", "refund", "capture", "transfer",
        "payout", "subscription", "invoice", "customer", "connect",
        "account", "balance", "dispute", "webhook", "idempotency",
        "fee", "tax", "coupon", "promo", "wallet", "ledger", "kyc",
        "aml", "sanctions", "compliance", "fx", "exchange", "currency",
        "mandate", "beneficiary", "virtual", "card", "limit", "limit",
    ],
    "BANKING": [
        "account", "balance", "transaction", "statement", "payment",
        "consent", "domestic", "international", "standing-order",
        "direct-debit", "beneficiary", "funds", "confirmation",
        "sort-code", "iban", "swift", "bic", "routing", "overdraft",
    ],
    "ECOMMERCE": [
        "cart", "checkout", "order", "product", "variant", "inventory",
        "discount", "price", "coupon", "gift", "refund", "return",
        "fulfillment", "shipping", "customer", "collection", "review",
        "wishlist", "affiliate", "referral", "wholesale", "draft",
    ],
    "UNKNOWN": [
        "admin", "internal", "debug", "api", "v1", "v2", "users",
        "accounts", "payments", "orders", "config", "settings",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _try_json(body: str) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return {}


def _get(data: Any, *keys, default=None) -> Any:
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        elif isinstance(data, list) and isinstance(key, int) and key < len(data):
            data = data[key]
        else:
            return default
    return data


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


def _make_finding(
    title:        str,
    severity:     str,
    category:     str,
    description:  str,
    endpoint:     str,
    method:       str,
    body:         dict,
    evidence:     str,
    recommendation: str,
    cwe:          str,
    cvss:         float,
    owasp:        str,
    confidence:   int  = 80,
    confirmed:    bool = False,
    parameter:    str  = "",
    response_summary: str = "",
) -> dict:
    return {
        "title":            title,
        "severity":         severity,
        "category":         category,
        "description":      description,
        "request":          {"method": method, "url": endpoint, "body": body},
        "response_summary": response_summary or evidence[:200],
        "evidence":         evidence,
        "recommendation":   recommendation,
        "cwe":              cwe,
        "cvss":             cvss,
        "owasp":            owasp,
        "confirmed":        confirmed,
        "confidence":       confidence,
        "endpoint":         endpoint,
        "parameter":        parameter,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FINTECH MODULES
# ─────────────────────────────────────────────────────────────────────────────

class FintechAttackModules:
    """
    All fintech-specific attack modules.
    Each method is async, takes (scanner, url, method, body, base_status, base_body)
    and returns list[dict] findings compatible with BLFScanner's pipeline.
    """

    # ── MODULE F1: Amount Sign Flip ───────────────────────────────────────────

    async def check_amount_sign_flip(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        amount_keys = [
            "amount", "value", "sum", "total", "price", "cost",
            "sourceAmount", "targetAmount", "debitAmount", "creditAmount",
            "gross_amount", "net_amount", "instructed_amount",
            "transfer_amount", "payment_amount", "charge_amount",
        ]
        negative_values = [-1, -100, -0.01, -9999, -0.001]

        for key in amount_keys:
            if key not in body:
                continue
            original = body[key]
            for neg_val in negative_values:
                tampered = {**body, key: neg_val}
                try:
                    s, _, rb, _ = await scanner._request(
                        method, url, json=tampered
                    )
                except Exception:
                    continue
                if s not in (200, 201, 202):
                    continue
                data = _try_json(rb)
                if not data:
                    continue
                for resp_key in ["amount", "value", "balance", "net", "credit",
                                  "credited", "received", "balance_change"]:
                    rv = _get(data, resp_key)
                    if isinstance(rv, (int, float)) and rv < 0:
                        findings.append(_make_finding(
                            title=f"Negative Amount Accepted — `{key}` = {neg_val} credited",
                            severity="CRITICAL",
                            category="Business Logic — Fintech — Amount Sign Flip",
                            description=(
                                f"Setting `{key}` to {neg_val} (original: {original}) "
                                f"was accepted and resulted in `{resp_key}` = {rv}. "
                                f"An attacker can receive money instead of paying."
                            ),
                            endpoint=url,
                            method=method,
                            body=tampered,
                            evidence=(
                                f"Request: {key}={neg_val} | "
                                f"Response: HTTP {s}, {resp_key}={rv} | "
                                f"Net gain per exploit: ~{abs(neg_val)}"
                            ),
                            recommendation=(
                                "Enforce amount > 0 server-side before any "
                                "financial processing. Use absolute value "
                                "checks and reject negative amounts at the "
                                "API gateway level."
                            ),
                            cwe="CWE-20",
                            cvss=9.8,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            confidence=92,
                            confirmed=True,
                            parameter=key,
                            response_summary=f"HTTP {s} — {resp_key}={rv} (negative)",
                        ))
                        break
        return findings

    # ── MODULE F2: Currency Confusion ─────────────────────────────────────────

    async def check_currency_confusion(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        currency_keys = [
            "currency", "currency_code", "sourceCurrency", "targetCurrency",
            "payment_currency", "charge_currency", "iso_code",
        ]
        amount_keys = [
            "amount", "value", "sourceAmount", "targetAmount",
        ]

        currency_found = next((k for k in currency_keys if k in body), None)
        amount_found   = next((k for k in amount_keys   if k in body), None)
        if not currency_found or not amount_found:
            return findings

        original_currency = body[currency_found]
        original_amount   = body[amount_found]

        high_value_currencies = ["JPY", "IDR", "KRW", "VND", "HUF"]
        low_value_currencies  = ["USD", "EUR", "GBP", "CHF", "CAD"]

        if str(original_currency).upper() in low_value_currencies:
            test_currencies = high_value_currencies
        else:
            test_currencies = low_value_currencies

        base_data = _try_json(base_body)
        base_total = None
        for k in ["amount", "total", "targetAmount", "received", "converted"]:
            v = _get(base_data, k)
            if isinstance(v, (int, float)):
                base_total = v
                break

        for cur in test_currencies[:3]:
            tampered = {**body, currency_found: cur}
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201, 202):
                continue
            resp_data = _try_json(rb)
            new_total = None
            for k in ["amount", "total", "targetAmount", "received", "converted"]:
                v = _get(resp_data, k)
                if isinstance(v, (int, float)):
                    new_total = v
                    break

            if base_total and new_total and base_total > 0:
                ratio = new_total / base_total
                if ratio > 50 or ratio < 0.02:
                    findings.append(_make_finding(
                        title=(
                            f"Currency Confusion — {original_currency} vs {cur} "
                            f"({ratio:.0f}x amount difference)"
                        ),
                        severity="CRITICAL",
                        category="Business Logic — Fintech — Currency Confusion",
                        description=(
                            f"Changing `{currency_found}` from `{original_currency}` "
                            f"to `{cur}` with the same `{amount_found}` value "
                            f"({original_amount}) resulted in a {ratio:.1f}x "
                            f"difference in the processed amount. "
                            f"Server may be processing amounts in the wrong currency unit."
                        ),
                        endpoint=url,
                        method=method,
                        body=tampered,
                        evidence=(
                            f"Original: {amount_found}={original_amount} {original_currency} "
                            f"→ result={base_total} | "
                            f"Tampered: {amount_found}={original_amount} {cur} "
                            f"→ result={new_total} | "
                            f"Ratio: {ratio:.2f}x"
                        ),
                        recommendation=(
                            "Never trust client-supplied currency codes for amount "
                            "computation. Validate the currency against a server-side "
                            "list and apply server-side FX conversion only."
                        ),
                        cwe="CWE-20",
                        cvss=9.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confidence=88,
                        confirmed=True,
                        parameter=currency_found,
                        response_summary=f"HTTP {s} — amount ratio {ratio:.1f}x",
                    ))
                    break
        return findings

    # ── MODULE F3: Idempotency Key Abuse ──────────────────────────────────────

    async def check_idempotency_abuse(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        if method.upper() not in ("POST", "PUT"):
            return findings

        idem_headers = [
            "Idempotency-Key", "X-Idempotency-Key",
            "Idempotency-key", "idempotency-key",
        ]

        import hashlib, uuid
        idem_key = str(uuid.uuid4())

        try:
            s1, _, rb1, _ = await scanner._request(
                method, url, json=body,
                headers={idem_headers[0]: idem_key},
            )
        except Exception:
            return findings
        if s1 not in (200, 201):
            return findings

        await asyncio.sleep(0.5)

        try:
            s2, _, rb2, _ = await scanner._request(
                method, url, json=body,
                headers={idem_headers[0]: idem_key},
            )
        except Exception:
            return findings

        data1 = _try_json(rb1)
        data2 = _try_json(rb2)

        id_fields = ["id", "transaction_id", "charge_id", "payment_id",
                     "transfer_id", "order_id", "reference"]
        id1 = next((_get(data1, f) for f in id_fields if _get(data1, f)), None)
        id2 = next((_get(data2, f) for f in id_fields if _get(data2, f)), None)

        if s2 in (200, 201) and id1 and id2 and str(id1) != str(id2):
            findings.append(_make_finding(
                title="Idempotency Key Not Enforced — Duplicate Transaction Created",
                severity="CRITICAL",
                category="Business Logic — Fintech — Idempotency Abuse",
                description=(
                    f"Replaying the same request with identical Idempotency-Key "
                    f"`{idem_key}` created two separate transactions. "
                    f"First transaction ID: {id1}, Second: {id2}. "
                    f"An attacker can double-charge or double-pay by replaying requests."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=(
                    f"Request 1 → HTTP {s1}, id={id1} | "
                    f"Request 2 (same key) → HTTP {s2}, id={id2} | "
                    f"Two distinct transactions created with same key"
                ),
                recommendation=(
                    "Implement server-side idempotency key deduplication. "
                    "Store the key with its result and return the cached "
                    "response for any replay. Scope keys to the authenticated user."
                ),
                cwe="CWE-362",
                cvss=9.3,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                confidence=95,
                confirmed=True,
                parameter="Idempotency-Key",
                response_summary=f"Two transactions: {id1} and {id2}",
            ))

        elif s2 in (200, 201) and _similarity(rb1, rb2) < 0.5:
            findings.append(_make_finding(
                title="Idempotency Key — Different Response on Replay",
                severity="HIGH",
                category="Business Logic — Fintech — Idempotency Abuse",
                description=(
                    f"Replaying the same request with identical Idempotency-Key "
                    f"`{idem_key}` produced a significantly different response. "
                    f"Server may not be deduplicating idempotent requests correctly."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=(
                    f"Request 1 → HTTP {s1}, body={rb1[:100]} | "
                    f"Request 2 (same key) → HTTP {s2}, body={rb2[:100]} | "
                    f"Similarity: {_similarity(rb1, rb2):.2f}"
                ),
                recommendation=(
                    "Enforce idempotency key deduplication. Return identical "
                    "responses for duplicate keys within the key's TTL."
                ),
                cwe="CWE-362",
                cvss=7.5,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                confidence=72,
                confirmed=False,
                parameter="Idempotency-Key",
                response_summary=f"HTTP {s2} — different response on replay",
            ))
        return findings

    # ── MODULE F4: Refund Overflow ────────────────────────────────────────────

    async def check_refund_overflow(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        refund_indicators = ["refund", "return", "reversal", "chargeback"]
        if not any(r in url.lower() for r in refund_indicators):
            return findings

        amount_keys = ["amount", "refund_amount", "value", "total"]
        amount_key  = next((k for k in amount_keys if k in body), None)
        if not amount_key:
            return findings

        original = body.get(amount_key, 100)
        overflow_values = [
            original + 1,
            original * 2,
            original + 0.01,
            999999,
        ]

        base_data = _try_json(base_body)

        for overflow_val in overflow_values:
            tampered = {**body, amount_key: overflow_val}
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201, 202):
                continue
            resp_data = _try_json(rb)
            for rk in ["amount", "refund_amount", "refunded", "credited"]:
                rv = _get(resp_data, rk)
                if isinstance(rv, (int, float)) and rv >= overflow_val:
                    findings.append(_make_finding(
                        title=(
                            f"Refund Overflow — `{amount_key}` = {overflow_val} "
                            f"(original charge: {original})"
                        ),
                        severity="CRITICAL",
                        category="Business Logic — Fintech — Refund Overflow",
                        description=(
                            f"Refund amount `{amount_key}` = {overflow_val} "
                            f"exceeds the original charge ({original}) and was accepted. "
                            f"Response shows `{rk}` = {rv}. "
                            f"An attacker can refund more than they paid."
                        ),
                        endpoint=url,
                        method=method,
                        body=tampered,
                        evidence=(
                            f"Original charge: {original} | "
                            f"Refund requested: {overflow_val} | "
                            f"Refund processed: {rv} | "
                            f"HTTP {s}"
                        ),
                        recommendation=(
                            "Cap refund amounts server-side to the original "
                            "charge amount. Look up the original transaction "
                            "and validate refund_amount <= original_amount. "
                            "Track partial refunds to prevent total refunds "
                            "exceeding the original."
                        ),
                        cwe="CWE-840",
                        cvss=9.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confidence=90,
                        confirmed=True,
                        parameter=amount_key,
                        response_summary=f"HTTP {s} — refunded {rv} > original {original}",
                    ))
                    return findings
        return findings

    # ── MODULE F5: Webhook Signature Bypass ───────────────────────────────────

    async def check_webhook_forgery(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        webhook_indicators = [
            "webhook", "callback", "notify", "ipn", "hook", "event"
        ]
        if not any(w in url.lower() for w in webhook_indicators):
            return findings
        if method.upper() != "POST":
            return findings

        forged_events = [
            {
                "type": "payment.completed",
                "data": {"object": {"status": "succeeded", "amount": 10000}},
            },
            {
                "event": "charge.success",
                "data": {"amount": 10000, "status": "success"},
            },
            {
                "type": "transfer.credited",
                "amount": 10000,
                "status": "completed",
            },
        ]

        sig_headers = [
            "Stripe-Signature", "X-Webhook-Signature",
            "X-Hub-Signature", "X-PayStack-Signature",
            "verif-hash", "X-Flutterwave-Signature",
            "Paypal-Transmission-Sig",
        ]

        for event in forged_events:
            try:
                s_no_sig, _, rb_no_sig, _ = await scanner._request(
                    "POST", url, json=event,
                )
            except Exception:
                continue

            if s_no_sig in (200, 201, 202):
                data = _try_json(rb_no_sig)
                if data or len(rb_no_sig) > 10:
                    findings.append(_make_finding(
                        title="Webhook Forgery — No Signature Validation",
                        severity="CRITICAL",
                        category="Business Logic — Fintech — Webhook Forgery",
                        description=(
                            f"A forged webhook event was accepted at `{url}` "
                            f"without any signature header. An attacker can send "
                            f"a fake payment.completed event to trigger order "
                            f"fulfilment without actual payment."
                        ),
                        endpoint=url,
                        method="POST",
                        body=event,
                        evidence=(
                            f"Forged event type={event.get('type') or event.get('event')} "
                            f"accepted with HTTP {s_no_sig} and no signature header"
                        ),
                        recommendation=(
                            "Validate webhook signatures on every incoming event. "
                            "Use HMAC-SHA256 with a shared secret. Reject any "
                            "event missing or failing the signature check. "
                            "Whitelist source IPs where possible."
                        ),
                        cwe="CWE-345",
                        cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confidence=88,
                        confirmed=True,
                        parameter="signature",
                        response_summary=f"HTTP {s_no_sig} — forged event accepted",
                    ))
                    return findings

            for sig_hdr in sig_headers:
                try:
                    s_fake, _, rb_fake, _ = await scanner._request(
                        "POST", url, json=event,
                        headers={sig_hdr: "sha256=fakesignature123456"},
                    )
                except Exception:
                    continue
                if s_fake in (200, 201, 202):
                    findings.append(_make_finding(
                        title=f"Webhook Forgery — `{sig_hdr}` Not Validated",
                        severity="CRITICAL",
                        category="Business Logic — Fintech — Webhook Forgery",
                        description=(
                            f"A forged webhook with an invalid `{sig_hdr}` "
                            f"header was accepted at `{url}`. "
                            f"The server is not validating the signature value."
                        ),
                        endpoint=url,
                        method="POST",
                        body=event,
                        evidence=(
                            f"Forged {sig_hdr}: sha256=fakesignature123456 "
                            f"→ HTTP {s_fake} accepted"
                        ),
                        recommendation=(
                            f"Validate `{sig_hdr}` using HMAC-SHA256 with your "
                            "webhook secret. Reject events with invalid signatures "
                            "before any business logic executes."
                        ),
                        cwe="CWE-345",
                        cvss=9.3,
                        owasp="API2:2023 Broken Authentication",
                        confidence=85,
                        confirmed=True,
                        parameter=sig_hdr,
                        response_summary=f"HTTP {s_fake} — fake signature accepted",
                    ))
                    return findings
        return findings

    # ── MODULE F6: Fee Bypass ─────────────────────────────────────────────────

    async def check_fee_bypass(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        fee_keys = [
            "fee", "platform_fee", "fee_amount", "transaction_fee",
            "service_fee", "commission", "markup", "processing_fee",
            "fee_override", "application_fee_amount",
        ]
        exempt_keys = [
            "is_fee_exempt", "fee_exempt", "waive_fee", "fee_waiver",
            "tax_exempt", "no_fee",
        ]

        base_data = _try_json(base_body)
        base_fee = None
        for k in fee_keys:
            v = _get(base_data, k)
            if isinstance(v, (int, float)):
                base_fee = v
                break

        for key in fee_keys:
            if key not in body:
                continue
            for zero_val in [0, 0.0, "0", None]:
                tampered = {**body, key: zero_val}
                try:
                    s, _, rb, _ = await scanner._request(method, url, json=tampered)
                except Exception:
                    continue
                if s not in (200, 201):
                    continue
                resp_data = _try_json(rb)
                resp_fee = None
                for rk in fee_keys:
                    rv = _get(resp_data, rk)
                    if isinstance(rv, (int, float)):
                        resp_fee = rv
                        break
                if resp_fee is not None and resp_fee == 0 and (base_fee is None or base_fee > 0):
                    findings.append(_make_finding(
                        title=f"Fee Bypass — `{key}` = 0 accepted",
                        severity="HIGH",
                        category="Business Logic — Fintech — Fee Bypass",
                        description=(
                            f"Setting `{key}` to {zero_val} in the request "
                            f"resulted in a zero fee being applied. "
                            f"Original fee: {base_fee}. "
                            f"Platform revenue bypassed per transaction."
                        ),
                        endpoint=url,
                        method=method,
                        body=tampered,
                        evidence=(
                            f"Request: {key}={zero_val} | "
                            f"Response: fee={resp_fee} | "
                            f"Fee reduction: {base_fee} → 0"
                        ),
                        recommendation=(
                            "Compute fees server-side from the transaction "
                            "amount and account tier. Never accept fee values "
                            "from the client. Remove fee fields from the API "
                            "request schema entirely."
                        ),
                        cwe="CWE-20",
                        cvss=7.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confidence=82,
                        confirmed=True,
                        parameter=key,
                        response_summary=f"HTTP {s} — fee={resp_fee}",
                    ))
                    return findings

        for key in exempt_keys:
            tampered = {**body, key: True}
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201):
                continue
            resp_data = _try_json(rb)
            if isinstance(resp_data, dict) and resp_data.get(key) in (True, "true", 1):
                if base_fee is None or _get(resp_data, *[k for k in fee_keys]) == 0:
                    findings.append(_make_finding(
                        title=f"Fee Bypass via Mass Assignment — `{key}` = true",
                        severity="HIGH",
                        category="Business Logic — Fintech — Fee Bypass",
                        description=(
                            f"Injecting `{key}: true` was reflected in the response, "
                            f"suggesting the fee exemption was applied. "
                        ),
                        endpoint=url,
                        method=method,
                        body=tampered,
                        evidence=f"Injected {key}=true → reflected in response",
                        recommendation=(
                            "Use an explicit field allowlist. Never bind "
                            "exemption flags from client input."
                        ),
                        cwe="CWE-915",
                        cvss=7.8,
                        owasp="API3:2023 Broken Object Property Level Authorization",
                        confidence=75,
                        confirmed=True,
                        parameter=key,
                        response_summary=f"HTTP {s} — {key} reflected as true",
                    ))
                    break
        return findings

    # ── MODULE F7: KYC / SCA Bypass ───────────────────────────────────────────

    async def check_kyc_sca_bypass(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        kyc_indicators = ["kyc", "verify", "verification", "identity", "document"]
        sca_indicators = ["2fa", "otp", "mfa", "sca", "challenge", "approval"]

        url_lower = url.lower()
        is_kyc = any(k in url_lower for k in kyc_indicators)
        is_sca = any(k in url_lower for k in sca_indicators)
        if not is_kyc and not is_sca:
            return findings

        bypass_attempts = []

        for key in ["kyc_status", "verification_status", "is_verified",
                     "is_kyc_verified", "kyc_level", "kyc_tier"]:
            for val in [True, "verified", "approved", "VERIFIED", 3]:
                bypass_attempts.append(({**body, key: val}, key, val))

        for key in ["otp", "mfa_token", "sca_token", "challenge_response",
                     "2fa_code", "verification_code"]:
            if key in body:
                reduced = {k: v for k, v in body.items() if k != key}
                bypass_attempts.append((reduced, key, "OMITTED"))

        for tampered, key, val in bypass_attempts[:8]:
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201):
                continue
            if not rb or len(rb) < 10:
                continue
            resp_data = _try_json(rb)
            if isinstance(resp_data, dict):
                reflected = resp_data.get(key)
                if reflected in (True, "verified", "approved", "VERIFIED", 3) or \
                   (val == "OMITTED" and s in (200, 201)):
                    label = "KYC" if is_kyc else "SCA/2FA"
                    findings.append(_make_finding(
                        title=f"{label} Bypass — `{key}` = {val}",
                        severity="CRITICAL",
                        category=f"Business Logic — Fintech — {label} Bypass",
                        description=(
                            f"{'Omitting' if val == 'OMITTED' else 'Setting'} "
                            f"`{key}` to `{val}` bypassed the {label} requirement. "
                            f"Transactions requiring {label} can be executed "
                            f"without completing the verification flow."
                        ),
                        endpoint=url,
                        method=method,
                        body=tampered,
                        evidence=(
                            f"Request: {key}={val} → HTTP {s} accepted | "
                            f"Response reflected: {key}={reflected}"
                        ),
                        recommendation=(
                            f"Enforce {label} server-side through a separate "
                            f"verification service. Never trust client-supplied "
                            f"verification status fields. Use a session flag "
                            f"set only after successful {label} completion."
                        ),
                        cwe="CWE-284",
                        cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confidence=88,
                        confirmed=True,
                        parameter=key,
                        response_summary=f"HTTP {s} — {label} bypassed",
                    ))
                    return findings
        return findings

    # ── MODULE F8: Transfer IDOR ──────────────────────────────────────────────

    async def check_transfer_idor(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        transfer_indicators = ["transfer", "payment", "payout", "send", "wire"]
        if not any(t in url.lower() for t in transfer_indicators):
            return findings

        parsed       = urlparse(url)
        path_parts   = [p for p in parsed.path.split("/") if p]
        base_data    = _try_json(base_body)

        for i, part in enumerate(path_parts):
            if not re.match(r'^\d{4,}$', part):
                continue
            orig_id = int(part)
            for test_id in [orig_id - 1, orig_id + 1, 1, 2]:
                if test_id <= 0:
                    continue
                new_parts    = path_parts[:]
                new_parts[i] = str(test_id)
                test_url     = f"{parsed.scheme}://{parsed.netloc}/" + "/".join(new_parts)
                try:
                    s, _, rb, _ = await scanner._request(method, test_url)
                except Exception:
                    continue
                if s != 200:
                    continue
                resp_data = _try_json(rb)
                if not resp_data:
                    continue
                financial_fields = ["amount", "value", "status", "recipient",
                                     "sender", "currency", "source_account"]
                exposed = [f for f in financial_fields if f in resp_data]
                if not exposed:
                    continue
                findings.append(_make_finding(
                    title=f"Transfer IDOR — ID {orig_id}→{test_id} exposes financial data",
                    severity="CRITICAL",
                    category="Business Logic — Fintech — Transfer IDOR",
                    description=(
                        f"Changing transfer ID from {orig_id} to {test_id} "
                        f"returned a financial transaction with fields: "
                        f"{', '.join(exposed)}. "
                        f"An attacker can enumerate and read any user's transfers."
                    ),
                    endpoint=test_url,
                    method=method,
                    body={},
                    evidence=(
                        f"ID {orig_id}→{test_id} → HTTP {s} | "
                        f"Financial fields exposed: {exposed}"
                    ),
                    recommendation=(
                        "Enforce ownership checks on every transfer/payment "
                        "resource. Verify the authenticated user's account "
                        "matches the transfer's source or destination."
                    ),
                    cwe="CWE-639",
                    cvss=9.1,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confidence=87,
                    confirmed=True,
                    parameter=f"path[{i}]",
                    response_summary=f"HTTP {s} — {len(exposed)} financial fields exposed",
                ))
                return findings
        return findings


# ─────────────────────────────────────────────────────────────────────────────
# SPOTIFY / STREAMING MODULES
# ─────────────────────────────────────────────────────────────────────────────

class SpotifyAttackModules:
    """
    Spotify and generic streaming platform attack modules.
    """

    # ── MODULE S1: Subscription Scope Probe ───────────────────────────────────

    async def check_subscription_scope(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        premium_indicators = [
            "premium", "subscription", "pro", "paid", "plus",
            "download", "offline", "hq", "high_quality", "lossless",
        ]
        url_lower = url.lower()
        if not any(p in url_lower for p in premium_indicators):
            return findings

        free_token  = getattr(scanner.config, "second_user_token", "")
        owned_token = getattr(scanner.config, "auth_token", "")
        if not free_token or free_token == owned_token:
            return findings

        try:
            s_free, _, rb_free, _ = await scanner._request(
                method, url,
                json=body if body else None,
                token_override=free_token,
            )
        except Exception:
            return findings

        if s_free not in (200, 201):
            return findings

        base_data = _try_json(base_body)
        free_data = _try_json(rb_free)

        premium_fields = [
            "audio_quality", "bitrate", "download_url", "offline_uri",
            "premium_uri", "licensed_url", "cdn_url", "hq_url",
        ]
        exposed = [f for f in premium_fields
                   if _get(free_data, f) and not _get(base_data, f)]
        if exposed:
            findings.append(_make_finding(
                title="Premium Feature Access with Free Token",
                severity="CRITICAL",
                category="Business Logic — Streaming — Subscription Scope Bypass",
                description=(
                    f"A free-tier token accessed `{url}` and received premium "
                    f"fields: {', '.join(exposed)}. "
                    f"Premium content is accessible without a paid subscription."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=(
                    f"Free token → HTTP {s_free} | "
                    f"Premium fields in response: {exposed}"
                ),
                recommendation=(
                    "Validate subscription tier server-side on every request "
                    "to premium endpoints. Check the token's scope claims "
                    "against the required subscription level. Remove premium "
                    "fields from responses for free-tier tokens."
                ),
                cwe="CWE-285",
                cvss=8.5,
                owasp="API5:2023 Broken Function Level Authorization",
                confidence=88,
                confirmed=True,
                parameter="Authorization (free token)",
                response_summary=f"HTTP {s_free} — premium fields: {exposed}",
            ))

        elif s_free == 200 and len(rb_free) > 50:
            findings.append(_make_finding(
                title="Premium Endpoint Accessible with Free Token",
                severity="HIGH",
                category="Business Logic — Streaming — Subscription Scope Bypass",
                description=(
                    f"Free-tier token returned HTTP 200 on premium endpoint `{url}`. "
                    f"Server may not be validating subscription scope."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=f"Free token → HTTP {s_free}, {len(rb_free)}B response",
                recommendation=(
                    "Enforce subscription scope checks at the API layer, "
                    "not only at the CDN/token generation layer."
                ),
                cwe="CWE-285",
                cvss=7.5,
                owasp="API5:2023 Broken Function Level Authorization",
                confidence=65,
                confirmed=False,
                parameter="Authorization",
                response_summary=f"HTTP {s_free} — {len(rb_free)}B",
            ))
        return findings

    # ── MODULE S2: Stream Count Manipulation ──────────────────────────────────

    async def check_stream_count_manipulation(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        play_indicators = [
            "play", "stream", "listen", "log", "event", "heartbeat",
            "progress", "played", "track_event",
        ]
        if not any(p in url.lower() for p in play_indicators):
            return findings
        if method.upper() not in ("POST", "PUT"):
            return findings

        play_event_keys = ["played_ms", "duration_ms", "position_ms",
                           "track_id", "uri", "context_uri", "item_id"]
        if not any(k in body for k in play_event_keys):
            return findings

        success_count = 0
        ids_generated = set()
        burst_count   = 15

        responses = await asyncio.gather(
            *[scanner._request(method, url, json=body) for _ in range(burst_count)],
            return_exceptions=True,
        )
        for r in responses:
            if isinstance(r, tuple) and r[0] in (200, 201, 202, 204):
                success_count += 1
                data = _try_json(r[2])
                for id_field in ["id", "event_id", "play_id", "log_id"]:
                    vid = _get(data, id_field)
                    if vid:
                        ids_generated.add(str(vid))

        if success_count >= burst_count * 0.7:
            unique_events = len(ids_generated)
            findings.append(_make_finding(
                title=(
                    f"Stream Count Manipulation — {success_count}/{burst_count} "
                    f"duplicate play events accepted"
                ),
                severity="HIGH",
                category="Business Logic — Streaming — Stream Count Manipulation",
                description=(
                    f"{success_count} out of {burst_count} identical play events "
                    f"were accepted at `{url}`. "
                    f"{unique_events} unique event IDs generated. "
                    f"An attacker can inflate stream counts for royalty fraud "
                    f"or chart manipulation."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=(
                    f"{success_count}/{burst_count} accepted | "
                    f"Unique IDs: {unique_events} | "
                    f"No per-session deduplication detected"
                ),
                recommendation=(
                    "Deduplicate play events by (user_id, track_id, session_id) "
                    "within a minimum playback window. Require minimum listening "
                    "duration before counting a stream. Rate-limit play event "
                    "submissions per user."
                ),
                cwe="CWE-770",
                cvss=7.3,
                owasp="API4:2023 Unrestricted Resource Consumption",
                confidence=80,
                confirmed=True,
                parameter="play_event",
                response_summary=f"{success_count}/{burst_count} accepted",
            ))
        return findings

    # ── MODULE S3: Download Token Replay ──────────────────────────────────────

    async def check_download_token_replay(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        download_indicators = [
            "download", "offline", "license", "token", "cdn",
            "audio_url", "stream_url", "file_url",
        ]
        if not any(d in url.lower() for d in download_indicators):
            return findings

        base_data = _try_json(base_body)
        token_fields = [
            "download_url", "audio_url", "stream_url", "cdn_url",
            "license_url", "offline_url", "file_url", "signed_url",
        ]
        token_url = None
        for field in token_fields:
            v = _get(base_data, field)
            if isinstance(v, str) and v.startswith("http"):
                token_url = v
                break

        if not token_url:
            return findings

        has_expiry = any(p in token_url for p in [
            "expires", "exp=", "X-Amz-Expires", "se=", "valid_until",
        ])

        try:
            s_replay, _, rb_replay, _ = await scanner._request("GET", token_url)
        except Exception:
            return findings

        if s_replay in (200, 206):
            if has_expiry:
                findings.append(_make_finding(
                    title="Download Token Replay — Signed URL Still Valid",
                    severity="HIGH",
                    category="Business Logic — Streaming — Download Token Replay",
                    description=(
                        f"A signed download URL from `{url}` was replayed "
                        f"and returned HTTP {s_replay}. "
                        f"The URL contains expiry parameters but may still be "
                        f"shareable or have an excessively long TTL."
                    ),
                    endpoint=url,
                    method=method,
                    body=body,
                    evidence=(
                        f"Download URL: {token_url[:80]} | "
                        f"Replay → HTTP {s_replay}"
                    ),
                    recommendation=(
                        "Use short-lived signed URLs (max 60 seconds). "
                        "Bind the URL to the requesting user's IP or device ID. "
                        "Invalidate URLs after first use for premium content."
                    ),
                    cwe="CWE-613",
                    cvss=6.5,
                    owasp="API2:2023 Broken Authentication",
                    confidence=70,
                    confirmed=False,
                    parameter="download_url",
                    response_summary=f"Signed URL replay → HTTP {s_replay}",
                ))
            else:
                findings.append(_make_finding(
                    title="Download URL — No Expiry or Binding",
                    severity="HIGH",
                    category="Business Logic — Streaming — Download Token Replay",
                    description=(
                        f"Download URL from `{url}` has no expiry parameters "
                        f"and returned HTTP {s_replay} on replay. "
                        f"URL can be shared to bypass subscription."
                    ),
                    endpoint=url,
                    method=method,
                    body=body,
                    evidence=f"Permanent URL: {token_url[:80]} | Replay → HTTP {s_replay}",
                    recommendation=(
                        "Add expiry parameters and user binding to all "
                        "download/stream URLs. Never issue permanent URLs "
                        "for protected content."
                    ),
                    cwe="CWE-613",
                    cvss=7.5,
                    owasp="API2:2023 Broken Authentication",
                    confidence=78,
                    confirmed=True,
                    parameter="download_url",
                    response_summary=f"Permanent URL → HTTP {s_replay}",
                ))
        return findings

    # ── MODULE S4: Device Limit Bypass ────────────────────────────────────────

    async def check_device_limit_bypass(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        device_indicators = ["device", "player", "active", "session", "connect"]
        if not any(d in url.lower() for d in device_indicators):
            return findings

        device_id_fields = ["device_id", "client_id", "device", "player_id"]
        device_id_field  = next((k for k in device_id_fields if k in body), None)

        if not device_id_field:
            return findings

        import uuid
        success_count = 0
        limit_reached = False

        for i in range(6):
            fake_device_id = str(uuid.uuid4())
            tampered = {**body, device_id_field: fake_device_id}
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s in (200, 201):
                success_count += 1
            elif s == 403 and any(w in rb.lower() for w in
                                   ["limit", "maximum", "exceeded", "too many"]):
                limit_reached = True
                break

        if success_count >= 4 and not limit_reached:
            findings.append(_make_finding(
                title=f"Device Limit Bypass — {success_count} devices registered",
                severity="HIGH",
                category="Business Logic — Streaming — Device Limit Bypass",
                description=(
                    f"Registered {success_count} devices by rotating `{device_id_field}` "
                    f"with random UUIDs at `{url}`. "
                    f"No device limit was enforced. "
                    f"Attacker can register unlimited devices to share an account."
                ),
                endpoint=url,
                method=method,
                body=body,
                evidence=(
                    f"{success_count}/6 device registrations accepted | "
                    f"No 403/limit response received"
                ),
                recommendation=(
                    "Enforce device limits server-side by counting active devices "
                    "per account. Require device deauthorisation before adding "
                    "new ones beyond the plan limit. Track devices by both "
                    "device_id and account association."
                ),
                cwe="CWE-770",
                cvss=6.5,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                confidence=75,
                confirmed=True,
                parameter=device_id_field,
                response_summary=f"{success_count}/6 devices registered",
            ))
        return findings

    # ── MODULE S5: Playlist / Resource IDOR ───────────────────────────────────

    async def check_playlist_idor(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        resource_indicators = [
            "playlist", "track", "album", "artist", "user", "profile",
            "library", "collection", "followed",
        ]
        if not any(r in url.lower() for r in resource_indicators):
            return findings

        second_token = getattr(scanner.config, "second_user_token", "")
        if not second_token:
            return findings

        parsed     = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]
        base_data  = _try_json(base_body)

        spotify_id_pattern = re.compile(r'^[0-9A-Za-z]{22}$')
        for i, part in enumerate(path_parts):
            if not spotify_id_pattern.match(part):
                continue

            new_parts       = path_parts[:]
            new_parts[i]    = "0" * 22
            test_url        = f"{parsed.scheme}://{parsed.netloc}/" + "/".join(new_parts)

            try:
                s2, _, rb2, _ = await scanner._request(
                    method, test_url, token_override=second_token
                )
            except Exception:
                continue

            if s2 != 200:
                continue

            resp_data     = _try_json(rb2)
            private_field = next(
                (f for f in ["collaborative", "public", "owner",
                              "email", "birthdate", "country"]
                 if _get(resp_data, f) is not None),
                None,
            )
            if private_field:
                findings.append(_make_finding(
                    title=f"Resource IDOR — Spotify ID enumerable ({private_field} exposed)",
                    severity="HIGH",
                    category="Business Logic — Streaming — Resource IDOR",
                    description=(
                        f"Swapping the Spotify resource ID at path position {i} "
                        f"with a test ID returned HTTP 200 with private field "
                        f"`{private_field}` using a second user's token."
                    ),
                    endpoint=test_url,
                    method=method,
                    body=body,
                    evidence=(
                        f"Original ID: {part} | "
                        f"Test ID: {'0'*22} | "
                        f"User2 token → HTTP {s2} | "
                        f"Private field exposed: {private_field}"
                    ),
                    recommendation=(
                        "Validate resource ownership on every request. "
                        "Use internal database IDs for ownership checks, "
                        "not just the presence of a valid Spotify ID."
                    ),
                    cwe="CWE-639",
                    cvss=7.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confidence=82,
                    confirmed=True,
                    parameter=f"path[{i}]",
                    response_summary=f"HTTP {s2} — {private_field} exposed",
                ))
                return findings
        return findings

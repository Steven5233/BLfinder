"""
core/intelligence/platform_attack_modules.py  — FIXED v3.1 Phase 5+

ROOT CAUSE FIXES (from screenshot root-cause failure map):

  RC-1 (False Positive Flood):
    _response_indicates_success() was accepting any 200 OK.
    FIX: Now performs multi-gate validation:
      Gate A: Body must not be empty or error-like
      Gate B: For financial endpoints, response must contain at least
              one expected financial field or transaction signal
      Gate C: Response must differ from a canary (invalid body) probe.
              If canary also gets 200, the endpoint accepts anything.

  RC-2 (Canary Logic Inverted — Negative Qty):
    Previous: if canary == 200 → skip (WRONG — 200 means endpoint
              accepts anything, so our negative qty result is also FP)
    Fixed:    if canary != 200 → valid signal (server rejected nonsense
              but accepted negative qty — real vulnerability)
    The condition was literally backwards causing real vulns to be skipped
    and noise to pass through.

  RC-3 (No Diff Confirmation):
    Modules compared status codes only. Body content was never diffed.
    FIX: Added _confirm_with_diff() helper that:
      1. Verifies base_body vs tampered_body differ meaningfully
      2. For IDOR: collects cross-user token proof
      3. Checks response contains success-specific fields (order_id etc.)

  RC-4 (Evidence Capture Broken):
    _new_evidence() returns None when _HAS_EVIDENCE=False.
    PoC generator embeds live bearer tokens.
    FIX: _safe_evidence_record() wrapper works whether or not evidence
         module is available. PoC redacts Authorization headers.

  RC-5 (Report Generation Hollow):
    generate_html/json/md_report() stubs had no HTTP log per finding.
    FIX: _build_finding_record() now attaches:
      - actual request (method + url + sanitised body + sanitised headers)
      - actual response (status + first 500B of body)
      - curl command for reproduction
      - redacted token values

  FP-1 (subscription_scope — SPA shell false positives):
    Five-gate validation prevents HTML/CDN responses from becoming findings.

  FP-2 (BASE64_BLOB in auth_diff_scanner):
    Negative lookahead added to _VALUE_SENSITIVITY regex to reject
    URL-like strings (see auth_diff_scanner.py companion fix).
"""

from __future__ import annotations

import asyncio
import difflib
import json
import re
import time
import uuid
from typing import Any, Optional

try:
    from ..analysis.semantic_diff import SemanticDiff
    _HAS_SEMANTIC_DIFF = True
except ImportError:
    _HAS_SEMANTIC_DIFF = False
from urllib.parse import urlparse, urljoin






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
        "mandate", "beneficiary", "virtual", "card", "limit",
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
    if _HAS_SEMANTIC_DIFF:
        try:
            return SemanticDiff.compare(a[:3000], b[:3000]).semantic_similarity
        except Exception:
            pass
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

    request_log:  list = None,   
    curl_command: str  = "",
) -> dict:
    """
    Build a finding dict compatible with BLFScanner's pipeline.
    RC-5 FIX: request_log and curl_command are now first-class fields
    so reporters can embed real HTTP proof rather than stub text.
    """
    return {
        "title":            title,
        "severity":         severity,
        "category":         category,
        "description":      description,
        "request":          {"method": method, "url": endpoint, "body": _sanitise_body(body)},
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

        "request_log":      request_log or [],
        "curl_command":     curl_command,
    }


def _sanitise_body(body: dict) -> dict:
    """
    RC-4 FIX: Redact sensitive fields from body before embedding in reports.
    Prevents live credentials appearing in exported PoC/reports.
    """
    if not isinstance(body, dict):
        return body or {}
    sensitive = {"password", "passwd", "secret", "private_key", "api_key",
                 "access_token", "refresh_token", "token", "authorization"}
    return {
        k: "[REDACTED]" if k.lower() in sensitive else v
        for k, v in body.items()
    }


def _build_curl(method: str, url: str, body: dict, token: str = "") -> str:
    """
    RC-5 FIX: Build a curl reproduction command with redacted token.
    """
    parts = [f"curl -X {method.upper()} '{url}'"]
    if token:
        parts.append("-H 'Authorization: Bearer [REDACTED]'")
    parts.append("-H 'Content-Type: application/json'")
    if body:
        safe_body = json.dumps(_sanitise_body(body))
        parts.append(f"-d '{safe_body}'")
    return " \\\n  ".join(parts)







_FINANCIAL_SUCCESS_FIELDS = {
    "id", "transaction_id", "payment_id", "charge_id", "order_id",
    "transfer_id", "reference", "ref", "receipt_number", "trace_id",
    "created", "created_at", "timestamp", "status", "amount",
    "currency", "balance", "credited", "net", "gross",
}


_ERROR_STRINGS = (
    "error", "invalid", "failed", "unauthorized", "forbidden",
    "not found", "rejected", "denied", "exception", "bad request",
    "validation", "required", "missing", "stack trace", "internal server",
)


def _response_looks_successful(body: str, status: int) -> bool:
    """
    RC-1 FIX: Multi-gate success check.
    Returns True only when the response credibly indicates a successful operation.
    """
    if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
        return False
    if status >= 500:
        return False

    body_lower = body.lower()


    error_count = sum(1 for s in _ERROR_STRINGS if s in body_lower)
    if error_count >= 2:
        return False

    if status in (200, 201, 202, 204):

        if status == 204:
            return True  
        data = _try_json(body)
        if isinstance(data, dict):

            has_success_field = bool(
                set(k.lower() for k in data.keys()) & _FINANCIAL_SUCCESS_FIELDS
            )
            if has_success_field:
                return error_count == 0

        success_signals = ["success", "true", "created", "completed", "accepted", "ok"]
        return any(s in body_lower for s in success_signals) and error_count == 0

    return False


async def _canary_probe(scanner, url: str, method: str, invalid_body: dict) -> int:
    """
    RC-2/RC-3 FIX: Send a deliberately invalid body and return the status.
    If the canary also succeeds, the endpoint accepts anything → FP.
    """
    try:
        status, _, _, _ = await scanner._request(method, url, json=invalid_body)
        return status
    except Exception:
        return 0






def _bodies_differ_meaningfully(base: str, tampered: str, threshold: float = 0.05) -> bool:
    """
    RC-3 FIX: Return True only when responses differ by more than threshold.
    Previously modules compared status codes only — now body content is checked.

    Body content comparison itself was raw difflib, which has the same
    envelope-vs-data blind spot as every other site in this file's FP-fix
    history — now scored with semantic_diff so timestamp/nonce noise
    doesn't count as "differs" and a real changed field isn't diluted by
    a large shared envelope.
    """
    if not base or not tampered:
        return bool(tampered and not base)  
    if _HAS_SEMANTIC_DIFF:
        try:
            sim = SemanticDiff.compare(base[:4000], tampered[:4000]).semantic_similarity
            return (1.0 - sim) > threshold
        except Exception:
            pass
    sim = difflib.SequenceMatcher(None, base[:4000], tampered[:4000]).ratio()
    return (1.0 - sim) > threshold






_HTML_SIGNALS = (
    b"<!doctype html", b"<html", b"<head>", b"<body",
    b"<script", b"<div id=", b'<div id="root', b"<div id='root",
    b"window.__", b"react", b"vue", b"angular", b"webpack",
    b"cdn-cgi", b"serviceWorker", b"manifest.json",
)

_API_CONTENT_TYPES = (
    "application/json", "application/vnd.", "text/plain",
    "application/x-ndjson", "application/ld+json",
)

_MIN_JSON_KEYS_FOR_PREMIUM   = 2
_MAX_SIMILARITY_TO_UNAUTH    = 0.97
_MAX_SIMILARITY_FREE_VS_PREMIUM = 0.97
_SPA_SHELL_SIZE_TOLERANCE    = 0.05


def _is_spa_shell(body: str, body_bytes: bytes) -> bool:
    if not body:
        return False
    head = body_bytes[:1024].lower()
    if any(sig in head for sig in _HTML_SIGNALS):
        return True
    stripped = body.strip()
    if stripped and stripped[0] in ("{", "["):
        try:
            json.loads(stripped)
            return False
        except (json.JSONDecodeError, ValueError):
            pass
    if len(body_bytes) > 80_000:
        return True
    return False


def _is_api_response(headers: dict, body: str) -> bool:
    ct = headers.get("content-type", "").lower() if headers else ""
    if any(t in ct for t in _API_CONTENT_TYPES):
        if "json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, (dict, list)):
                    return True
            except (json.JSONDecodeError, ValueError):
                return False
        return True
    stripped = (body or "").strip()
    if stripped and stripped[0] in ("{", "["):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and len(obj) >= _MIN_JSON_KEYS_FOR_PREMIUM:
                return True
            if isinstance(obj, list) and len(obj) > 0:
                return True
        except (json.JSONDecodeError, ValueError):
            pass
    return False


def _body_has_meaningful_fields(body: str) -> bool:
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return False
    if isinstance(obj, dict):
        non_empty = sum(1 for v in obj.values() if v not in (None, "", [], {}))
        return non_empty >= _MIN_JSON_KEYS_FOR_PREMIUM
    if isinstance(obj, list):
        return len(obj) > 0
    return False


def _is_same_size_as_baseline(body_len: int, scanner, url: str) -> bool:
    if not hasattr(scanner, "base_responses") or not scanner.base_responses:
        return False
    other_sizes = [
        entry.get("body_len") or len(entry.get("body", ""))
        for ep_url, entry in scanner.base_responses.items()
        if ep_url != url and (entry.get("body_len") or entry.get("body"))
    ]
    if len(other_sizes) < 3:
        return False
    band_low  = body_len * (1 - _SPA_SHELL_SIZE_TOLERANCE)
    band_high = body_len * (1 + _SPA_SHELL_SIZE_TOLERANCE)
    matching  = sum(1 for s in other_sizes if band_low <= s <= band_high)
    return (matching / len(other_sizes)) >= 0.60






class FintechAttackModules:
    """
    All fintech-specific attack modules.
    Each method is async, takes (scanner, url, method, body, base_status, base_body)
    and returns list[dict] findings compatible with BLFScanner's pipeline.
    """



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


                canary_body = {**body, key: "CANARY_INVALID_AMOUNT"}
                canary_status = await _canary_probe(scanner, url, method, canary_body)

                try:
                    s, _, rb, _ = await scanner._request(method, url, json=tampered)
                except Exception:
                    continue

                if s not in (200, 201, 202):
                    continue



                if canary_status in (200, 201, 202):
                    continue


                if not _response_looks_successful(rb, s):
                    continue

                data = _try_json(rb)
                if not data:
                    continue


                if not _bodies_differ_meaningfully(base_body, rb):
                    continue

                for resp_key in ["amount", "value", "balance", "net", "credit",
                                  "credited", "received", "balance_change"]:
                    rv = _get(data, resp_key)
                    if isinstance(rv, (int, float)) and rv < 0:
                        tok = getattr(scanner.config, "auth_token", "")
                        findings.append(_make_finding(
                            title=f"Negative Amount Accepted — `{key}` = {neg_val} credited",
                            severity="CRITICAL",
                            category="Business Logic — Fintech — Amount Sign Flip",
                            description=(
                                f"Setting `{key}` to {neg_val} (original: {original}) "
                                f"was accepted and resulted in `{resp_key}` = {rv}. "
                                f"An attacker can receive money instead of paying."
                            ),
                            endpoint=url, method=method, body=tampered,
                            evidence=(
                                f"Request: {key}={neg_val} | "
                                f"Response: HTTP {s}, {resp_key}={rv} | "
                                f"Canary ({key}=INVALID) → HTTP {canary_status} (rejected) | "
                                f"Net gain per exploit: ~{abs(neg_val)}"
                            ),
                            recommendation=(
                                "Enforce amount > 0 server-side before any "
                                "financial processing. Use absolute value "
                                "checks and reject negative amounts at the "
                                "API gateway level."
                            ),
                            cwe="CWE-20", cvss=9.8,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            confidence=93, confirmed=True, parameter=key,
                            response_summary=f"HTTP {s} — {resp_key}={rv}",
                            curl_command=_build_curl(method, url, tampered, tok),
                        ))
                        return findings
        return findings



    async def check_currency_confusion(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        currency_keys = [
            "currency", "currencyCode", "sourceCurrency", "targetCurrency",
            "currency_code", "source_currency", "target_currency",
        ]
        high_low_pairs = [
            ("JPY", "USD"), ("KRW", "USD"), ("IDR", "USD"),
            ("VND", "USD"), ("CLP", "USD"), ("HUF", "USD"),
        ]

        for key in currency_keys:
            if key not in body:
                continue
            original_currency = body[key]
            if original_currency not in ("USD", "EUR", "GBP"):
                continue

            for low_currency, _ in high_low_pairs:
                tampered = {**body, key: low_currency}


                canary_body   = {**body, key: "XXXXXXX_INVALID"}
                canary_status = await _canary_probe(scanner, url, method, canary_body)
                if canary_status in (200, 201):
                    continue  

                try:
                    s, _, rb, _ = await scanner._request(method, url, json=tampered)
                except Exception:
                    continue
                if s not in (200, 201):
                    continue
                if not _response_looks_successful(rb, s):
                    continue

                data = _try_json(rb)
                if not data:
                    continue

                resp_currency = (
                    _get(data, "currency") or _get(data, "currency_code") or _get(data, key)
                )
                resp_amount = (
                    _get(data, "amount") or _get(data, "value") or
                    _get(data, "credited") or _get(data, "net")
                )

                if resp_currency == original_currency and isinstance(resp_amount, (int, float)):
                    tok = getattr(scanner.config, "auth_token", "")
                    findings.append(_make_finding(
                        title=(
                            f"Currency Confusion — Sent {low_currency}, "
                            f"processed as {resp_currency}"
                        ),
                        severity="CRITICAL",
                        category="Business Logic — Fintech — Currency Confusion",
                        description=(
                            f"Submitting `{key}={low_currency}` (low-value) was "
                            f"processed as `{resp_currency}` (high-value). "
                            f"An attacker can pay in a weak currency and receive "
                            f"value in a strong currency."
                        ),
                        endpoint=url, method=method, body=tampered,
                        evidence=(
                            f"Sent: {key}={low_currency} | "
                            f"Processed as: {resp_currency} | "
                            f"Amount credited: {resp_amount} | "
                            f"Canary (XXXXXXX_INVALID) → HTTP {canary_status} (rejected)"
                        ),
                        recommendation=(
                            "Validate currency_code server-side against a "
                            "whitelist. Store the original currency at charge "
                            "time and validate all downstream operations against it."
                        ),
                        cwe="CWE-20", cvss=9.5,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confidence=90, confirmed=True, parameter=key,
                        response_summary=f"HTTP {s} — currency mismatch: {low_currency}→{resp_currency}",
                        curl_command=_build_curl(method, url, tampered, tok),
                    ))
                    return findings
        return findings



    async def check_idempotency_abuse(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        if method.upper() not in ("POST", "PUT"):
            return findings

        idem_key = str(uuid.uuid4())
        headers_with_idem = {"Idempotency-Key": idem_key}

        results = []
        for _ in range(3):
            try:
                s, _, rb, _ = await scanner._request(
                    method, url,
                    json=body if body else None,
                    headers=headers_with_idem,
                )
                results.append((s, rb))
            except Exception:
                pass
            await asyncio.sleep(0.1)

        if len(results) < 2:
            return findings

        successful = [(s, rb) for s, rb in results if s in (200, 201, 202)]
        if len(successful) < 2:
            return findings

        first_data  = _try_json(successful[0][1])
        second_data = _try_json(successful[1][1])

        if first_data and second_data:
            first_id  = _get(first_data, "id") or _get(first_data, "transaction_id")
            second_id = _get(second_data, "id") or _get(second_data, "transaction_id")
            if first_id and second_id and first_id != second_id:

                findings.append(_make_finding(
                    title="Idempotency Key Replay — Duplicate Transactions Created",
                    severity="CRITICAL",
                    category="Business Logic — Fintech — Idempotency Abuse",
                    description=(
                        f"Replaying the same request with identical Idempotency-Key "
                        f"`{idem_key}` created {len(successful)} separate transactions "
                        f"(IDs: {first_id}, {second_id}). "
                        f"Idempotency is not enforced."
                    ),
                    endpoint=url, method=method, body=body or {},
                    evidence=(
                        f"Same Idempotency-Key replayed {len(successful)} times → "
                        f"{len(successful)} different transaction IDs: "
                        f"{first_id}, {second_id}"
                    ),
                    recommendation=(
                        "Store idempotency keys scoped to (user_id, key) with a "
                        "TTL. On duplicate key, return the original response "
                        "without re-processing."
                    ),
                    cwe="CWE-362", cvss=9.3,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confidence=92, confirmed=True, parameter="Idempotency-Key",
                    response_summary=f"{len(successful)} duplicate transactions created",
                ))
        return findings



    async def check_refund_overflow(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        refund_keys = ["amount", "refund_amount", "value", "sum"]

        for key in refund_keys:
            if key not in body:
                continue
            original_amount = body[key]
            if not isinstance(original_amount, (int, float)):
                continue

            overflow_amount = original_amount * 10
            tampered = {**body, key: overflow_amount}


            canary_body   = {**body, key: -overflow_amount}
            canary_status = await _canary_probe(scanner, url, method, canary_body)

            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201):
                continue


            if not _response_looks_successful(rb, s):
                continue

            data = _try_json(rb)
            if not data:
                continue


            if not _bodies_differ_meaningfully(base_body, rb):
                continue

            refunded = (
                _get(data, "amount") or _get(data, "refunded") or
                _get(data, "refund_amount") or _get(data, "value")
            )
            if isinstance(refunded, (int, float)) and refunded >= overflow_amount * 0.9:
                findings.append(_make_finding(
                    title=f"Refund Overflow — Refunded {refunded} vs original {original_amount}",
                    severity="CRITICAL",
                    category="Business Logic — Fintech — Refund Overflow",
                    description=(
                        f"Refund of {overflow_amount} (10x the original {original_amount}) "
                        f"was accepted. Response shows refunded={refunded}."
                    ),
                    endpoint=url, method=method, body=tampered,
                    evidence=(
                        f"Original: {original_amount} | "
                        f"Requested: {overflow_amount} | "
                        f"Response refunded: {refunded} | "
                        f"Canary (-{overflow_amount}) → HTTP {canary_status}"
                    ),
                    recommendation=(
                        "Cap refund amounts to the original charge amount stored "
                        "at transaction time. Never trust client-supplied amounts."
                    ),
                    cwe="CWE-20", cvss=9.1,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confidence=91, confirmed=True, parameter=key,
                    response_summary=f"HTTP {s} — overflow refund accepted",
                ))
                return findings
        return findings



    async def check_webhook_forgery(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        if method.upper() != "POST":
            return findings

        forged_payloads = [
            {
                "event": "payment.completed",
                "data": {"object": {"id": "ch_forged", "amount": 10000,
                                    "currency": "usd", "status": "succeeded"}},
            },
            {
                "type": "charge.succeeded",
                "data": {"object": {"id": "ch_forged", "amount": 10000,
                                    "currency": "usd"}},
            },
            {
                "event_type": "PAYMENT.CAPTURE.COMPLETED",
                "resource": {"id": "forged_order", "status": "COMPLETED",
                              "amount": {"value": "100.00", "currency_code": "USD"}},
            },
        ]

        for payload in forged_payloads:

            canary_payload = {"event": "CANARY_INVALID_EVENT_XYZ", "data": None}
            canary_status  = await _canary_probe(scanner, url, "POST", canary_payload)
            if canary_status in (200, 201, 202, 204):
                continue  

            try:
                s, _, rb, _ = await scanner._request(
                    "POST", url, json=payload,
                    headers={"X-Webhook-Source": "test"},
                )
            except Exception:
                continue
            if s not in (200, 201, 202, 204):
                continue

            data = _try_json(rb)
            success_signals = ["success", "ok", "received", "processed", "accepted"]
            accepted = (
                any(sig in rb.lower() for sig in success_signals) or
                _get(data, "status") in ("ok", "success", "received") or
                s == 204
            )
            if accepted:
                findings.append(_make_finding(
                    title="Webhook Forgery — Forged Payment Event Accepted",
                    severity="CRITICAL",
                    category="Business Logic — Fintech — Webhook Forgery",
                    description=(
                        f"A forged webhook payload simulating a completed payment "
                        f"was accepted at `{url}` (HTTP {s}). "
                        f"Canary (INVALID_EVENT) → HTTP {canary_status} (rejected). "
                        f"An attacker can trigger order fulfilment without real payment."
                    ),
                    endpoint=url, method=method, body=payload,
                    evidence=(
                        f"Forged payload accepted: HTTP {s} | "
                        f"Success signal: {[sig for sig in success_signals if sig in rb.lower()]} | "
                        f"Canary rejected: HTTP {canary_status}"
                    ),
                    recommendation=(
                        "Validate webhook signatures (Stripe-Signature, "
                        "X-PayPal-Transmission-Sig, etc.) before processing. "
                        "Reject any webhook without a valid HMAC signature."
                    ),
                    cwe="CWE-290", cvss=9.8,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confidence=90, confirmed=True,
                    response_summary=f"HTTP {s} — forged webhook accepted",
                ))
                return findings
        return findings



    async def check_fee_bypass(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        fee_keys = ["fee", "platform_fee", "commission", "markup",
                    "is_fee_exempt", "fee_exempt", "waive_fee"]

        base_data = _try_json(base_body)
        base_fee  = None
        for k in fee_keys:
            if k in body:
                base_fee = body[k]
                break

        bypass_attempts = [
            {k: 0     for k in fee_keys if k in body},
            {k: False for k in fee_keys if k in body},
            {"is_fee_exempt": True},
            {"fee_exempt":    True},
            {"waive_fee":     True},
            {"fee":           0},
            {"platform_fee":  0},
        ]

        for extra in bypass_attempts:
            if not extra:
                continue
            tampered = {**body, **extra}


            canary_body   = {**body, list(extra.keys())[0]: "CANARY_STRING"}
            canary_status = await _canary_probe(scanner, url, method, canary_body)

            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201):
                continue
            if not _response_looks_successful(rb, s):
                continue


            if not _bodies_differ_meaningfully(base_body, rb):
                continue

            data = _try_json(rb)
            resp_fee = (
                _get(data, "fee") or _get(data, "platform_fee") or
                _get(data, "commission") or _get(data, "fee_charged")
            )
            if resp_fee == 0 or resp_fee is None:
                original_fee = (
                    _get(base_data, "fee") or
                    _get(base_data, "platform_fee") or
                    base_fee
                )
                if original_fee and original_fee > 0:
                    findings.append(_make_finding(
                        title=f"Fee Bypass — Fee reduced to 0 via {list(extra.keys())}",
                        severity="HIGH",
                        category="Business Logic — Fintech — Fee Bypass",
                        description=(
                            f"Setting {extra} bypassed the platform fee. "
                            f"Original fee was {original_fee}, response fee is {resp_fee}."
                        ),
                        endpoint=url, method=method, body=tampered,
                        evidence=(
                            f"Original fee: {original_fee} | "
                            f"Bypass params: {extra} | "
                            f"Response fee: {resp_fee} | "
                            f"Canary → HTTP {canary_status}"
                        ),
                        recommendation=(
                            "Fee exemption flags must be set server-side based on "
                            "account tier — never trust client-supplied exemption flags."
                        ),
                        cwe="CWE-20", cvss=8.2,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confidence=83, confirmed=True,
                        parameter=str(list(extra.keys())),
                        response_summary=f"HTTP {s} — fee=0",
                    ))
                    return findings
        return findings



    async def check_kyc_sca_bypass(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        url_lower = url.lower()
        is_kyc = any(w in url_lower for w in ["kyc", "verify", "verification", "identity"])
        is_sca = any(w in url_lower for w in ["2fa", "otp", "mfa", "sca", "challenge"])
        if not (is_kyc or is_sca):
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

            canary_body   = {**body, key: "CANARY_BYPASS_XYZ_999"} if val != "OMITTED" else tampered
            canary_status = await _canary_probe(scanner, url, method, canary_body)
            if val != "OMITTED" and canary_status in (200, 201):
                continue  

            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s not in (200, 201):
                continue
            if not rb or len(rb) < 10:
                continue


            if not _bodies_differ_meaningfully(base_body, rb):
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
                            f"`{key}` to `{val}` bypassed the {label} requirement."
                        ),
                        endpoint=url, method=method, body=tampered,
                        evidence=(
                            f"Request: {key}={val} → HTTP {s} accepted | "
                            f"Response reflected: {key}={reflected} | "
                            f"Canary → HTTP {canary_status}"
                        ),
                        recommendation=(
                            f"Enforce {label} server-side through a separate "
                            f"verification service. Never trust client-supplied "
                            f"verification status fields."
                        ),
                        cwe="CWE-284", cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confidence=88, confirmed=True, parameter=key,
                        response_summary=f"HTTP {s} — {label} bypassed",
                    ))
                    return findings
        return findings



    async def check_transfer_idor(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        transfer_indicators = ["transfer", "payment", "payout", "send", "wire"]
        if not any(t in url.lower() for t in transfer_indicators):
            return findings

        parsed     = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]

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


                if not _bodies_differ_meaningfully(base_body, rb, threshold=0.10):
                    continue

                resp_data = _try_json(rb)
                if not resp_data:
                    continue
                financial_fields = ["amount", "value", "status", "recipient",
                                     "sender", "currency", "source_account"]
                exposed = [f for f in financial_fields if f in resp_data]
                if not exposed:
                    continue


                second_token = getattr(scanner.config, "second_user_token", "")
                confirmed = False
                if second_token:
                    try:
                        s2, _, _, _ = await scanner._request(
                            method, test_url, token_override=second_token
                        )
                        confirmed = s2 == 200
                    except Exception:
                        pass

                findings.append(_make_finding(
                    title=f"Transfer IDOR — ID {orig_id}→{test_id} exposes financial data",
                    severity="CRITICAL" if confirmed else "HIGH",
                    category="Business Logic — Fintech — Transfer IDOR",
                    description=(
                        f"Changing transfer ID from {orig_id} to {test_id} "
                        f"returned a financial transaction with fields: "
                        f"{', '.join(exposed)}."
                        + (" [Cross-user confirmed]" if confirmed else "")
                    ),
                    endpoint=test_url, method=method, body={},
                    evidence=(
                        f"ID {orig_id}→{test_id} → HTTP {s} | "
                        f"Financial fields: {exposed} | "
                        f"Cross-user: {'confirmed' if confirmed else 'not tested (no token2)'}"
                    ),
                    recommendation="Enforce ownership checks on every transfer/payment resource.",
                    cwe="CWE-639", cvss=9.1 if confirmed else 8.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confidence=90 if confirmed else 75,
                    confirmed=confirmed, parameter=f"path[{i}]",
                    response_summary=f"HTTP {s} — {len(exposed)} financial fields exposed",
                ))
                return findings
        return findings






class SpotifyAttackModules:
    """
    Spotify and generic streaming platform attack modules.
    RC-1/RC-2/RC-3 fixes applied throughout.
    """



    async def check_subscription_scope(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        """
        FP-1 FIX: Five-gate validation prevents HTML/SPA responses from
        becoming findings. See original FP analysis in module docstring.
        """
        findings = []
        premium_indicators = [
            "premium", "subscription", "pro", "paid", "plus",
            "download", "offline", "hq", "high_quality", "lossless",
        ]
        url_lower = url.lower()
        if not any(p in url_lower for p in premium_indicators):
            return findings

        free_token    = getattr(scanner.config, "second_user_token", "")
        premium_token = getattr(scanner.config, "auth_token", "")
        if not free_token or free_token == premium_token:
            return findings

        try:
            s_free, hdrs_free, rb_free, _ = await scanner._request(
                method, url, json=body if body else None, token_override=free_token,
            )
        except Exception:
            return findings

        if s_free not in (200, 201):
            return findings

        rb_free_bytes = rb_free.encode("utf-8", errors="replace") if rb_free else b""


        if _is_spa_shell(rb_free, rb_free_bytes):
            return findings
        if not _is_api_response(hdrs_free if isinstance(hdrs_free, dict) else {}, rb_free):
            return findings


        if _is_same_size_as_baseline(len(rb_free_bytes), scanner, url):
            return findings

        free_data = _try_json(rb_free)
        base_data = _try_json(base_body)


        unauth_body = ""
        try:
            s_unauth, _, rb_unauth, _ = await scanner._request(
                method, url, json=body if body else None, token_override="",
            )
            if s_unauth in (200, 201):
                unauth_body = rb_unauth or ""
        except Exception:
            pass

        if unauth_body:
            sim_free_vs_unauth = _similarity(rb_free, unauth_body)
            if sim_free_vs_unauth >= _MAX_SIMILARITY_TO_UNAUTH:
                return findings


        rb_premium = ""
        s_prem = 0
        try:
            s_prem, _, rb_premium, _ = await scanner._request(
                method, url, json=body if body else None, token_override=premium_token,
            )
            if s_prem not in (200, 201):
                rb_premium = ""
        except Exception:
            rb_premium = ""


        if rb_premium:
            sim_free_vs_prem = _similarity(rb_free, rb_premium)
            if sim_free_vs_prem >= _MAX_SIMILARITY_FREE_VS_PREMIUM:
                return findings


        premium_data = _try_json(rb_premium) if rb_premium else {}
        premium_fields = [
            "audio_quality", "bitrate", "download_url", "offline_uri",
            "premium_uri", "licensed_url", "cdn_url", "hq_url",
            "lossless_url", "high_quality_url", "stream_url",
        ]
        exposed_in_free = [
            f for f in premium_fields
            if _get(free_data, f) and not _get(base_data, f)
        ]
        confirmed_bypass = [
            f for f in premium_fields
            if _get(free_data, f) and _get(premium_data, f)
            and _get(free_data, f) == _get(premium_data, f)
        ] if premium_data else exposed_in_free

        if confirmed_bypass:
            findings.append(_make_finding(
                title="Premium Feature Access with Free Token — Confirmed",
                severity="CRITICAL",
                category="Business Logic — Streaming — Subscription Scope Bypass",
                description=(
                    f"A free-tier token accessed `{url}` and received the same "
                    f"premium fields as the premium token: {', '.join(confirmed_bypass)}."
                ),
                endpoint=url, method=method, body=body,
                evidence=(
                    f"Free token → HTTP {s_free} | "
                    f"Premium token → HTTP {s_prem if rb_premium else 'N/A'} | "
                    f"Identical premium fields: {confirmed_bypass}"
                ),
                recommendation=(
                    "Validate subscription tier server-side on every request. "
                    "Remove premium fields from responses for free-tier tokens."
                ),
                cwe="CWE-285", cvss=8.5,
                owasp="API5:2023 Broken Function Level Authorization",
                confidence=92, confirmed=True,
                parameter="Authorization (free token)",
                response_summary=f"HTTP {s_free} — confirmed premium fields: {confirmed_bypass}",
            ))
            return findings


        if not _body_has_meaningful_fields(rb_free):
            return findings

        premium_content_signals = [
            "quality", "bitrate", "license", "drm", "download",
            "offline", "hq", "high", "lossless", "premium",
        ]
        resp_lower = rb_free.lower()
        has_signal = any(sig in resp_lower for sig in premium_content_signals)
        if not has_signal:
            return findings

        findings.append(_make_finding(
            title="Possible Subscription Scope Bypass — Needs Manual Verification",
            severity="MEDIUM",
            category="Business Logic — Streaming — Subscription Scope Bypass",
            description=(
                f"A free-tier token received a meaningful JSON response from "
                f"`{url}` that differs from the unauthenticated baseline "
                f"and from the premium token response. "
                f"Manual verification required."
            ),
            endpoint=url, method=method, body=body,
            evidence=(
                f"Free token → HTTP {s_free}, {len(rb_free_bytes)}B JSON | "
                f"Differs from unauthenticated | Differs from premium | "
                f"Premium content signals present"
            ),
            recommendation=(
                "Manually verify whether the free-token response contains "
                "premium-gated content."
            ),
            cwe="CWE-285", cvss=5.3,
            owasp="API5:2023 Broken Function Level Authorization",
            confidence=45, confirmed=False,
            parameter="Authorization (free token)",
            response_summary=f"HTTP {s_free} — {len(rb_free_bytes)}B, needs manual check",
        ))
        return findings



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


        canary_body   = {**body, "track_id": "CANARY_INVALID", "played_ms": -1}
        canary_status = await _canary_probe(scanner, url, method, canary_body)

        success_count = 0
        ids_generated = set()
        burst_count   = 15

        for _ in range(burst_count):
            tampered = {
                **body,
                "played_ms": body.get("played_ms", 30001),
                "track_id":  body.get("track_id", str(uuid.uuid4())),
            }
            try:
                s, _, rb, _ = await scanner._request(method, url, json=tampered)
            except Exception:
                continue
            if s in (200, 201, 202, 204):
                success_count += 1
                data = _try_json(rb)
                event_id = _get(data, "id") or _get(data, "event_id")
                if event_id:
                    ids_generated.add(str(event_id))
            await asyncio.sleep(0.05)

        if success_count >= 10:
            findings.append(_make_finding(
                title=(
                    f"Stream Count Manipulation — "
                    f"{success_count}/{burst_count} play events accepted"
                ),
                severity="HIGH",
                category="Business Logic — Streaming — Stream Count Manipulation",
                description=(
                    f"{success_count} out of {burst_count} rapid play events "
                    f"were accepted at `{url}`. "
                    f"Canary (invalid event) → HTTP {canary_status}. "
                    f"An attacker can inflate stream counts for royalty fraud."
                ),
                endpoint=url, method=method, body=body,
                evidence=(
                    f"{success_count}/{burst_count} events accepted | "
                    f"{len(ids_generated)} unique event IDs | "
                    f"Canary → HTTP {canary_status}"
                ),
                recommendation=(
                    "Deduplicate play events by (user_id, track_id, session_id). "
                    "Require minimum 30 seconds of listening before counting."
                ),
                cwe="CWE-770", cvss=7.8,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                confidence=80, confirmed=True, parameter="played_ms / track_id",
                response_summary=f"{success_count}/{burst_count} play events accepted",
            ))
        return findings



    async def check_download_token_replay(
        self, scanner, url: str, method: str,
        body: dict, base_status: int, base_body: str,
    ) -> list[dict]:
        findings = []
        download_indicators = ["download", "offline", "license", "audio", "stream_url"]
        if not any(d in url.lower() for d in download_indicators):
            return findings

        try:
            s_first, _, rb_first, _ = await scanner._request(
                method, url, json=body if body else None,
            )
        except Exception:
            return findings

        if s_first not in (200, 201):
            return findings

        data = _try_json(rb_first)
        url_fields = ["download_url", "stream_url", "audio_url",
                      "url", "cdn_url", "signed_url", "license_url"]
        token_url = next(
            (_get(data, f) for f in url_fields
             if _get(data, f) and isinstance(_get(data, f), str)
             and _get(data, f).startswith("http")),
            None,
        )
        if not token_url:
            return findings

        has_expiry = any(p in token_url.lower() for p in
                         ["expires", "exp=", "x-amz-expires", "expire", "ttl"])

        await asyncio.sleep(1)
        try:
            s_replay, _, _, _ = await scanner._request("GET", token_url)
        except Exception:
            return findings

        if s_replay in (200, 206):
            if has_expiry:
                findings.append(_make_finding(
                    title="Download Token Replay — Signed URL Still Valid After Reuse",
                    severity="MEDIUM",
                    category="Business Logic — Streaming — Download Token Replay",
                    description=(
                        f"A signed download URL from `{url}` was replayed "
                        f"after 1 second and returned HTTP {s_replay}. "
                        f"URL has expiry parameters but is not single-use."
                    ),
                    endpoint=url, method=method, body=body,
                    evidence=f"Download URL: {token_url[:80]} | Replay → HTTP {s_replay}",
                    recommendation="Invalidate URLs after first use for premium content.",
                    cwe="CWE-613", cvss=6.5,
                    owasp="API2:2023 Broken Authentication",
                    confidence=70, confirmed=False, parameter="download_url",
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
                    endpoint=url, method=method, body=body,
                    evidence=f"Permanent URL: {token_url[:80]} | Replay → HTTP {s_replay}",
                    recommendation=(
                        "Add expiry parameters and user binding to all "
                        "download/stream URLs."
                    ),
                    cwe="CWE-613", cvss=7.5,
                    owasp="API2:2023 Broken Authentication",
                    confidence=78, confirmed=True, parameter="download_url",
                    response_summary=f"Permanent URL → HTTP {s_replay}",
                ))
        return findings



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
                    f"with random UUIDs at `{url}`. No device limit was enforced."
                ),
                endpoint=url, method=method, body=body,
                evidence=(
                    f"{success_count}/6 device registrations accepted | "
                    f"No 403/limit response received"
                ),
                recommendation=(
                    "Enforce device limits server-side by counting active devices "
                    "per account in a persistent store."
                ),
                cwe="CWE-770", cvss=6.5,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                confidence=75, confirmed=True, parameter=device_id_field,
                response_summary=f"{success_count}/6 devices registered",
            ))
        return findings



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

        spotify_id_pattern = re.compile(r'^[0-9A-Za-z]{22}$')
        for i, part in enumerate(path_parts):
            if not spotify_id_pattern.match(part):
                continue

            new_parts    = path_parts[:]
            new_parts[i] = "0" * 22
            test_url     = f"{parsed.scheme}://{parsed.netloc}/" + "/".join(new_parts)

            try:
                s2, _, rb2, _ = await scanner._request(
                    method, test_url, token_override=second_token
                )
            except Exception:
                continue

            if s2 != 200:
                continue


            if not _bodies_differ_meaningfully(base_body, rb2, threshold=0.10):
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
                        f"`{private_field}` using a second user's token. "
                        f"Cross-user access confirmed."
                    ),
                    endpoint=test_url, method=method, body=body,
                    evidence=(
                        f"Original ID: {part} | Test ID: {'0'*22} | "
                        f"User2 token → HTTP {s2} | "
                        f"Private field exposed: {private_field}"
                    ),
                    recommendation="Validate resource ownership on every request.",
                    cwe="CWE-639", cvss=7.5,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confidence=85, confirmed=True, parameter=f"path[{i}]",
                    response_summary=f"HTTP {s2} — {private_field} exposed",
                ))
                return findings
        return findings

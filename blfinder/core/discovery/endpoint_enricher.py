"""
core/discovery/endpoint_enricher.py  — BLFinder v3.1 FIXED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enriches discovered endpoints with real body parameters and query params
so that BLFinder's attack modules have concrete fields to manipulate.

FIXES APPLIED:
  BUG-A : cookies + extra_headers now accepted and forwarded to every HTTP
          probe so cookie-authenticated targets (1win.com, cf_clearance,
          1w_token) are probed correctly instead of getting 401/403.
  BUG-B : ssl= driven by verify_ssl param; was hardcoded False in two places.
  BUG-E : "if self.verbose or True" guard removed; summary always prints
          once at the end cleanly.
  BUG-H : proxy now accepted and forwarded to every probe request so
          enrichment traffic flows through Burp when --proxy is set.
  WEAK-5: Body-skip threshold raised from 2 keys to a domain-aware check:
          only skip when body has >= 5 keys AND already contains at least
          one financial/attack-relevant field. Prevents under-enriched
          endpoints from being skipped prematurely.

HOW IT WORKS — four layered strategies
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Layer 1 — Response-driven inference
  Sends the real request, reads the JSON response, and mirrors the response
  field structure back as request parameters. Also parses 400/422 validation
  error messages to extract required field names.

Layer 2 — Path-pattern dictionary
  Maps URL path segments to known parameter sets covering betting/gaming,
  fintech/payments, auth/account, e-commerce, streaming, admin.

Layer 3 — Schema extraction
  Parses OpenAPI-style schemas, JSON Schema, and GraphQL introspection
  fragments embedded in response bodies.

Layer 4 — Method promotion
  Creates POST twins for GET endpoints that are likely also POST-able.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode


# ─────────────────────────────────────────────────────────────────────────────
# Path-pattern parameter dictionary
# ─────────────────────────────────────────────────────────────────────────────


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

_PATH_PARAM_DB: list[tuple[list[str], dict]] = [

    # ── Betting / Gaming ──────────────────────────────────────────────────────
    (["bet", "place-bet", "place_bet", "wager"],
     {"match_id": 1, "market_id": 1, "selection_id": 1,
      "odds": 1.85, "stake": 10.00, "bet_type": "single",
      "currency": "USD"}),

    (["cashout", "cash-out", "cash_out"],
     {"bet_id": 1, "amount": 10.00, "currency": "USD"}),

    (["bonus", "bonus-accrual", "pwa-bonus", "free-money",
      "promo", "promotion", "claim"],
     {"bonus_id": 1, "promo_code": "PROMO1", "user_id": 1,
      "amount": 0.00, "currency": "USD", "bonus_type": "deposit"}),

    (["export", "accrual", "accrual-export"],
     {"user_id": 1, "from_date": "2024-01-01",
      "to_date": "2024-12-31", "format": "json"}),

    (["tournament", "league", "competition"],
     {"tournament_id": 1, "sport_id": 1, "status": "live"}),

    (["match", "event", "fixture", "game", "dota", "prematch", "live"],
     {"match_id": 1, "sport_id": 1, "tournament_id": 1,
      "include_odds": True}),

    (["odds", "markets", "selections"],
     {"match_id": 1, "market_type": "1x2", "currency": "USD"}),

    (["stream", "live-stream", "watch"],
     {"match_id": 1, "quality": "hd", "token": ""}),

    # ── Fintech / Payments ────────────────────────────────────────────────────
    (["deposit", "top-up", "topup", "fund", "add-money"],
     {"amount": 100.00, "currency": "USD", "payment_method": "card",
      "card_number": "4111111111111111", "cvv": "123",
      "expiry": "12/25", "return_url": "https://example.com"}),

    (["withdraw", "withdrawal", "payout"],
     {"amount": 50.00, "currency": "USD",
      "wallet_address": "", "payment_method": "bank_transfer",
      "bank_account": "", "user_id": 1}),

    (["transfer", "send", "wire", "remit"],
     {"from_account": 1, "to_account": 2,
      "amount": 10.00, "currency": "USD",
      "description": "test", "idempotency_key": "idem-001"}),

    (["refund", "reversal", "chargeback", "return"],
     {"transaction_id": 1, "amount": 10.00,
      "currency": "USD", "reason": "customer_request"}),

    (["payment", "pay", "charge", "invoice"],
     {"amount": 99.99, "currency": "USD",
      "description": "test payment",
      "idempotency_key": "pay-001",
      "metadata": {"order_id": 1}}),

    (["webhook", "callback", "notify", "ipn", "hook"],
     {"event": "payment.completed", "transaction_id": 1,
      "amount": 100.00, "currency": "USD",
      "status": "success", "signature": "fake_sig"}),

    (["fee", "commission", "markup"],
     {"amount": 100.00, "currency": "USD",
      "fee": 0.00, "is_fee_exempt": False,
      "waive_fee": False}),

    (["kyc", "verify", "verification", "identity"],
     {"user_id": 1, "document_type": "passport",
      "document_number": "AB123456",
      "skip_verification": False,
      "verified": False}),

    (["balance", "wallet", "account-balance"],
     {"user_id": 1, "currency": "USD", "include_bonus": True}),

    # ── Auth / Account ────────────────────────────────────────────────────────
    (["login", "signin", "sign-in", "auth", "authenticate"],
     {"username": "test@example.com", "password": "password123",
      "remember_me": False, "device_id": "dev-001"}),

    (["register", "signup", "sign-up", "create-account"],
     {"email": "test@example.com", "password": "password123",
      "username": "testuser", "phone": "+1234567890",
      "referral_code": "", "country": "US",
      "date_of_birth": "1990-01-01"}),

    (["logout", "signout", "sign-out", "revoke"],
     {"session_id": "", "all_devices": False}),

    (["password", "reset-password", "change-password", "forgot"],
     {"old_password": "old123", "new_password": "new123",
      "confirm_password": "new123", "reset_token": ""}),

    (["2fa", "otp", "mfa", "totp", "verify-otp"],
     {"code": "123456", "user_id": 1,
      "method": "sms", "skip": False}),

    (["session", "token", "refresh"],
     {"refresh_token": "", "grant_type": "refresh_token",
      "client_id": ""}),

    (["profile", "user", "account", "me", "settings"],
     {"user_id": 1, "email": "test@example.com",
      "username": "testuser", "role": "user",
      "is_admin": False, "is_verified": False,
      "subscription": "free"}),

    (["device", "device-limit", "devices"],
     {"device_id": "dev-001", "device_name": "Chrome/Linux",
      "user_id": 1, "limit": 3}),

    # ── Admin / Management ────────────────────────────────────────────────────
    (["admin", "management", "manage", "ops",
      "operations", "sys", "system", "internal"],
     {"user_id": 1, "action": "get",
      "resource": "users", "page": 1, "limit": 50,
      "include_deleted": False, "admin_token": ""}),

    (["config", "configuration", "settings", "feature-flags"],
     {"key": "max_withdrawal", "value": None,
      "environment": "production", "override": False}),

    (["debug", "test", "health", "ping", "status"],
     {"verbose": False, "include_internals": False}),

    (["app", "download", "install", "pwa"],
     {"platform": "android", "version": "latest",
      "channel": "stable", "user_id": 1}),

    # ── E-commerce / Orders ───────────────────────────────────────────────────
    (["order", "purchase", "checkout", "cart"],
     {"product_id": 1, "quantity": 1, "price": 99.99,
      "currency": "USD", "coupon_code": "",
      "discount": 0.00}),

    (["coupon", "voucher", "promo-code", "discount"],
     {"code": "SAVE10", "amount": 10.00,
      "user_id": 1, "product_id": 1,
      "stackable": False}),

    (["subscription", "plan", "upgrade", "premium"],
     {"plan_id": 1, "user_id": 1,
      "billing_cycle": "monthly",
      "price": 9.99, "currency": "USD",
      "trial": False}),

    # ── IDOR / Resource Access ────────────────────────────────────────────────
    (["report", "statement", "history", "transactions", "activity"],
     {"user_id": 1, "account_id": 1,
      "from_date": "2024-01-01", "to_date": "2024-12-31",
      "page": 1, "limit": 50, "format": "json"}),

    (["notification", "message", "inbox"],
     {"user_id": 1, "read": False,
      "page": 1, "limit": 20}),

    (["upload", "file", "document", "attachment"],
     {"user_id": 1, "file_type": "pdf",
      "purpose": "kyc", "overwrite": False}),
]

# Fields whose presence in a body means the endpoint is already well-enriched
_CRITICAL_ATTACK_FIELDS: frozenset[str] = frozenset({
    "amount", "currency", "stake", "odds", "bet_id", "price",
    "fee", "discount", "transfer_id", "quantity", "qty",
    "coupon", "coupon_code", "promo_code", "role", "is_admin",
    "plan", "user_id", "account_id", "payment_method",
})

# ── Method promotion list ─────────────────────────────────────────────────────
_PROMOTE_TO_POST = [
    "login", "register", "signup", "signin",
    "deposit", "withdraw", "transfer", "refund",
    "bet", "wager", "cashout", "pay", "payment",
    "bonus", "claim", "promo", "coupon",
    "verify", "kyc", "2fa", "otp", "mfa",
    "logout", "revoke", "reset", "change",
    "create", "update", "delete", "submit",
    "order", "checkout", "purchase",
    "upload", "export",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _url_path_segments(url: str) -> list[str]:
    try:
        path = urlparse(url).path
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/endpoint_enricher.py#1", e)
        path = url
    segments = [s.lower() for s in path.split("/") if s]
    expanded: list[str] = []
    for seg in segments:
        expanded.append(seg)
        for part in re.split(r"[-_]", seg):
            if part and part not in expanded:
                expanded.append(part)
    return expanded


def _match_path_patterns(url: str) -> dict:
    segments = set(_url_path_segments(url))
    merged: dict = {}
    for keywords, params in _PATH_PARAM_DB:
        if any(kw in segments for kw in keywords):
            for k, v in params.items():
                if k not in merged:
                    merged[k] = v
    return merged


def _extract_fields_from_json(obj: Any, depth: int = 0) -> dict:
    if depth > 3 or not isinstance(obj, dict):
        return {}
    result: dict = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            result.update(_extract_fields_from_json(v, depth + 1))
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                result.update(_extract_fields_from_json(v[0], depth + 1))
            else:
                result[k] = v[0] if v else None
        elif isinstance(v, (str, int, float, bool)) or v is None:
            result[k] = v
    return result


def _extract_fields_from_error(body: str) -> dict:
    fields: dict = {}

    # FastAPI/Pydantic: {"detail": [{"loc": ["body", "field"], ...}]}
    try:
        obj = json.loads(body)
        detail = obj.get("detail") or obj.get("details")
        if isinstance(detail, list):
            for item in detail:
                if isinstance(item, dict):
                    loc = item.get("loc") or []
                    if len(loc) >= 2 and loc[0] in ("body", "query", "json"):
                        field_name = loc[-1]
                        if isinstance(field_name, str):
                            fields[field_name] = None
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Django REST / Flask: {"field_name": ["error message"]}
    try:
        obj = json.loads(body)
        errors = obj.get("errors") or obj.get("field_errors") or {}
        if isinstance(errors, dict):
            for k in errors:
                if isinstance(k, str) and not k.startswith("_"):
                    fields[k] = None
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Free-text: "field_name is required / invalid"
    field_pattern = re.compile(
        r'\b([a-z][a-z0-9_]{1,40})\b'
        r'\s*(?:is\s+(?:required|invalid|missing|not\s+found|'
        r'must\s+be)|:\s*(?:required|invalid))',
        re.IGNORECASE,
    )
    for m in field_pattern.finditer(body):
        name = m.group(1).lower()
        if name not in ("error", "message", "status", "code",
                        "detail", "description", "type"):
            fields[name] = None

    # "Missing required fields: field1, field2"
    missing_pattern = re.compile(
        r'(?:missing|required)\s+(?:required\s+)?fields?\s*:?\s*'
        r'([a-z0-9_,\s]+)',
        re.IGNORECASE,
    )
    for m in missing_pattern.finditer(body):
        for part in re.split(r'[,\s]+', m.group(1)):
            part = part.strip().lower()
            if part and len(part) > 1:
                fields[part] = None

    return fields


def _infer_value(field_name: str, existing_value: Any = None) -> Any:
    if existing_value is not None:
        return existing_value
    name = field_name.lower()

    if re.search(r'_id$|^id$|^uid$', name):                 return 1
    if re.search(r'match_id|event_id|game_id', name):        return 1
    if re.search(r'user_id|account_id|player_id', name):     return 1
    if re.search(r'^amount$|^sum$|^total$|^price$|^value$', name): return 10.00
    if re.search(r'^stake$|^bet$|^wager$', name):            return 10.00
    if re.search(r'^odds$', name):                           return 1.85
    if re.search(r'^quantity$|^qty$|^count$|^limit$', name): return 1
    if re.search(r'^page$|^offset$', name):                  return 1
    if re.search(r'^fee$|^commission$|^discount$', name):    return 0.00
    if re.search(r'^currency$|^currency_code$|_currency$', name): return "USD"
    if re.search(r'^is_|^has_|^can_|^should_|^enable|^disable|^skip|^bypass', name): return False
    if re.search(r'exempt|waive|override|admin|verified|active', name): return False
    if re.search(r'date|time|at$|_on$', name):               return "2024-01-01"
    if re.search(r'from|start', name):                       return "2024-01-01"
    if re.search(r'to$|end|until', name):                    return "2024-12-31"
    if re.search(r'token|secret|key|password|pass$|pwd', name): return ""
    if re.search(r'code$|otp|pin$', name):                   return "123456"
    if re.search(r'email$|mail$', name):                     return "test@example.com"
    if re.search(r'phone|mobile|tel', name):                 return "+1234567890"
    if re.search(r'username|login$|handle$', name):          return "testuser"
    if re.search(r'url$|link$|redirect|callback', name):     return "https://example.com"
    if re.search(r'type$|kind$|method$', name):              return "default"
    if re.search(r'status$|state$', name):                   return "active"
    if re.search(r'format$|output$', name):                  return "json"
    if re.search(r'platform$|os$|device$', name):            return "android"
    if re.search(r'version$', name):                         return "1"
    if re.search(r'country$|region$|locale$|lang', name):    return "US"
    return ""


def _extract_query_params(url: str) -> dict:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/endpoint_enricher.py#2", e)
        return {}


def _should_promote_to_post(url: str, existing_method: str) -> bool:
    if existing_method.upper() != "GET":
        return False
    segments = _url_path_segments(url)
    return any(seg in _PROMOTE_TO_POST for seg in segments)


def _clean_url(url: str) -> str:
    try:
        p = urlparse(url)
        return p._replace(query="", fragment="").geturl()
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/endpoint_enricher.py#3", e)
        return url


def _extract_schema_fields(body: str) -> dict:
    fields: dict = {}
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return fields

    # JSON Schema properties
    props = obj.get("properties") or {}
    if isinstance(props, dict):
        for k, v in props.items():
            schema_type = v.get("type") if isinstance(v, dict) else None
            fields[k] = _infer_value_from_schema_type(schema_type)

    # OpenAPI requestBody
    req_body = (
        obj.get("requestBody", {}).get("content", {})
           .get("application/json", {}).get("schema", {})
    )
    for k, v in (req_body.get("properties") or {}).items():
        schema_type = v.get("type") if isinstance(v, dict) else None
        fields[k] = _infer_value_from_schema_type(schema_type)

    # GraphQL introspection
    gql_fields = (
        obj.get("data", {}).get("__type", {}).get("fields") or []
    )
    for f in gql_fields:
        if isinstance(f, dict) and "name" in f:
            fields[f["name"]] = None

    return fields


def _infer_value_from_schema_type(schema_type: str | None) -> Any:
    if schema_type == "integer":  return 1
    if schema_type == "number":   return 1.0
    if schema_type == "boolean":  return False
    if schema_type == "array":    return []
    if schema_type == "object":   return {}
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# EndpointEnricher
# ─────────────────────────────────────────────────────────────────────────────

class EndpointEnricher:
    """
    Enriches bare endpoint dicts with real body parameters so BLFinder's
    attack modules have concrete fields to manipulate.

    FIXED: now accepts cookies, extra_headers, proxy, verify_ssl so
    cookie-authenticated targets and proxy-intercepted sessions work correctly.
    """

    def __init__(
        self,
        target_url:    str,
        auth_token:    str   = "",
        second_token:  str   = "",
        api_key_sid:    str  = "",
        api_key_secret: str  = "",
        cookies:       dict  = None,    # BUG-A FIX: cookie auth support
        extra_headers: dict  = None,    # BUG-A FIX: custom headers
        proxy:         str   = "",      # BUG-H FIX: proxy support
        verify_ssl:    bool  = True,    # BUG-B FIX: was hardcoded False
        verbose:       bool  = False,
        timeout_s:     int   = 10,
        concurrency:   int   = 8,
        promote_get:   bool  = True,
        rate_limit_s:  float = 0.1,
    ):
        self.target_url     = target_url.rstrip("/")
        self.auth_token     = auth_token
        self.second_token   = second_token
        self.api_key_sid    = api_key_sid
        self.api_key_secret = api_key_secret
        self.cookies       = dict(cookies) if cookies else {}
        self.extra_headers = dict(extra_headers) if extra_headers else {}
        self.proxy         = proxy or ""
        self.verify_ssl    = verify_ssl
        self.verbose       = verbose
        self.timeout_s     = timeout_s
        self.concurrency   = concurrency
        self.promote_get   = promote_get
        self.rate_limit_s  = rate_limit_s

        self._stats = {
            "total":            0,
            "enriched":         0,
            "from_response":    0,
            "from_error":       0,
            "from_schema":      0,
            "from_patterns":    0,
            "promoted":         0,
            "already_had_body": 0,
        }

    # ── Public API ─────────────────────────────────────────────────────────

    async def enrich(self, endpoints: list[dict], session) -> list[dict]:
        """
        Main entry point. Returns enriched endpoint list.
        Never mutates the input list.
        """
        self._stats["total"] = len(endpoints)

        sem   = asyncio.Semaphore(self.concurrency)
        tasks = [self._enrich_one(ep, session, sem) for ep in endpoints]
        enriched_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[dict] = []
        for original, result in zip(endpoints, enriched_list):
            if isinstance(result, Exception):
                if self.verbose:
                    print(f"  [enricher] error for {original.get('url', '')[:60]}: {result}")
                results.append(dict(original))
            else:
                results.append(result)

        if self.promote_get:
            promoted = self._promote_get_endpoints(results)
            results.extend(promoted)
            self._stats["promoted"] = len(promoted)

        # BUG-E FIX: removed misleading "or True" — summary always prints once
        self._print_summary()
        return results

    # ── Per-endpoint enrichment ────────────────────────────────────────────

    async def _enrich_one(self, ep: dict, session, sem: asyncio.Semaphore) -> dict:
        async with sem:
            await asyncio.sleep(self.rate_limit_s)

            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            body   = dict(ep.get("body") or {})
            params = dict(ep.get("params") or {})

            # WEAK-5 FIX: domain-aware skip threshold.
            # Only skip when body is substantial AND contains a known
            # financial/attack-relevant field — avoids skipping endpoints
            # that have 2+ keys but are missing critical attack fields.
            _body_is_fully_enriched = (
                body and
                len(body) >= 5 and
                any(k in _CRITICAL_ATTACK_FIELDS for k in body)
            )
            if _body_is_fully_enriched:
                self._stats["already_had_body"] += 1
                return dict(ep)

            url_params = _extract_query_params(url)
            params.update(url_params)

            response_fields, error_fields, schema_fields = (
                await self._probe_endpoint(url, method, body, params, session)
            )

            pattern_fields = _match_path_patterns(url)

            # Merge: response > error > schema > patterns
            merged_body: dict = {}
            merged_body.update(pattern_fields)
            merged_body.update(schema_fields)
            merged_body.update(error_fields)
            merged_body.update(response_fields)

            final_body: dict = {k: _infer_value(k, v) for k, v in merged_body.items()}

            if method == "GET" and final_body and not params:
                params.update(final_body)
                final_body = {}

            enriched = bool(final_body or params)
            if enriched:
                self._stats["enriched"] += 1
                if response_fields: self._stats["from_response"] += 1
                if error_fields:    self._stats["from_error"]    += 1
                if schema_fields:   self._stats["from_schema"]   += 1
                if pattern_fields:  self._stats["from_patterns"] += 1

            if self.verbose and enriched:
                all_keys = list(final_body.keys() or params.keys())
                print(
                    f"  [enricher] {method} {url[-60:]!r:60s} "
                    f"→ {len(all_keys)} fields: "
                    f"{', '.join(all_keys[:6])}"
                    f"{'...' if len(all_keys) > 6 else ''}"
                )

            result = dict(ep)
            result["body"]   = final_body
            result["params"] = params
            return result

    # ── HTTP probe ─────────────────────────────────────────────────────────

    async def _probe_endpoint(
        self, url: str, method: str, body: dict, params: dict, session,
    ) -> tuple[dict, dict, dict]:
        """
        Send a real request and extract field information from the response.
        BUG-A FIX: cookies and extra_headers attached.
        BUG-B FIX: ssl= uses self.verify_ssl (not hardcoded False).
        BUG-H FIX: proxy forwarded when set.
        """
        response_fields: dict = {}
        error_fields:    dict = {}
        schema_fields:   dict = {}

        # Build headers — extra_headers applied first, then auth on top
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.extra_headers:                          # BUG-A FIX
            headers.update(self.extra_headers)
        if self.auth_token:
            token = self.auth_token
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token
        elif self.api_key_sid and self.api_key_secret:
            import base64
            raw = f"{self.api_key_sid}:{self.api_key_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")

        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.timeout_s)
            req_kwargs: dict = {
                "headers": headers,
                "ssl":     self.verify_ssl,             # BUG-B FIX
                "timeout": timeout,
            }
            if self.cookies:                            # BUG-A FIX
                req_kwargs["cookies"] = self.cookies
            if self.proxy:                              # BUG-H FIX
                req_kwargs["proxy"] = self.proxy
            if params:
                req_kwargs["params"] = params
            if method in ("POST", "PUT", "PATCH") and body:
                req_kwargs["json"] = body

            async with session.request(method, url, **req_kwargs) as resp:
                status = resp.status
                try:
                    resp_text = await resp.text(errors="replace")
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/endpoint_enricher.py#4", e)
                    resp_text = ""

                if status in (200, 201):
                    try:
                        obj = json.loads(resp_text)
                        response_fields = _extract_fields_from_json(obj)
                    except (json.JSONDecodeError, TypeError):
                        pass
                    schema_fields = _extract_schema_fields(resp_text)

                elif status in (400, 422, 405, 415):
                    error_fields  = _extract_fields_from_error(resp_text)
                    schema_fields = _extract_schema_fields(resp_text)

                elif status in (401, 403):
                    schema_fields = _extract_schema_fields(resp_text)

        except Exception as e:
            if self.verbose:
                print(f"  [enricher] probe failed {url[-50:]}: {type(e).__name__}: {e}")

        return response_fields, error_fields, schema_fields

    # ── Method promotion ───────────────────────────────────────────────────

    def _promote_get_endpoints(self, endpoints: list[dict]) -> list[dict]:
        existing_post_urls: set[str] = {
            _clean_url(ep["url"])
            for ep in endpoints
            if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
        }

        promoted: list[dict] = []
        for ep in endpoints:
            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            params = ep.get("params") or {}

            if method != "GET":
                continue
            if not _should_promote_to_post(url, method):
                continue

            clean = _clean_url(url)
            if clean in existing_post_urls:
                continue

            pattern_body = _match_path_patterns(url)
            if params:
                pattern_body.update(params)
            if not pattern_body:
                continue

            final_body = {k: _infer_value(k, v) for k, v in pattern_body.items()}

            promoted.append({
                "url":    clean,
                "method": "POST",
                "body":   final_body,
                "params": {},
                "_meta":  {"source": "promoted_from_get", "original_url": url},
            })
            existing_post_urls.add(clean)

        return promoted

    # ── Summary ────────────────────────────────────────────────────────────

    def _print_summary(self) -> None:
        s = self._stats
        print(
            f"\n[enricher] Enrichment complete: "
            f"{s['enriched']}/{s['total']} endpoints enriched, "
            f"{s['promoted']} POST twins promoted"
        )
        print(
            f"           Sources: "
            f"response_mirror={s['from_response']} "
            f"error_parse={s['from_error']} "
            f"schema={s['from_schema']} "
            f"path_patterns={s['from_patterns']} "
            f"already_had_body={s['already_had_body']}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# BLFinder integration hook
# ─────────────────────────────────────────────────────────────────────────────

async def enrich_endpoints(
    endpoints:     list[dict],
    target_url:    str,
    auth_token:    str   = "",
    second_token:  str   = "",
    api_key_sid:    str  = "",
    api_key_secret: str  = "",
    cookies:       dict  = None,    # BUG-A FIX
    extra_headers: dict  = None,    # BUG-A FIX
    proxy:         str   = "",      # BUG-H FIX
    verify_ssl:    bool  = True,    # BUG-B FIX
    timeout_s:     int   = 10,
    concurrency:   int   = 8,
    verbose:       bool  = False,
    promote_get:   bool  = True,
) -> list[dict]:
    """
    Convenience wrapper called from blfinder.py.
    All auth material (cookies, headers, proxy, ssl) forwarded correctly.
    """
    try:
        import aiohttp
    except ImportError:
        print("[!] endpoint_enricher: aiohttp not installed — enrichment skipped")
        return endpoints

    enricher = EndpointEnricher(
        target_url     = target_url,
        auth_token     = auth_token,
        second_token   = second_token,
        api_key_sid    = api_key_sid,
        api_key_secret = api_key_secret,
        cookies       = cookies or {},
        extra_headers = extra_headers or {},
        proxy         = proxy or "",
        verify_ssl    = verify_ssl,
        verbose       = verbose,
        timeout_s     = timeout_s,
        concurrency   = concurrency,
        promote_get   = promote_get,
    )

    # BUG-B FIX: ssl= driven by verify_ssl, not hardcoded False
    connector = aiohttp.TCPConnector(ssl=verify_ssl, limit=concurrency)
    timeout   = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        return await enricher.enrich(endpoints, session)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

async def _cli_main() -> None:
    import argparse

    p = argparse.ArgumentParser(
        description="BLFinder Endpoint Enricher",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
EXAMPLES:
  python endpoint_enricher.py \\
    --input endpoints.json --output enriched.json \\
    --target https://1win.com \\
    --token eyJhbGciOiJIUzI1NiJ9... \\
    --cookie 1w_token=7afc35d8-... \\
    --cookie cf_clearance=1wE8LW... \\
    --verbose

  # Dry run — pattern-only, no HTTP
  python endpoint_enricher.py \\
    --input endpoints.json --output enriched.json \\
    --target https://1win.com --dry-run
""",
    )
    p.add_argument("--input",       "-i",  required=True,  help="Input endpoints JSON file")
    p.add_argument("--output",      "-o",  required=True,  help="Output enriched JSON file")
    p.add_argument("--target",      "-t",  required=True,  help="Target base URL")
    p.add_argument("--token",       "-T",  default="",     help="Auth token")
    p.add_argument("--token2",      "-T2", default="",     help="Second user auth token")
    p.add_argument("--cookie",      "-c",  action="append", default=[], metavar="name=value",
                   help="Cookie to attach to every probe (repeatable)")
    p.add_argument("--header",      "-H",  action="append", default=[], metavar="Key:Value",
                   help="Extra request header (repeatable)")
    p.add_argument("--proxy",              default="",     help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--no-ssl-verify",      action="store_true", help="Disable TLS verification")
    p.add_argument("--verbose",     "-v",  action="store_true")
    p.add_argument("--dry-run",            action="store_true",
                   help="Pattern inference only, no HTTP requests")
    p.add_argument("--no-promote",         action="store_true",
                   help="Skip GET→POST promotion")
    p.add_argument("--concurrency",        type=int, default=8)
    p.add_argument("--timeout",            type=int, default=10)
    p.add_argument("--stats",              action="store_true")

    args = p.parse_args()

    # Parse cookies and headers from CLI
    cookies: dict = {}
    for c in args.cookie:
        if "=" in c:
            k, _, v = c.partition("=")
            cookies[k.strip()] = v.strip()

    extra_headers: dict = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    try:
        with open(args.input) as f:
            endpoints: list[dict] = json.load(f)
        if not isinstance(endpoints, list):
            print(f"[!] Expected a JSON array in {args.input}")
            return
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Could not load {args.input}: {e}")
        return

    print(f"[*] Loaded {len(endpoints)} endpoints from {args.input}")

    if args.dry_run:
        print("[*] Dry run — using path-pattern inference only (no HTTP requests)")
        enriched: list[dict] = []
        enriched_count = 0
        for ep in endpoints:
            ep_copy = dict(ep)
            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            body   = ep.get("body") or {}

            # WEAK-5 FIX: use domain-aware threshold
            if body and len(body) >= 5 and any(k in _CRITICAL_ATTACK_FIELDS for k in body):
                enriched.append(ep_copy)
                continue

            pattern_body = _match_path_patterns(url)
            if pattern_body:
                final = {k: _infer_value(k, v) for k, v in pattern_body.items()}
                if method == "GET":
                    ep_copy["params"] = final
                    ep_copy["body"]   = {}
                else:
                    ep_copy["body"]   = final
                    ep_copy["params"] = {}
                enriched_count += 1
                if args.verbose:
                    print(f"  {method} {url[-70:]:70s} → {list(final.keys())[:6]}")
            enriched.append(ep_copy)

        print(f"[+] Dry run: {enriched_count}/{len(endpoints)} enriched via patterns")
    else:
        print(f"[*] Enriching with HTTP probing (concurrency={args.concurrency})...")
        t0 = time.time()
        enriched = await enrich_endpoints(
            endpoints     = endpoints,
            target_url    = args.target,
            auth_token    = args.token,
            second_token  = args.token2,
            cookies       = cookies,
            extra_headers = extra_headers,
            proxy         = args.proxy,
            verify_ssl    = not args.no_ssl_verify,
            timeout_s     = args.timeout,
            concurrency   = args.concurrency,
            verbose       = args.verbose,
            promote_get   = not args.no_promote,
        )
        print(f"[*] Enrichment took {time.time() - t0:.1f}s")

    try:
        with open(args.output, "w") as f:
            json.dump(enriched, f, indent=2)
        print(f"\n[+] Enriched endpoints saved → {args.output}")
        print(f"[+] Total: {len(enriched)} (original: {len(endpoints)}, added: {len(enriched)-len(endpoints)})")
    except OSError as e:
        print(f"[!] Could not save {args.output}: {e}")
        return

    if args.stats or args.verbose:
        bodies  = sum(1 for ep in enriched if ep.get("body"))
        params  = sum(1 for ep in enriched if ep.get("params"))
        neither = sum(1 for ep in enriched if not ep.get("body") and not ep.get("params"))
        posts   = sum(1 for ep in enriched if ep.get("method","GET").upper() == "POST")
        gets    = sum(1 for ep in enriched if ep.get("method","GET").upper() == "GET")
        print(f"\n  Breakdown:")
        print(f"    POST endpoints : {posts}")
        print(f"    GET endpoints  : {gets}")
        print(f"    With body      : {bodies}")
        print(f"    With params    : {params}")
        print(f"    Still bare     : {neither}")


if __name__ == "__main__":
    asyncio.run(_cli_main())

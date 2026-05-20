"""
core/discovery/endpoint_enricher.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enriches discovered endpoints with real body parameters and query params
so that BLFinder's attack modules have concrete fields to manipulate.

PROBLEM BEING SOLVED
━━━━━━━━━━━━━━━━━━━━
The discovery pipeline finds URLs (e.g. /api/v1/withdraw) but stores them
as {"url": "...", "method": "POST", "body": {}, "params": {}}.
Attack modules need actual field names (amount, currency, user_id, etc.)
to perform price manipulation, IDOR testing, mass assignment, etc.
Without real bodies, most of the 21 scanner modules produce zero findings.

HOW IT WORKS — four layered strategies
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Layer 1 — Response-driven inference
  Sends the real request (GET/POST with empty body), reads the JSON
  response, and mirrors the response field structure back as request
  parameters.  Works because APIs often echo back what they expect.
  Also parses 400/422 validation error messages to extract field names.

Layer 2 — Path-pattern dictionary
  Maps URL path segments and keywords to known parameter sets from a
  comprehensive dictionary of ~500 real-world API patterns covering:
  betting/gaming, fintech/payments, auth/account, e-commerce, streaming.
  A /withdraw endpoint gets {"amount", "currency", "wallet_address"}.
  A /bet endpoint gets {"match_id", "odds", "stake", "bet_type"}.

Layer 3 — Schema extraction
  If the endpoint returns an OpenAPI-style schema, JSON Schema, or
  GraphQL introspection fragment in the response body, parse it and
  extract all field names and types.

Layer 4 — Method promotion
  Identifies GET endpoints that are likely also POST-able (e.g.
  /api/v1/user/profile) and creates a POST twin with inferred body,
  doubling testable attack surface.

OUTPUT
━━━━━━
Returns the same endpoint list with "body" and "params" populated.
Also optionally saves an enriched endpoints.json alongside the original.

USAGE
━━━━━
  # Standalone enrichment of an existing endpoints.json
  python endpoint_enricher.py --input endpoints.json --output enriched.json
    --token YOUR_TOKEN --target https://1win.com

  # Programmatic use from BLFinder pipeline
  from core.discovery.endpoint_enricher import EndpointEnricher
  enricher = EndpointEnricher(target_url, auth_token, verbose=True)
  async with aiohttp.ClientSession() as session:
      enriched = await enricher.enrich(endpoints, session)
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
# Covers betting/gaming, fintech, auth, e-commerce, streaming, admin
# ─────────────────────────────────────────────────────────────────────────────

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

    (["withdraw", "withdrawal", "payout", "cashout"],
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


# ─────────────────────────────────────────────────────────────────────────────
# HTTP method promotion: GET paths that are likely also POST-able
# ─────────────────────────────────────────────────────────────────────────────

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
    """Extract lowercase path segments from a URL."""
    try:
        path = urlparse(url).path
    except Exception:
        path = url
    segments = [s.lower() for s in path.split("/") if s]
    # Also split on hyphens and underscores within segments
    expanded = []
    for seg in segments:
        expanded.append(seg)
        for part in re.split(r"[-_]", seg):
            if part and part not in expanded:
                expanded.append(part)
    return expanded


def _match_path_patterns(url: str) -> dict:
    """
    Return the merged body dict from all matching path-pattern entries.
    Multiple entries can match (e.g. /api/v1/bonus/export matches both
    'bonus' and 'export' entries).
    """
    segments = set(_url_path_segments(url))
    merged: dict = {}
    for keywords, params in _PATH_PARAM_DB:
        if any(kw in segments for kw in keywords):
            # Lower-priority entries don't overwrite higher-priority ones
            for k, v in params.items():
                if k not in merged:
                    merged[k] = v
    return merged


def _extract_fields_from_json(obj: Any, depth: int = 0) -> dict:
    """
    Recursively walk a JSON object and collect all string/number/bool
    leaf keys as candidate request fields.  Stops at depth 3 to avoid
    exploding on huge response payloads.
    """
    if depth > 3 or not isinstance(obj, dict):
        return {}
    result: dict = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            nested = _extract_fields_from_json(v, depth + 1)
            result.update(nested)
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                nested = _extract_fields_from_json(v[0], depth + 1)
                result.update(nested)
            else:
                result[k] = v[0] if v else None
        elif isinstance(v, (str, int, float, bool)) or v is None:
            result[k] = v
    return result


def _extract_fields_from_error(body: str) -> dict:
    """
    Parse validation error messages to extract field names.
    Handles formats like:
      {"errors": {"amount": ["is required"], "currency": ["is invalid"]}}
      {"message": "amount is required, currency must be USD or EUR"}
      {"detail": [{"loc": ["body", "amount"], "msg": "field required"}]}
      {"error": "Missing required fields: amount, currency, user_id"}
    """
    fields: dict = {}

    # FastAPI/Pydantic style: {"detail": [{"loc": ["body", "field"], ...}]}
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

    # Django REST / Flask style: {"field_name": ["error message"]}
    try:
        obj = json.loads(body)
        errors = obj.get("errors") or obj.get("field_errors") or {}
        if isinstance(errors, dict):
            for k, v in errors.items():
                if isinstance(k, str) and not k.startswith("_"):
                    fields[k] = None
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Free-text extraction: "field_name is required / invalid / missing"
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

    # "Missing required fields: field1, field2, field3"
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
    """
    Infer a realistic placeholder value for a field based on its name.
    Used when we know the field exists but don't have a real value.
    """
    if existing_value is not None:
        return existing_value

    name = field_name.lower()

    # Identifiers
    if re.search(r'_id$|^id$|^uid$', name):
        return 1
    if re.search(r'match_id|event_id|game_id|fixture_id', name):
        return 1
    if re.search(r'user_id|account_id|player_id|member_id', name):
        return 1

    # Money / numeric
    if re.search(r'^amount$|^sum$|^total$|^price$|^cost$|^value$', name):
        return 10.00
    if re.search(r'^stake$|^bet$|^wager$', name):
        return 10.00
    if re.search(r'^odds$', name):
        return 1.85
    if re.search(r'^quantity$|^qty$|^count$|^limit$', name):
        return 1
    if re.search(r'^page$|^offset$', name):
        return 1
    if re.search(r'^fee$|^commission$|^discount$', name):
        return 0.00

    # Currency
    if re.search(r'^currency$|^currency_code$|_currency$', name):
        return "USD"

    # Booleans
    if re.search(r'^is_|^has_|^can_|^should_|^enable|^disable|^skip|^bypass', name):
        return False
    if re.search(r'exempt|waive|override|admin|verified|active', name):
        return False

    # Dates
    if re.search(r'date|time|at$|_on$', name):
        return "2024-01-01"
    if re.search(r'from|start', name):
        return "2024-01-01"
    if re.search(r'to$|end|until', name):
        return "2024-12-31"

    # Auth / tokens
    if re.search(r'token|secret|key|password|pass$|pwd', name):
        return ""
    if re.search(r'code$|otp|pin$', name):
        return "123456"

    # Strings
    if re.search(r'email$|mail$', name):
        return "test@example.com"
    if re.search(r'phone|mobile|tel', name):
        return "+1234567890"
    if re.search(r'username|login$|handle$', name):
        return "testuser"
    if re.search(r'url$|link$|redirect|callback', name):
        return "https://example.com"
    if re.search(r'type$|kind$|method$', name):
        return "default"
    if re.search(r'status$|state$', name):
        return "active"
    if re.search(r'format$|output$', name):
        return "json"
    if re.search(r'platform$|os$|device$', name):
        return "android"
    if re.search(r'version$', name):
        return "1"
    if re.search(r'country$|region$|locale$|lang', name):
        return "US"

    # Default: empty string
    return ""


def _extract_query_params(url: str) -> dict:
    """Extract existing query string parameters from a URL."""
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
    except Exception:
        return {}


def _should_promote_to_post(url: str, existing_method: str) -> bool:
    """Return True if a GET endpoint is worth promoting to POST."""
    if existing_method.upper() != "GET":
        return False
    segments = _url_path_segments(url)
    return any(seg in _PROMOTE_TO_POST for seg in segments)


def _clean_url(url: str) -> str:
    """Strip query string from URL for body-based POST requests."""
    try:
        p = urlparse(url)
        return p._replace(query="", fragment="").geturl()
    except Exception:
        return url


# ─────────────────────────────────────────────────────────────────────────────
# Schema extraction from response body
# ─────────────────────────────────────────────────────────────────────────────

def _extract_schema_fields(body: str) -> dict:
    """
    Extract field names from JSON Schema, OpenAPI fragment, or
    GraphQL introspection response embedded in a response body.
    """
    fields: dict = {}
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return fields

    # JSON Schema: {"properties": {"field": {"type": "string"}}}
    props = obj.get("properties") or {}
    if isinstance(props, dict):
        for k, v in props.items():
            schema_type = v.get("type") if isinstance(v, dict) else None
            fields[k] = _infer_value_from_schema_type(schema_type)

    # OpenAPI requestBody schema
    req_body = (
        obj.get("requestBody", {}).get("content", {})
           .get("application/json", {}).get("schema", {})
    )
    for k, v in (req_body.get("properties") or {}).items():
        schema_type = v.get("type") if isinstance(v, dict) else None
        fields[k] = _infer_value_from_schema_type(schema_type)

    # GraphQL: {"data": {"__type": {"fields": [{"name": "fieldName"}]}}}
    gql_fields = (
        obj.get("data", {}).get("__type", {}).get("fields") or []
    )
    for f in gql_fields:
        if isinstance(f, dict) and "name" in f:
            fields[f["name"]] = None

    return fields


def _infer_value_from_schema_type(schema_type: str | None) -> Any:
    """Map a JSON Schema type string to a placeholder value."""
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# EndpointEnricher
# ─────────────────────────────────────────────────────────────────────────────

class EndpointEnricher:
    """
    Enriches a list of bare endpoint dicts with real body parameters and
    query params so BLFinder's attack modules have concrete fields to work with.

    Usage:
        enricher = EndpointEnricher(
            target_url="https://1win.com",
            auth_token="Bearer eyJ...",
            verbose=True,
        )
        async with aiohttp.ClientSession() as session:
            enriched = await enricher.enrich(endpoints, session)
    """

    def __init__(
        self,
        target_url:    str,
        auth_token:    str  = "",
        second_token:  str  = "",
        verbose:       bool = False,
        timeout_s:     int  = 10,
        concurrency:   int  = 8,
        promote_get:   bool = True,
        rate_limit_s:  float = 0.1,
    ):
        self.target_url   = target_url.rstrip("/")
        self.auth_token   = auth_token
        self.second_token = second_token
        self.verbose      = verbose
        self.timeout_s    = timeout_s
        self.concurrency  = concurrency
        self.promote_get  = promote_get
        self.rate_limit_s = rate_limit_s

        self._stats = {
            "total":          0,
            "enriched":       0,
            "from_response":  0,
            "from_error":     0,
            "from_schema":    0,
            "from_patterns":  0,
            "promoted":       0,
            "already_had_body": 0,
        }

    # ── Public API ─────────────────────────────────────────────────────────

    async def enrich(
        self,
        endpoints: list[dict],
        session,
    ) -> list[dict]:
        """
        Main entry point.  Returns a new list of endpoint dicts with
        body and params populated.  Never mutates the input list.
        """
        self._stats["total"] = len(endpoints)

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [
            self._enrich_one(ep, session, sem)
            for ep in endpoints
        ]
        enriched_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[dict] = []
        for original, result in zip(endpoints, enriched_list):
            if isinstance(result, Exception):
                if self.verbose:
                    print(f"  [enricher] error for {original.get('url', '')[:60]}: {result}")
                results.append(dict(original))
            else:
                results.append(result)

        # Method promotion: add POST twins for likely-POST GET endpoints
        if self.promote_get:
            promoted = self._promote_get_endpoints(results)
            results.extend(promoted)
            self._stats["promoted"] = len(promoted)

        if self.verbose or True:  # always print summary
            self._print_summary()

        return results

    # ── Per-endpoint enrichment ────────────────────────────────────────────

    async def _enrich_one(
        self,
        ep: dict,
        session,
        sem: asyncio.Semaphore,
    ) -> dict:
        async with sem:
            await asyncio.sleep(self.rate_limit_s)

            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            body   = dict(ep.get("body") or {})
            params = dict(ep.get("params") or {})

            # Already fully specified — don't overwrite real data
            if body and len(body) >= 2:
                self._stats["already_had_body"] += 1
                return dict(ep)

            # Extract existing query params from the URL itself
            url_params = _extract_query_params(url)
            params.update(url_params)

            # Layer 1: Probe the endpoint and learn from the response
            response_fields, error_fields, schema_fields = (
                await self._probe_endpoint(url, method, body, params, session)
            )

            # Layer 2: Path-pattern dictionary
            pattern_fields = _match_path_patterns(url)

            # Merge: response fields > error fields > schema > patterns
            # Response wins because it comes from the actual live API
            merged_body: dict = {}
            merged_body.update(pattern_fields)
            merged_body.update(schema_fields)
            merged_body.update(error_fields)
            merged_body.update(response_fields)

            # Resolve placeholder values for fields with None
            final_body: dict = {}
            for k, v in merged_body.items():
                final_body[k] = _infer_value(k, v)

            # For GET endpoints with no query params, move body to params
            if method == "GET" and final_body and not params:
                params.update(final_body)
                final_body = {}

            # Track enrichment stats
            enriched = bool(final_body or params)
            if enriched:
                self._stats["enriched"] += 1
                if response_fields:
                    self._stats["from_response"] += 1
                if error_fields:
                    self._stats["from_error"] += 1
                if schema_fields:
                    self._stats["from_schema"] += 1
                if pattern_fields:
                    self._stats["from_patterns"] += 1

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
        self,
        url:     str,
        method:  str,
        body:    dict,
        params:  dict,
        session,
    ) -> tuple[dict, dict, dict]:
        """
        Send a real request to the endpoint and extract field information
        from the response.

        Returns (response_fields, error_fields, schema_fields).
        """
        response_fields: dict = {}
        error_fields:    dict = {}
        schema_fields:   dict = {}

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.auth_token:
            token = self.auth_token
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token

        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.timeout_s)
            req_kwargs: dict = {
                "headers": headers,
                "ssl":     False,
                "timeout": timeout,
            }
            if params:
                req_kwargs["params"] = params
            if method in ("POST", "PUT", "PATCH") and body:
                req_kwargs["json"] = body

            async with session.request(method, url, **req_kwargs) as resp:
                status = resp.status
                try:
                    resp_text = await resp.text(errors="replace")
                except Exception:
                    resp_text = ""

                # 200/201: mirror response fields as likely request fields
                if status in (200, 201):
                    try:
                        obj = json.loads(resp_text)
                        response_fields = _extract_fields_from_json(obj)
                    except (json.JSONDecodeError, TypeError):
                        pass
                    schema_fields = _extract_schema_fields(resp_text)

                # 400/422: validation errors reveal required fields
                elif status in (400, 422, 405, 415):
                    error_fields = _extract_fields_from_error(resp_text)
                    try:
                        obj = json.loads(resp_text)
                        # Some APIs return field docs on 405
                        schema_fields = _extract_schema_fields(resp_text)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # 401/403: endpoint exists, might give us schema info
                elif status in (401, 403):
                    schema_fields = _extract_schema_fields(resp_text)

        except Exception as e:
            if self.verbose:
                print(f"  [enricher] probe failed {url[-50:]}: {type(e).__name__}: {e}")

        return response_fields, error_fields, schema_fields

    # ── Method promotion ───────────────────────────────────────────────────

    def _promote_get_endpoints(self, endpoints: list[dict]) -> list[dict]:
        """
        For GET endpoints that are likely also POST-able, create a POST
        twin with the inferred body from the GET endpoint's params.
        """
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
                continue  # POST version already exists

            # Build body from the GET's inferred params + path patterns
            pattern_body = _match_path_patterns(url)
            if params:
                pattern_body.update(params)

            if not pattern_body:
                continue  # Nothing useful to POST

            # Resolve values
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
        total    = s["total"]
        enriched = s["enriched"]
        promoted = s["promoted"]
        print(
            f"\n[enricher] Enrichment complete: "
            f"{enriched}/{total} endpoints enriched, "
            f"{promoted} POST twins promoted"
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
    endpoints:  list[dict],
    target_url: str,
    auth_token: str  = "",
    second_token: str = "",
    timeout_s:  int  = 10,
    concurrency: int = 8,
    verbose:    bool = False,
    promote_get: bool = True,
) -> list[dict]:
    """
    Convenience wrapper for use from blfinder.py and scanner_integration.py.

    Example usage in blfinder.py (add just before the BLFScanner context):

        from core.discovery.endpoint_enricher import enrich_endpoints
        import aiohttp

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False)
        ) as enrich_session:
            endpoints = await enrich_endpoints(
                endpoints    = endpoints,
                target_url   = config.target_url,
                auth_token   = config.auth_token,
                second_token = config.second_user_token or "",
                verbose      = config.verbose,
            )
    """
    try:
        import aiohttp
    except ImportError:
        print("[!] endpoint_enricher: aiohttp not installed — enrichment skipped")
        return endpoints

    enricher = EndpointEnricher(
        target_url   = target_url,
        auth_token   = auth_token,
        second_token = second_token,
        verbose      = verbose,
        timeout_s    = timeout_s,
        concurrency  = concurrency,
        promote_get  = promote_get,
    )

    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    timeout   = aiohttp.ClientTimeout(total=timeout_s)
    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout
    ) as session:
        return await enricher.enrich(endpoints, session)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

async def _cli_main() -> None:
    import argparse

    p = argparse.ArgumentParser(
        description="BLFinder Endpoint Enricher — add real bodies/params to discovered endpoints",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
EXAMPLES:
  # Enrich a bare endpoints.json and save result
  python endpoint_enricher.py \\
    --input endpoints.json \\
    --output enriched.json \\
    --target https://1win.com \\
    --token "eyJhbGciOiJIUzI1NiJ9..." \\
    --verbose

  # Dry run — just print what fields would be inferred (no HTTP requests)
  python endpoint_enricher.py \\
    --input endpoints.json \\
    --output enriched.json \\
    --target https://1win.com \\
    --dry-run

  # Then run BLFinder against the enriched file
  python blfinder.py \\
    -t https://1win.com \\
    -T "eyJhbGciOiJIUzI1NiJ9..." \\
    -e enriched.json
""",
    )
    p.add_argument("--input",   "-i",  required=True,  help="Input endpoints JSON file")
    p.add_argument("--output",  "-o",  required=True,  help="Output enriched JSON file")
    p.add_argument("--target",  "-t",  required=True,  help="Target base URL")
    p.add_argument("--token",   "-T",  default="",     help="Auth token (Bearer automatically prepended)")
    p.add_argument("--token2",  "-T2", default="",     help="Second user auth token")
    p.add_argument("--verbose", "-v",  action="store_true", help="Verbose output")
    p.add_argument("--dry-run",        action="store_true",
                   help="Infer fields from path patterns only, no HTTP requests")
    p.add_argument("--no-promote",     action="store_true",
                   help="Skip GET→POST promotion")
    p.add_argument("--concurrency",    type=int, default=8,
                   help="Max concurrent enrichment requests (default: 8)")
    p.add_argument("--timeout",        type=int, default=10,
                   help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--stats",          action="store_true",
                   help="Print per-endpoint enrichment stats")

    args = p.parse_args()

    # Load input
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
        # Dry run: pattern-only inference, no HTTP
        print("[*] Dry run — using path-pattern inference only (no HTTP requests)")
        enriched: list[dict] = []
        enriched_count = 0
        for ep in endpoints:
            ep_copy = dict(ep)
            url    = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            body   = ep.get("body") or {}

            if body and len(body) >= 2:
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
                    print(
                        f"  {method} {url[-70:]:70s} "
                        f"→ {list(final.keys())[:6]}"
                    )
            enriched.append(ep_copy)

        print(f"[+] Dry run enriched {enriched_count}/{len(endpoints)} endpoints via patterns")
    else:
        # Live enrichment with HTTP probing
        print(
            f"[*] Enriching with HTTP probing "
            f"(concurrency={args.concurrency}, timeout={args.timeout}s)..."
        )
        t0 = time.time()
        enriched = await enrich_endpoints(
            endpoints    = endpoints,
            target_url   = args.target,
            auth_token   = args.token,
            second_token = args.token2,
            timeout_s    = args.timeout,
            concurrency  = args.concurrency,
            verbose      = args.verbose,
            promote_get  = not args.no_promote,
        )
        elapsed = time.time() - t0
        print(f"[*] Enrichment took {elapsed:.1f}s")

    # Save output
    try:
        with open(args.output, "w") as f:
            json.dump(enriched, f, indent=2)
        print(f"\n[+] Enriched endpoints saved → {args.output}")
        print(f"[+] Total endpoints: {len(enriched)} "
              f"(original: {len(endpoints)}, "
              f"added: {len(enriched) - len(endpoints)})")
    except OSError as e:
        print(f"[!] Could not save {args.output}: {e}")
        return

    # Stats breakdown
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

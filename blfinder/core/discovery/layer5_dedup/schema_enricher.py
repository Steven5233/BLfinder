"""
BLFinder v3.1 — core/discovery/layer5_dedup/schema_enricher.py
Body schema + parameter hint attachment for discovered endpoints.

Termux-safe: stdlib + aiohttp only.

What this does
--------------
After all discovery layers run, many endpoints have an empty body dict {}.
The scanner's business logic modules (price manipulation, mass assignment,
IDOR, etc.) are vastly more effective when they get a realistic starting
body instead of empty {} — they need to know which fields exist, which
are numeric (prices, quantities), which are IDs.

The enricher fills three gaps:

Gap 1 — No body, but we have an OpenAPI schema
  Already handled by openapi_parser.py. schema_hint is populated.
  Enricher copies schema_hint → body if body is empty.

Gap 2 — No body, no spec, but endpoint returns JSON
  Fetch the endpoint with GET. If it returns JSON, use the response
  structure to infer what a POST/PUT body should look like.
  Example: GET /users/1 → {"id":1,"name":"…","email":"…","role":"user"}
  Inferred POST body: {"name":"test","email":"user@example.com","role":"user"}
  (numeric/id fields are stripped from write bodies)

Gap 3 — Endpoint has no params dict
  Probe with OPTIONS to get Allow header.
  Try common query param names based on path keywords.
  For paginated endpoints: inject limit/offset/page/per_page.

FP-reduction
  - Only make live requests for endpoints with method POST/PUT/PATCH
    that still have an empty body after spec enrichment.
  - Cap live enrichment at 20 endpoints to avoid extra traffic.
  - Use GET on the same base path to infer write body — this is a
    read-only operation that cannot cause side effects.
  - Never enrich endpoints tagged 'debug' or sourced from 'wordlist'
    with low confidence.
  - Enriched bodies get a marker _enriched=True so the scanner knows
    to treat them as inferred (lower weight for canary comparisons).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse, urljoin


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

from ..models import DiscoveredEndpoint, DiscoveryConfig, SOURCE_WORDLIST


# ─────────────────────────────────────────────────────────────────────────────
# Field-level inference helpers
# ─────────────────────────────────────────────────────────────────────────────

# Fields that look like server-generated IDs — strip from write bodies
_READONLY_FIELD_PATTERNS = re.compile(
    r'^(?:id|_id|uuid|created_at|updated_at|deleted_at|created|updated|'
    r'timestamp|version|etag|revision|seq|sequence|hash|checksum|'
    r'modified_at|modified|inserted_at|inserted)$',
    re.IGNORECASE,
)

# Fields that are almost always present in write bodies
_ALWAYS_INCLUDE = frozenset({
    "name", "title", "email", "phone", "username", "password",
    "description", "type", "status", "role", "amount", "price",
    "quantity", "currency", "code", "value", "data",
})

# Type examples for JSON values
_TYPE_EXAMPLES: dict[str, Any] = {
    int:   1,
    float: 1.0,
    bool:  True,
    str:   "test",
    list:  [],
    dict:  {},
}


def _is_readonly_field(name: str) -> bool:
    return bool(_READONLY_FIELD_PATTERNS.match(name))


def _infer_example_value(key: str, current_val: Any) -> Any:
    """
    Given a response field key+value, return a plausible write-body example.
    """
    k = key.lower()

    # If current value is a useful type, use its type for example generation
    if isinstance(current_val, bool):
        return True
    if isinstance(current_val, int):
        # IDs look like integers — keep them as is for path testing
        if "id" in k:
            return 1
        return current_val if 0 <= current_val < 100000 else 1
    if isinstance(current_val, float):
        return round(current_val, 2) if current_val > 0 else 1.0
    if isinstance(current_val, list):
        return []
    if isinstance(current_val, dict):
        return {}

    # String field — use format hints
    if "email" in k:
        return "user@example.com"
    if "phone" in k or "mobile" in k:
        return "+1234567890"
    if "password" in k or "secret" in k:
        return "Password123!"
    if "url" in k or "link" in k or "href" in k:
        return "https://example.com"
    if "date" in k or "time" in k or "at" in k:
        return "2024-01-01T00:00:00Z"
    if "amount" in k or "price" in k or "cost" in k or "fee" in k:
        return 99.99
    if "quantity" in k or "qty" in k or "count" in k:
        return 1
    if "code" in k or "coupon" in k or "promo" in k:
        return "TEST10"
    if "currency" in k:
        return "USD"
    if "status" in k:
        return "active" if isinstance(current_val, str) else current_val
    if "role" in k:
        return current_val if isinstance(current_val, str) else "user"
    if "type" in k:
        return current_val if isinstance(current_val, str) else "standard"

    # Default: use the current value if it's a short string, else "test"
    if isinstance(current_val, str) and len(current_val) < 50:
        return current_val
    return "test"


def _response_to_write_body(response_data: Any, depth: int = 0) -> dict:
    """
    Convert a GET response body into an inferred POST/PUT body.
    - Strips read-only fields (id, created_at, etc.)
    - Converts values to safe examples
    - Depth-limited to 2 levels
    """
    if depth > 2 or not isinstance(response_data, dict):
        return {}

    write_body: dict = {}
    for key, val in response_data.items():
        # Skip read-only server fields
        if _is_readonly_field(key):
            continue
        # Skip null values unless the key is in the always-include set
        if val is None and key.lower() not in _ALWAYS_INCLUDE:
            continue
        # Recurse into nested objects (one level only)
        if isinstance(val, dict) and depth == 0:
            nested = _response_to_write_body(val, depth + 1)
            if nested:
                write_body[key] = nested
            continue
        write_body[key] = _infer_example_value(key, val)

    return write_body


def _infer_params_from_path(path: str) -> dict:
    """
    Infer likely query parameters from path keywords.
    e.g. /orders → {limit:10, offset:0, status:"active"}
    """
    params: dict = {}
    lp = path.lower()

    # Pagination — almost every list endpoint
    if any(k in lp for k in (
        "list", "all", "users", "orders", "products", "items",
        "transactions", "payments", "accounts", "events", "logs",
    )):
        params["limit"]  = 10
        params["offset"] = 0

    # Search endpoints
    if "search" in lp or "suggest" in lp or "autocomplete" in lp:
        params["q"] = "test"

    # Status filter
    if any(k in lp for k in ("orders", "transactions", "payments", "tasks", "jobs")):
        params["status"] = "active"

    # Date range (reports, analytics, statements)
    if any(k in lp for k in ("report", "analytics", "stat", "statement", "export")):
        params["from"] = "2024-01-01"
        params["to"]   = "2024-12-31"

    return params


# ─────────────────────────────────────────────────────────────────────────────
# OPTIONS-based method discovery
# ─────────────────────────────────────────────────────────────────────────────

async def _probe_options(
    url: str,
    session: Any,
    headers: dict,
    timeout: int,
) -> list[str]:
    """
    Send OPTIONS request. Parse Allow/Access-Control-Allow-Methods header
    to discover which HTTP methods the endpoint actually supports.
    Returns list of method strings.
    """
    try:
        async with session.options(
            url, headers=headers, allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
        ) as resp:
            allow = (
                resp.headers.get("Allow", "")
                or resp.headers.get("Access-Control-Allow-Methods", "")
            )
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                valid   = {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"}
                return [m for m in methods if m in valid]
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer5_dedup/schema_enricher.py#1", e)
        pass
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Main enricher class
# ─────────────────────────────────────────────────────────────────────────────

class SchemaEnricher:
    """
    Enriches DiscoveredEndpoints with realistic body schemas and query params.
    Should be run as the last step in layer5_dedup, after scoring.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def enrich(
        self,
        endpoints:  list[DiscoveredEndpoint],
        session:    Any,
        config:     "DiscoveryConfig",
        auth_token: str = "",
    ) -> list[DiscoveredEndpoint]:
        """
        Enrich all endpoints in-place. Returns the same list.
        """
        t0 = time.time()

        headers: dict = {
            "Accept":           "application/json, */*",
            "X-Requested-With": "XMLHttpRequest",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # ── Gap 1: copy schema_hint → body for spec-verified endpoints ────────
        spec_fixed = 0
        for ep in endpoints:
            if ep.schema_hint and not ep.body and ep.method in ("POST", "PUT", "PATCH"):
                ep.body = dict(ep.schema_hint)
                spec_fixed += 1

        # ── Gap 3: add inferred query params where missing ────────────────────
        for ep in endpoints:
            if not ep.params and ep.method == "GET":
                inferred = _infer_params_from_path(urlparse(ep.url).path)
                if inferred:
                    ep.params = inferred

        # ── OPTIONS method discovery for unknown-method endpoints ─────────────
        options_candidates = [
            ep for ep in endpoints
            if ep.method == "GET"
            and not ep.http_methods_allowed
            and ep.confidence >= 0.70
        ][:30]   # cap at 30 OPTIONS probes

        if options_candidates:
            options_results = await asyncio.gather(
                *[
                    _probe_options(ep.url, session, headers, config.timeout_s)
                    for ep in options_candidates
                ],
                return_exceptions=True,
            )
            for ep, methods in zip(options_candidates, options_results):
                if isinstance(methods, list) and methods:
                    ep.http_methods_allowed = methods

        # ── Gap 2: live GET → inferred write body ─────────────────────────────
        # Only for POST/PUT/PATCH with empty body, not from wordlist, confidence ≥ 0.65
        live_candidates = [
            ep for ep in endpoints
            if ep.method in ("POST", "PUT", "PATCH")
            and not ep.body
            and ep.source != SOURCE_WORDLIST
            and ep.confidence >= 0.65
            and "debug" not in ep.tags
        ][:20]   # cap at 20 live enrichment probes

        enriched_count = 0

        async def enrich_one(ep: DiscoveredEndpoint) -> None:
            nonlocal enriched_count
            # Build the GET URL for the same resource
            # POST /api/v1/orders → GET /api/v1/orders/1
            parsed = urlparse(ep.url)
            path   = parsed.path.rstrip("/")

            # Try the endpoint itself (GET version)
            get_url = urlunparse(parsed._replace(
                path=path, query="", fragment=""
            ))
            try:
                async with session.get(
                    get_url, headers=headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    if resp.status not in (200, 201):
                        # Try with /1 appended
                        get_url2 = get_url.rstrip("/") + "/1"
                        async with session.get(
                            get_url2, headers=headers,
                            allow_redirects=True,
                            timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                            ssl=False,
                        ) as resp2:
                            if resp2.status not in (200, 201):
                                return
                            body_text = await resp2.text(errors="replace")
                    else:
                        body_text = await resp.text(errors="replace")

                try:
                    data = json.loads(body_text)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer5_dedup/schema_enricher.py#2", e)
                    return

                # Handle list responses: use first item
                if isinstance(data, list) and data:
                    data = data[0]
                elif isinstance(data, dict):
                    # Unwrap common envelope keys
                    for wrap_key in ("data", "result", "item", "record", "user",
                                     "order", "product", "account"):
                        if wrap_key in data and isinstance(data[wrap_key], dict):
                            data = data[wrap_key]
                            break
                        if wrap_key in data and isinstance(data[wrap_key], list):
                            items = data[wrap_key]
                            if items and isinstance(items[0], dict):
                                data = items[0]
                            break

                if not isinstance(data, dict) or not data:
                    return

                write_body = _response_to_write_body(data)
                if write_body:
                    write_body["_enriched"] = True   # marker for scanner
                    ep.body         = write_body
                    ep.schema_hint  = {k: v for k, v in write_body.items()
                                       if k != "_enriched"}
                    ep.response_hint = data
                    enriched_count  += 1

                    if self.verbose:
                        print(
                            f"  [enricher] {ep.method} {ep.url[:60]} "
                            f"← inferred {len(write_body)} fields"
                        )

            except Exception as e:
                if self.verbose:
                    print(f"  [enricher] error {ep.url}: {e}")

        if live_candidates:
            await asyncio.gather(*[enrich_one(ep) for ep in live_candidates])

        elapsed = time.time() - t0
        total_with_body = sum(1 for ep in endpoints if ep.body)

        if self.verbose or spec_fixed or enriched_count:
            print(
                f"  [+] Schema enricher: "
                f"{spec_fixed} spec-filled, "
                f"{enriched_count} live-inferred, "
                f"{total_with_body}/{len(endpoints)} endpoints have body "
                f"({elapsed:.1f}s)"
            )

        return endpoints

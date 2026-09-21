"""
BLFinder v3.1 — core/discovery/layer5_dedup/normaliser.py
URL canonicalisation + template collapse.

Pure functions, no I/O, Termux-safe (stdlib only).

Strategy
--------
Two endpoints that normalise to the same *template* are the same endpoint.
Template collapsing replaces concrete IDs with placeholders so:
  /orders/123/items/456   →   /orders/{id}/items/{id}
  /users/abc-123-def      →   /users/{uuid}
  /api/v1/products/99     →   /api/v1/products/{id}

This prevents the scanner from wasting requests on N variations of one endpoint
and ensures dedup works across sources (OpenAPI found /orders/{id}, wordlist
probed /orders/123 — they're the same thing).
"""

from __future__ import annotations

import re
from urllib.parse import (
    urlparse, urlunparse, urlencode,
    parse_qs, quote, unquote,
)




import os as _os
import sys as _sys





_BLF_DEBUG = bool(_os.environ.get("BLFINDER_DEBUG"))


def _blf_dbg(where: str, err: BaseException) -> None:
    if _BLF_DEBUG:
        print(f"[debug] {where}: {type(err).__name__}: {err}", file=_sys.stderr)

_RE_UUID      = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
_RE_NUMERIC   = re.compile(r'^\d{1,20}$')
_RE_HEX_ID    = re.compile(r'^[0-9a-f]{16,64}$', re.IGNORECASE)
_RE_SLUG_ID   = re.compile(
    r'^[a-z0-9]{4,8}-[a-z0-9]{4,8}-[a-z0-9]{4,8}$',
    re.IGNORECASE,
)
_RE_BASE64_ID = re.compile(r'^[A-Za-z0-9+/=]{20,}$')
_RE_MIXED_ID  = re.compile(r'^[a-z]{2,6}[0-9]{3,}$', re.IGNORECASE)


_KEYWORD_SEGMENTS = frozenset({
    "api", "v1", "v2", "v3", "v4", "v5", "internal", "legacy", "beta",
    "admin", "public", "private", "static", "assets", "health", "metrics",
    "ping", "status", "docs", "swagger", "openapi", "graphql", "gql",
    "auth", "oauth", "sso", "login", "logout", "register", "me",
    "users", "orders", "payments", "products", "cart", "checkout",
    "profile", "settings", "dashboard", "reports", "analytics",
    "webhooks", "events", "notifications", "search", "suggest",
    "upload", "download", "export", "import", "batch",
    "true", "false", "null", "undefined",
})


def is_id_segment(segment: str) -> bool:
    """Return True if a path segment looks like a concrete ID, not a keyword."""
    if not segment:
        return False
    s = segment.lower()
    if s in _KEYWORD_SEGMENTS:
        return False
    if _RE_NUMERIC.match(segment):
        return True
    if _RE_UUID.match(segment):
        return True
    if _RE_HEX_ID.match(segment):
        return True
    if _RE_SLUG_ID.match(segment):
        return True
    if _RE_MIXED_ID.match(segment):
        return True

    if len(segment) >= 20 and re.match(r'^[A-Za-z0-9_-]+$', segment):
        return True
    return False


def id_placeholder(segment: str) -> str:
    """Return the right placeholder token for a given ID segment."""
    if _RE_UUID.match(segment):
        return "{uuid}"
    if _RE_NUMERIC.match(segment):
        return "{id}"
    if _RE_HEX_ID.match(segment):
        return "{hex_id}"
    return "{id}"


def normalise_path(path: str) -> tuple[str, list[str]]:
    """
    Replace ID-like segments with placeholders.
    Returns (template_path, [list_of_original_ids]).

    Example:
        /orders/123/items/456  →  ("/orders/{id}/items/{id}", ["123", "456"])
    """
    parts = path.rstrip("/").split("/")
    ids_found: list[str] = []
    normalised: list[str] = []

    for part in parts:
        decoded = unquote(part)
        if is_id_segment(decoded):
            ids_found.append(decoded)
            normalised.append(id_placeholder(decoded))
        else:
            normalised.append(part.lower())

    return "/".join(normalised), ids_found


def normalise_url(url: str) -> tuple[str, str]:
    """
    Fully normalise a URL:
    - lowercase scheme + host
    - collapse ID segments in path
    - sort + normalise query params (for dedup; query is stripped from template)
    - remove default ports (80/443)
    - strip fragment

    Returns (canonical_url, template_key) where template_key is used for dedup.
    template_key strips the query string entirely.
    """
    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer5_dedup/normaliser.py#1", e)
        return url, url

    scheme = (parsed.scheme or "https").lower()
    host   = (parsed.netloc or "").lower()


    if host.endswith(":80") and scheme == "http":
        host = host[:-3]
    elif host.endswith(":443") and scheme == "https":
        host = host[:-4]

    template_path, _ = normalise_path(parsed.path or "/")


    qs_dict = parse_qs(parsed.query, keep_blank_values=False)
    canonical_qs = urlencode(
        sorted((k, v[0]) for k, v in qs_dict.items() if v)
    )

    canonical = urlunparse((scheme, host, template_path, "", canonical_qs, ""))
    template  = urlunparse((scheme, host, template_path, "", "", ""))

    return canonical, template


def extract_id_params(path: str) -> list[str]:
    """
    Return the names of path segments that look like parameter placeholders.
    Works on both concrete paths (/orders/123) and templated ones (/orders/{id}).
    """
    id_params: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if seg.startswith("{") and seg.endswith("}"):
            id_params.append(seg[1:-1])
        elif is_id_segment(unquote(seg)):
            id_params.append("id")
    return id_params


def canonicalise_method(method: str) -> str:
    m = method.upper().strip()
    valid = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    return m if m in valid else "GET"


def normalise_body(body: Any) -> dict:
    """
    Ensure body is always a dict (never None, list-root is wrapped).
    Recursively lowercases string values that look like test artifacts.
    """
    if body is None:
        return {}
    if isinstance(body, dict):
        return body
    if isinstance(body, list):
        return {"items": body}
    return {}


def dedup_key(url: str, method: str) -> str:
    """
    Unique deduplication key for an endpoint.
    Two URLs that differ only in concrete ID values get the same key.
    """
    _, template = normalise_url(url)
    return f"{canonicalise_method(method)}|{template}"


def batch_normalise(
    endpoints: list[dict],
) -> list[dict]:
    """
    Normalise a list of raw endpoint dicts and remove duplicates.
    Each dict must have at least 'url' and optionally 'method'.
    Returns deduplicated list with 'normalised_template' added to each.
    """
    seen:   set[str]   = set()
    result: list[dict] = []

    for ep in endpoints:
        url    = ep.get("url", "")
        method = ep.get("method", "GET")
        key    = dedup_key(url, method)

        if key in seen:
            continue
        seen.add(key)

        _, template = normalise_url(url)
        ep = dict(ep)
        ep["normalised_template"] = template
        ep["id_params"]           = extract_id_params(urlparse(url).path)
        result.append(ep)

    return result

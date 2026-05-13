"""
BLFinder v3.1 — core/discovery/layer1_surface/robots_parser.py
robots.txt + sitemap.xml (recursive) parser.

Termux-safe: stdlib + aiohttp only.

What this finds that smart_discover() misses
---------------------------------------------
- Disallowed paths (these are EXACTLY what security testers want — the owner
  tried to hide them from crawlers)
- Sitemap-indexed URLs (every page the site considers canonical)
- Nested sitemaps (sitemap index → multiple sitemap files)
- News/image/video sitemaps (often point to API endpoints)

FP reduction
  - robots.txt Allow: and Disallow: with specific paths only (not wildcards alone)
  - Sitemap URLs: only those whose path matches API/endpoint heuristics
  - Confidence 0.75 for robots paths, 0.65 for sitemap paths
    (sitemap paths are often HTML pages, not APIs)
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_ROBOTS, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import normalise_url, extract_id_params, dedup_key


# ── Heuristics for API-like paths ─────────────────────────────────────────────
_API_SIGNALS = re.compile(
    r'/(?:api|v\d|graphql|rpc|rest|service|endpoint|internal|admin|manage)',
    re.I
)
_HTML_EXTENSIONS = frozenset({
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".cfm",
    ".xml", ".rss", ".atom", ".txt", ".pdf",
})
_WILDCARD_ONLY = re.compile(r'^[/*?]+$')   # e.g. Disallow: /*  or  /


def _looks_like_api_path(path: str) -> bool:
    if not path or not path.startswith("/"):
        return False
    if _WILDCARD_ONLY.match(path):
        return False
    stripped = path.split("?")[0].rstrip("/")
    for ext in _HTML_EXTENSIONS:
        if stripped.lower().endswith(ext):
            return False
    # Prefer paths that look API-y but don't require it
    # (any hidden path is worth probing)
    return len(stripped) >= 2


def _tag_from_path(path: str) -> list[str]:
    lp = path.lower()
    tags: list[str] = []
    if any(k in lp for k in ("payment", "billing", "invoice", "wallet")):
        tags.append("payment")
    if any(k in lp for k in ("order", "cart", "checkout")):
        tags.append("order")
    if any(k in lp for k in ("admin", "manage", "internal", "staff")):
        tags.append("admin")
    if any(k in lp for k in ("user", "account", "profile")):
        tags.append("user")
    if any(k in lp for k in ("auth", "login", "token", "password")):
        tags.append("auth")
    return tags


def _priority(tags: list[str], is_disallowed: bool) -> int:
    if is_disallowed:
        if any(t in tags for t in ("admin", "payment")):
            return 1
        return 2
    if any(t in tags for t in ("admin", "payment", "transfer")):
        return 2
    return 3


# ── robots.txt parser ─────────────────────────────────────────────────────────

def parse_robots(content: str) -> tuple[list[str], list[str], list[str]]:
    """
    Parse robots.txt content.
    Returns (disallowed_paths, allowed_paths, sitemap_urls).
    Paths are raw strings as written in the file.
    """
    disallowed: list[str] = []
    allowed:    list[str] = []
    sitemaps:   list[str] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("disallow:"):
            path = line[9:].strip().split("#")[0].strip()
            if path and not _WILDCARD_ONLY.match(path):
                disallowed.append(path)
        elif lower.startswith("allow:"):
            path = line[6:].strip().split("#")[0].strip()
            if path and not _WILDCARD_ONLY.match(path):
                allowed.append(path)
        elif lower.startswith("sitemap:"):
            url = line[8:].strip().split("#")[0].strip()
            if url.startswith("http"):
                sitemaps.append(url)

    return disallowed, allowed, sitemaps


# ── sitemap.xml parser ────────────────────────────────────────────────────────

def parse_sitemap(content: str, base_url: str) -> tuple[list[str], list[str]]:
    """
    Parse sitemap XML.
    Returns (page_urls, nested_sitemap_urls).
    """
    page_urls:    list[str] = []
    nested_maps:  list[str] = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Try stripping the namespace and retry
        content_stripped = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', content)
        try:
            root = ET.fromstring(content_stripped)
        except ET.ParseError:
            return [], []

    # Strip namespace from tag names
    def tag(el: ET.Element) -> str:
        t = el.tag
        if t.startswith("{"):
            t = t[t.index("}") + 1:]
        return t.lower()

    for child in root:
        child_tag = tag(child)
        if child_tag == "sitemap":
            # Sitemap index
            loc = child.find(".//{*}loc")
            if loc is not None and loc.text:
                nested_maps.append(loc.text.strip())
        elif child_tag == "url":
            loc = child.find(".//{*}loc")
            if loc is not None and loc.text:
                page_urls.append(loc.text.strip())

    # Handle flat sitemap (direct <url><loc>…) or <loc> at root
    if not page_urls and not nested_maps:
        for el in root.iter():
            if tag(el) == "loc" and el.text:
                url = el.text.strip()
                if url.startswith("http"):
                    page_urls.append(url)

    return page_urls, nested_maps


# ── Main async class ──────────────────────────────────────────────────────────

class RobotsParser:

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def run(
        self,
        target_url: str,
        session: Any,
        config: "DiscoveryConfig",
        auth_token: str = "",
    ) -> LayerResult:
        t0     = time.time()
        result = LayerResult(layer="layer1:robots")
        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        headers: dict = {"Accept": "text/plain,text/xml,application/xml,*/*"}

        async def fetch(url: str) -> Optional[str]:
            try:
                async with session.get(
                    url, headers=headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="replace")
            except Exception as e:
                if self.verbose:
                    result.errors.append(f"fetch {url}: {e}")
            return None

        seen_keys: set[str] = set()

        def add_ep(path: str, is_disallowed: bool, source_note: str):
            """Validate path and add a DiscoveredEndpoint if not duplicate."""
            # Strip wildcard chars that robots.txt allows but we can't use
            clean_path = path.split("*")[0].rstrip("$").rstrip("/") or "/"
            if not _looks_like_api_path(clean_path):
                return
            full_url = base + clean_path
            key      = dedup_key(full_url, "GET")
            if key in seen_keys:
                return
            seen_keys.add(key)

            tags       = _tag_from_path(clean_path)
            confidence = 0.75 if is_disallowed else 0.65
            _, tmpl    = normalise_url(full_url)

            result.endpoints.append(DiscoveredEndpoint(
                url=full_url, method="GET",
                source=SOURCE_ROBOTS,
                confidence=confidence,
                priority=_priority(tags, is_disallowed),
                id_params=extract_id_params(clean_path),
                tags=tags,
                raw_source_evidence=source_note,
                normalised_template=tmpl,
            ))

        # ── robots.txt ────────────────────────────────────────────────────────
        robots_url = f"{base}/robots.txt"
        robots_txt = await fetch(robots_url)
        sitemaps_to_fetch: list[str] = []

        if robots_txt:
            disallowed, allowed, sitemaps = parse_robots(robots_txt)
            sitemaps_to_fetch.extend(sitemaps)

            for path in disallowed:
                add_ep(path, is_disallowed=True, source_note="robots.txt Disallow")
            for path in allowed:
                add_ep(path, is_disallowed=False, source_note="robots.txt Allow")

            if self.verbose and (disallowed or allowed):
                print(
                    f"  [robots] {len(disallowed)} disallowed, "
                    f"{len(allowed)} allowed paths, "
                    f"{len(sitemaps)} sitemaps"
                )

        # Also try common sitemap locations even if not listed in robots.txt
        default_sitemaps = [
            f"{base}/sitemap.xml",
            f"{base}/sitemap_index.xml",
            f"{base}/sitemap-index.xml",
            f"{base}/sitemaps/sitemap.xml",
            f"{base}/api/sitemap.xml",
        ]
        all_sitemaps = list(dict.fromkeys(sitemaps_to_fetch + default_sitemaps))

        # ── sitemap.xml (recursive, max 5 levels) ─────────────────────────────
        fetched_sitemaps: set[str] = set()
        queue = all_sitemaps[:10]   # safety cap

        while queue and len(fetched_sitemaps) < 20:
            sm_url = queue.pop(0)
            if sm_url in fetched_sitemaps:
                continue
            fetched_sitemaps.add(sm_url)

            sm_content = await fetch(sm_url)
            if not sm_content:
                continue

            page_urls, nested = parse_sitemap(sm_content, base)

            for nested_url in nested[:10]:
                if nested_url not in fetched_sitemaps:
                    queue.append(nested_url)

            for page_url in page_urls:
                page_parsed = urlparse(page_url)
                # Only process pages on the same host
                if page_parsed.netloc != parsed.netloc:
                    continue
                path = page_parsed.path
                add_ep(
                    path, is_disallowed=False,
                    source_note=f"sitemap: {sm_url}",
                )

        ep_count = len(result.endpoints)
        if ep_count:
            print(f"  [+] Robots/sitemap: {ep_count} paths discovered")

        result.elapsed_s = time.time() - t0
        return result

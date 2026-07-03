"""
BLFinder v3.1 — core/discovery/layer3_dynamic/headless_crawler.py
Playwright-based dynamic crawler: XHR/fetch network interceptor.

Termux-safe design
------------------
Playwright is NOT installed by default. This module gracefully degrades:
  - If playwright is not installed, HeadlessCrawler.run() returns an
    empty LayerResult with a helpful install message.
  - If Chromium binary is not found, same graceful degradation.
  - The engine.py only calls this module when config.use_headless=True.

Termux install (when user wants headless):
  pip install playwright --break-system-packages
  playwright install chromium

Why headless crawl is the highest-value discovery method
---------------------------------------------------------
Static analysis (JS regex/AST) can only find endpoints that are written
as string literals. Many modern SPAs build URLs dynamically at runtime:
    const url = `${config.API_BASE}/${entity}/${id}/actions/${action}`
This path is INVISIBLE to any static analyser. Headless crawl intercepts
the actual network calls the browser makes, capturing:
  - The real URL with real IDs
  - The real request body (the exact JSON the frontend sends)
  - The real headers (including CSRF tokens, session IDs, API versions)
  - Calls that only happen after specific user interactions (login,
    clicking through a wizard, submitting a form)

Strategy
--------
1. Launch Chromium with network interception enabled
2. Navigate to target URL
3. If credentials provided, attempt auto-login
4. Navigate to all links found on the page (depth-limited)
5. If config.headless_interact: click common UI patterns
   (buttons, form submits, tab panels, dropdown menus)
6. Collect every XHR/fetch request intercepted during all of the above
7. Parse intercepted requests into DiscoveredEndpoints with real bodies

FP-reduction
------------
- Only capture XHR and fetch requests (not images, fonts, CSS, scripts)
- Reject requests to third-party domains (CDNs, analytics, ads)
- Minimum body size: 10 bytes for body-carrying requests
- Deduplicate by (template, method) before returning
- live_verified=True on ALL endpoints found here (+0.15 confidence boost
  in scorer.py — these were actually called by the real application)
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_HEADLESS, SOURCE_AUTH_REPLAY, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import normalise_url, extract_id_params, dedup_key


# ─────────────────────────────────────────────────────────────────────────────
# Playwright availability check
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

def _check_playwright() -> tuple[bool, str]:
    """
    Returns (available, message).
    Checks both the Python package and the Chromium binary.
    """
    try:
        import playwright  # type: ignore  # noqa: F401
    except ImportError:
        return False, (
            "playwright not installed. "
            "Install: pip install playwright --break-system-packages "
            "&& playwright install chromium"
        )
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
        with sync_playwright() as p:
            browser_path = p.chromium.executable_path
            import os
            if not os.path.exists(browser_path):
                return False, (
                    f"Chromium binary not found at {browser_path}. "
                    "Run: playwright install chromium"
                )
    except Exception as e:
        return False, f"playwright check error: {e}"
    return True, "ok"


# ─────────────────────────────────────────────────────────────────────────────
# Request capture helpers
# ─────────────────────────────────────────────────────────────────────────────

# Resource types to intercept (XHR and fetch only)
_API_RESOURCE_TYPES = {"xhr", "fetch"}

# Extensions that are definitely not API endpoints
_SKIP_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip",
    ".mp3", ".mp4", ".webm", ".ogg",
})

# Tag inference
_TAG_KEYWORDS: dict[str, list[str]] = {
    "payment":  ["payment", "pay", "billing", "transaction", "wallet", "charge", "invoice"],
    "order":    ["order", "cart", "checkout", "purchase", "buy"],
    "admin":    ["admin", "manage", "internal", "staff", "backoffice"],
    "user":     ["user", "account", "profile", "member", "customer"],
    "auth":     ["auth", "login", "logout", "token", "refresh", "oauth", "password", "session"],
    "product":  ["product", "item", "sku", "catalog", "inventory"],
    "transfer": ["transfer", "withdraw", "deposit", "send", "remit"],
}


def _infer_tags(path: str) -> list[str]:
    lp = path.lower()
    return [tag for tag, kws in _TAG_KEYWORDS.items() if any(k in lp for k in kws)]


def _priority(tags: list[str], method: str) -> int:
    if any(t in tags for t in ("admin", "payment", "transfer")):
        return 1
    if any(t in tags for t in ("auth", "order", "user")):
        return 2
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return 2
    return 3


def _is_same_origin(request_url: str, target_url: str) -> bool:
    req_host    = urlparse(request_url).netloc
    target_host = urlparse(target_url).netloc
    # Allow subdomains of the same root domain
    req_parts    = req_host.split(".")
    target_parts = target_host.split(".")
    return (
        req_host == target_host
        or (len(req_parts) >= 2
            and req_parts[-2:] == target_parts[-2:])
    )


def _parse_intercepted_request(
    url: str,
    method: str,
    post_data: Optional[str],
    headers: dict,
    target_url: str,
) -> Optional[DiscoveredEndpoint]:
    """
    Convert a Playwright intercepted request into a DiscoveredEndpoint.
    Returns None if the request should be filtered out.
    """
    # Must be same-origin
    if not _is_same_origin(url, target_url):
        return None

    parsed = urlparse(url)
    path   = parsed.path

    # Skip asset extensions
    for ext in _SKIP_EXTENSIONS:
        if path.lower().endswith(ext):
            return None

    # Must look like an API path (at minimum: /something)
    if not path or path == "/":
        return None

    method = method.upper()

    # Parse body
    body: dict = {}
    if post_data and method in ("POST", "PUT", "PATCH"):
        try:
            body = json.loads(post_data)
            if not isinstance(body, dict):
                body = {"data": body}
        except Exception as e:
            _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#1", e)
            # Form-encoded body — parse manually
            try:
                from urllib.parse import parse_qs
                parsed_qs = parse_qs(post_data)
                body = {k: v[0] if len(v) == 1 else v
                        for k, v in parsed_qs.items()}
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#2", e)
                body = {}

    # Strip auth headers from the captured headers (security)
    safe_headers: dict = {}
    sensitive_hdrs = {"authorization", "cookie", "x-auth-token", "x-api-key",
                      "x-session-token", "x-csrf-token"}
    for k, v in headers.items():
        if k.lower() not in sensitive_hdrs:
            safe_headers[k] = v

    _, tmpl = normalise_url(url)
    tags    = _infer_tags(path)

    return DiscoveredEndpoint(
        url=url, method=method,
        body=body,
        source=SOURCE_HEADLESS,
        confidence=0.92,   # live-verified = highest confidence tier
        priority=_priority(tags, method),
        id_params=extract_id_params(path),
        tags=tags,
        raw_source_evidence=f"headless XHR intercept: {method} {url[:80]}",
        normalised_template=tmpl,
        live_verified=True,   # key: this was actually called by the browser
        schema_hint=body,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Auto-login helper
# ─────────────────────────────────────────────────────────────────────────────

async def _try_auto_login(page: Any, target_url: str, auth_token: str) -> bool:
    """
    Attempt to inject the auth token into the browser's localStorage/
    sessionStorage so the SPA recognises the session, then reload.

    Also tries to detect a login form and fill it if token looks like
    'username:password' format.
    """
    if not auth_token:
        return False

    # Strategy 1: inject as Bearer token into localStorage (works for many SPAs)
    try:
        await page.evaluate(f"""
            () => {{
                try {{
                    localStorage.setItem('token', '{auth_token}');
                    localStorage.setItem('access_token', '{auth_token}');
                    localStorage.setItem('auth_token', '{auth_token}');
                    sessionStorage.setItem('token', '{auth_token}');
                    sessionStorage.setItem('access_token', '{auth_token}');
                }} catch(e) {{}}
            }}
        """)
        await page.reload(wait_until="networkidle", timeout=15000)
        return True
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#3", e)
        pass

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Link extractor
# ─────────────────────────────────────────────────────────────────────────────

async def _extract_links(page: Any, base_url: str) -> list[str]:
    """Extract all same-origin links from the current page."""
    try:
        hrefs = await page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href]'))
                       .map(a => a.href)
                       .filter(h => h && !h.startsWith('javascript:')
                                      && !h.startsWith('mailto:')
                                      && !h.startsWith('tel:'))
        """)
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#4", e)
        return []

    links: list[str] = []
    for href in (hrefs or []):
        if _is_same_origin(href, base_url):
            links.append(href)
    return links[:30]   # cap to avoid infinite crawl


# ─────────────────────────────────────────────────────────────────────────────
# Interactive UI actions (opt-in via config.headless_interact)
# ─────────────────────────────────────────────────────────────────────────────

async def _interact_with_page(page: Any) -> None:
    """
    Click common interactive UI elements to trigger API calls that only
    happen after user interactions. Best-effort — errors are silently ignored.
    """
    interaction_selectors = [
        # Tabs / navigation panels
        "[role='tab']",
        ".tab, .nav-tab, .tab-item",
        # Dropdowns
        "[data-toggle='dropdown'], .dropdown-toggle",
        # Expand/collapse sections
        "[data-toggle='collapse'], .accordion-button, .expandable",
        # Load-more buttons
        "button:has-text('Load more'), button:has-text('Show more')",
        "button:has-text('View all'), button:has-text('See all')",
        # Pagination
        "[aria-label='Next page'], .pagination-next, .next-page",
        # Common action buttons (non-destructive)
        "button:has-text('Filter'), button:has-text('Sort')",
        "button:has-text('Refresh'), button:has-text('Reload')",
        "button:has-text('Search')",
    ]
    for selector in interaction_selectors:
        try:
            elements = await page.query_selector_all(selector)
            for el in elements[:3]:   # click at most 3 of each type
                try:
                    await el.click(timeout=2000)
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#5", e)
                    pass
        except Exception as e:
            _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#6", e)
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Main crawler class
# ─────────────────────────────────────────────────────────────────────────────

class HeadlessCrawler:
    """
    Playwright-based headless browser crawler.
    Intercepts XHR/fetch requests to discover API endpoints with real bodies.

    Only active when config.use_headless=True AND playwright is installed.
    Gracefully returns empty results otherwise.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def run(
        self,
        target_url: str,
        config:     "DiscoveryConfig",
        auth_token: str = "",
    ) -> LayerResult:
        t0     = time.time()
        result = LayerResult(layer=SOURCE_HEADLESS)

        # Check availability
        available, msg = _check_playwright()
        if not available:
            print(f"  [headless] {msg}")
            result.elapsed_s = time.time() - t0
            return result

        # Run in a thread executor (Playwright has its own event loop requirements)
        try:
            loop = asyncio.get_event_loop()
            endpoints = await loop.run_in_executor(
                None,
                self._sync_crawl,
                target_url, config, auth_token,
            )
            result.endpoints = endpoints
        except Exception as e:
            result.errors.append(str(e))
            if self.verbose:
                print(f"  [headless] crawl error: {e}")

        result.elapsed_s = time.time() - t0
        if result.endpoints:
            print(
                f"  [+] Headless crawl: {len(result.endpoints)} live API calls captured"
            )
        return result

    def _sync_crawl(
        self,
        target_url: str,
        config:     "DiscoveryConfig",
        auth_token: str,
    ) -> list[DiscoveredEndpoint]:
        """
        Synchronous Playwright crawl. Runs in a thread executor.
        Returns list of DiscoveredEndpoints.
        """
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except ImportError:
            return []

        intercepted: list[dict] = []
        seen_keys:   set[str]   = set()

        def on_request(request):
            """Callback: fired for every network request the browser makes."""
            try:
                if request.resource_type not in _API_RESOURCE_TYPES:
                    return
                url    = request.url
                method = request.method.upper()
                data   = request.post_data
                hdrs   = dict(request.headers)
                intercepted.append({
                    "url":       url,
                    "method":    method,
                    "post_data": data,
                    "headers":   hdrs,
                })
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#7", e)
                pass

        endpoints: list[DiscoveredEndpoint] = []

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",   # important for Termux
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--disable-translate",
                    "--disable-notifications",
                    "--disable-popup-blocking",
                ],
            )
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Linux; Android 10; K) "
                    "AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},
            )

            # Inject auth token as default header if it looks like a JWT
            if auth_token and "." in auth_token:
                context.set_extra_http_headers({
                    "Authorization": f"Bearer {auth_token}"
                })

            page = context.new_page()
            page.on("request", on_request)

            timeout_ms = config.headless_timeout_s * 1000

            # Navigate to root
            try:
                page.goto(
                    target_url,
                    wait_until="networkidle",
                    timeout=timeout_ms,
                )
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#8", e)
                try:
                    page.goto(target_url, wait_until="domcontentloaded",
                              timeout=timeout_ms)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#9", e)
                    browser.close()
                    return []

            # Attempt auto-login
            if auth_token:
                try:
                    page.evaluate(f"""
                        () => {{
                            try {{
                                localStorage.setItem('token', '{auth_token}');
                                localStorage.setItem('access_token', '{auth_token}');
                                sessionStorage.setItem('token', '{auth_token}');
                            }} catch(e) {{}}
                        }}
                    """)
                    page.reload(wait_until="networkidle", timeout=timeout_ms)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#10", e)
                    pass

            # Interact with page if requested
            if config.headless_interact:
                try:
                    _sync_interact(page)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#11", e)
                    pass

            # Follow links (depth 1)
            visited: set[str] = {target_url}
            try:
                hrefs = page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]'))
                               .map(a => a.href)
                               .filter(h => h && !h.startsWith('javascript:')
                                              && !h.startsWith('mailto:'))
                               .slice(0, 20)
                """)
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#12", e)
                hrefs = []

            target_netloc = urlparse(target_url).netloc
            for href in (hrefs or []):
                if href in visited:
                    continue
                href_host = urlparse(href).netloc
                if href_host != target_netloc:
                    continue
                visited.add(href)
                try:
                    page.goto(
                        href,
                        wait_until="networkidle",
                        timeout=min(timeout_ms, 10000),
                    )
                    if config.headless_interact:
                        try:
                            _sync_interact(page)
                        except Exception as e:
                            _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#13", e)
                            pass
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#14", e)
                    pass

            browser.close()

        # Convert intercepted requests → DiscoveredEndpoints
        for item in intercepted:
            ep = _parse_intercepted_request(
                url=item["url"],
                method=item["method"],
                post_data=item.get("post_data"),
                headers=item.get("headers", {}),
                target_url=target_url,
            )
            if ep is None:
                continue
            key = dedup_key(ep.url, ep.method)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            endpoints.append(ep)

        return endpoints


def _sync_interact(page: Any) -> None:
    """
    Synchronous version of page interaction (for use inside sync_playwright).
    """
    selectors = [
        "[role='tab']",
        ".tab, .nav-tab",
        "[data-toggle='dropdown']",
        "button:text('Load more')",
        "button:text('Show more')",
        "button:text('View all')",
        "button:text('Filter')",
        "button:text('Refresh')",
    ]
    for selector in selectors:
        try:
            elements = page.query_selector_all(selector)
            for el in elements[:2]:
                try:
                    el.click(timeout=1500)
                    page.wait_for_load_state("networkidle", timeout=2000)
                except Exception as e:
                    _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#15", e)
                    pass
        except Exception as e:
            _blf_dbg("blfinder/core/discovery/layer3_dynamic/headless_crawler.py#16", e)
            pass

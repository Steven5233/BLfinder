"""
BLFinder v3.1 — core/discovery/layer2_static/js_ast_parser.py
JavaScript endpoint extraction: regex pass + lightweight AST pass.

Termux-safe: stdlib + aiohttp only.
No Node.js, no npm, no C extensions required.

Two-pass strategy (FP-reduction aligned)
-----------------------------------------
Pass 1 — Regex harvest (fast, ~70% recall)
  Targets the specific string patterns that appear in real API client code.
  Each pattern is tuned to the actual JS libraries in use (axios, fetch,
  superagent, ky, got, request, XMLHttpRequest).

Pass 2 — Lightweight AST (structural, ~+20% recall)
  Tokenises the JS and walks string literals + object property assignments.
  Catches endpoints hidden in variables, constants, and router definitions.

FP reduction
  - Minimum path length: 4 chars after the leading /
  - Require at least one path separator beyond the root
  - Reject pure asset paths (.css, .png, .svg, .woff, etc.)
  - Reject localhost / 127.0.0.1 / data: / chrome-extension:
  - Require the path to contain at least one alpha character (not /123/456)
  - Confidence: 0.70 for regex, 0.80 for AST (structural match is stronger)
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_JS_REGEX, SOURCE_JS_AST, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import normalise_url, extract_id_params, dedup_key


# ── Asset extensions to reject ────────────────────────────────────────────────
_ASSET_EXTS = frozenset({
    ".css", ".scss", ".less", ".sass",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg",
    ".pdf", ".zip", ".gz", ".tar",
    ".map",          # source maps
    ".md", ".txt",
})

# Prefixes that are definitely not API endpoints
_REJECT_PREFIXES = (
    "data:", "blob:", "javascript:", "mailto:", "tel:",
    "chrome-extension://", "moz-extension://",
    "#", "//localhost", "//127.0.0.1", "//0.0.0.0",
)

# Only accept paths that match this shape
_PATH_SHAPE = re.compile(
    r'^/[a-zA-Z][a-zA-Z0-9_/-]{2,80}$'
)


# ── Regex patterns (Pass 1) ───────────────────────────────────────────────────
# Each group captures a path string.  Patterns are ordered by specificity.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # fetch('/api/…') / fetch(`/api/…`)
    ("fetch_call",
     re.compile(r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*[`"']([/][^`"'\s<>]{3,80})[`"']''', re.I)),

    # axios({ url: '/api/…' }) / request({ uri: '/api/…' })
    ("axios_obj",
     re.compile(r'''(?:url|uri|endpoint|path)\s*:\s*[`"']([/][^`"'\s<>]{3,80})[`"']''', re.I)),

    # const API = '/api/v1'
    ("const_assign",
     re.compile(r'''(?:const|let|var)\s+\w+\s*=\s*[`"']([/][a-zA-Z][^`"'\s<>]{2,79})[`"']''', re.I)),

    # baseURL: 'https://api.example.com/v1'  — extract the path only
    ("base_url",
     re.compile(r'''baseURL?\s*[=:]\s*[`"']https?://[^/`"']+([/][^`"'\s<>]{1,80})[`"']''', re.I)),

    # Express-style router: router.get('/path', handler) / app.post('/…')
    ("express_route",
     re.compile(r'''(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*[`"']([/][^`"'\s<>]{2,80})[`"']''', re.I)),

    # React-Router / Vue-Router: path: '/route'  component:
    ("router_path",
     re.compile(r'''(?:^|,|\{)\s*path\s*:\s*[`"']([/][^`"'\s<>]{1,80})[`"']''', re.I | re.M)),

    # String template literals: `/api/orders/${id}`  — capture prefix
    ("template_literal",
     re.compile(r'`([/][a-zA-Z][a-zA-Z0-9_/-]{1,60})\$\{', re.I)),

    # XMLHttpRequest.open('GET', '/path')
    ("xhr_open",
     re.compile(r'''\.open\s*\(\s*[`"'][A-Z]+[`"']\s*,\s*[`"']([/][^`"'\s<>]{3,80})[`"']''', re.I)),

    # ky.get('/path') / got('/path') / superagent.get('/path')
    ("ky_got",
     re.compile(r'''(?:ky|got|request|superagent|needle)\s*(?:\.[a-z]+)?\s*\(\s*[`"']([/][^`"'\s<>]{3,80})[`"']''', re.I)),

    # Apollo / GraphQL: uri: '/graphql'
    ("apollo_uri",
     re.compile(r'''uri\s*:\s*[`"']([/][^`"'\s<>]{2,80})[`"']''', re.I)),

    # Bare string that looks exactly like an API path (as property value or array item)
    ("bare_path",
     re.compile(r'''[`"']([/](?:api|v\d|internal|graphql|rpc)[/][^`"'\s<>]{2,70})[`"']''', re.I)),
]

# Method keywords that appear near a URL in the same expression
_METHOD_HINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\.(delete|del)\s*\(', re.I), "DELETE"),
    (re.compile(r'\.(put)\s*\(',         re.I), "PUT"),
    (re.compile(r'\.(patch)\s*\(',       re.I), "PATCH"),
    (re.compile(r'\.(post)\s*\(',        re.I), "POST"),
    (re.compile(r'method\s*:\s*["`\']POST["`\']', re.I), "POST"),
    (re.compile(r'method\s*:\s*["`\']PUT["`\']',  re.I), "PUT"),
    (re.compile(r'method\s*:\s*["`\']DELETE["`\']', re.I), "DELETE"),
    (re.compile(r'method\s*:\s*["`\']PATCH["`\']',  re.I), "PATCH"),
]


def _is_valid_api_path(path: str) -> bool:
    """FP filter: return True only for plausible API paths."""
    if not path or not path.startswith("/"):
        return False
    for prefix in _REJECT_PREFIXES:
        if path.lower().startswith(prefix):
            return False
    # Must have at least one non-slash char after leading /
    stripped = path.lstrip("/")
    if len(stripped) < 3:
        return False
    # Reject pure asset paths
    for ext in _ASSET_EXTS:
        if stripped.lower().endswith(ext):
            return False
    # Must match overall shape
    if not _PATH_SHAPE.match(path.rstrip("/")):
        return False
    # Must contain at least one letter
    if not re.search(r'[a-zA-Z]', path):
        return False
    return True


def _infer_method_from_context(context: str) -> str:
    """Peek at ~200 chars around the match for HTTP method hints."""
    for pattern, method in _METHOD_HINTS:
        if pattern.search(context):
            return method
    return "GET"


def _regex_pass(js_content: str, base_url: str) -> list[tuple[str, str, str]]:
    """
    Pass 1: regex extraction.
    Returns list of (path, method, evidence_note).
    """
    results: list[tuple[str, str, str]] = []
    for name, pattern in _PATTERNS:
        for m in pattern.finditer(js_content):
            path = m.group(1)
            if not _is_valid_api_path(path):
                continue
            # Look at surrounding context (±200 chars) for method hints
            start   = max(0, m.start() - 200)
            end     = min(len(js_content), m.end() + 200)
            context = js_content[start:end]
            method  = _infer_method_from_context(context)
            results.append((path, method, f"regex:{name}"))
    return results


def _ast_pass(js_content: str) -> list[tuple[str, str, str]]:
    """
    Pass 2: lightweight token-level AST walk.
    Extracts string literals and checks if they look like API paths.

    We tokenise by splitting on string delimiters and examining each
    string token — this catches paths stored in variables or arrays
    that the regex patterns might not see.
    """
    results: list[tuple[str, str, str]] = []

    # Tokenise: find all string literals (single, double, backtick)
    string_pattern = re.compile(
        r'''(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`)'''
    )
    for m in string_pattern.finditer(js_content):
        raw = m.group(1) or m.group(2) or m.group(3) or ""
        # Skip very long strings (they're prose, not paths)
        if len(raw) > 200:
            continue
        # Check if the string IS an API path
        if _is_valid_api_path(raw):
            # Look at property name to the left for method hint
            pre = js_content[max(0, m.start()-50):m.start()]
            method = _infer_method_from_context(pre + raw)
            results.append((raw, method, "ast:string_literal"))
            continue
        # Check if the string contains a path as a substring (e.g. full URL)
        url_match = re.search(r'https?://[^/\s`"\']+([/][a-zA-Z][a-zA-Z0-9_/-]{2,79})', raw)
        if url_match:
            path = url_match.group(1)
            if _is_valid_api_path(path):
                results.append((path, "GET", "ast:full_url"))

    return results


def _extract_import_urls(js_content: str, current_url: str, base_url: str) -> list[str]:
    """
    Find import/require statements pointing to other JS files so we can
    recursively fetch them.
    """
    patterns = [
        re.compile(r'''import\s+.*?\s+from\s+[`"']([^`"']+\.js(?:\?[^`"']*)?)[`"']'''),
        re.compile(r'''require\s*\(\s*[`"']([^`"']+\.js(?:\?[^`"']*)?)[`"']\s*\)'''),
        re.compile(r'''import\s*\(\s*[`"']([^`"']+\.js(?:\?[^`"']*)?)[`"']\s*\)'''),
        re.compile(r'''<script[^>]+src\s*=\s*[`"']([^`"']+\.js(?:\?[^`"']*)?)[`"']'''),
    ]
    urls: list[str] = []
    for pat in patterns:
        for m in pat.finditer(js_content):
            href = m.group(1)
            if href.startswith("http"):
                urls.append(href)
            elif href.startswith("/"):
                urls.append(base_url.rstrip("/") + href)
            else:
                urls.append(urljoin(current_url, href))
    return urls


# ── Tag + priority helpers (same logic as openapi_parser) ────────────────────
_TAG_KEYWORDS: dict[str, list[str]] = {
    "payment":  ["payment", "pay", "billing", "invoice", "charge", "transaction",
                 "refund", "wallet", "balance"],
    "order":    ["order", "cart", "checkout", "purchase"],
    "admin":    ["admin", "manage", "internal", "staff"],
    "user":     ["user", "account", "profile", "member"],
    "auth":     ["auth", "login", "logout", "token", "refresh", "oauth", "password"],
    "product":  ["product", "item", "sku", "catalog", "inventory"],
    "transfer": ["transfer", "withdraw", "deposit", "send"],
}


def _infer_tags(path: str) -> list[str]:
    lp = path.lower()
    return [tag for tag, kws in _TAG_KEYWORDS.items() if any(k in lp for k in kws)]


def _priority(tags: list[str]) -> int:
    if any(t in tags for t in ("admin", "payment", "transfer")):
        return 1
    if any(t in tags for t in ("auth", "order", "user")):
        return 2
    return 3


# ── Main async class ──────────────────────────────────────────────────────────

class JSASTParser:
    """
    Fetches JS files referenced from the target page and extracts API paths
    using both regex and AST passes.
    """

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
        result = LayerResult(layer="layer2:js")
        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        headers: dict = {"Accept": "text/javascript,application/javascript,*/*"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # ── Step 1: fetch the root HTML to collect initial JS URLs ────────────
        js_urls_to_fetch: list[str] = []
        html_content = ""
        try:
            async with session.get(
                target_url, headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    html_content = await resp.text(errors="replace")
        except Exception as e:
            result.errors.append(f"root fetch: {e}")
            result.elapsed_s = time.time() - t0
            return result

        # Extract JS file URLs from the HTML
        for m in re.finditer(
            r'<script[^>]+src\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
            html_content, re.I,
        ):
            href = m.group(1)
            if href.startswith("http"):
                js_urls_to_fetch.append(href)
            elif href.startswith("/"):
                js_urls_to_fetch.append(base + href)
            else:
                js_urls_to_fetch.append(urljoin(target_url, href))

        # Also run passes directly on inline <script> content
        inline_scripts = re.findall(
            r'<script(?:[^>]*)>(.*?)</script>', html_content, re.S | re.I
        )
        inline_results: list[tuple[str, str, str]] = []
        for inline in inline_scripts:
            inline_results.extend(_regex_pass(inline, base))
            inline_results.extend(_ast_pass(inline))

        # ── Step 2: fetch and parse each JS file (with recursive import follow) ─
        fetched:     set[str]   = set()
        all_raw:     list[tuple[str, str, str]] = list(inline_results)
        queue:       list[str]  = list(js_urls_to_fetch[:config.max_js_files])
        depth_count: int        = 0
        max_depth                = 3

        while queue and len(fetched) < config.max_js_files:
            url = queue.pop(0)
            if url in fetched:
                continue
            fetched.add(url)

            try:
                async with session.get(
                    url, headers=headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        continue
                    ct      = resp.headers.get("Content-Type", "")
                    content = await resp.text(errors="replace")

                # Reject non-JS (e.g. redirected to login HTML)
                if "<html" in content[:300].lower() and "script" not in ct.lower():
                    continue

                # Both passes on this file
                all_raw.extend(_regex_pass(content, base))
                all_raw.extend(_ast_pass(content))

                # Follow imports if enabled and within depth
                if config.follow_js_imports and depth_count < max_depth:
                    imports = _extract_import_urls(content, url, base)
                    for imp in imports:
                        if imp not in fetched and len(fetched) + len(queue) < config.max_js_files:
                            queue.append(imp)
                    depth_count += 1

            except Exception as e:
                if self.verbose:
                    result.errors.append(f"js fetch {url}: {e}")

        # ── Step 3: deduplicate raw results and build DiscoveredEndpoints ─────
        seen_keys: set[str] = set()

        for path, method, evidence in all_raw:
            full_url = base + path
            key      = dedup_key(full_url, method)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            source     = SOURCE_JS_AST if "ast:" in evidence else SOURCE_JS_REGEX
            confidence = 0.80 if source == SOURCE_JS_AST else 0.70
            _, tmpl    = normalise_url(full_url)
            tags       = _infer_tags(path)

            ep = DiscoveredEndpoint(
                url=full_url, method=method,
                source=source, confidence=confidence,
                priority=_priority(tags),
                id_params=extract_id_params(path),
                tags=tags,
                raw_source_evidence=evidence,
                normalised_template=tmpl,
            )
            result.endpoints.append(ep)

        if result.endpoints:
            print(
                f"  [+] JS analysis: {len(fetched)} files, "
                f"{len(result.endpoints)} endpoints extracted"
            )
        elif self.verbose:
            print(f"  [JS] {len(fetched)} files analysed, no endpoints found")

        result.elapsed_s = time.time() - t0
        return result

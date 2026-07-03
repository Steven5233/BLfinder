"""
BLFinder v3.1 — core/discovery/layer4_wordlist/smart_wordlist.py
Context-seeded wordlist generator + async endpoint prober.

Termux-safe: stdlib + aiohttp only.

Strategy (FP-reduction aligned)
---------------------------------
The wordlist is NOT static. It is built at runtime by combining:
  1. Domain-context nouns (extracted from hostname + page title + meta desc)
  2. Already-discovered path segments from earlier layers
  3. Business-tag segments (if config.business_tags is set)
  4. Response body keys from baseline responses (field names → path guesses)
  5. A tiered base wordlist (depth 1=200 words … depth 5=10,000+ words)

A probed path is only added as a finding if the response:
  - Returns HTTP 200, 201, 204, 301, or 302
  - Is NOT a soft-404 (detected by comparing to a known-bad canary path)
  - Is NOT an HTML page (checked via Content-Type + body sniff)
  - Returns at least 20 bytes

Confidence: 0.60 for wordlist-only finds (lowest tier — needs scanner verification)
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse


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

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_WORDLIST, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import normalise_url, extract_id_params, dedup_key


# ── Tiered base wordlist ──────────────────────────────────────────────────────
# Depth 1: high-signal universal paths (~200)
_BASE_DEPTH1 = [
    # Core REST resource names
    "users","user","accounts","account","profile","profiles",
    "me","self","session","sessions","auth","login","logout",
    "register","signup","token","tokens","refresh",
    "orders","order","cart","carts","checkout","payments","payment",
    "products","product","items","item","catalog","catalogue",
    "search","suggest","autocomplete","query",
    "admin","manage","management","dashboard","settings","config",
    "health","status","ping","metrics","info","version",
    "api","v1","v2","v3","internal","legacy","beta","public",
    "graphql","rpc","ws","websocket",
    # Common sub-paths
    "list","all","detail","details","create","update","delete","remove",
    "upload","download","export","import","batch","bulk","sync",
    "notifications","notification","events","event","webhooks","webhook",
    "reports","report","analytics","stats","logs","log","audit",
    "transactions","transaction","invoices","invoice","billing",
    "subscriptions","subscription","plans","plan","pricing",
    "transfers","transfer","withdraw","deposit","balance","wallet",
    "permissions","permission","roles","role","groups","group",
    "files","file","images","image","media","documents","document",
    "comments","comment","reviews","review","ratings","rating",
    "messages","message","inbox","outbox","thread","threads",
    "friends","followers","following","contacts","connections",
    "addresses","address","shipping","delivery",
    "coupons","coupon","vouchers","voucher","promo","promos","discount",
    "categories","category","tags","tag","labels","label",
    "campaigns","campaign","offers","offer",
    "customers","customer","vendors","vendor","merchants","merchant",
    "employees","employee","staff","team","members","member",
    "applications","application","apps","app","integrations","integration",
    "keys","key","secrets","secret","credentials","credential",
    "password","passwords","reset","confirm","verify","verification",
    "2fa","mfa","otp","totp","backup","recover","recovery",
]

# Depth 2: adds common sub-resource paths (~500 total with depth 1)
_BASE_DEPTH2 = _BASE_DEPTH1 + [
    "list","count","summary","overview","recent","latest","popular","featured",
    "activate","deactivate","enable","disable","lock","unlock","block","unblock",
    "approve","reject","cancel","complete","finalize","submit","draft","publish",
    "archive","restore","clone","duplicate","merge","split",
    "assign","unassign","attach","detach","link","unlink",
    "bulk","batch","multi","mass",
    "metadata","meta","attributes","attribute","properties","property","fields",
    "schema","schemas","types","type","enums","enum","constants",
    "templates","template","presets","preset","defaults","default",
    "history","timeline","activity","feed","stream","changes","changelog",
    "preferences","preference","options","option","flags","flag","features",
    "banks","bank","cards","card","ach","sepa","iban","swift","routing",
    "kyc","aml","compliance","verification","identity","onboarding",
    "referrals","referral","affiliates","affiliate","partners","partner",
    "quotes","quote","proposals","proposal","estimates","estimate","bids","bid",
    "assets","stock","inventory","warehouse","fulfillment","logistics",
    "tracking","shipments","shipment","packages","package","parcels","parcel",
    "returns","refunds","refund","chargebacks","chargeback","disputes","dispute",
    "receipts","receipt","statements","statement","ledger","journal","entries",
    "service","services","tasks","task","jobs","job","queue","queues","workers","worker",
    "cache","flush","purge","invalidate","refresh","reload",
    "test","tests","debug","trace","diagnostic","diagnostics","probe",
    "docs","documentation","help","faq","terms","privacy","legal",
    "geo","location","locations","places","place","regions","region","zones","zone",
    "currencies","currency","rates","rate","exchange","convert",
    "language","languages","locale","locales","i18n","translations","translation",
    "theme","themes","skin","skins","branding","brand","logo","banner",
    "integrations","oauth","sso","saml","ldap","scim","provisioning",
    "webhooks","callbacks","events","triggers","automation","workflow","workflows",
    "slack","jira","github","gitlab","zendesk","salesforce","hubspot","stripe",
    "mobile","ios","android","web","desktop","native",
    "public","private","protected","restricted","hidden","internal",
]

# Depth 3: adds less common + framework-specific paths
_BASE_DEPTH3 = _BASE_DEPTH2 + [
    "actuator","actuator/health","actuator/info","actuator/metrics",
    "actuator/env","actuator/beans","actuator/mappings",
    "_health","_status","_debug","_info","_metrics","_ping","_ready","_live",
    "ready","live","liveness","readiness","healthz","healthcheck",
    "swagger","openapi","api-docs","redoc","rapidoc",
    "admin/users","admin/settings","admin/logs","admin/stats","admin/dashboard",
    "api/health","api/status","api/info","api/version","api/config",
    "internal/health","internal/admin","internal/metrics","internal/debug",
    "ops","operations","maintenance","manage/users","manage/settings",
    "system","systems","server","servers","cluster","clusters","nodes","node",
    "plugins","plugin","modules","module","extensions","extension","addons","addon",
    "hooks","actions","filters","middleware","interceptors","processors",
    "batch/jobs","batch/status","batch/run","batch/cancel",
    "cron","scheduled","scheduler","jobs/status","jobs/run",
    "cache/keys","cache/stats","cache/flush",
    "proxy","proxies","gateway","gateways","relay","relays",
    "feeds","feed","rss","atom","sitemap",
    "backup","backups","restore","snapshots","snapshot",
    "import/status","export/status","export/download",
    "signup","register","onboard","invite","invites","invitations","invitation",
    "login/sso","login/oauth","login/magic","login/passwordless",
    "verify/email","verify/phone","verify/identity",
    "reset/password","reset/token","forgot/password",
    "payment/methods","payment/cards","payment/bank","payment/wallet",
    "checkout/session","checkout/complete","checkout/confirm",
    "order/status","order/track","order/cancel","order/refund",
    "product/search","product/suggest","product/related","product/reviews",
    "user/me","user/profile","user/settings","user/preferences",
    "users/search","users/invite","users/import","users/export",
    "token/refresh","token/revoke","token/validate","token/introspect",
]

# Depth 4 and 5 add full OWASP and SecLists-inspired paths
_BASE_DEPTH4 = _BASE_DEPTH3 + [
    f"api/v{i}" for i in range(1, 10)
] + [
    f"v{i}" for i in range(1, 10)
] + [
    "api/v1/users","api/v1/accounts","api/v1/orders","api/v1/payments",
    "api/v2/users","api/v2/accounts","api/v2/orders","api/v2/payments",
    "api/v1/admin","api/v2/admin","api/v1/me","api/v2/me",
    "api/v1/profile","api/v1/settings","api/v1/config",
    "api/v1/tokens","api/v1/sessions","api/v1/auth",
    "api/v1/products","api/v1/catalog","api/v1/categories",
    "api/v1/cart","api/v1/checkout","api/v1/transactions",
    "api/v1/notifications","api/v1/messages","api/v1/events",
    "api/v1/webhooks","api/v1/files","api/v1/upload","api/v1/media",
    "api/v1/reports","api/v1/analytics","api/v1/stats","api/v1/metrics",
    "api/v1/internal","api/v1/system","api/v1/health","api/v1/status",
    "rest/v1","rest/v2","rest/v3",
    "services/v1","services/v2",
    "mobile/v1","mobile/v2","mobile/api",
    "app/v1","app/v2","app/api",
    "v1/auth","v1/users","v1/orders","v1/payments","v1/admin",
    "v2/auth","v2/users","v2/orders","v2/payments","v2/admin",
]

_BASE_DEPTH5 = _BASE_DEPTH4  # depth 5 relies on context expansion below

_DEPTH_TO_BASE = {
    1: _BASE_DEPTH1,
    2: _BASE_DEPTH2,
    3: _BASE_DEPTH3,
    4: _BASE_DEPTH4,
    5: _BASE_DEPTH5,
}

# Business-tag wordlist segments
_TAG_SEGMENTS: dict[str, list[str]] = {
    "payment": [
        "payment","payments","pay","billing","invoice","invoices",
        "charge","charges","transaction","transactions","refund","refunds",
        "wallet","wallets","balance","balances","payout","payouts",
        "card","cards","bank","banks","ach","sepa","stripe","paypal",
        "checkout","checkout/session","payment/methods","payment/intents",
        "subscriptions","subscription","plans","plan","price","prices",
        "coupon","coupons","discount","discounts","promo","promos",
    ],
    "order": [
        "order","orders","cart","carts","checkout","purchase","purchases",
        "buy","basket","baskets","wishlist","wishlists","line-items",
        "order/status","order/track","order/cancel","order/refund",
        "returns","return","refund","refunds","exchange","exchanges",
        "shipments","shipment","tracking","fulfillment",
    ],
    "admin": [
        "admin","admin/users","admin/settings","admin/logs","admin/stats",
        "admin/orders","admin/payments","admin/dashboard","admin/config",
        "manage","management","backoffice","staff","operator","superuser",
        "internal","internal/admin","internal/users","internal/config",
        "panel","console","control","cp",
    ],
    "user": [
        "user","users","account","accounts","profile","profiles","me","self",
        "member","members","customer","customers","client","clients",
        "user/profile","user/settings","user/preferences","user/avatar",
        "users/search","users/invite","users/import","users/export",
        "user/notifications","user/activity","user/history",
    ],
    "auth": [
        "auth","auth/login","auth/logout","auth/register","auth/token",
        "auth/refresh","auth/verify","auth/reset","auth/forgot",
        "login","logout","register","signup","signin","signout",
        "token","tokens","session","sessions","oauth","oauth2","sso",
        "password","password/reset","password/change","password/forgot",
        "mfa","2fa","otp","totp","verify","verification","confirm",
    ],
    "fintech": [
        "transfer","transfers","withdraw","withdrawal","deposit","deposits",
        "beneficiary","beneficiaries","account/balance","account/statement",
        "statements","ledger","journal","kyc","aml","compliance",
        "sanctions","screening","risk","fraud","limits","limit",
        "exchange","rates","convert","conversion",
        "send","receive","remit","remittance",
    ],
}


# ── Context seed extraction ───────────────────────────────────────────────────

def _extract_domain_nouns(hostname: str) -> list[str]:
    """
    Extract business-relevant nouns from the domain name.
    e.g. 'shop.example.com' → ['shop'], 'api.paymentco.io' → ['payment']
    """
    parts = hostname.lower().replace("-", ".").replace("_", ".").split(".")
    # Remove generic TLDs and subdomains
    stop = {"www", "api", "app", "dev", "staging", "test", "beta",
            "prod", "com", "net", "org", "io", "co", "uk", "us", "eu"}
    nouns = [p for p in parts if p and p not in stop and len(p) > 2]
    return nouns[:3]


def _extract_body_key_paths(response_body: str) -> list[str]:
    """
    Mine JSON field names from baseline responses and turn them into path guesses.
    If the response contains "order_id", try /orders as a path.
    """
    if not response_body:
        return []
    # Extract all JSON keys
    keys = re.findall(r'"([a-z][a-z0-9_]{1,30})"', response_body.lower())
    paths: set[str] = set()
    for k in set(keys):
        # Pluralise and use as a path
        base = k.rstrip("_id").rstrip("id").strip("_")
        if len(base) >= 3:
            paths.add(f"/{base}s")
            paths.add(f"/{base}")
    return list(paths)[:30]


def _build_wordlist(
    config: "DiscoveryConfig",
    discovered_paths: list[str],
    baseline_bodies: list[str],
    hostname: str,
    page_html: str = "",
) -> list[str]:
    """
    Build the full contextual wordlist for a target.
    """
    depth = max(1, min(5, config.wordlist_depth))
    words: set[str] = set(_DEPTH_TO_BASE[depth])

    # Add domain nouns
    for noun in _extract_domain_nouns(hostname):
        words.add(noun)
        words.add(f"{noun}s")
        words.add(f"api/{noun}")
        words.add(f"api/{noun}s")
        words.add(f"v1/{noun}")
        words.add(f"v1/{noun}s")

    # Add business tag segments
    for tag in config.business_tags:
        for seg in _TAG_SEGMENTS.get(tag.lower(), []):
            words.add(seg)

    # Add segments derived from already-discovered paths
    for path in discovered_paths:
        for seg in path.strip("/").split("/"):
            if seg and len(seg) >= 2 and not re.match(r'^\d+$', seg):
                words.add(seg)
                # Add common sub-resources
                words.add(f"{seg}/list")
                words.add(f"{seg}/search")

    # Add paths derived from baseline response keys (depth 3+)
    if depth >= 3:
        for body in baseline_bodies[:5]:
            for path in _extract_body_key_paths(body):
                words.add(path.lstrip("/"))

    # Extract nouns from page title / meta description
    if page_html:
        title_m = re.search(r'<title[^>]*>(.*?)</title>', page_html, re.I | re.S)
        if title_m:
            title_words = re.findall(r'[a-z]{3,}', title_m.group(1).lower())
            for w in title_words[:10]:
                if len(w) >= 3:
                    words.add(w)

    return [w.strip("/") for w in sorted(words) if w and len(w) >= 2]


# ── Soft-404 canary ───────────────────────────────────────────────────────────

async def _get_canary_fingerprint(
    base: str, session: Any, timeout: int, headers: dict
) -> Optional[str]:
    """
    Fetch a known-nonexistent path to establish the soft-404 fingerprint.
    Returns the MD5 of the response body, or None if we can't determine it.
    """
    canary = f"{base}/blfinder_canary_xyz_does_not_exist_9z9z9"
    try:
        async with session.get(
            canary, headers=headers, allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=timeout), ssl=False,
        ) as resp:
            if resp.status in (200, 404):
                body = await resp.text(errors="replace")
                return hashlib.md5(body[:500].encode()).hexdigest()
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/layer4_wordlist/smart_wordlist.py#1", e)
        pass
    return None


def _is_real_api_response(
    status: int,
    content_type: str,
    body: str,
    canary_hash: Optional[str],
) -> bool:
    """
    FP filter: return True only for responses that look like real API endpoints.
    """
    if status not in (200, 201, 204, 301, 302, 401, 403):
        return False
    if len(body) < 10:
        return False
    # Soft-404 check
    if canary_hash:
        body_hash = hashlib.md5(body[:500].encode()).hexdigest()
        if body_hash == canary_hash:
            return False
    # Reject pure HTML
    ct = content_type.lower()
    if "text/html" in ct and "<html" in body[:200].lower():
        # Exception: if body also looks like JSON (some API gateways do this)
        if not body.strip().startswith("{") and not body.strip().startswith("["):
            return False
    return True


# ── Main async class ──────────────────────────────────────────────────────────

class SmartWordlist:

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def run(
        self,
        target_url: str,
        session: Any,
        config: "DiscoveryConfig",
        auth_token: str = "",
        discovered_paths: Optional[list[str]] = None,
        baseline_bodies:  Optional[list[str]] = None,
    ) -> LayerResult:
        if config.no_wordlist:
            return LayerResult(layer=SOURCE_WORDLIST)

        t0     = time.time()
        result = LayerResult(layer=SOURCE_WORDLIST)
        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        headers: dict = {
            "Accept": "application/json,*/*",
            "X-Requested-With": "XMLHttpRequest",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # Fetch root for context
        page_html = ""
        try:
            async with session.get(
                target_url, headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    page_html = await resp.text(errors="replace")
        except Exception as e:
            _blf_dbg("blfinder/core/discovery/layer4_wordlist/smart_wordlist.py#2", e)
            pass

        # Establish soft-404 fingerprint
        canary_hash = await _get_canary_fingerprint(
            base, session, config.timeout_s, headers
        )
        if self.verbose:
            print(f"  [wordlist] canary hash: {canary_hash or 'n/a'}")

        # Build wordlist
        wordlist = _build_wordlist(
            config,
            discovered_paths or [],
            baseline_bodies or [],
            parsed.netloc,
            page_html,
        )

        if self.verbose:
            print(f"  [wordlist] probing {len(wordlist)} paths (depth={config.wordlist_depth})")

        seen_keys: set[str] = set()

        def _tag_from_word(word: str) -> list[str]:
            tags: list[str] = []
            lw = word.lower()
            tag_map = {
                "payment": ["payment","pay","billing","transaction","wallet","balance","card"],
                "order":   ["order","cart","checkout","purchase","shipment"],
                "admin":   ["admin","manage","internal","staff","backoffice","panel","console"],
                "user":    ["user","account","profile","member","customer"],
                "auth":    ["auth","login","token","session","password","oauth","sso"],
            }
            for tag, kws in tag_map.items():
                if any(k in lw for k in kws):
                    tags.append(tag)
            return tags

        async def probe(word: str) -> Optional[DiscoveredEndpoint]:
            path     = "/" + word.lstrip("/")
            full_url = base + path
            key      = dedup_key(full_url, "GET")
            if key in seen_keys:
                return None

            try:
                async with session.get(
                    full_url, headers=headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    status = resp.status
                    ct     = resp.headers.get("Content-Type", "")
                    body   = await resp.text(errors="replace")

                    if not _is_real_api_response(status, ct, body, canary_hash):
                        return None

                    seen_keys.add(key)
                    _, tmpl = normalise_url(full_url)
                    tags    = _tag_from_word(word)

                    priority = 3
                    if any(t in tags for t in ("admin","payment")):
                        priority = 1
                    elif any(t in tags for t in ("auth","order","user")):
                        priority = 2

                    if self.verbose:
                        print(f"  [wl+] {status} {full_url}")

                    return DiscoveredEndpoint(
                        url=full_url, method="GET",
                        source=SOURCE_WORDLIST,
                        confidence=0.60,
                        priority=priority,
                        id_params=extract_id_params(path),
                        tags=tags,
                        raw_source_evidence=f"wordlist depth={config.wordlist_depth}",
                        normalised_template=tmpl,
                    )
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/layer4_wordlist/smart_wordlist.py#3", e)
                return None

        # Probe in concurrent batches (Termux-friendly: small batches)
        batch_size = 15
        for i in range(0, len(wordlist), batch_size):
            batch    = wordlist[i:i + batch_size]
            findings = await asyncio.gather(*[probe(w) for w in batch])
            for ep in findings:
                if ep:
                    result.endpoints.append(ep)

        ep_count = len(result.endpoints)
        if ep_count:
            print(f"  [+] Wordlist: {ep_count} live paths found")

        result.elapsed_s = time.time() - t0
        return result

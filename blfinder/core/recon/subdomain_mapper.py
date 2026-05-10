"""
BLFinder Phase 3 — core/recon/subdomain_mapper.py
Subdomain Mapper

Discovers the real API attack surface for a target domain via:
  1. Certificate transparency (crt.sh) — finds all issued TLS certs
  2. Common subdomain wordlist probing
  3. Live host detection + response fingerprinting
  4. API surface scoring — ranks subdomains by attack value

The Twilio example: twilio.com scores LOW (marketing site),
console.twilio.com scores HIGH (authenticated console),
api.twilio.com scores CRITICAL (REST API surface).

Rate limiting: crt.sh requests are throttled to 1/second.
All probes use async batching with configurable concurrency.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


# ── Scoring constants ─────────────────────────────────────────────────────────

# Subdomains containing these keywords score higher
_HIGH_VALUE_KEYWORDS = {
    "api":         50,
    "console":     45,
    "dashboard":   45,
    "app":         40,
    "portal":      40,
    "admin":       50,
    "manage":      40,
    "internal":    50,
    "graphql":     50,
    "gql":         50,
    "gateway":     45,
    "service":     35,
    "services":    35,
    "backend":     45,
    "dev":         30,
    "staging":     30,
    "beta":        30,
    "v1":          40,
    "v2":          40,
    "v3":          40,
    "rest":        45,
    "rpc":         45,
    "data":        35,
    "platform":    35,
    "cloud":       25,
    "auth":        45,
    "sso":         40,
    "oauth":       40,
    "login":       35,
    "account":     35,
    "accounts":    35,
    "monitor":     35,
    "metrics":     35,
    "insights":    35,
    "reporting":   30,
}

# Subdomains containing these keywords score lower (less interesting)
_LOW_VALUE_KEYWORDS = {
    "www": -20, "mail": -30, "smtp": -30, "ftp": -30,
    "blog": -20, "docs": -10, "help": -10, "support": -10,
    "cdn": -30, "static": -30, "assets": -30, "media": -30,
    "status": -10, "marketing": -20,
}

# Common subdomain wordlist for brute force probing
_COMMON_SUBDOMAINS = [
    # API tiers
    "api", "api2", "api3", "api-v1", "api-v2", "api-v3",
    "v1", "v2", "v3", "v4",
    # Console / Dashboard
    "console", "dashboard", "app", "portal", "manage", "management",
    # Auth
    "auth", "sso", "login", "oauth", "identity",
    # Internal
    "internal", "internal-api", "private", "backend",
    "admin", "administrator",
    # GraphQL
    "graphql", "gql",
    # Gateway
    "gateway", "proxy", "service", "services",
    # Data
    "data", "analytics", "metrics", "reporting", "insights", "monitor",
    # Dev/Staging
    "dev", "development", "staging", "stage", "beta", "sandbox",
    "test", "testing", "qa",
    # Cloud
    "cloud", "platform",
    # Accounts
    "account", "accounts", "my", "user", "users", "customer",
    # REST
    "rest", "rpc",
]


@dataclass
class SubdomainResult:
    """A single discovered subdomain with metadata."""
    hostname:    str
    ip:          str = ""
    status:      int = 0
    title:       str = ""
    server:      str = ""
    content_type: str = ""
    response_size: int = 0
    is_live:     bool = False
    score:       int = 0
    source:      str = ""    # "crtsh", "wordlist", "provided"
    api_paths:   list[str] = field(default_factory=list)
    notes:       list[str] = field(default_factory=list)

    @property
    def base_url(self) -> str:
        return f"https://{self.hostname}"

    @property
    def priority(self) -> str:
        if self.score >= 40:
            return "CRITICAL"
        if self.score >= 25:
            return "HIGH"
        if self.score >= 10:
            return "MEDIUM"
        return "LOW"

    @property
    def is_api_surface(self) -> bool:
        return self.score >= 25 and self.is_live


@dataclass
class SubdomainMapResult:
    """Full result of a subdomain mapping operation."""
    target_domain:  str
    subdomains:     list[SubdomainResult] = field(default_factory=list)
    total_found:    int = 0
    live_count:     int = 0
    api_count:      int = 0
    elapsed_sec:    float = 0.0
    crtsh_count:    int = 0
    wordlist_count: int = 0

    @property
    def high_priority(self) -> list[SubdomainResult]:
        return [s for s in self.subdomains if s.priority in ("CRITICAL", "HIGH")]

    @property
    def all_base_urls(self) -> list[str]:
        return [s.base_url for s in self.subdomains if s.is_live]

    def to_endpoints(self) -> list[dict]:
        """
        Convert high-priority discovered subdomains to endpoints.json format
        for injection into the scanner.
        """
        endpoints = []
        common_api_paths = [
            "/api/v1", "/api/v2", "/api", "/v1", "/v2",
            "/graphql", "/api/graphql",
            "/api/users", "/api/me",
            "/api/orders", "/api/payments",
        ]
        for sub in self.high_priority:
            if not sub.is_live:
                continue
            for path in sub.api_paths or common_api_paths[:4]:
                endpoints.append({
                    "url":    f"https://{sub.hostname}{path}",
                    "method": "GET",
                    "body":   {},
                    "params": {},
                    "_source": f"subdomain_mapper:{sub.source}",
                })
        return endpoints


class SubdomainMapper:
    """
    Discovers subdomains and ranks them by API attack surface value.

    Usage:
        mapper = SubdomainMapper(verbose=True)
        result = await mapper.map("twilio.com", max_wordlist=50)

        for sub in result.high_priority:
            print(f"{sub.priority}: {sub.hostname} (score={sub.score})")

        # Inject into scanner
        extra_endpoints = result.to_endpoints()
    """

    _CRTSH_URL   = "https://crt.sh/?q={domain}&output=json"
    _CRTSH_DELAY = 1.2    # seconds between crt.sh requests
    _PROBE_CONCURRENCY = 10

    def __init__(self, verbose: bool = False):
        self.verbose   = verbose
        self._last_crtsh_request = 0.0

    async def map(
        self,
        target_domain: str,
        max_wordlist:  int = 100,
        use_crtsh:     bool = True,
        use_wordlist:  bool = True,
        session: "aiohttp.ClientSession | None" = None,
    ) -> SubdomainMapResult:
        """
        Run full subdomain discovery for a target domain.

        Args:
            target_domain: e.g. "twilio.com" or "console.twilio.com"
            max_wordlist:  How many wordlist probes to run (default 100)
            use_crtsh:     Enable certificate transparency lookup
            use_wordlist:  Enable wordlist brute force
            session:       Optional aiohttp session (creates one if None)
        """
        start       = time.time()
        base_domain = _extract_root_domain(target_domain)
        result      = SubdomainMapResult(target_domain=base_domain)

        if self.verbose:
            print(f"[*] Subdomain mapping: {base_domain}")

        # Create session if not provided
        own_session = session is None
        if own_session and _HAS_AIOHTTP:
            connector = aiohttp.TCPConnector(ssl=False, limit=20)
            session   = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10),
            )

        try:
            found_hostnames: set[str] = set()

            # Step 1: Certificate transparency
            if use_crtsh:
                crt_hosts = await self._query_crtsh(base_domain, session)
                found_hostnames.update(crt_hosts)
                result.crtsh_count = len(crt_hosts)
                if self.verbose:
                    print(f"  [+] crt.sh: {len(crt_hosts)} subdomains")

            # Step 2: Wordlist probing
            if use_wordlist:
                wordlist = _COMMON_SUBDOMAINS[:max_wordlist]
                wl_hosts = [
                    f"{word}.{base_domain}" for word in wordlist
                ]
                found_hostnames.update(wl_hosts)
                result.wordlist_count = len(wl_hosts)

            # Always include the base domain and www
            found_hostnames.add(base_domain)
            found_hostnames.add(f"www.{base_domain}")

            result.total_found = len(found_hostnames)
            if self.verbose:
                print(f"  [*] Total candidates: {result.total_found}")

            # Step 3: Live host probing
            subdomain_objects = [
                SubdomainResult(hostname=h, source="crtsh" if h in (crt_hosts if use_crtsh else set()) else "wordlist")
                for h in sorted(found_hostnames)
            ]

            live_results = await self._probe_live(subdomain_objects, session)
            result.subdomains = live_results
            result.live_count = sum(1 for s in live_results if s.is_live)
            result.api_count  = sum(1 for s in live_results if s.is_api_surface)

            if self.verbose:
                print(
                    f"  [*] Live: {result.live_count}, "
                    f"API surface: {result.api_count}"
                )
                for sub in result.high_priority:
                    print(
                        f"  [{sub.priority}] {sub.hostname} "
                        f"(score={sub.score})"
                    )

        finally:
            if own_session and session:
                await session.close()

        result.elapsed_sec = time.time() - start
        return result

    # ── crt.sh query ──────────────────────────────────────────────────────────

    async def _query_crtsh(
        self, domain: str, session
    ) -> set[str]:
        """Query certificate transparency logs via crt.sh."""
        if session is None:
            return set()

        # Rate limit
        since_last = time.time() - self._last_crtsh_request
        if since_last < self._CRTSH_DELAY:
            await asyncio.sleep(self._CRTSH_DELAY - since_last)
        self._last_crtsh_request = time.time()

        url = self._CRTSH_URL.format(domain=domain)
        hostnames: set[str] = set()

        try:
            async with session.get(
                url,
                headers={"User-Agent": "BLFinder/3.0 security-research"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    return hostnames
                text = await resp.text()
                try:
                    entries = json.loads(text)
                    for entry in entries:
                        # name_value can be "*.domain.com\nsubdomain.domain.com"
                        raw = entry.get("name_value", "") or entry.get("common_name", "")
                        for name in raw.split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and _is_valid_subdomain(name, domain):
                                hostnames.add(name.lower())
                except (json.JSONDecodeError, ValueError, KeyError):
                    # crt.sh sometimes returns malformed JSON
                    pass

        except asyncio.TimeoutError:
            if self.verbose:
                print("  [!] crt.sh timeout")
        except Exception as e:
            if self.verbose:
                print(f"  [!] crt.sh error: {e}")

        return hostnames

    # ── Live probing ──────────────────────────────────────────────────────────

    async def _probe_live(
        self,
        subdomains: list[SubdomainResult],
        session,
    ) -> list[SubdomainResult]:
        """Probe a list of subdomains for liveness in async batches."""
        if session is None:
            # No session — just score based on hostname
            for sub in subdomains:
                sub.score = _score_hostname(sub.hostname)
            return sorted(subdomains, key=lambda s: s.score, reverse=True)

        semaphore = asyncio.Semaphore(self._PROBE_CONCURRENCY)

        async def probe_one(sub: SubdomainResult) -> SubdomainResult:
            async with semaphore:
                return await self._probe_single(sub, session)

        results = await asyncio.gather(
            *[probe_one(s) for s in subdomains],
            return_exceptions=True,
        )

        live = []
        for r in results:
            if isinstance(r, SubdomainResult):
                live.append(r)
            elif isinstance(r, Exception) and self.verbose:
                print(f"  [!] Probe error: {r}")

        return sorted(live, key=lambda s: s.score, reverse=True)

    async def _probe_single(
        self,
        sub: SubdomainResult,
        session,
    ) -> SubdomainResult:
        """Probe a single subdomain for liveness and metadata."""
        url = f"https://{sub.hostname}"
        sub.score = _score_hostname(sub.hostname)

        try:
            async with session.get(
                url,
                allow_redirects=True,
                max_redirects=3,
                timeout=aiohttp.ClientTimeout(total=8),
                headers={"User-Agent": "Mozilla/5.0 BLFinder/3.0"},
            ) as resp:
                sub.status  = resp.status
                sub.is_live = resp.status not in (0,)
                body        = await resp.text(errors="replace")

                # Extract metadata
                for k, v in resp.headers.items():
                    k_lower = k.lower()
                    if k_lower == "server":
                        sub.server = v[:50]
                    elif k_lower == "content-type":
                        sub.content_type = v.lower()

                sub.response_size = len(body)
                sub.title         = _extract_title(body)

                # Boost score for JSON responses (API surface)
                if "json" in sub.content_type:
                    sub.score += 20
                    sub.notes.append("Returns JSON")

                # Boost for API-related response patterns
                if _body_looks_like_api(body):
                    sub.score += 15
                    sub.notes.append("API-like response body")

                # Auth-required responses are very valuable
                if resp.status in (401, 403):
                    sub.score += 10
                    sub.notes.append(f"Auth required (HTTP {resp.status})")

                # Probe common API paths for live subdomains
                if sub.score >= 20 and sub.is_live:
                    sub.api_paths = await self._discover_api_paths(
                        sub.hostname, session
                    )

        except asyncio.TimeoutError:
            sub.notes.append("Timeout")
        except aiohttp.ClientConnectorError:
            sub.is_live = False
            sub.notes.append("Connection refused or DNS failed")
        except Exception as e:
            sub.notes.append(f"Error: {str(e)[:40]}")

        return sub

    async def _discover_api_paths(
        self, hostname: str, session
    ) -> list[str]:
        """Quick probe for common API paths on a live subdomain."""
        candidates = [
            "/api/v1", "/api/v2", "/api", "/v1", "/v2",
            "/graphql", "/api/graphql", "/health", "/status",
        ]
        live_paths = []
        for path in candidates:
            url = f"https://{hostname}{path}"
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                    headers={"User-Agent": "Mozilla/5.0 BLFinder/3.0"},
                ) as resp:
                    if resp.status in (200, 201, 401, 403):
                        live_paths.append(path)
            except Exception:
                pass
        return live_paths


# ── Scoring ───────────────────────────────────────────────────────────────────

def _score_hostname(hostname: str) -> int:
    """Score a hostname by its likely API attack surface value."""
    score    = 0
    hostname = hostname.lower()
    parts    = hostname.split(".")

    # Score based on subdomain keywords
    for part in parts[:-2]:   # Exclude the TLD parts
        for keyword, pts in _HIGH_VALUE_KEYWORDS.items():
            if keyword in part:
                score += pts
                break
        for keyword, pts in _LOW_VALUE_KEYWORDS.items():
            if keyword in part:
                score += pts
                break

    # Penalty for deeply nested subdomains (likely CDN)
    if len(parts) > 4:
        score -= 10

    return max(0, score)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_root_domain(domain: str) -> str:
    """Extract root domain from URL or hostname."""
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _is_valid_subdomain(name: str, parent_domain: str) -> bool:
    """Validate that a name is a subdomain of the parent domain."""
    name = name.lower().strip()
    if not name:
        return False
    if not name.endswith(f".{parent_domain}") and name != parent_domain:
        return False
    # Filter out wildcards and garbage
    if "*" in name or " " in name:
        return False
    # Basic hostname validation
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', name):
        return False
    return True


def _extract_title(html: str) -> str:
    """Extract the <title> tag from HTML."""
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    if m:
        return m.group(1).strip()[:80]
    return ""


def _body_looks_like_api(body: str) -> bool:
    """Quick check if a response body looks like an API response."""
    if not body:
        return False
    b = body.strip()
    if b.startswith("{") or b.startswith("["):
        try:
            json.loads(b)
            return True
        except (json.JSONDecodeError, ValueError):
            pass
    return False

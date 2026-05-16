"""
core/discovery/hidden_endpoint_hunter.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HIDDEN ENDPOINT DISCOVERY ENGINE
Strategic algorithm for finding undocumented, internal, and legacy API paths
that frequently lack modern security controls.

ALGORITHM OVERVIEW
══════════════════

Phase 1 — Technology Fingerprinting
  Identify the framework/stack from response headers, error pages, and
  meta-tokens. Selects a framework-specific wordlist instead of generic paths.
  Django → /api/admin/, /__debug__/
  Laravel → /api/telescope/, /horizon/
  Spring  → /actuator/, /management/
  Rails   → /rails/info/, /sidekiq/
  Express → /graphql, /_health
  etc.

Phase 2 — Known Path Mutation (High-Value Prefix/Suffix Injection)
  Takes every already-discovered path and mutates it with high-value
  prefixes and suffixes that developers add for internal/admin variants:

  Discovered: /api/v1/users
  Generates:
    /api/v1/internal/users        ← internal namespace
    /api/v1/admin/users           ← admin namespace
    /api/v1/users/admin           ← admin suffix
    /api/v1/private/users         ← private namespace
    /api/v1/users/export          ← data export (high value)
    /api/v1/users/debug           ← debug endpoint
    /api/v1/users/all             ← bypass pagination
    /api/v1/users/bulk            ← bulk operations
    /api/v1/users/delete          ← destructive ops (often unprotected)
    /api/v1/users/purge
    /api/v1/staff/users           ← staff namespace
    /api/v1/users?include_deleted=true
    /api/v2/internal/users        ← cross-version internal
    /api/internal/v1/users        ← internal prefix before version

Phase 3 — Response-Driven Recursive Expansion
  When an endpoint returns a JSON object with string values that look like
  paths ("/api/v1/payments/confirm"), those paths are queued for probing.
  When a 200 response is received, extract all sub-paths and recurse
  up to max_depth levels.

Phase 4 — Mobile API Path Discovery
  Modern apps have separate mobile API surfaces. Probes common mobile
  path patterns:
    /mobile/api/v1/...
    /app/api/...
    /mapi/...
    /ios/api/...
    /android/api/...
  Also probes with mobile User-Agent headers to trigger mobile-specific
  routing in the backend.

Phase 5 — Historical High-Value Path Mining
  A curated list of paths that have appeared in real HackerOne reports,
  security research, and breach disclosures — paths that developers
  leave exposed because they assume no one knows they exist.

Phase 6 — Parameter Brute-Force on Silent Endpoints
  Some hidden endpoints return 404 with no body normally but respond to
  specific query parameters. Tests a curated list of "activation params":
    ?debug=true, ?admin=1, ?internal=true, ?format=json,
    ?_format=json, ?api_key=test, ?token=test, ?XDEBUG_SESSION=1

Phase 7 — HTTP Method Expansion
  Many hidden endpoints only respond to non-standard methods.
  Tests OPTIONS first (reveals allowed methods), then tests each allowed
  method that wasn't in the original discovery.

SCORING
═══════
Each candidate is scored before probing:
  +30  path contains high-value keyword (admin, internal, debug, export)
  +20  path matches framework-specific pattern
  +15  path is a mutation of a confirmed-200 endpoint
  +10  path found in historical HackerOne corpus
  +5   path has a version component (v1, v2, internal)
  -10  path is obviously static (*.css, *.js, *.png, *.woff)

Only paths with score > 0 are probed. High-score paths are probed first.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin, urlencode


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HiddenEndpoint:
    url:        str
    method:     str  = "GET"
    score:      int  = 0
    source:     str  = ""          # which phase found it
    status:     int  = 0
    body:       str  = ""
    params:     dict = field(default_factory=dict)
    body_fields: dict = field(default_factory=dict)
    is_interesting: bool = False
    interest_reason: str = ""


@dataclass
class HunterResult:
    endpoints:   list[HiddenEndpoint] = field(default_factory=list)
    tech_stack:  list[str]            = field(default_factory=list)
    total_probed: int                 = 0
    total_found:  int                 = 0
    errors:      list[str]            = field(default_factory=list)
    elapsed_s:   float                = 0.0

    def summary(self) -> str:
        return (
            f"[hidden_hunter] {self.total_found} hidden endpoints found "
            f"from {self.total_probed} probed "
            f"| stack: {', '.join(self.tech_stack) or 'unknown'} "
            f"| {self.elapsed_s:.1f}s"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Technology fingerprinting signatures
# ─────────────────────────────────────────────────────────────────────────────

TECH_SIGNATURES: dict[str, dict] = {
    "django": {
        "headers": ["x-frame-options", "csrftoken"],
        "body_patterns": [
            r"Django", r"CSRF verification", r"DisallowedHost",
            r"django\.core", r"using=.*django",
        ],
        "paths": [
            "/admin/", "/admin/login/", "/api/admin/",
            "/__debug__/", "/django-admin/",
            "/api/schema/", "/api/docs/",
            "/api/v1/admin/", "/api/v2/admin/",
            "/internal/admin/", "/_internal/",
        ],
    },
    "laravel": {
        "headers": ["x-powered-by: php", "laravel_session", "xsrf-token"],
        "body_patterns": [
            r"Laravel", r"Illuminate\\", r"laravel",
            r"Whoops!", r"\.blade\.php",
        ],
        "paths": [
            "/api/telescope/", "/telescope/", "/telescope/api/",
            "/horizon/", "/horizon/api/",
            "/api/user/", "/sanctum/csrf-cookie",
            "/api/admin/", "/_ignition/",
            "/api/v1/admin/", "/api/internal/",
        ],
    },
    "spring": {
        "headers": ["x-application-context", "x-content-type-options"],
        "body_patterns": [
            r"Spring Framework", r"Whitelabel Error Page",
            r"org\.springframework", r"application/hal\+json",
        ],
        "paths": [
            "/actuator", "/actuator/health", "/actuator/info",
            "/actuator/env", "/actuator/mappings", "/actuator/beans",
            "/actuator/metrics", "/actuator/loggers",
            "/actuator/httptrace", "/actuator/heapdump",
            "/management/", "/management/health",
            "/api/actuator/", "/monitor/",
            "/internal/actuator/",
        ],
    },
    "express": {
        "headers": ["x-powered-by: express"],
        "body_patterns": [
            r"Cannot GET", r"Cannot POST",
            r"express", r"node_modules",
        ],
        "paths": [
            "/graphql", "/api/graphql", "/_health",
            "/health", "/healthz", "/ready",
            "/metrics", "/debug", "/api/debug/",
            "/api/internal/", "/api/admin/",
            "/__admin", "/api/v1/internal/",
        ],
    },
    "rails": {
        "headers": ["x-runtime", "x-request-id"],
        "body_patterns": [
            r"ActionController", r"ActiveRecord",
            r"Rails\.application", r"config/routes",
        ],
        "paths": [
            "/rails/info/", "/rails/info/properties",
            "/rails/mailers", "/rails/routes",
            "/sidekiq/", "/resque/",
            "/admin/", "/api/admin/",
            "/cable", "/api/v1/admin/",
            "/internal/", "/api/internal/",
        ],
    },
    "fastapi": {
        "headers": ["x-process-time"],
        "body_patterns": [
            r'"detail":', r"FastAPI", r"pydantic",
            r'"type":"about:blank"',
        ],
        "paths": [
            "/docs", "/redoc", "/openapi.json",
            "/api/v1/docs", "/api/docs",
            "/api/v1/admin/", "/api/admin/",
            "/api/internal/", "/metrics",
            "/health", "/api/v1/health",
        ],
    },
    "wordpress": {
        "headers": ["x-pingback"],
        "body_patterns": [
            r"wp-content", r"wp-json", r"WordPress",
            r"wp-login", r"xmlrpc\.php",
        ],
        "paths": [
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts",
            "/wp-json/", "/wp-admin/",
            "/wp-login.php", "/xmlrpc.php",
            "/wp-json/wc/v3/", "/wp-json/wc/v2/",
            "/wp-cron.php", "/?author=1",
            "/wp-json/wp/v2/media",
        ],
    },
    "graphql": {
        "headers": [],
        "body_patterns": [
            r'"__schema"', r'"__typename"',
            r"graphql", r'"data":\s*\{',
        ],
        "paths": [
            "/graphql", "/api/graphql", "/query",
            "/gql", "/graphql/console",
            "/graphiql", "/playground",
            "/api/v1/graphql", "/v1/graphql",
            "/api/v2/graphql",
        ],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# High-value path mutation prefixes and suffixes
# ─────────────────────────────────────────────────────────────────────────────

# Prefixes injected between the base path and the resource name
HIGH_VALUE_PREFIXES = [
    "internal", "admin", "private", "staff", "sys",
    "system", "manage", "management", "ops", "operations",
    "debug", "test", "dev", "develop", "development",
    "staging", "qa", "uat", "beta", "experimental",
    "v0", "v2", "v3", "legacy", "old", "deprecated",
    "hidden", "secret", "confidential", "restricted",
    "privileged", "superadmin", "super", "root",
    "partner", "vendor", "third-party", "b2b",
    "backoffice", "back-office", "backend", "core",
    "platform", "service", "svc", "micro",
]

# Suffixes appended to the resource path
HIGH_VALUE_SUFFIXES = [
    "admin", "internal", "debug", "test", "all",
    "export", "dump", "download", "bulk", "batch",
    "delete", "purge", "destroy", "wipe", "reset",
    "config", "configuration", "settings", "setup",
    "metrics", "stats", "statistics", "analytics",
    "audit", "log", "logs", "history", "trace",
    "raw", "full", "complete", "unfiltered",
    "hidden", "archived", "deleted", "inactive",
    "list", "search", "query", "find",
    "impersonate", "sudo", "escalate", "promote",
    "token", "key", "secret", "credentials",
    "backup", "restore", "migrate", "seed",
]

# Full path segments that are almost always high-value
HIGH_VALUE_SEGMENTS = [
    "/admin", "/internal", "/private", "/staff",
    "/debug", "/test", "/dev", "/ops",
    "/superadmin", "/root", "/system",
    "/manage", "/management", "/backoffice",
    "/dashboard/admin", "/api/admin",
    "/api/internal", "/api/private",
    "/api/v1/internal", "/api/v1/admin",
    "/api/v1/private", "/api/v1/staff",
    "/api/v2/internal", "/api/v2/admin",
    "/v1/internal", "/v1/admin",
    "/internal/api", "/internal/v1",
    "/privileged", "/restricted",
]

# ─────────────────────────────────────────────────────────────────────────────
# Mobile API path patterns
# ─────────────────────────────────────────────────────────────────────────────

MOBILE_BASE_PATHS = [
    "/mobile", "/mobile/api", "/mobile/v1", "/mobile/v2",
    "/app", "/app/api", "/app/v1", "/app/v2",
    "/mapi", "/mapi/v1", "/mapi/v2",
    "/ios", "/ios/api", "/ios/v1",
    "/android", "/android/api", "/android/v1",
    "/native", "/native/api",
    "/client", "/client/api", "/client/v1",
    "/api/mobile", "/api/mobile/v1", "/api/mobile/v2",
    "/api/app", "/api/app/v1",
    "/api/ios", "/api/android",
    "/api/native", "/api/client",
    "/api/v1/mobile", "/api/v2/mobile",
    "/m/api", "/m/v1",
    "/mob/api", "/mob/v1",
]

MOBILE_USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Mobile Safari/537.36",
    "Dart/3.0 (dart:io)",  # Flutter apps
    "okhttp/4.11.0",       # Android native
    "Alamofire/5.8.1",     # iOS native
]

# ─────────────────────────────────────────────────────────────────────────────
# Historical HackerOne corpus — real paths from disclosed reports
# ─────────────────────────────────────────────────────────────────────────────

HISTORICAL_HIGH_VALUE_PATHS = [
    # Internal/admin panels found in real reports
    "/api/v1/internal/users",
    "/api/v1/internal/admin",
    "/api/v1/internal/accounts",
    "/api/v1/internal/payments",
    "/api/v1/internal/orders",
    "/api/v1/admin/users",
    "/api/v1/admin/accounts",
    "/api/v1/admin/impersonate",
    "/api/v1/admin/sudo",
    "/api/v1/admin/config",
    "/api/v1/admin/debug",
    "/api/v1/admin/export",
    "/api/v1/admin/metrics",
    "/api/v1/admin/logs",
    "/api/v2/internal/users",
    "/api/v2/admin/users",
    "/api/v2/admin/impersonate",

    # Debug / diagnostic endpoints (commonly left open)
    "/debug", "/debug/vars", "/debug/pprof",
    "/debug/pprof/heap", "/debug/pprof/goroutine",
    "/_debug", "/_debug/vars",
    "/api/debug", "/api/debug/info",
    "/api/v1/debug", "/api/v1/debug/config",
    "/diagnostics", "/api/diagnostics",
    "/status", "/api/status", "/api/v1/status",
    "/health", "/healthz", "/health/check",
    "/ping", "/api/ping", "/api/v1/ping",
    "/info", "/api/info", "/server-info",
    "/version", "/api/version", "/api/v1/version",

    # Actuator endpoints (Spring, Go, etc.)
    "/actuator", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/httptrace",
    "/actuator/heapdump", "/actuator/threaddump",
    "/actuator/loggers", "/actuator/metrics",
    "/actuator/health/liveness", "/actuator/health/readiness",
    "/manage/health", "/management/health",
    "/management/env", "/management/info",

    # Config/credentials endpoints (found in breaches)
    "/api/v1/config", "/api/config", "/config.json",
    "/api/v1/settings", "/api/settings",
    "/api/v1/secrets", "/api/secrets",
    "/env", "/.env", "/api/env",
    "/api/v1/env", "/environment",

    # User impersonation (critical finding if accessible)
    "/api/v1/users/{id}/impersonate",
    "/api/v1/admin/impersonate",
    "/api/v1/users/impersonate",
    "/admin/impersonate",
    "/api/v1/sudo",
    "/api/v1/become",
    "/api/v1/switch-user",
    "/api/v1/login-as",

    # Export/dump endpoints (data exposure)
    "/api/v1/users/export",
    "/api/v1/orders/export",
    "/api/v1/payments/export",
    "/api/v1/accounts/export",
    "/api/v1/users/dump",
    "/api/v1/data/export",
    "/export/users", "/export/data",
    "/api/v1/reports/generate",
    "/api/v1/admin/export",

    # Bulk/batch operations (often skip row-level checks)
    "/api/v1/users/bulk",
    "/api/v1/users/batch",
    "/api/v1/orders/bulk",
    "/api/v1/bulk/delete",
    "/api/v1/batch/update",
    "/api/v1/bulk/update",
    "/api/bulk", "/api/batch",

    # Soft-delete recovery
    "/api/v1/users/deleted",
    "/api/v1/orders/archived",
    "/api/v1/accounts/suspended",
    "/api/v1/users/inactive",
    "/api/v1/trash",
    "/api/v1/recyclebin",

    # Token/key management
    "/api/v1/tokens", "/api/v1/api-keys",
    "/api/v1/admin/tokens",
    "/api/v1/service-accounts",
    "/api/v1/internal/tokens",

    # Old mobile API paths (from mobile app reversing reports)
    "/api/mobile/v1/users",
    "/mobile/api/v1/auth",
    "/mapi/v1/users",
    "/app/api/users",
    "/api/v1/mobile/users",
    "/api/v1/app/config",

    # GraphQL (often has weaker auth than REST)
    "/graphql", "/api/graphql", "/query",
    "/gql", "/graphiql", "/playground",
    "/api/v1/graphql", "/api/v2/graphql",

    # Webhook / callback endpoints
    "/api/v1/webhooks", "/webhooks",
    "/api/v1/callbacks", "/callbacks",
    "/api/v1/notifications/internal",

    # Background job / queue management
    "/sidekiq", "/resque", "/horizon",
    "/api/v1/jobs", "/api/v1/tasks",
    "/api/v1/queue", "/api/v1/workers",
    "/admin/jobs", "/api/admin/jobs",

    # Payment/financial internals (highest value)
    "/api/v1/payments/internal",
    "/api/v1/payments/admin",
    "/api/v1/finance/report",
    "/api/v1/billing/admin",
    "/api/v1/subscriptions/admin",
    "/api/v1/refunds/admin",
    "/api/v1/transactions/export",
    "/api/v1/payout/admin",
    "/api/v1/wallet/admin",
    "/api/v1/bank/admin",

    # Partner/B2B APIs (frequently underdeveloped auth)
    "/api/partner/v1/",
    "/api/b2b/v1/",
    "/api/vendor/v1/",
    "/partner/api/",
    "/b2b/api/",

    # Testing/QA endpoints left in production
    "/api/v1/test",
    "/api/test/",
    "/api/v1/test/reset",
    "/api/v1/test/seed",
    "/api/v1/test/users",
    "/api/v1/qa/",
    "/api/qa/",
    "/api/dev/",
    "/api/v1/dev/",
    "/api/staging/",
    "/test/api/",
    "/dev/api/",
]

# ─────────────────────────────────────────────────────────────────────────────
# "Activation" query parameters — some endpoints are hidden behind params
# ─────────────────────────────────────────────────────────────────────────────

ACTIVATION_PARAMS = [
    {"debug": "true"},
    {"debug": "1"},
    {"admin": "true"},
    {"admin": "1"},
    {"internal": "true"},
    {"internal": "1"},
    {"_debug": "1"},
    {"format": "json"},
    {"_format": "json"},
    {"XDEBUG_SESSION": "1"},
    {"XDEBUG_PROFILE": "1"},
    {"show_all": "true"},
    {"include_internal": "true"},
    {"full": "true"},
    {"raw": "true"},
    {"expand": "all"},
    {"verbose": "1"},
    {"trace": "1"},
    {"test": "true"},
    {"preview": "true"},
    {"beta": "true"},
    {"dev": "true"},
    {"mode": "debug"},
    {"mode": "admin"},
    {"mode": "internal"},
    {"_admin": "1"},
    {"__debug__": "1"},
    {"api_key": "test"},
    {"api_key": ""},
    {"token": "test"},
    {"bypass": "true"},
    {"override": "true"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Response interest scoring
# ─────────────────────────────────────────────────────────────────────────────

INTERESTING_STATUS_CODES = {200, 201, 301, 302, 401, 403}
# 401/403 are interesting — they mean the endpoint EXISTS but is protected
# That's more valuable than a 404 (endpoint doesn't exist)

INTERESTING_BODY_PATTERNS = [
    # Credential/secret exposure
    r'"(password|secret|token|api_key|access_key|private_key|credentials)"',
    r'"(aws_|gcp_|azure_)(key|secret|token)',
    # Internal data
    r'"(internal|admin|staff|privileged|superuser)":\s*true',
    r'"role":\s*"(admin|superadmin|staff|internal|root)"',
    # Error leakage (reveals endpoint exists and its structure)
    r'(stack trace|traceback|exception|error.*line \d+)',
    r'(ValidationError|TypeError|ValueError|KeyError)',
    r'"detail":\s*"(Authentication|Permission|Not authenticated)',
    # Business data (high value)
    r'"(email|phone|ssn|dob|credit_card|bank_account|routing_number)"',
    r'"(salary|income|balance|amount|revenue|profit)":\s*\d',
    # Debug info
    r'(DEBUG|TRACE|development mode|debug mode)',
    r'"(config|configuration|settings|env)":\s*\{',
]

BORING_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
    ".html", ".htm", ".xml", ".txt", ".md",
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Hunter class
# ─────────────────────────────────────────────────────────────────────────────

class HiddenEndpointHunter:
    """
    Strategic hidden endpoint discovery engine.
    Finds undocumented, internal, legacy, and mobile API paths that
    conventional crawlers and wordlists miss.
    """

    def __init__(self, verbose: bool = False):
        self.verbose      = verbose
        self._seen:       set[str]  = set()
        self._soft404_hashes: set[str] = set()
        self._tech_stack: list[str] = []
        self._confirmed_200_paths: list[str] = []

    # ── Entry point ───────────────────────────────────────────────────────────

    async def hunt(
        self,
        target_url:        str,
        session,
        auth_token:        str  = "",
        known_paths:       list[str] = None,
        timeout_s:         int  = 10,
        max_workers:       int  = 8,
        skip_activation:   bool = False,
        skip_mobile:       bool = False,
        skip_mutation:     bool = False,
    ) -> HunterResult:
        """
        Run all discovery phases against target_url.

        Parameters
        ──────────
        target_url      : base URL (e.g. https://api.target.com)
        session         : active aiohttp.ClientSession
        auth_token      : Bearer token for authenticated probes
        known_paths     : paths already discovered by other layers
                          (fed into mutation phase)
        timeout_s       : per-request timeout
        max_workers     : concurrent probe limit
        skip_activation : skip query-param activation probes (saves time)
        skip_mobile     : skip mobile path probes (saves time)
        skip_mutation   : skip path mutation (saves time, reduces coverage)
        """
        start = time.time()
        result = HunterResult()
        known_paths = list(known_paths or [])

        parsed   = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ── Establish soft-404 baseline ───────────────────────────────────────
        await self._build_soft404_baseline(base_url, session, auth_token, timeout_s)

        # ── Phase 1: Technology fingerprinting ────────────────────────────────
        self._tech_stack = await self._fingerprint(
            base_url, session, auth_token, timeout_s
        )
        result.tech_stack = self._tech_stack
        if self._tech_stack:
            print(f"  [hunter:tech]   detected: {', '.join(self._tech_stack)}")

        # ── Build candidate list ──────────────────────────────────────────────
        candidates: list[tuple[int, str, str]] = []
        # (score, path, source_label)

        # Phase 1 paths: technology-specific
        for tech in self._tech_stack:
            for path in TECH_SIGNATURES[tech]["paths"]:
                candidates.append((
                    self._score_path(path, source="tech_specific"),
                    path,
                    f"tech:{tech}",
                ))

        # Phase 5 paths: historical corpus
        for path in HISTORICAL_HIGH_VALUE_PATHS:
            if "{" not in path:  # skip template paths for now
                candidates.append((
                    self._score_path(path, source="historical"),
                    path,
                    "historical",
                ))

        # Phase 4 paths: mobile
        if not skip_mobile:
            for path in MOBILE_BASE_PATHS:
                candidates.append((
                    self._score_path(path, source="mobile"),
                    path,
                    "mobile",
                ))

        # Phase 2 paths: mutation of known paths
        if not skip_mutation and known_paths:
            for mutated_path, source in self._mutate_paths(known_paths):
                candidates.append((
                    self._score_path(mutated_path, source="mutation") + 15,
                    mutated_path,
                    source,
                ))

        # Deduplicate, filter boring, sort by score descending
        seen_candidates: set[str] = set(known_paths)
        unique: list[tuple[int, str, str]] = []
        for score, path, source in candidates:
            if path not in seen_candidates and score > 0:
                ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
                if ext.lower() not in BORING_EXTENSIONS:
                    seen_candidates.add(path)
                    unique.append((score, path, source))

        unique.sort(key=lambda x: x[0], reverse=True)

        if self.verbose:
            print(f"  [hunter]        {len(unique)} candidates to probe")

        # ── Probe candidates concurrently ─────────────────────────────────────
        semaphore = asyncio.Semaphore(max_workers)
        probe_tasks = [
            self._probe_with_sem(
                semaphore, base_url, path, source, score,
                session, auth_token, timeout_s,
            )
            for score, path, source in unique
        ]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        found_endpoints: list[HiddenEndpoint] = []
        for r in probe_results:
            if isinstance(r, HiddenEndpoint) and r.status != 0:
                found_endpoints.append(r)
            elif isinstance(r, Exception) and self.verbose:
                result.errors.append(str(r)[:100])

        result.total_probed = len(unique)

        # ── Phase 3: Response-driven recursive expansion ──────────────────────
        confirmed_200 = [
            ep for ep in found_endpoints
            if ep.status == 200 and ep.body
        ]
        if confirmed_200:
            expanded = await self._recursive_expand(
                confirmed_200, base_url, session, auth_token,
                timeout_s, semaphore, seen_candidates,
            )
            found_endpoints.extend(expanded)
            result.total_probed += len(expanded)

        # ── Phase 6: Activation parameter probing ─────────────────────────────
        # Test activation params on endpoints that returned non-200 —
        # sometimes a hidden endpoint only responds when the right param is sent
        if not skip_activation:
            silent_endpoints = [
                ep for ep in found_endpoints
                if ep.status in (404, 400, 403, 401)
            ][:20]  # limit to 20 to save time
            activated = await self._probe_activation_params(
                silent_endpoints, session, auth_token, timeout_s, semaphore
            )
            found_endpoints.extend(activated)

        # ── Phase 7: HTTP method expansion on 200/403 endpoints ───────────────
        interesting = [
            ep for ep in found_endpoints
            if ep.status in (200, 403)
        ][:15]  # limit to 15
        expanded_methods = await self._expand_http_methods(
            interesting, session, auth_token, timeout_s, semaphore
        )
        found_endpoints.extend(expanded_methods)

        # ── Mobile UA probing on interesting paths ─────────────────────────────
        if not skip_mobile:
            mobile_variants = await self._probe_mobile_ua(
                [ep for ep in found_endpoints if ep.status == 200][:10],
                session, auth_token, timeout_s, semaphore,
            )
            found_endpoints.extend(mobile_variants)

        # ── Score and mark interesting findings ───────────────────────────────
        for ep in found_endpoints:
            ep.is_interesting, ep.interest_reason = self._is_interesting(ep)

        # Filter: only report endpoints that got a real response
        reportable = [
            ep for ep in found_endpoints
            if ep.status in INTERESTING_STATUS_CODES
        ]
        reportable.sort(key=lambda e: (e.is_interesting, e.score), reverse=True)

        result.endpoints    = reportable
        result.total_found  = len(reportable)
        result.elapsed_s    = round(time.time() - start, 1)

        print(f"  {result.summary()}")
        return result

    # ── Phase 1: Technology fingerprinting ────────────────────────────────────

    async def _fingerprint(
        self, base_url: str, session, auth_token: str, timeout_s: int
    ) -> list[str]:
        """
        Probe the root URL and a 404 page to identify the tech stack.
        Returns a list of detected technology names.
        """
        detected = []
        probe_urls = [
            base_url + "/",
            base_url + "/nonexistent_blfinder_fingerprint_" + hashlib.md5(
                base_url.encode()
            ).hexdigest()[:8],
        ]
        headers = self._build_headers(auth_token)

        for url in probe_urls:
            try:
                async with session.get(
                    url, headers=headers,
                    timeout=self._timeout(timeout_s),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    body         = await resp.text(errors="replace")
                    resp_headers = dict(resp.headers)
                    header_str   = " ".join(
                        f"{k.lower()}: {v.lower()}"
                        for k, v in resp_headers.items()
                    )

                    for tech, sigs in TECH_SIGNATURES.items():
                        if tech in detected:
                            continue
                        # Check headers
                        if any(h in header_str for h in sigs["headers"]):
                            detected.append(tech)
                            continue
                        # Check body
                        if any(
                            re.search(p, body[:5000], re.I)
                            for p in sigs["body_patterns"]
                        ):
                            detected.append(tech)
            except Exception:
                pass

        # Always include graphql as a candidate — it's universal
        if "graphql" not in detected:
            detected.append("graphql")

        return list(dict.fromkeys(detected))  # deduplicate preserving order

    # ── Soft-404 baseline ─────────────────────────────────────────────────────

    async def _build_soft404_baseline(
        self, base_url: str, session, auth_token: str, timeout_s: int
    ) -> None:
        """
        Probe two guaranteed-nonexistent paths to build a soft-404 fingerprint.
        Responses that match these hashes are silently skipped.
        """
        canaries = [
            "/blfinder_canary_a1b2c3d4e5/nonexistent",
            "/api/blfinder_canary_f6g7h8i9/nonexistent",
        ]
        headers = self._build_headers(auth_token)
        for path in canaries:
            try:
                async with session.get(
                    base_url + path, headers=headers,
                    timeout=self._timeout(timeout_s), ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    # Hash first 2000 chars — catches body-level soft-404
                    h = hashlib.md5(body[:2000].encode()).hexdigest()
                    self._soft404_hashes.add(h)
                    # Also hash the status code + first 500 chars
                    h2 = hashlib.md5(
                        f"{resp.status}{body[:500]}".encode()
                    ).hexdigest()
                    self._soft404_hashes.add(h2)
            except Exception:
                pass

    # ── Phase 2: Path mutation ────────────────────────────────────────────────

    def _mutate_paths(
        self, known_paths: list[str]
    ) -> list[tuple[str, str]]:
        """
        Generate high-value mutations of known paths.
        Returns (mutated_path, source_label) tuples.
        """
        mutations: list[tuple[str, str]] = []
        seen: set[str] = set()

        for path in known_paths:
            parsed = urlparse(path)
            clean  = parsed.path.rstrip("/")
            if not clean or clean == "/":
                continue

            # Split into parts: /api/v1/users → ["api", "v1", "users"]
            parts = [p for p in clean.split("/") if p]
            if not parts:
                continue

            # Find version component if present
            ver_idx = next(
                (i for i, p in enumerate(parts)
                 if re.match(r'^v\d+$', p, re.I) or p in (
                     "v1", "v2", "v3", "internal", "legacy", "beta"
                 )), None
            )

            resource = parts[-1]   # last component = resource name

            # Mutation 1: inject prefix after version
            if ver_idx is not None and ver_idx < len(parts) - 1:
                pre_ver  = parts[:ver_idx + 1]
                post_ver = parts[ver_idx + 1:]
                for prefix in HIGH_VALUE_PREFIXES[:12]:  # top 12 only
                    mutated = "/" + "/".join(pre_ver + [prefix] + post_ver)
                    if mutated not in seen:
                        seen.add(mutated)
                        mutations.append((mutated, f"mutation:prefix:{prefix}"))

            # Mutation 2: append suffix to resource
            for suffix in HIGH_VALUE_SUFFIXES[:12]:
                mutated = clean + "/" + suffix
                if mutated not in seen:
                    seen.add(mutated)
                    mutations.append((mutated, f"mutation:suffix:{suffix}"))

            # Mutation 3: replace version number
            if ver_idx is not None:
                current_ver = parts[ver_idx]
                for alt_ver in ["v1", "v2", "v3", "internal", "legacy", "beta", "v0"]:
                    if alt_ver != current_ver:
                        new_parts = list(parts)
                        new_parts[ver_idx] = alt_ver
                        mutated = "/" + "/".join(new_parts)
                        if mutated not in seen:
                            seen.add(mutated)
                            mutations.append((mutated, f"mutation:version:{alt_ver}"))

            # Mutation 4: prefix the whole path with internal/admin
            for prefix in ["internal", "admin", "private", "staff"]:
                mutated = "/" + prefix + clean
                if mutated not in seen:
                    seen.add(mutated)
                    mutations.append((mutated, f"mutation:global_prefix:{prefix}"))

        return mutations

    # ── Probe with semaphore ──────────────────────────────────────────────────

    async def _probe_with_sem(
        self,
        sem:        asyncio.Semaphore,
        base_url:   str,
        path:       str,
        source:     str,
        score:      int,
        session,
        auth_token: str,
        timeout_s:  int,
    ) -> Optional[HiddenEndpoint]:
        async with sem:
            return await self._probe(
                base_url, path, source, score,
                session, auth_token, timeout_s,
            )

    async def _probe(
        self,
        base_url:   str,
        path:       str,
        source:     str,
        score:      int,
        session,
        auth_token: str,
        timeout_s:  int,
        method:     str = "GET",
        extra_ua:   str = "",
    ) -> Optional[HiddenEndpoint]:
        """Send a single probe request and return a HiddenEndpoint or None."""
        full_url = base_url + path if path.startswith("/") else path
        if full_url in self._seen:
            return None
        self._seen.add(full_url)

        headers = self._build_headers(auth_token, ua_override=extra_ua)

        try:
            async with session.request(
                method, full_url,
                headers=headers,
                timeout=self._timeout(timeout_s),
                ssl=False,
                allow_redirects=True,
            ) as resp:
                status = resp.status
                body   = await resp.text(errors="replace")

                # Skip soft-404 responses
                body_hash = hashlib.md5(body[:2000].encode()).hexdigest()
                if body_hash in self._soft404_hashes:
                    return None
                combo_hash = hashlib.md5(
                    f"{status}{body[:500]}".encode()
                ).hexdigest()
                if combo_hash in self._soft404_hashes:
                    return None

                # 404 with a non-generic body is still interesting
                # (means the endpoint exists but the resource doesn't)
                # 404 with generic body → skip
                if status == 404:
                    if len(body) < 50 or not any(
                        c in body for c in ["{", "[", "api", "endpoint"]
                    ):
                        return None

                ep = HiddenEndpoint(
                    url=full_url, method=method,
                    score=score, source=source,
                    status=status, body=body[:1000],
                )

                if self.verbose:
                    print(f"  [hunter:{source[:8]}] [{status}] {path[:65]}")

                return ep

        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    # ── Phase 3: Recursive expansion ─────────────────────────────────────────

    async def _recursive_expand(
        self,
        confirmed_eps: list[HiddenEndpoint],
        base_url:      str,
        session,
        auth_token:    str,
        timeout_s:     int,
        semaphore:     asyncio.Semaphore,
        seen_paths:    set[str],
        max_depth:     int = 2,
    ) -> list[HiddenEndpoint]:
        """
        Extract paths from 200-response bodies and probe them recursively.
        """
        new_found: list[HiddenEndpoint] = []
        queue = list(confirmed_eps)
        depth = 0

        while queue and depth < max_depth:
            extracted_paths: set[str] = set()

            for ep in queue:
                # Extract paths from JSON values
                try:
                    data = json.loads(ep.body)
                    for path in self._extract_paths_from_json(data):
                        if path not in seen_paths:
                            extracted_paths.add(path)
                except (json.JSONDecodeError, ValueError):
                    pass

                # Extract paths from body text (regex)
                for match in re.findall(
                    r'["\'](/(?:api|v\d+|internal|admin)[^"\'<>\s]{2,80})["\']',
                    ep.body,
                ):
                    clean = match.split("?")[0]
                    if clean not in seen_paths:
                        extracted_paths.add(clean)

            if not extracted_paths:
                break

            seen_paths.update(extracted_paths)
            tasks = [
                self._probe_with_sem(
                    semaphore, base_url, path, "recursive_expansion",
                    self._score_path(path, "recursive") + 10,
                    session, auth_token, timeout_s,
                )
                for path in extracted_paths
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            next_queue = []
            for r in results:
                if isinstance(r, HiddenEndpoint) and r.status == 200:
                    new_found.append(r)
                    next_queue.append(r)

            queue = next_queue
            depth += 1

        return new_found

    def _extract_paths_from_json(self, data, depth: int = 0) -> list[str]:
        """Recursively extract path-like string values from a JSON object."""
        paths = []
        if depth > 4:
            return paths
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and v.startswith("/") and len(v) > 3:
                    if re.match(r'^/[a-zA-Z0-9_\-/]+$', v):
                        paths.append(v.split("?")[0])
                elif isinstance(v, (dict, list)):
                    paths.extend(self._extract_paths_from_json(v, depth + 1))
        elif isinstance(data, list):
            for item in data[:10]:
                paths.extend(self._extract_paths_from_json(item, depth + 1))
        return paths

    # ── Phase 6: Activation parameter probing ────────────────────────────────

    async def _probe_activation_params(
        self,
        endpoints:  list[HiddenEndpoint],
        session,
        auth_token: str,
        timeout_s:  int,
        semaphore:  asyncio.Semaphore,
    ) -> list[HiddenEndpoint]:
        """Test activation query params on silent/blocked endpoints."""
        new_found = []
        for ep in endpoints:
            for params in ACTIVATION_PARAMS[:10]:   # top 10 params
                param_str = "&".join(f"{k}={v}" for k, v in params.items())
                url_with_param = ep.url + "?" + param_str
                if url_with_param in self._seen:
                    continue
                self._seen.add(url_with_param)

                headers = self._build_headers(auth_token)
                try:
                    async with semaphore:
                        async with session.get(
                            url_with_param, headers=headers,
                            timeout=self._timeout(timeout_s), ssl=False,
                        ) as resp:
                            if resp.status != ep.status:
                                body = await resp.text(errors="replace")
                                new_ep = HiddenEndpoint(
                                    url=url_with_param,
                                    method="GET",
                                    score=ep.score + 20,
                                    source=f"activation:{list(params.keys())[0]}",
                                    status=resp.status,
                                    body=body[:1000],
                                    params=params,
                                )
                                new_found.append(new_ep)
                                if self.verbose:
                                    print(
                                        f"  [hunter:activation] [{resp.status}] "
                                        f"{url_with_param[:65]}"
                                    )
                except Exception:
                    pass
        return new_found

    # ── Phase 7: HTTP method expansion ────────────────────────────────────────

    async def _expand_http_methods(
        self,
        endpoints:  list[HiddenEndpoint],
        session,
        auth_token: str,
        timeout_s:  int,
        semaphore:  asyncio.Semaphore,
    ) -> list[HiddenEndpoint]:
        """Test non-standard HTTP methods on interesting endpoints."""
        new_found = []
        for ep in endpoints:
            # First get allowed methods from OPTIONS
            try:
                async with semaphore:
                    async with session.options(
                        ep.url,
                        headers=self._build_headers(auth_token),
                        timeout=self._timeout(timeout_s),
                        ssl=False,
                    ) as resp:
                        allow_hdr = resp.headers.get("Allow", "") or \
                                    resp.headers.get("Access-Control-Allow-Methods", "")
                        allowed   = {
                            m.strip().upper()
                            for m in allow_hdr.split(",") if m.strip()
                        }
            except Exception:
                allowed = set()

            # Try methods not in original discovery
            to_try = (
                (allowed or {"POST", "PUT", "PATCH", "DELETE"}) -
                {ep.method.upper()}
            )
            for method in list(to_try)[:3]:    # max 3 extra methods
                key = f"{method}:{ep.url}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                try:
                    async with semaphore:
                        async with session.request(
                            method, ep.url,
                            headers=self._build_headers(auth_token),
                            timeout=self._timeout(timeout_s),
                            ssl=False,
                        ) as resp:
                            if resp.status in INTERESTING_STATUS_CODES:
                                body = await resp.text(errors="replace")
                                new_found.append(HiddenEndpoint(
                                    url=ep.url, method=method,
                                    score=ep.score + 10,
                                    source="method_expansion",
                                    status=resp.status,
                                    body=body[:1000],
                                ))
                except Exception:
                    pass
        return new_found

    # ── Mobile UA probing ─────────────────────────────────────────────────────

    async def _probe_mobile_ua(
        self,
        endpoints:  list[HiddenEndpoint],
        session,
        auth_token: str,
        timeout_s:  int,
        semaphore:  asyncio.Semaphore,
    ) -> list[HiddenEndpoint]:
        """Re-probe interesting endpoints with mobile User-Agent headers."""
        new_found = []
        for ep in endpoints[:5]:   # top 5 only
            for ua in MOBILE_USER_AGENTS[:2]:   # 2 UAs
                key = f"mobile_ua:{ua[:20]}:{ep.url}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                result = await self._probe(
                    "", ep.url, "mobile_ua", ep.score,
                    session, auth_token, timeout_s, extra_ua=ua,
                )
                if result and result.status == 200 and result.body != ep.body:
                    result.source = "mobile_ua"
                    new_found.append(result)
        return new_found

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score_path(self, path: str, source: str = "") -> int:
        """Assign a priority score to a candidate path."""
        score  = 5   # base
        pl     = path.lower()

        # High-value keywords
        if any(k in pl for k in [
            "admin", "internal", "private", "staff", "debug",
            "export", "dump", "impersonate", "sudo", "config",
            "secret", "credential", "token", "key", "delete",
            "purge", "bulk", "batch", "all", "raw",
        ]):
            score += 30

        # Version component
        if re.search(r'/v\d+/', pl) or any(
            s in pl for s in ["/internal/", "/legacy/", "/beta/"]
        ):
            score += 5

        # Historical corpus match
        if source == "historical":
            score += 10

        # Tech-specific
        if source.startswith("tech:"):
            score += 20

        # Mobile
        if source == "mobile":
            score += 5

        # Mutation of confirmed 200
        if source.startswith("mutation:"):
            score += 15

        # Actuator paths (Spring Boot) — extremely high value
        if "actuator" in pl or "management" in pl:
            score += 25

        # GraphQL — high value
        if "graphql" in pl or "/gql" in pl:
            score += 20

        # Boring indicators
        if any(pl.endswith(ext) for ext in BORING_EXTENSIONS):
            score = -999

        return score

    # ── Interest scoring ──────────────────────────────────────────────────────

    def _is_interesting(self, ep: HiddenEndpoint) -> tuple[bool, str]:
        """Determine if a found endpoint is security-relevant."""
        # 401/403 = endpoint exists but protected (still valuable)
        if ep.status in (401, 403):
            return True, f"Protected endpoint exists (HTTP {ep.status}) — auth bypass target"

        if ep.status != 200:
            return False, ""

        body_l = ep.body.lower()

        for pattern in INTERESTING_BODY_PATTERNS:
            if re.search(pattern, ep.body, re.I):
                return True, f"Sensitive data pattern: {pattern[:50]}"

        if any(k in body_l for k in [
            "password", "secret", "token", "api_key", "private",
            "credential", "internal", "admin", "debug", "config",
        ]):
            return True, "Sensitive keyword in response body"

        if ep.status == 200 and len(ep.body) > 100:
            return True, f"Undocumented endpoint returned {len(ep.body)}B response"

        return False, ""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_headers(
        self, auth_token: str, ua_override: str = ""
    ) -> dict:
        headers = {
            "User-Agent": ua_override or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept":          "application/json, text/html, */*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type":    "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        return headers

    @staticmethod
    def _timeout(timeout_s: int):
        import aiohttp
        return aiohttp.ClientTimeout(total=timeout_s, connect=5)


# ─────────────────────────────────────────────────────────────────────────────
# Integration helper — called from blfinder.py run_deep_discovery()
# ─────────────────────────────────────────────────────────────────────────────

async def run_hidden_hunter(
    target_url:  str,
    session,
    auth_token:  str  = "",
    known_paths: list = None,
    verbose:     bool = False,
    timeout_s:   int  = 10,
    max_workers: int  = 8,
    tags:        list = None,
) -> list[dict]:
    """
    Convenience wrapper. Returns endpoint dicts compatible with BLFScanner.
    Call this from run_deep_discovery() in blfinder.py.

    Example:
        from core.discovery.hidden_endpoint_hunter import run_hidden_hunter
        hidden = await run_hidden_hunter(
            target_url  = args.target,
            session     = disc_session,
            auth_token  = args.token,
            known_paths = [ep["url"] for ep in existing_endpoints],
            verbose     = args.verbose,
        )
        # Merge into endpoints list
        for ep in hidden:
            key = (ep["url"], ep.get("method", "GET"))
            if key not in existing_keys:
                endpoints.append(ep)
                existing_keys.add(key)
    """
    hunter = HiddenEndpointHunter(verbose=verbose)
    result = await hunter.hunt(
        target_url  = target_url,
        session     = session,
        auth_token  = auth_token,
        known_paths = known_paths or [],
        timeout_s   = timeout_s,
        max_workers = max_workers,
    )

    return [
        {
            "url":    ep.url,
            "method": ep.method,
            "body":   ep.body_fields or {},
            "params": ep.params or {},
            "_meta":  {
                "source":          ep.source,
                "score":           ep.score,
                "is_interesting":  ep.is_interesting,
                "interest_reason": ep.interest_reason,
                "status":          ep.status,
                "hunter":          True,
            },
        }
        for ep in result.endpoints
        if ep.status in INTERESTING_STATUS_CODES
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("hidden_endpoint_hunter.py — self-test")
    print("=" * 60)

    hunter = HiddenEndpointHunter(verbose=False)

    print("\n[TEST 1] Path scoring")
    assert hunter._score_path("/api/v1/admin/users") > 30
    assert hunter._score_path("/api/v1/internal/config") > 30
    assert hunter._score_path("/actuator/env") >= 30
    assert hunter._score_path("/static/logo.png") < 0
    assert hunter._score_path("/api/v1/users/export") > 30
    print("  PASS")

    print("\n[TEST 2] Path mutation")
    mutations = hunter._mutate_paths(["/api/v1/users", "/api/v2/orders"])
    paths = [m[0] for m in mutations]
    assert "/api/v1/internal/users" in paths, f"missing internal mutation, got: {paths[:5]}"
    assert "/api/v1/users/export"   in paths, f"missing export suffix"
    assert "/api/v1/admin/users"    in paths, f"missing admin mutation"
    print(f"  PASS — {len(mutations)} mutations generated")

    print("\n[TEST 3] JSON path extraction")
    data = {
        "links": {
            "self": "/api/v1/users/1",
            "orders": "/api/v1/users/1/orders",
            "admin": "/api/v1/admin/users/1",
        },
        "user_id": 1,
    }
    paths = hunter._extract_paths_from_json(data)
    assert "/api/v1/users/1" in paths
    assert "/api/v1/admin/users/1" in paths
    print(f"  PASS — {len(paths)} paths extracted from JSON")

    print("\n[TEST 4] Interest scoring")
    ep_creds = HiddenEndpoint(
        url="/api/v1/config", method="GET", score=50,
        status=200, body='{"api_key": "secret123", "db_password": "hunter2"}'
    )
    ep_403 = HiddenEndpoint(
        url="/api/v1/admin", method="GET", score=40,
        status=403, body='Forbidden'
    )
    ep_boring = HiddenEndpoint(
        url="/api/v1/ping", method="GET", score=5,
        status=200, body='{"status": "ok"}'
    )
    assert hunter._is_interesting(ep_creds)[0] is True
    assert hunter._is_interesting(ep_403)[0]   is True
    assert hunter._is_interesting(ep_boring)[0] is False  # short generic body
    print("  PASS")

    print("\n[TEST 5] Historical corpus coverage")
    assert len(HISTORICAL_HIGH_VALUE_PATHS) >= 80
    actuator_paths = [p for p in HISTORICAL_HIGH_VALUE_PATHS if "actuator" in p]
    admin_paths    = [p for p in HISTORICAL_HIGH_VALUE_PATHS if "/admin" in p]
    assert len(actuator_paths) >= 5, "Need Spring actuator paths"
    assert len(admin_paths)    >= 5, "Need admin paths"
    print(f"  PASS — {len(HISTORICAL_HIGH_VALUE_PATHS)} historical paths, "
          f"{len(actuator_paths)} actuator, {len(admin_paths)} admin")

    print("\n[TEST 6] Tech signatures complete")
    for tech, sigs in TECH_SIGNATURES.items():
        assert "paths" in sigs, f"{tech} missing paths"
        assert len(sigs["paths"]) >= 3, f"{tech} has too few paths"
    print(f"  PASS — {len(TECH_SIGNATURES)} tech stacks with signatures")

    print("\n" + "=" * 60)
    print("All tests passed.")
    print("=" * 60)
    print()
    print("Deploy: save as core/discovery/hidden_endpoint_hunter.py")
    print()
    print("In blfinder.py, inside run_deep_discovery(), add after other layers:")
    print()
    print("  from core.discovery.hidden_endpoint_hunter import run_hidden_hunter")
    print("  hidden = await run_hidden_hunter(")
    print("      target_url  = args.target,")
    print("      session     = session,")
    print("      auth_token  = args.token,")
    print("      known_paths = [ep.url for ep in all_endpoints],")
    print("      verbose     = args.verbose,")
    print("  )")
    print("  all_endpoints.extend(<convert hidden to DiscoveredEndpoint>)")

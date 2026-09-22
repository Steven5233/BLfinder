"""
core/scanner.py  — BLFScanner v3.1 Phase 5+ 
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BLFinder v3.1 Phase 5 — core/scanner.py
Complete scanner with all phases integrated + Deep Discovery Engine.

Phase 1: Multi-step flows, blind IDOR, session management, OAuth2
Phase 2: Evidence capture, real HTTP proof, HackerOne report generation
Phase 3: Endpoint validation, response classification, subdomain recon,
         JS secret extraction, soft-404 prevention
Phase 4: Mass IDOR enumeration, GraphQL deep scan, WebSocket scanner,
         API version abuse, business context classifier
Phase 5: Live dashboard integration, profile system, DB deduplication,
         findings queue for TUI consumption
Phase 5+: Deep Discovery Engine — JS AST, OpenAPI, smart wordlist,
          version permutation, headless crawl, soft-404 filter,
          priority scoring, schema enrichment

"""

from __future__ import annotations

import asyncio
import aiohttp
import base64
import copy
import difflib
import hashlib
import itertools
import json
import re
import time
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, urlunparse

from .models import Finding, ScanConfig, Severity
from .confidence import ConfidenceEngine, severity_from_confidence
from .poc import PoCGenerator
from .verifier import FindingVerifier
from .checkpoint import ScanCheckpoint

try:
    from .intelligence.field_type_engine import (
        FieldType, infer_field_type, is_attack_relevant,
        generate_payloads, generate_time_payloads, build_canary_value,
        PostureCache, is_non_api_path, pollution_probe_value,
    )
    _HAS_FIELD_TYPING = True
except ImportError:
    _HAS_FIELD_TYPING = False


try:
    from .analysis.semantic_diff import SemanticDiff
    from .analysis.field_extractor import build_volatile_map, VolatileFieldExtractor
    _HAS_SEMANTIC = True
except ImportError:
    _HAS_SEMANTIC = False

try:
    from .oracles.blind_idor import BlindIDORScanner
    _HAS_BLIND_IDOR = True
except ImportError:
    _HAS_BLIND_IDOR = False

try:
    from .oracles.timing_oracle import TimingOracle
    _HAS_TIMING = True
except ImportError:
    _HAS_TIMING = False

try:
    from .auth.session_manager import SessionManager, RefreshConfig
    _HAS_SESSION = True
except ImportError:
    _HAS_SESSION = False

try:
    from .auth.oauth_handler import OAuthHandler, OAuthConfig
    _HAS_OAUTH = True
except ImportError:
    _HAS_OAUTH = False

try:
    from .flows.flow_replayer import FlowReplayer
    from .flows.flow_templates import FlowTemplates
    _HAS_FLOWS = True
except ImportError:
    _HAS_FLOWS = False


try:
    from .evidence.capture import EvidenceCapture, EvidencePackage
    from .evidence.http_recorder import HTTPRecorder
    _HAS_EVIDENCE = True
except ImportError:
    _HAS_EVIDENCE = False


try:
    from .validation.endpoint_validator import (
        EndpointValidator, ValidationConfig, ValidationResult,
    )
    from .validation.response_classifier import (
        ResponseClassifier, ResponseClass, ClassifiedResponse,
    )
    _HAS_VALIDATION = True
except ImportError:
    _HAS_VALIDATION = False

try:
    from .recon.subdomain_mapper import SubdomainMapper, SubdomainMapResult
    _HAS_SUBDOMAIN = True
except ImportError:
    _HAS_SUBDOMAIN = False

try:
    from .recon.js_secret_extractor import JSSecretExtractor, JSExtractionResult
    _HAS_JS_EXTRACT = True
except ImportError:
    _HAS_JS_EXTRACT = False


try:
    from .modules.idor_mass_enum import IDORMassEnumerator
    _HAS_IDOR_ENUM = True
except ImportError:
    _HAS_IDOR_ENUM = False

try:
    from .modules.graphql_deep import GraphQLDeepScanner
    _HAS_GQL_DEEP = True
except ImportError:
    _HAS_GQL_DEEP = False

try:
    from .modules.websocket_scanner import WebSocketScanner
    _HAS_WEBSOCKET = True
except ImportError:
    _HAS_WEBSOCKET = False

try:
    from .modules.api_version_abuse import APIVersionScanner
    _HAS_VERSION = True
except ImportError:
    _HAS_VERSION = False

try:
    from .modules.cors_scanner import CORSScanner
    _HAS_CORS = True
except ImportError:
    _HAS_CORS = False

try:
    from .modules.security_headers import SecurityHeaderAuditor
    _HAS_SEC_HEADERS = True
except ImportError:
    _HAS_SEC_HEADERS = False

try:
    from .modules.jwt_alg_confusion import JWTAlgConfusionScanner
    _HAS_JWT_CONFUSION = True
except ImportError:
    _HAS_JWT_CONFUSION = False

try:
    from .modules.tenant_bola import TenantBOLAScanner
    _HAS_TENANT_BOLA = True
except ImportError:
    _HAS_TENANT_BOLA = False

try:
    from .modules.ssrf_scanner import SSRFScanner
    _HAS_SSRF = True
except ImportError:
    _HAS_SSRF = False

try:
    from .modules.csrf_scanner import CSRFScanner
    _HAS_CSRF = True
except ImportError:
    _HAS_CSRF = False

try:
    from .modules.source_code_scanner import SourceCodeScanner
    _HAS_SOURCE_SCAN = True
except ImportError:
    _HAS_SOURCE_SCAN = False

try:
    from .intelligence.business_classifier import BusinessClassifier, AttackPlan
    _HAS_CLASSIFIER = True
except ImportError:
    _HAS_CLASSIFIER = False


try:
    from .tui.live_dashboard import DashboardState, LiveDashboard
    _HAS_TUI = True
except ImportError:
    _HAS_TUI = False


try:
    from .discovery.engine import DeepDiscoveryEngine
    from .discovery.models import DiscoveryConfig
    _HAS_DEEP_DISCOVERY = True
except ImportError:
    _HAS_DEEP_DISCOVERY = False






_IDOR_ID_PATTERNS: list[re.Pattern] = [
    re.compile(r'^\d{1,15}$'),                                                              
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I), 
    re.compile(r'^[0-9a-f]{24}$', re.I),                                                    
    re.compile(r'^[a-z]{2,4}_[A-Za-z0-9]{10,}$'),                                          
    re.compile(r'^[0-9A-Za-z]{22}$'),                                                       
    re.compile(r'^[0-9a-f]{12,40}$', re.I),                                                 
]
_NUMERIC_ONLY = re.compile(r'^\d{1,15}$')
_IDOR_SKIP_WORDS = frozenset({
    "api", "v1", "v2", "v3", "v4", "internal", "legacy", "beta", "alpha",
    "admin", "user", "users", "account", "accounts", "payment", "payments",
    "order", "orders", "product", "products", "me", "profile", "settings",
    "config", "list", "all", "search", "create", "update", "delete",
    "get", "post", "put", "patch", "true", "false", "null", "none",
    "json", "xml", "csv", "graphql", "health", "ping", "status", "docs",
    "transfer", "transfers",
})


def _is_id_segment(segment: str) -> bool:
    if not segment or segment.lower() in _IDOR_SKIP_WORDS:
        return False
    return any(p.match(segment) for p in _IDOR_ID_PATTERNS)


def _generate_id_variants(segment: str) -> list[str]:
    variants: list[str] = []
    if _NUMERIC_ONLY.match(segment):
        orig = int(segment)
        for delta in (-1, 1, 2):
            c = orig + delta
            if c > 0:
                variants.append(str(c))
        for fixed in (1, 2, 3):
            if str(fixed) != segment:
                variants.append(str(fixed))
    elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-', segment, re.I):
        parts = segment.split("-")
        try:
            last_int = int(parts[-1], 16)
            for delta in (1, -1):
                new_last = format((last_int + delta) & 0xFFFFFFFFFFFF, "012x")
                variants.append("-".join(parts[:-1] + [new_last]))
        except ValueError:
            pass
        variants.append("00000000-0000-0000-0000-000000000000")
    elif re.match(r'^[0-9a-f]{24}$', segment, re.I):
        try:
            base = segment[:-6]
            tail = int(segment[-6:], 16)
            for delta in (1, -1):
                variants.append(base + format((tail + delta) & 0xFFFFFF, "06x"))
        except ValueError:
            pass
    elif re.match(r'^[a-z]{2,4}_[A-Za-z0-9]{10,}$', segment):
        prefix = segment.split("_")[0] + "_"
        variants.extend([prefix + "test1234567890", prefix + "0000000000"])
    else:
        variants.extend(["1", "2", "9999999"])
    return list(dict.fromkeys(v for v in variants if v and v != segment))[:5]






_PRIVILEGE_PATTERNS = [
    re.compile(r'^is_', re.I),        re.compile(r'^has_', re.I),
    re.compile(r'^can_', re.I),       re.compile(r'_level$', re.I),
    re.compile(r'_tier$', re.I),      re.compile(r'_limit$', re.I),
    re.compile(r'_override$', re.I),  re.compile(r'_multiplier$', re.I),
    re.compile(r'^role', re.I),       re.compile(r'verified$', re.I),
    re.compile(r'exempt$', re.I),     re.compile(r'bypass$', re.I),
    re.compile(r'admin', re.I),       re.compile(r'status$', re.I),
]







_FAILURE_INDICATOR_PATTERNS = [
    re.compile(r'\berror\b', re.I),        re.compile(r'\binvalid\b', re.I),
    re.compile(r'\bfailed\b', re.I),       re.compile(r'\bunauthorized\b', re.I),
    re.compile(r'\bforbidden\b', re.I),    re.compile(r'\bnot\s+found\b', re.I),
    re.compile(r'\brejected\b', re.I),     re.compile(r'\bdenied\b', re.I),
    re.compile(r'\bexception\b', re.I),    re.compile(r'\bbad\s+request\b', re.I),
    re.compile(r'\bvalidation\s+failed\b', re.I),
    re.compile(r'\brequired\b', re.I),     re.compile(r'\bmissing\b', re.I),
    re.compile(r'\bstack\s+trace\b', re.I),
]
_SUCCESS_INDICATOR_PATTERNS = [
    re.compile(r'\bsuccess\b', re.I),      re.compile(r'\bcreated\b', re.I),
    re.compile(r'\bupdated\b', re.I),      re.compile(r'\bconfirmed\b', re.I),
    re.compile(r'\bprocessed\b', re.I),    re.compile(r'\bcompleted\b', re.I),
    re.compile(r'\baccepted\b', re.I),     re.compile(r'"?\bok\b"?\s*[,:}]', re.I),
    re.compile(r'"order_id"', re.I),       re.compile(r'"transaction_id"', re.I),
    re.compile(r'"payment_id"', re.I),


    re.compile(r'"id"\s*:', re.I),         re.compile(r'"token"\s*:', re.I),
    re.compile(r':\s*true\b', re.I),
]


def _looks_privilege_field(name: str, value: Any) -> bool:
    if any(p.search(name) for p in _PRIVILEGE_PATTERNS):
        return True
    if isinstance(value, bool) and value is False:
        return any(w in name.lower() for w in
                   ["admin", "vip", "premium", "verified", "approved",
                    "staff", "exempt", "bypass", "override"])
    if isinstance(value, (int, float)) and value == 0:
        return any(w in name.lower() for w in
                   ["level", "tier", "limit", "multiplier", "credits"])
    return False


def _discover_dynamic_fields(response_body: str) -> list[tuple[str, Any]]:
    discovered: list[tuple[str, Any]] = []
    try:
        data = json.loads(response_body)
    except Exception:
        return discovered
    _STATIC_KEYS = {
        "is_admin", "admin", "role", "is_premium", "premium", "subscription",
        "plan", "credits", "balance", "is_staff", "approved", "email_verified",
        "kyc_verified", "price_override", "tax_exempt", "fee_waiver",
    }

    def _walk(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            if k not in _STATIC_KEYS and _looks_privilege_field(k, v):
                if isinstance(v, bool):
                    discovered.append((k, True))
                elif isinstance(v, (int, float)) and v == 0:
                    discovered.append((k, 3))
                elif isinstance(v, str):
                    for elevated in ("admin", "verified", "vip", "premium", "approved"):
                        if elevated not in str(v).lower():
                            discovered.append((k, elevated))
                            break
            if isinstance(v, dict):
                _walk(v)

    _walk(data)
    return discovered[:10]






_RACE_INDICATORS = frozenset([

    "redeem", "transfer", "withdraw", "claim", "checkout",
    "purchase", "buy", "confirm", "coupon", "reward", "spin",

    "bet", "wager", "stake", "cashout", "cash-out", "cash_out",
    "bonus", "accrual", "bonus-accrual", "bonus_accrual",
    "settlement", "settle", "payout", "pay-out", "pay_out",
    "deposit", "topup", "top-up", "top_up", "fund",
    "refund", "reversal", "chargeback", "order", "invoice",
    "charge", "pay", "enroll", "subscribe", "activate",
])







_RACE_BODY_KEY_HINTS = frozenset([
    "action", "op", "operation", "type", "event", "intent", "command",
])
_GRAPHQL_MUTATION_HINTS = frozenset([
    "mutation", "redeem", "transfer", "withdraw", "claim", "checkout",
    "purchase", "confirm", "applycoupon", "cashout", "payout", "deposit",
    "refund", "settle", "activate", "subscribe",
])







_IDENTIFIER_KEY_HINTS = (
    "id", "uuid", "transaction_id", "txn_id", "order_id", "orderid",
    "redemption_id", "receipt_id", "ticket_id", "coupon_id", "booking_id",
    "reference", "ref", "confirmation_id", "payment_id", "charge_id",
)





_NUMERIC_SIGNAL_KEY_HINTS = (
    "balance", "credits", "remaining", "stock", "quantity", "qty",
    "points", "wallet", "available", "inventory", "uses_left",
)


def _looks_like_mutating_action(url: str, body: Any, params: Any = None) -> bool:
    """
    Broader trigger for the race-condition checks: matches on the URL
    (original behaviour) OR on body keys/values OR on GraphQL mutation
    naming, so single-endpoint GraphQL/RPC APIs aren't silently skipped.
    """
    if any(ind in url.lower() for ind in _RACE_INDICATORS):
        return True

    def _scan(obj: Any, depth: int = 0) -> bool:
        if depth > 4 or obj is None:
            return False
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                if kl in _RACE_BODY_KEY_HINTS and isinstance(v, str):
                    if any(ind in v.lower() for ind in _RACE_INDICATORS):
                        return True
                if kl in ("query", "operationname", "mutation") and isinstance(v, str):
                    vl = v.lower()
                    if any(h in vl for h in _GRAPHQL_MUTATION_HINTS):
                        return True
                if any(ind in kl for ind in _RACE_INDICATORS):
                    return True
                if _scan(v, depth + 1):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if _scan(item, depth + 1):
                    return True
        elif isinstance(obj, str):
            if any(h in obj.lower() for h in _GRAPHQL_MUTATION_HINTS):
                return True
        return False

    return _scan(body) or _scan(params)


def _find_identifier_values(body: str) -> set:
    """Extract candidate resource/transaction identifiers from a response body."""
    found: set = set()
    try:
        data = json.loads(body)
    except Exception:
        return found

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in _IDENTIFIER_KEY_HINTS and isinstance(v, (str, int)):
                    found.add(str(v))
                if isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return found


def _find_numeric_signals(body: str) -> dict:
    """Extract balance/quantity/stock-like numeric fields for a delta check."""
    signals: dict = {}
    try:
        data = json.loads(body)
    except Exception:
        return signals

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).lower() in _NUMERIC_SIGNAL_KEY_HINTS and isinstance(v, (int, float)):
                    signals[str(k).lower()] = v
                if isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return signals






_CF_CHALLENGE_SIGNALS = (
    "just a moment",
    "cf-browser-verification",
    "enable javascript and cookies",
    "checking your browser",
    "ddos-guard",
    "ray id",
)
_cf_challenge_count = 0
_cf_warned          = False
_CF_WARN_THRESHOLD  = 3


def _is_cf_challenge(status: int, headers: dict, body: str) -> bool:
    if status not in (403, 503):
        return False
    if not headers:
        return False
    if not any(k.lower() == "cf-ray" for k in headers):
        return False
    body_lower = (body or "").lower()
    return any(sig in body_lower for sig in _CF_CHALLENGE_SIGNALS)



UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "PostmanRuntime/7.37.0",
    "python-httpx/0.27.0",
    "axios/1.6.8",
]



class AdaptiveRateLimiter:
    def __init__(self, base_delay: float = 0.3):
        self.base_delay       = base_delay
        self.delays:          dict[str, float] = {}
        self.consecutive_429: dict[str, int]   = defaultdict(int)
        self.consecutive_ok:  dict[str, int]   = defaultdict(int)
        self.last_request:    dict[str, float]  = {}

    def get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    async def wait(self, url: str):
        domain     = self.get_domain(url)
        delay      = self.delays.get(domain, self.base_delay)
        since_last = time.time() - self.last_request.get(domain, 0)
        wait_time  = max(0.0, delay - since_last)
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        self.last_request[domain] = time.time()

    def record(self, url: str, status: int, elapsed: float):
        domain = self.get_domain(url)
        if status == 429:
            self.consecutive_429[domain] += 1
            self.consecutive_ok[domain]   = 0
            new_delay = min(30.0, self.base_delay * (2 ** self.consecutive_429[domain]))
            self.delays[domain] = new_delay
            print(f"  [!] 429 — backing off to {new_delay:.1f}s for {domain}")
        elif status in (200, 201, 204, 301, 302, 400, 401, 403, 404):
            self.consecutive_ok[domain]   += 1
            self.consecutive_429[domain]   = 0
            if self.consecutive_ok[domain] > 10:
                current = self.delays.get(domain, self.base_delay)
                self.delays[domain] = max(self.base_delay, current * 0.85)



def _build_discovery_config(scan_config: "ScanConfig") -> Optional["DiscoveryConfig"]:
    if not _HAS_DEEP_DISCOVERY:
        return None

    def _get(attr: str, default: Any = None) -> Any:
        return getattr(scan_config, attr, default)

    return DiscoveryConfig(
        auth_token              = _get("auth_token", ""),
        second_token            = _get("second_user_token", ""),
        timeout_s               = _get("timeout", 15),
        verbose                 = _get("verbose", False),
        use_headless            = _get("use_headless", False),
        headless_interact       = _get("headless_interact", False),
        headless_timeout_s      = _get("headless_timeout_s", 30),
        wordlist_depth          = _get("discovery_depth", 2),
        no_wordlist             = _get("no_wordlist", False),
        follow_js_imports       = True,
        max_js_files            = 30,
        graphql_deep            = _get("run_graphql_deep", False),
        openapi_paths           = _get("openapi_paths", []),
        proto_paths             = _get("proto_paths", []),
        include_versions        = _get(
            "include_versions",
            ["v1", "v2", "v3", "internal", "legacy", "beta"],
        ),
        business_tags           = _get("discovery_tags", []),
        subdomain_wordlist_size = _get("subdomain_wordlist_size", 50),
        save_discovery_path     = _get("save_discovery", ""),
        max_depth               = _get("max_depth", 4),
        use_shodan              = False,
    )


def _merge_discovered(
    existing:   list[dict],
    discovered: list[dict],
) -> tuple[list[dict], int]:
    idx_map: dict[str, int] = {}
    for i, ep in enumerate(existing):
        key = f"{ep.get('method','GET').upper()}|{ep.get('url','')}"
        idx_map[key] = i

    added = 0
    for ep_dict in discovered:
        key = f"{ep_dict.get('method','GET').upper()}|{ep_dict.get('url','')}"
        if key in idx_map:
            ex = existing[idx_map[key]]
            if not ex.get("body") and ep_dict.get("body"):
                ex["body"] = ep_dict["body"]
            if "_meta" not in ex and "_meta" in ep_dict:
                ex["_meta"] = ep_dict["_meta"]
        else:
            existing.append(ep_dict)
            idx_map[key] = len(existing) - 1
            added += 1

    return existing, added





class BLFScanner:

    def __init__(self, config: ScanConfig):
        self.config   = config
        self.findings: list[Finding] = []
        self.session:  Optional[aiohttp.ClientSession] = None
        self._burst_session: Optional[aiohttp.ClientSession] = None
        self.request_log: list[dict] = []
        self.base_responses: dict = {}
        self.rate_limiter = AdaptiveRateLimiter(config.rate_limit)
        self._ua_cycle    = itertools.cycle(UA_POOL)
        self.discovered_endpoints: list[dict] = []
        self._seen_findings: set = set()






        self._posture_cache = PostureCache() if _HAS_FIELD_TYPING else None
        self._admin_paths_probed: set[str] = set()


        self.confidence_engine = ConfidenceEngine()
        self.poc_generator     = PoCGenerator(config)
        self._verifier: Optional[FindingVerifier] = None





        self._checkpoint: Optional[ScanCheckpoint] = None
        if getattr(config, "checkpoint_path", ""):
            self._checkpoint = ScanCheckpoint.load_or_create(
                config.checkpoint_path, config.target_url
            )
            if getattr(config, "resume", False) and self._checkpoint.completed:
                print(f"[*] Resuming: {self._checkpoint.summary()}")


        self._session_mgr:   Optional[SessionManager]   = None
        self._blind_idor:    Optional[BlindIDORScanner]  = None
        self._timing_oracle: Optional[TimingOracle]      = None
        self._flow_replayer: Optional[FlowReplayer]      = None
        self._volatile_extractors: dict[str, Any] = {}
        self._baseline_samples:    dict[str, list[str]] = defaultdict(list)


        self._endpoint_validator:   Optional[EndpointValidator]  = None
        self._response_classifier:  Optional[ResponseClassifier] = None
        self._classified_responses: dict[str, ClassifiedResponse] = {}
        self._subdomain_map:  Optional[SubdomainMapResult]  = None
        self._js_secrets:     Optional[JSExtractionResult]  = None
        self._skipped_endpoints: list[str] = []


        self._idor_enumerator: Optional[IDORMassEnumerator] = None
        self._gql_deep:        Optional[GraphQLDeepScanner] = None
        self._ws_scanner:      Optional[WebSocketScanner]   = None
        self._version_scanner: Optional[APIVersionScanner]  = None
        self._cors_scanner:    Optional[CORSScanner]         = None
        self._sec_header_auditor: Optional[SecurityHeaderAuditor] = None
        self._jwt_scanner:     Optional[JWTAlgConfusionScanner] = None
        self._tenant_bola:     Optional[TenantBOLAScanner] = None
        self._ssrf_scanner:    Optional[SSRFScanner] = None
        self._csrf_scanner:    Optional[CSRFScanner] = None
        self._source_scanner:  Optional[SourceCodeScanner] = None
        self._classifier:      Optional[BusinessClassifier] = None
        self._attack_plan:     Optional[AttackPlan]          = None


        self._dashboard_state:          Optional[DashboardState] = None
        self._findings_queue:           Optional[asyncio.Queue]  = None
        self._profile_skip_modules:     set[str]  = set()
        self._profile_priority_modules: list[str] = []


        self._discovery_engine: Optional[DeepDiscoveryEngine] = None



    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl, limit=20, limit_per_host=5
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout, connect=10)
        self.session   = aiohttp.ClientSession(connector=connector, timeout=timeout)
        self._verifier = FindingVerifier(self, self.config)









        burst_connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl, limit=0, limit_per_host=0
        )
        self._burst_session = aiohttp.ClientSession(
            connector=burst_connector, timeout=timeout
        )


        if _HAS_BLIND_IDOR:
            self._blind_idor = BlindIDORScanner(self)
        if _HAS_TIMING:
            self._timing_oracle = TimingOracle(self)
        if _HAS_FLOWS:
            self._flow_replayer = FlowReplayer(self)
        if _HAS_SESSION and getattr(self.config, "refresh_config", None):
            self._session_mgr = SessionManager(self.config, self.config.refresh_config)
            self._session_mgr.initialize(self.session)


        if _HAS_VALIDATION:
            self._endpoint_validator  = EndpointValidator(self, ValidationConfig())
            self._response_classifier = ResponseClassifier()


        if _HAS_IDOR_ENUM:
            self._idor_enumerator = IDORMassEnumerator(self)
        if _HAS_GQL_DEEP:
            self._gql_deep = GraphQLDeepScanner(self)
        if _HAS_WEBSOCKET and getattr(self.config, "run_websocket", False):
            self._ws_scanner = WebSocketScanner(self)
        if _HAS_VERSION and getattr(self.config, "run_version_scan", False):
            self._version_scanner = APIVersionScanner(self)
        if _HAS_CORS:
            self._cors_scanner = CORSScanner(self)
        if _HAS_SEC_HEADERS:
            self._sec_header_auditor = SecurityHeaderAuditor(self)
        if _HAS_JWT_CONFUSION:
            self._jwt_scanner = JWTAlgConfusionScanner(self)
        if _HAS_TENANT_BOLA:
            self._tenant_bola = TenantBOLAScanner(self)
        if _HAS_SSRF and getattr(self.config, "run_ssrf", False):
            self._ssrf_scanner = SSRFScanner(self)
        if _HAS_CSRF:



            self._csrf_scanner = CSRFScanner(self)
        if _HAS_SOURCE_SCAN and getattr(self.config, "run_source_scan", False):
            self._source_scanner = SourceCodeScanner(self)
        if _HAS_CLASSIFIER:
            self._classifier = BusinessClassifier()


        self._findings_queue = asyncio.Queue()


        if _HAS_DEEP_DISCOVERY and not getattr(self.config, "no_deep_discovery", False):
            self._discovery_engine = DeepDiscoveryEngine(
                verbose=self.config.verbose
            )

        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
        if getattr(self, "_burst_session", None):
            await self._burst_session.close()



    def apply_profile(self, profile: dict):
        settings = profile.get("settings", {})
        if "rate_limit" in settings:
            self.rate_limiter.base_delay = settings["rate_limit"]
        if "fuzz_depth" in settings:
            self.config.fuzz_depth = settings["fuzz_depth"]
        if "min_confidence" in settings:
            self.config.min_confidence = settings["min_confidence"]
        self._profile_skip_modules     = set(profile.get("skip_modules", []))
        self._profile_priority_modules = profile.get("priority_modules", [])
        for key, val in settings.items():
            if not hasattr(self.config, key):
                setattr(self.config, key, val)

    def set_dashboard_state(self, state: "DashboardState"):
        self._dashboard_state = state

    def _update_dashboard(self, finding=None, endpoint: str = ""):
        if not self._dashboard_state:
            return
        if endpoint:
            self._dashboard_state.current_endpoint = endpoint[-50:]
        if finding:
            self._dashboard_state.add_finding(
                title=finding.title[:55],
                severity=(
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                ),
                confirmed=getattr(finding, "confirmed", False),
            )
        self._dashboard_state.total_requests = len(self.request_log)
        self._dashboard_state.total_429s     = sum(
            1 for r in self.request_log if r.get("status") == 429
        )



    @staticmethod
    def _basic_auth_value(sid: str, secret: str) -> str:
        raw = f"{sid}:{secret}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _build_headers(
        self,
        extra: dict = None,
        token: str = None,
        api_key: tuple = None,
    ) -> dict:
        ua = (
            next(self._ua_cycle)
            if getattr(self.config, "user_agent_rotate", True)
            else UA_POOL[0]
        )
        headers = {
            "User-Agent":       ua,
            "Accept":           "application/json, text/html, */*;q=0.8",
            "Accept-Language":  "en-US,en;q=0.9",
            "Content-Type":     "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        t = token if token is not None else (
            self._session_mgr.state.token
            if self._session_mgr and self._session_mgr.state.token
            else self.config.auth_token
        )
        sid, secret = (
            api_key if api_key is not None
            else (self.config.api_key_sid, self.config.api_key_secret)
        )
        if t:
            headers["Authorization"] = f"Bearer {t}"
        elif sid and secret:
            headers["Authorization"] = self._basic_auth_value(sid, secret)
        if self._session_mgr and self._session_mgr.state.csrf_token:
            csrf_hdr = self._session_mgr.state.csrf_header_name or "X-CSRF-Token"
            headers[csrf_hdr] = self._session_mgr.state.csrf_token
        headers.update(self.config.headers)
        if extra:
            headers.update(extra)
        return headers

    async def _read_body_capped(self, resp) -> str:
        limit = getattr(self.config, "max_body_bytes", 10_000_000)
        chunks = []
        total = 0
        async for chunk in resp.content.iter_chunked(65536):
            total += len(chunk)
            if total > limit:
                chunks.append(chunk[: limit - (total - len(chunk))])
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        encoding = resp.charset or "utf-8"
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        token_override: str = None,
        api_key_override: tuple = None,
        _retry_on_401: bool = True,
        **kwargs,
    ) -> tuple[int, dict, str, float]:
        """
        WEAK-4 FIX: Detects Cloudflare challenge pages and warns operator
        when cf_clearance has expired mid-scan instead of silently failing.
        """
        global _cf_challenge_count, _cf_warned

        if self._session_mgr and _retry_on_401:
            await self._session_mgr.ensure_valid(
                lambda: self._request(
                    method, url, headers=headers,
                    token_override=token_override,
                    _retry_on_401=False, **kwargs,
                )
            )

        await self.rate_limiter.wait(url)

        req_headers = self._build_headers(headers)
        if token_override is not None:
            if token_override == "":
                req_headers.pop("Authorization", None)
            else:
                req_headers["Authorization"] = f"Bearer {token_override}"
        elif api_key_override is not None:
            sid, secret = api_key_override
            if sid and secret:
                req_headers["Authorization"] = self._basic_auth_value(sid, secret)
            else:
                req_headers.pop("Authorization", None)

        cookies = dict(self.config.cookies)
        if self._session_mgr:
            cookies.update(self._session_mgr.get_cookies())

        start = time.time()
        try:
            async with self.session.request(
                method, url,
                headers=req_headers,
                cookies=cookies,
                allow_redirects=True,
                max_redirects=getattr(self.config, "max_redirects", 5),
                proxy=self.config.proxy if self.config.proxy else None,
                **kwargs,
            ) as resp:
                elapsed   = time.time() - start
                body      = await self._read_body_capped(resp)
                resp_hdrs = dict(resp.headers)
                self.rate_limiter.record(url, resp.status, elapsed)
                self.request_log.append({
                    "method":  method,
                    "url":     url,
                    "status":  resp.status,
                    "elapsed": round(elapsed, 3),
                })


                if _is_cf_challenge(resp.status, resp_hdrs, body):
                    _cf_challenge_count += 1
                    if _cf_challenge_count >= _CF_WARN_THRESHOLD and not _cf_warned:
                        _cf_warned = True
                        print(
                            "\n"
                            "  [!] ════════════════════════════════════════════════\n"
                            "  [!] CLOUDFLARE CHALLENGE — cf_clearance has expired\n"
                            "  [!] Multiple requests are being blocked.\n"
                            "  [!] ACTION: Open target in browser → export cookies\n"
                            "  [!]   → restart blfinder with new cf_clearance value\n"
                            "  [!] ════════════════════════════════════════════════\n"
                        )
                else:
                    if resp.status not in (403, 503):
                        _cf_challenge_count = 0

                if self._session_mgr:
                    self._session_mgr.absorb_response(
                        resp_hdrs, body, url, resp.status
                    )
                if resp.status == 401 and _retry_on_401 and self._session_mgr:
                    refreshed = await self._session_mgr.handle_401(url)
                    if refreshed:
                        return await self._request(
                            method, url, headers=headers,
                            token_override=token_override,
                            _retry_on_401=False, **kwargs,
                        )
                if self.config.verbose:
                    print(
                        f"  [{resp.status}] {method} {url[:80]} ({elapsed:.2f}s)"
                    )
                return resp.status, resp_hdrs, body, elapsed

        except asyncio.TimeoutError:
            return 0, {}, "TIMEOUT", time.time() - start
        except aiohttp.ClientConnectorError as e:
            return 0, {}, f"CONNECTION_ERROR: {str(e)[:100]}", time.time() - start
        except Exception as e:
            return 0, {}, f"ERROR: {str(e)[:100]}", time.time() - start



    def _new_evidence(self) -> "EvidenceCapture | None":
        if not _HAS_EVIDENCE:
            return None
        return EvidenceCapture(self)

    async def _req_ev(
        self,
        label: str,
        ev: "EvidenceCapture | None",
        method: str,
        url: str,
        req_body: dict | None = None,
        token_override: str | None = None,
        api_key_override: tuple | None = None,
        extra_headers: dict | None = None,
        **kwargs,
    ) -> tuple[int, dict, str, float]:
        status, resp_hdrs, resp_body, elapsed = await self._request(
            method, url,
            headers=extra_headers,
            token_override=token_override,
            api_key_override=api_key_override,
            json=req_body if req_body else None,
            **kwargs,
        )
        if ev is not None:
            built = self._build_headers(
                extra_headers,
                token=token_override,
                api_key=api_key_override,
            )
            ev.record(
                label=label, method=method, url=url,
                req_headers=built, req_body=req_body,
                resp_status=status, resp_headers=resp_hdrs,
                resp_body=resp_body, elapsed=elapsed,
            )
        return status, resp_hdrs, resp_body, elapsed

    def _build_pkg(
        self,
        ev: "EvidenceCapture | None",
        title: str,
        endpoint: str,
        vuln_type: str,
        confidence: int = 0,
        confirmed: bool = False,
        fp_notes: list[str] | None = None,
    ) -> "EvidencePackage | None":
        if ev is None or not _HAS_EVIDENCE:
            return None
        return ev.build_package(
            finding_title=title, endpoint=endpoint,
            vulnerability_type=vuln_type, confidence=confidence,
            confirmed=confirmed, fp_notes=fp_notes or [],
        )

    def _attach(self, f: Finding, pkg: "EvidencePackage | None") -> Finding:
        if pkg is not None:
            f.evidence_package = pkg  
            if pkg.summary:
                f.evidence = pkg.summary
        return f



    def _try_parse_json(self, body: str) -> dict | list:
        try:
            return json.loads(body)
        except Exception:
            return {}

    def _hash_response(self, body: str) -> str:
        return hashlib.md5(body.encode()).hexdigest()

    def _responses_differ_significantly(self, a: str, b: str) -> bool:
        if a == b:
            return False
        if _HAS_SEMANTIC:
            diff = SemanticDiff.compare(
                a, b, threshold=self.config.similarity_threshold
            )
            return diff.is_different
        sim = difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()
        return sim < (1.0 - self.config.similarity_threshold)

    def _response_indicates_success(self, body: str, status: int = 200) -> bool:
        """
        Word-boundary / JSON-shaped matching, not bare substrings. The old
        version matched "id" inside "paid"/"invalid"/"guide", "true" inside
        arbitrary prose, and "token" on any CSRF-token mention — all of
        which are load-bearing for JWT bypass and cross-tenant BOLA
        confirmation upstream, so a promiscuous match there produced real
        false positives/negatives, not just cosmetic noise.
        """
        if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
            return False
        if status >= 500:
            return False
        body_lower = body.lower()
        has_failure = any(p.search(body_lower) for p in _FAILURE_INDICATOR_PATTERNS)
        if status in (200, 201, 204):
            return not has_failure
        has_success = any(p.search(body_lower) for p in _SUCCESS_INDICATOR_PATTERNS)
        return has_success and not has_failure

    def _extract_discount(self, body: str) -> float:
        try:
            data = json.loads(body)
            for key in ["discount", "discount_amount", "savings", "coupon_value"]:
                if isinstance(data, dict) and key in data:
                    return float(data[key])
        except Exception:
            pass
        return 0.0

    def _mutate_nested(
        self, obj: Any, target_key: str, new_val: Any, depth: int = 0
    ) -> list[Any]:
        mutations = []
        if depth > self.config.fuzz_depth:
            return mutations
        if isinstance(obj, dict):
            if target_key in obj:
                m = copy.deepcopy(obj)
                m[target_key] = new_val
                mutations.append(m)
            for k, v in obj.items():
                for sub in self._mutate_nested(v, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[k] = sub
                    mutations.append(m)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                for sub in self._mutate_nested(item, target_key, new_val, depth + 1):
                    m = copy.deepcopy(obj)
                    m[i] = sub
                    mutations.append(m)
        return mutations

    async def _targeted_payloads_for(
        self, module: str, method: str, url: str, body: dict, key: str, original: Any
    ) -> list[Any]:
        """
        Type-aware, calibrated replacement for a fixed universal tamper
        list. Falls back to a conservative built-in list if the field
        typing engine isn't importable (keeps the scanner working even
        if that module is missing/broken).

        1. Infer the field's real type from its observed value.
        2. Check this endpoint's cached validation posture. If it hasn't
           been calibrated yet, fire ONE cheap canary request with an
           obviously wrong-typed value for this field and learn whether
           the endpoint rejects bad types (strict) or accepts anything
           (permissive) — the answer is cached per (method, url) so the
           other modules hitting the same endpoint reuse it instead of
           re-probing.
        3. Generate payloads that match the field's real type envelope
           (so they have a chance of reaching business logic) plus, only
           if the endpoint is permissive, a broader type-breaking set.
        """
        if not _HAS_FIELD_TYPING or self._posture_cache is None:
            return [0, 0.01, -1, -100, "0", 1]  

        ftype = infer_field_type(key, original)
        posture = self._posture_cache.get(method, url)

        if not posture.calibrated:
            canary_val = build_canary_value(ftype)
            for mutated in self._mutate_nested(body, key, canary_val):
                try:
                    status, _, resp_body, _ = await self._request(method, url, json=mutated)
                except Exception:
                    status, resp_body = 0, ""
                rejected = status in (400, 401, 403, 405, 409, 415, 422) or status == 0
                self._posture_cache.record_calibration(method, url, canary_rejected=rejected)
                if not rejected and not posture.weak_validation_finding_emitted:




                    posture.weak_validation_finding_emitted = True
                    self._flag_weak_type_validation(url, method, key, canary_val, status)
                break  

        return generate_payloads(ftype, original, permissive=not posture.strict)

    def _flag_weak_type_validation(
        self, url: str, method: str, key: str, canary_val: Any, status: int
    ) -> None:
        """
        Records a low-severity informational finding when an endpoint
        accepts an obviously wrong-typed value for a field. Kept low
        severity/confidence on its own — it's context for the report,
        not a headline bug — but it's exactly the kind of target where
        the broader (type-breaking) payload set is worth trying.
        """
        try:
            f = Finding(
                title=f"Weak Type Validation — `{key}` accepts wrong-typed input",
                severity=Severity.LOW,
                category="Input Validation",
                description=(
                    f"`{method} {url}` accepted a canary value of the wrong "
                    f"type (`{canary_val!r}`) for field `{key}` (HTTP {status}) "
                    f"instead of rejecting it at the validation layer. This "
                    f"widens the field's real attack surface — broader tamper "
                    f"payloads for this field are being tried as a result."
                ),
                request={"method": method, "url": url, "note": f"canary: {key}={canary_val!r}"},
                response_summary=f"HTTP {status}",
                evidence=f"Type-mismatched canary for `{key}` returned HTTP {status} (not rejected).",
                recommendation="Enforce strict schema/type validation server-side before business logic runs.",
                cwe="CWE-20", cvss=3.1,
                owasp="API8:2023 Security Misconfiguration",
                confidence=55, endpoint=url, parameter=key,
            )
            if f.confidence >= self.config.min_confidence:
                self.findings.append(f)
        except Exception:
            pass  

    def _finalize_finding(
        self,
        finding: Finding,
        base_body: str,
        tampered_body: str,
        base_status: int,
        tampered_status: int,
    ) -> Finding:
        finding = self.confidence_engine.score(
            finding, base_body, tampered_body, base_status, tampered_status
        )
        finding = severity_from_confidence(finding)
        finding.poc = self.poc_generator.generate(finding)
        return finding

    def _record_baseline_sample(self, url: str, body: str):
        if _HAS_SEMANTIC and body and not body.startswith(("TIMEOUT", "ERROR:")):
            self._baseline_samples[url].append(body)
            if len(self._baseline_samples[url]) == 3:
                self._volatile_extractors[url] = build_volatile_map(
                    self._baseline_samples[url], endpoint=url
                )



    async def smart_discover(self, seed_url: str) -> list[dict]:
        """
        Legacy discovery — regex crawl + common path probing.
        Used only when the deep discovery engine is unavailable.
        """
        print("[*] Smart Discovery (legacy) — crawling for endpoints...")
        found:   list[dict] = []
        visited: set[str]   = set()

        async def fetch_and_extract(url: str):
            if url in visited:
                return
            visited.add(url)
            status, headers, body, _ = await self._request("GET", url)
            if status != 200 or not body:
                return
            api_patterns = [
                r'(?:url|endpoint|api|path)\s*[=:]\s*["`\']([/][^`\'"<>\s]{3,80})["`\']',
                r'(?:fetch|axios|get|post|put|patch|delete)\s*\(\s*["`\']([/][^`\'"<>\s]{3,80})["`\']',
                r'/api/v?\d*/[a-z][a-z0-9_/-]{2,50}',
                r'/v\d+/[a-z][a-z0-9_/-]{2,50}',
            ]
            discovered: set[str] = set()
            for pat in api_patterns:
                for m in re.findall(pat, body, re.I):
                    if isinstance(m, str) and m.startswith("/"):
                        discovered.add(m.split("?")[0])
            js_urls = re.findall(
                r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body
            )
            parsed = urlparse(seed_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            for path in discovered:
                method = (
                    "POST"
                    if any(
                        k in path.lower()
                        for k in ["creat", "add", "submit", "order", "checkout"]
                    )
                    else "GET"
                )
                found.append({
                    "url": urljoin(base, path), "method": method,
                    "body": {}, "params": {},
                })
            for js_url in js_urls[:5]:
                full = (
                    urljoin(base, js_url)
                    if not js_url.startswith("http") else js_url
                )
                await fetch_and_extract(full)

        await fetch_and_extract(seed_url)

        common = [
            "/api/v1", "/api/v2", "/api", "/v1", "/v2",
            "/graphql", "/api/graphql", "/api/users", "/api/me",
            "/api/orders", "/api/payments", "/api/admin",
            "/swagger.json", "/openapi.json", "/api-docs",
        ]
        parsed = urlparse(seed_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        probes = await asyncio.gather(
            *[self._request("GET", f"{base}{p}") for p in common],
            return_exceptions=True,
        )
        for path, result in zip(common, probes):
            if isinstance(result, tuple) and result[0] == 200:
                ep_url = f"{base}{path}"
                found.append({
                    "url": ep_url, "method": "GET", "body": {}, "params": {},
                })
                print(f"  [+] Discovered: {ep_url}")
                if "openapi" in path or "swagger" in path:
                    found.extend(self._parse_openapi(result[2], base))

        self.discovered_endpoints = found
        print(f"  [*] Discovered {len(found)} endpoints\n")
        return found

    def _parse_openapi(self, spec_body: str, base_url: str) -> list[dict]:
        endpoints = []
        try:
            spec = json.loads(spec_body)
            for path, methods in spec.get("paths", {}).items():
                for method, info in methods.items():
                    if method.upper() not in (
                        "GET", "POST", "PUT", "PATCH", "DELETE"
                    ):
                        continue
                    body = {}
                    rb   = info.get("requestBody", {})
                    if rb:
                        schema = (
                            rb.get("content", {})
                            .get("application/json", {})
                            .get("schema", {})
                        )
                        for k, v in schema.get("properties", {}).items():
                            t = v.get("type", "string")
                            body[k] = (
                                1     if t in ("integer", "number")
                                else True  if t == "boolean"
                                else "test"
                            )
                    endpoints.append({
                        "url":    urljoin(base_url, path),
                        "method": method.upper(),
                        "body":   body, "params": {},
                    })
        except Exception:
            pass
        return endpoints



    async def _run_recon(self):
        target_domain = urlparse(self.config.target_url).netloc

        if _HAS_SUBDOMAIN and getattr(self.config, "run_subdomain_map", True):
            print("[*] Phase 3: Subdomain recon...")
            try:
                mapper = SubdomainMapper(verbose=self.config.verbose)
                self._subdomain_map = await mapper.map(
                    target_domain,
                    max_wordlist=getattr(self.config, "subdomain_wordlist_size", 50),
                    session=self.session,
                )
                r = self._subdomain_map
                print(
                    f"  [+] Subdomain recon: {r.live_count} live, "
                    f"{r.api_count} API surface"
                )
                for sub in r.high_priority[:5]:
                    print(f"  [{sub.priority}] {sub.hostname} (score={sub.score})")
                print()
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Subdomain recon error: {e}")

        if _HAS_JS_EXTRACT and getattr(self.config, "run_js_extract", False):
            print("[*] Phase 3: JS secret extraction...")
            try:
                extractor        = JSSecretExtractor(verbose=self.config.verbose)
                self._js_secrets = await extractor.extract(
                    self.config.target_url, session=self.session,
                )
                r = self._js_secrets
                print(
                    f"  [+] JS extraction: {r.js_files_scanned} files, "
                    f"{len(r.confirmed_secrets)} secrets found"
                )
                print()
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] JS extraction error: {e}")

    def _js_secrets_to_findings(self) -> list[Finding]:
        if not self._js_secrets:
            return []
        sev_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,   "LOW":  Severity.LOW,
        }
        findings = []
        for secret in self._js_secrets.confirmed_secrets:
            f = Finding(
                title=(
                    f"Secret in JS: {secret.pattern_name} "
                    f"in {_url_basename(secret.source_url)}"
                ),
                severity=sev_map.get(secret.severity, Severity.MEDIUM),
                category="Reconnaissance — JavaScript Secret",
                description=(
                    f"{secret.pattern_name} found in `{secret.source_url}` "
                    f"at line {secret.line_number}. Value: `{secret.redacted}`"
                ),
                request={
                    "method": "GET", "url": secret.source_url,
                    "note": "JavaScript file containing secret",
                },
                response_summary=(
                    f"Secret found in JS file (confidence {secret.confidence}%)"
                ),
                evidence=(
                    f"{secret.pattern_name} at line {secret.line_number}: "
                    f"`{secret.redacted}` | Context: {secret.context[:80]}"
                ),
                recommendation=(
                    "Remove secrets from client-side JavaScript. "
                    "Use server-side environment variables. "
                    "Rotate any exposed credentials immediately."
                ),
                cwe="CWE-312",
                cvss=8.0 if secret.severity == "CRITICAL" else 6.5,
                owasp="API2:2023 Broken Authentication",
                confirmed=True, confidence=secret.confidence,
                endpoint=secret.source_url,
            )
            f.poc = self.poc_generator.generate(f)
            findings.append(f)
        return findings



    async def _run_phase4_scans(self, endpoints: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        if _HAS_GQL_DEEP and self._gql_deep and getattr(
            self.config, "run_graphql_deep", False
        ):
            parsed = urlparse(self.config.target_url)
            base   = f"{parsed.scheme}://{parsed.netloc}"
            for gql_path in ["/graphql", "/api/graphql", "/query"]:
                gql_url = f"{base}{gql_path}"
                try:
                    result = await self._gql_deep.scan(gql_url)
                    findings.extend(result.findings)
                except Exception as e:
                    if self.config.verbose:
                        print(f"  [!] GraphQL deep error: {e}")

        if _HAS_WEBSOCKET and self._ws_scanner:
            try:
                ws_url_override = getattr(self.config, "ws_url", "")
                ws_eps = await self._ws_scanner.discover(self.config.target_url)
                if ws_url_override:
                    from .modules.websocket_scanner import WSEndpoint
                    ws_eps.insert(0, WSEndpoint(url=ws_url_override))
                for ep in ws_eps[:5]:
                    result = await self._ws_scanner.scan(ep)
                    findings.extend(result.findings)
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] WebSocket scan error: {e}")

        if _HAS_VERSION and self._version_scanner:
            try:
                known_eps = [ep.get("url", "") for ep in endpoints[:20]]
                result    = await self._version_scanner.scan(
                    self.config.target_url,
                    known_endpoints=known_eps,
                )
                findings.extend(result.all_findings)
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Version scan error: {e}")

        if _HAS_IDOR_ENUM and self._idor_enumerator:
            idor_range = getattr(self.config, "idor_range", 0)
            if idor_range > 0:
                for url, base_resp in list(self.base_responses.items())[:10]:
                    self._idor_enumerator.harvest_ids(base_resp.get("body", ""))
                    try:
                        result = await self._idor_enumerator.enumerate_path(
                            url=url, max_range=idor_range,
                        )
                        findings.extend(result.findings)
                    except Exception as e:
                        if self.config.verbose:
                            print(f"  [!] IDOR enum error on {url}: {e}")

            if (
                getattr(self.config, "idor_cross_endpoint", False)
                and self._idor_enumerator.harvested_ids
            ):
                for harvested_id in list(self._idor_enumerator.harvested_ids)[:5]:
                    try:
                        cross = await self._idor_enumerator.enumerate_cross_endpoint(
                            id_value=harvested_id,
                            endpoints=endpoints,
                        )
                        findings.extend(cross)
                    except Exception as e:
                        if self.config.verbose:
                            print(f"  [!] Cross-endpoint IDOR error: {e}")

        return findings



    def _write_dropped_findings(self, dropped: list) -> None:
        """
        Findings that passed the confidence filter but failed
        FindingVerifier's re-test are written here instead of vanishing
        silently — re-verification can have false negatives (flaky
        endpoints, session/state that only reproduces once, WAF rate
        limiting the re-test itself), so this is the manual-review safety
        net. Use --no-verify to skip re-verification entirely instead.
        """
        if not dropped:
            return
        try:
            import os as _os
            out_dir = getattr(self.config, "output_dir", ".") or "."
            _os.makedirs(out_dir, exist_ok=True)
            path = _os.path.join(out_dir, "dropped_findings.json")
            payload = []
            for f in dropped:
                payload.append({
                    "title": getattr(f, "title", ""),
                    "severity": getattr(getattr(f, "severity", None), "value", str(getattr(f, "severity", ""))),
                    "endpoint": getattr(f, "endpoint", ""),
                    "confidence": getattr(f, "confidence", 0),
                    "evidence": getattr(f, "evidence", ""),
                    "request": getattr(f, "request", {}),
                })
            with open(path, "w") as fh:
                json.dump(payload, fh, indent=2, default=str)
            print(
                f"  [*] {len(dropped)} finding(s) dropped by re-verification — "
                f"written to {path} for manual review (or re-run with --no-verify)"
            )
        except Exception as e:
            if getattr(self.config, "verbose", False):
                print(f"  [!] Could not write dropped_findings.json: {e}")

    async def run_all_modules(self, endpoints: list[dict]) -> list[Finding]:
        print(f"[*] BLFinder v3.1 Phase 5 — Target: {self.config.target_url}")
        print(f"[*] {len(endpoints)} endpoints queued\n")

        if self._dashboard_state:
            self._dashboard_state.total_endpoints = len(endpoints)


        if getattr(self.config, "run_recon", False):
            await self._run_recon()


        if self.config.smart_discovery:
            if (
                self._discovery_engine is not None
                and not getattr(self.config, "no_deep_discovery", False)
            ):
                disc_config = _build_discovery_config(self.config)
                if disc_config is not None:
                    try:
                        queue = await self._discovery_engine.discover(
                            target_url      = self.config.target_url,
                            session         = self.session,
                            config          = disc_config,
                            seed_endpoints  = endpoints[:],
                        )
                        discovered_list = queue.to_endpoint_list()
                        endpoints, added = _merge_discovered(endpoints, discovered_list)
                        print(
                            f"[*] Total after deep discovery: {len(endpoints)} endpoints "
                            f"(+{added} new)\n"
                        )
                    except Exception as e:
                        print(
                            f"  [!] Deep discovery error: {e} "
                            f"— continuing with {len(endpoints)} existing endpoints"
                        )
                        if self.config.verbose:
                            import traceback
                            traceback.print_exc()
            else:

                extra    = await self.smart_discover(self.config.target_url)
                existing = {(e["url"], e.get("method", "GET")) for e in endpoints}
                for ep in extra:
                    key = (ep["url"], ep.get("method", "GET"))
                    if key not in existing:
                        endpoints.append(ep)
                        existing.add(key)
                print(f"[*] Total after discovery: {len(endpoints)} endpoints\n")

            if self._dashboard_state:
                self._dashboard_state.total_endpoints = len(endpoints)


        if self._subdomain_map:
            sub_eps  = self._subdomain_map.to_endpoints()
            existing = {(e["url"], e.get("method", "GET")) for e in endpoints}
            added    = 0
            for ep in sub_eps:
                key = (ep["url"], ep.get("method", "GET"))
                if key not in existing:
                    endpoints.append(ep)
                    existing.add(key)
                    added += 1
            if added:
                print(f"  [+] Added {added} subdomain-discovered endpoints\n")
                if self._dashboard_state:
                    self._dashboard_state.total_endpoints = len(endpoints)


        if _HAS_CLASSIFIER and self._classifier:
            self._attack_plan = self._classifier.build_plan(endpoints)
            if getattr(self.config, "print_attack_plan", False):
                self._attack_plan.print_report(verbose=self.config.verbose)


        flow_findings: list[Finding] = []
        if _HAS_FLOWS and self._flow_replayer and getattr(
            self.config, "run_flows", False
        ):
            flow_findings = await self._run_flow_attacks()
            print(f"  [*] Flow attacks: {len(flow_findings)} findings\n")
            if self._checkpoint:
                self._checkpoint.add_findings(flow_findings)


        oauth_findings: list[Finding] = []
        if _HAS_OAUTH and getattr(self.config, "oauth_config", None):
            oauth_findings = await self._run_oauth_tests()
            if self._checkpoint:
                self._checkpoint.add_findings(oauth_findings)




        skipped_resumed = 0
        if self._checkpoint and getattr(self.config, "resume", False):
            filtered = []
            for ep in endpoints:
                url = ep.get("url", "")
                if not url.startswith("http"):
                    url = urljoin(self.config.target_url, url)
                method = ep.get("method", "GET").upper()
                if self._checkpoint.is_done(url, method):
                    skipped_resumed += 1
                else:
                    filtered.append(ep)
            endpoints = filtered
            if skipped_resumed:
                print(
                    f"  [*] Resume: skipping {skipped_resumed} already-checked "
                    f"endpoint(s), {len(endpoints)} remaining\n"
                )

        async def _run_and_checkpoint(url, method, body, params, meta):










            ep_findings = await self._run_endpoint_checks(url, method, body, params, meta=meta)
            if self._checkpoint:
                self._checkpoint.mark_done(url, method, ep_findings)
            return ep_findings

        tasks = []
        for ep in endpoints:
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self.config.target_url, url)

            body   = ep.get("body", {}) or {}
            meta   = ep.get("_meta", {})
            if not body and meta.get("schema_hint"):
                body = meta["schema_hint"]
            method = ep.get("method", "GET").upper()

            tasks.append(
                _run_and_checkpoint(url, method, body, ep.get("params", {}), meta)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        raw: list[Finding] = list(flow_findings) + list(oauth_findings)


        if self._checkpoint:
            raw.extend(self._checkpoint.findings)
        for r in results:
            if isinstance(r, list):
                raw.extend(r)


        raw.extend(await self._check_graphql_idor())


        if any([
            getattr(self.config, "run_graphql_deep", False),
            getattr(self.config, "run_websocket",    False),
            getattr(self.config, "run_version_scan", False),
            getattr(self.config, "idor_range", 0) > 0,
        ]):
            print("[*] Phase 4: Attack surface expansion...")
            phase4 = await self._run_phase4_scans(endpoints)
            raw.extend(phase4)
            print(f"  [+] Phase 4: {len(phase4)} additional findings\n")


        if self._js_secrets:
            raw.extend(self._js_secrets_to_findings())


        above   = [
            f for f in raw
            if getattr(f, "confidence", 0) >= self.config.min_confidence
        ]
        dropped = len(raw) - len(above)
        if dropped:
            print(
                f"  [*] Dropped {dropped} low-confidence findings "
                f"(< {self.config.min_confidence}%)"
            )


        if _HAS_VALIDATION and self._endpoint_validator and self._skipped_endpoints:
            stats = self._endpoint_validator.get_stats()
            print(
                f"  [*] Endpoint validation: "
                f"{stats['valid']} valid, "
                f"{stats['skipped']} skipped "
                f"({stats['soft_404']} soft-404, "
                f"{stats['waf']} WAF, "
                f"{stats.get('not_graphql',0)} not-graphql)"
            )


        if getattr(self.config, "skip_verification", False):
            print(f"  [*] Skipping re-verification (--no-verify): keeping all {len(above)} findings as-is")
            verified = above
        else:
            print(f"[*] Verifying {len(above)} findings...")
            verified = await self._verifier.verify_all(above, self.base_responses)






            if len(verified) < len(above):
                verified_keys = {
                    hashlib.md5(f"{f.title}{f.evidence}".encode()).hexdigest() for f in verified
                }
                dropped_findings = [
                    f for f in above
                    if hashlib.md5(f"{f.title}{f.evidence}".encode()).hexdigest() not in verified_keys
                ]
                self._write_dropped_findings(dropped_findings)


        seen:   set[str]      = set()
        unique: list[Finding] = []
        for f in verified:
            key = hashlib.md5(f"{f.title}{f.evidence}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(f)

        self.findings = unique
        print(f"[*] Final: {len(self.findings)} verified findings\n")

        for f in self.findings:
            if self._findings_queue:
                await self._findings_queue.put(f)




        if self._checkpoint:
            self._checkpoint.clear()

        return self.findings



    async def _run_endpoint_checks(
        self,
        url:    str,
        method: str,
        body:   dict,
        params: dict,
        meta:   dict = None,
    ) -> list[Finding]:
        findings: list[Finding] = []


        self._update_dashboard(endpoint=url)
        if self._dashboard_state:
            self._dashboard_state.scanned_endpoints += 1
            while self._dashboard_state.paused:
                await asyncio.sleep(0.5)


        is_graphql = any(seg in url.lower() for seg in ["/graphql", "/gql", "/query"])
        if _HAS_VALIDATION and self._endpoint_validator:
            val_report = await self._endpoint_validator.validate(
                url, method, body, is_graphql=is_graphql
            )
            if val_report.should_skip:
                self._skipped_endpoints.append(url)
                if self.config.verbose:
                    print(f"  [SKIP] {url[:70]} — {val_report.summary}")
                return findings


        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body if body else None,
            params=params if params else None,
        )
        if status == 0:
            return findings

        self.base_responses[url] = {
            "status":  status, "body": base_body,
            "hash":    self._hash_response(base_body),
            "elapsed": elapsed, "headers": headers,
        }
        self._record_baseline_sample(url, base_body)









        confidence_cap = 100
        classified = None
        if _HAS_VALIDATION and self._response_classifier:
            classified = self._response_classifier.classify(
                url, status, headers, base_body, elapsed
            )
            self._classified_responses[url] = classified
            self.base_responses[url]["response_class"] = classified.response_class.value

            if classified.suppress_findings:
                if self.config.verbose:
                    print(
                        f"  [SUPPRESS] {url[:60]} — "
                        f"{classified.classification_note}"
                    )
                return findings

            confidence_cap = classified.confidence_cap
            if (
                self.config.verbose
                and classified.response_class.value != "REAL_API_JSON"
            ):
                print(
                    f"  [CLASS] {url[:60]} → "
                    f"{classified.response_class.value} "
                    f"(cap={confidence_cap}%)"
                )













        early_skip = self._profile_skip_modules
        early_findings: list[Finding] = []
        if _HAS_SEC_HEADERS and self._sec_header_auditor and "security_headers" not in early_skip:
            early_findings.extend(
                self._sec_header_auditor.audit(url, method, status, headers, base_body)
            )
        if _HAS_CORS and self._cors_scanner and "cors" not in early_skip:
            early_findings.extend(await self._cors_scanner.check(url, method))
        if _HAS_JWT_CONFUSION and self._jwt_scanner and "jwt_alg_confusion" not in early_skip:
            early_findings.extend(await self._jwt_scanner.scan(url, method))
        if _HAS_TENANT_BOLA and self._tenant_bola and "tenant_bola" not in early_skip:
            early_findings.extend(await self._tenant_bola.check(url, method, status, base_body))
        if _HAS_SSRF and self._ssrf_scanner and "ssrf" not in early_skip:
            early_findings.extend(
                await self._ssrf_scanner.check(url, method, params, body, headers, base_body)
            )
        if _HAS_CSRF and self._csrf_scanner and "csrf" not in early_skip:
            early_findings.extend(
                await self._csrf_scanner.check(url, method, params, body, headers, status, base_body)
            )
        if _HAS_SOURCE_SCAN and self._source_scanner and "source_scan" not in early_skip:
            early_findings.extend(
                await self._source_scanner.check(url, method, status, headers, base_body)
            )

        for f in early_findings:
            if confidence_cap < 100:
                f.confidence = min(getattr(f, "confidence", 0), confidence_cap)
            findings.append(f)
            self._update_dashboard(finding=f)
            if self._findings_queue:
                try:
                    self._findings_queue.put_nowait(f)
                except asyncio.QueueFull:
                    pass


        if _HAS_IDOR_ENUM and self._idor_enumerator:
            self._idor_enumerator.harvest_ids(base_body)


        skip_set: set[str] = set(self._profile_skip_modules)
        if _HAS_CLASSIFIER and self._classifier:
            ep_profile = self._classifier.classify(url, body)
            skip_set.update(ep_profile.skip_modules)


        all_checks = [
            ("price_manipulation",   self._check_price_manipulation(url, method, body, params, status, base_body)),
            ("negative_quantity",    self._check_quantity_negative(url, method, body, params, status, base_body)),
            ("workflow_bypass",      self._check_workflow_bypass(url, method, body, params, status, base_body)),
            ("mass_assignment",      self._check_mass_assignment(url, method, body, params, status, base_body)),
            ("idor_bola",            self._check_idor_bola(url, method, body, params, status, base_body, headers)),
            ("bopla",                self._check_bopla(url, method, body, params, status, base_body)),
            ("privilege_escalation", self._check_privilege_escalation(url, method, body, params, status, base_body)),
            ("bfla",                 self._check_function_level_access(url, method, body, params, status, base_body)),
            ("coupon_stacking",      self._check_coupon_stacking(url, method, body, params, status, base_body)),
            ("time_bypass",          self._check_time_logic_bypass(url, method, body, params, status, base_body)),
            ("integer_overflow",     self._check_integer_overflow(url, method, body, params, status, base_body)),
            ("hidden_parameter",     self._check_hidden_parameter_disclosure(url, method, body, params, status, base_body)),
            ("state_machine_abuse",  self._check_state_machine_abuse(url, method, body, params, status, base_body)),
            ("race_condition",       self._check_race_condition(url, method, body, params, status, base_body)),
            ("jwt_manipulation",     self._check_jwt_manipulation(url, method, body, params, status, base_body, headers)),
            ("account_enumeration",  self._check_account_enumeration(url, method, body, params, status, base_body)),
            ("limit_offset",         self._check_limit_offset_manipulation(url, method, body, params, status, base_body)),
            ("soft_delete_bypass",   self._check_soft_delete_bypass(url, method, body, params, status, base_body)),
            ("http_method_override", self._check_http_method_override(url, method, body, params, status, base_body)),
            ("parameter_pollution",  self._check_parameter_pollution(url, method, body, params, status, base_body)),
            ("blind_idor",           self._check_blind_idor(url, method, body, params, status, base_body)),
        ]

        checks_to_run = [coro for name, coro in all_checks if name not in skip_set]
        results = await asyncio.gather(*checks_to_run, return_exceptions=True)

        raw_findings: list[Finding] = []
        for r in results:
            if isinstance(r, list):
                raw_findings.extend(r)
            elif isinstance(r, Exception) and self.config.verbose:
                print(f"  [!] Module error: {r}")

        for f in raw_findings:
            if confidence_cap < 100:
                f.confidence = min(getattr(f, "confidence", 0), confidence_cap)
            findings.append(f)
            self._update_dashboard(finding=f)
            if self._findings_queue:
                try:
                    self._findings_queue.put_nowait(f)
                except asyncio.QueueFull:
                    pass

        return findings






    async def _check_price_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        price_keys = [
            "price", "amount", "total", "cost", "fee", "charge",
            "unit_price", "subtotal", "payment_amount", "order_total",
            "grand_total", "final_price", "shipping_cost", "discount_amount",
        ]

        def find_price_fields(obj, keys, results, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(pk in k.lower() for pk in keys):
                        results.append((path + f".{k}" if path else k, k, v))
                    find_price_fields(v, keys, results, path + f".{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_price_fields(item, keys, results, path + f"[{i}]")

        price_fields: list[tuple] = []
        find_price_fields(body, price_keys, price_fields)

        for field_path, key, original in price_fields:







            if _HAS_FIELD_TYPING and not is_attack_relevant("price_manipulation", key, original):
                continue

            tamper_values = await self._targeted_payloads_for(
                "price_manipulation", method, url, body, key, original
            )
            for tampered in tamper_values:
                for mutated_body in self._mutate_nested(body, key, tampered):
                    ev = self._new_evidence()
                    await self._req_ev("baseline", ev, method, url, req_body=body)
                    status, _, resp_body, _ = await self._req_ev(
                        "attack", ev, method, url, req_body=mutated_body
                    )
                    if status not in (200, 201):
                        continue
                    if not self._response_indicates_success(resp_body, status):
                        continue
                    resp_data = self._try_parse_json(resp_body)
                    confirmed       = False
                    evidence_detail = ""
                    if isinstance(resp_data, dict):
                        for rk, rv in resp_data.items():
                            if any(pk in rk.lower() for pk in price_keys):
                                if isinstance(rv, (int, float)) and rv != original:
                                    confirmed       = True
                                    evidence_detail = f" → server returned {rk}={rv}"
                                    break
                    pkg = self._build_pkg(
                        ev, title=f"Price Manipulation — {field_path}",
                        endpoint=url, vuln_type="Price Manipulation",
                        confidence=85 if confirmed else 60, confirmed=confirmed,
                    )
                    f = Finding(
                        title=f"Price Manipulation — `{field_path}` accepted `{tampered}`",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Price Manipulation",
                        description=(
                            f"Field `{field_path}` at `{url}` (original: `{original}`) "
                            f"accepted tampered value `{tampered}`.{evidence_detail}"
                        ),
                        request={"method": method, "url": url, "body": mutated_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=(
                            f"Original={original} → Tampered={tampered} "
                            f"→ HTTP {status}{evidence_detail}"
                        ),
                        recommendation="Compute all prices server-side from a trusted catalog.",
                        cwe="CWE-20", cvss=9.1,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=confirmed, endpoint=url, parameter=field_path,
                    )
                    self._attach(f, pkg)
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    break
            if findings:
                break
        return findings


    async def _check_quantity_negative(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        qty_keys = ["quantity", "qty", "count", "units", "items", "amount", "number", "stock"]
        for key in qty_keys:
            if key not in body:
                continue
            original = body[key]



            if _HAS_FIELD_TYPING and not is_attack_relevant("negative_quantity", key, original):
                continue
            tampered_values = await self._targeted_payloads_for(
                "negative_quantity", method, url, body, key, original
            )
            for tampered in tampered_values:
                test_body = {**body, key: tampered}
                ev = self._new_evidence()
                await self._req_ev("baseline", ev, method, url, req_body=body)
                status, _, resp_body, _ = await self._req_ev("attack", ev, method, url, req_body=test_body)
                if status not in (200, 201):
                    continue
                if not self._response_indicates_success(resp_body, status):
                    continue



                pkg = self._build_pkg(ev, title=f"Negative Quantity — {key}={tampered}",
                                      endpoint=url, vuln_type="Negative Quantity", confidence=80)
                f = Finding(
                    title=f"Negative Quantity Exploit — `{key}` = {tampered} accepted",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Negative Value",
                    description=f"`{key}` = {tampered} (original: {original}) accepted at `{url}`.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"qty={tampered} → HTTP {status} (canary → {cs} ✓)",
                    recommendation="Enforce qty >= 1 server-side.",
                    cwe="CWE-20", cvss=9.3,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    endpoint=url, parameter=key,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings


    async def _check_idor_bola(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings: list[Finding] = []
        parsed        = urlparse(url)
        path_segments = parsed.path.split("/")

        for seg_idx, segment in enumerate(path_segments):
            if not segment:
                continue

            if not _is_id_segment(segment):
                continue
            original_id = segment
            for test_id in _generate_id_variants(segment):
                new_segs = path_segments[:]
                new_segs[seg_idx] = str(test_id)
                test_url = urlunparse(parsed._replace(path="/".join(new_segs)))
                ev = self._new_evidence()
                await self._req_ev("baseline", ev, method, url, req_body=body if body else None)
                status, _, resp_body, _ = await self._req_ev("attack", ev, method, test_url,
                                                              req_body=body if body else None)
                if status != 200:
                    continue
                if not self._responses_differ_significantly(base_body, resp_body):
                    continue
                if any(t in resp_body.lower() for t in [
                    "not found", "no resource", "does not exist"
                ]):
                    continue
                confirmed = False
                _s2_sid    = getattr(self.config, "second_api_key_sid", "")
                _s2_secret = getattr(self.config, "second_api_key_secret", "")
                if self.config.second_user_token or (_s2_sid and _s2_secret):
                    s2, _, _, _ = await self._req_ev(
                        "cross_user", ev, method, test_url,
                        req_body=body if body else None,
                        token_override=self.config.second_user_token or None,
                        api_key_override=(
                            (_s2_sid, _s2_secret)
                            if not self.config.second_user_token else None
                        ),
                    )
                    confirmed = s2 == 200
                if self.config.no_auth_check:
                    await self._req_ev("no_auth", ev, method, url,
                                       req_body=body if body else None, token_override="")
                pkg = self._build_pkg(
                    ev, title=f"IDOR — Path ID {original_id}→{test_id}",
                    endpoint=test_url, vuln_type="IDOR/BOLA",
                    confidence=91 if confirmed else 75, confirmed=confirmed,
                )
                f = Finding(
                    title=f"IDOR/BOLA — Path ID {original_id}→{test_id} returned different resource",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    category="Business Logic — IDOR/BOLA",
                    description=(
                        f"Changing path ID {original_id}→{test_id} at `{test_url}` "
                        f"returned different data. "
                        f"{'Cross-user CONFIRMED.' if confirmed else ''}"
                    ),
                    request={"method": method, "url": test_url},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=(
                        f"ID {original_id}→{test_id}: different response "
                        f"{'[CONFIRMED]' if confirmed else ''}"
                    ),
                    recommendation="Enforce ownership checks on every request.",
                    cwe="CWE-639", cvss=9.1 if confirmed else 8.1,
                    owasp="API1:2023 Broken Object Level Authorization",
                    confirmed=confirmed, endpoint=test_url, parameter=f"path[{seg_idx}]",
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                if confirmed:
                    break

        if self.config.no_auth_check:
            ev_na = self._new_evidence()
            await self._req_ev("baseline", ev_na, method, url, req_body=body if body else None)
            s_na, _, rb_na, _ = await self._req_ev("attack", ev_na, method, url,
                                                    req_body=body if body else None, token_override="")
            if s_na in (200, 201) and self._response_indicates_success(rb_na, s_na):











                if _HAS_SEMANTIC:
                    is_same = not SemanticDiff.compare(
                        base_body[:2000], rb_na[:2000], threshold=0.15
                    ).is_different
                else:
                    sim = difflib.SequenceMatcher(None, base_body[:2000], rb_na[:2000]).ratio()
                    is_same = sim > 0.7
                if is_same:
                    pkg_na = self._build_pkg(ev_na, title="Unauthenticated Access",
                                             endpoint=url, vuln_type="Missing Authentication",
                                             confidence=90, confirmed=True)
                    f = Finding(
                        title="Unauthenticated Access — resource accessible without token",
                        severity=Severity.CRITICAL,
                        category="Business Logic — Missing Authentication",
                        description=(
                            f"No Authorization header at `{url}` returned "
                            f"HTTP {s_na} with {sim:.0%} similarity."
                        ),
                        request={"method": method, "url": url, "note": "No Authorization"},
                        response_summary=f"HTTP {s_na} — {rb_na[:300]}",
                        evidence=f"No-auth → HTTP {s_na}, similarity={sim:.0%}",
                        recommendation="Require authentication on all non-public endpoints.",
                        cwe="CWE-306", cvss=9.8,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True, endpoint=url,
                    )
                    self._attach(f, pkg_na)
                    f = self._finalize_finding(f, base_body, rb_na, base_status, s_na)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
        return findings


    async def _check_bopla(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []






        if method.upper() not in ("GET", "HEAD"):
            return findings
        if _HAS_FIELD_TYPING and is_non_api_path(url):
            return findings
        base_len = len(base_body)
        for probe in [
            {"expand": "all"}, {"fields": "*"}, {"include": "all"},
            {"verbose": "1"}, {"full": "true"}, {"show_private": "1"},
        ]:
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "GET", url)
            status, _, resp_body, elapsed = await self._request(
                "GET", url, params={**params, **probe}
            )
            if ev:
                ev.record(
                    label="attack", method="GET",
                    url=url + "?" + "&".join(f"{k}={v}" for k, v in probe.items()),
                    req_headers=self._build_headers(), req_body=None,
                    resp_status=status, resp_headers={},
                    resp_body=resp_body, elapsed=elapsed,
                )
            if status != 200 or len(resp_body) <= base_len * 1.15:
                continue
            base_data = self._try_parse_json(base_body)
            new_data  = self._try_parse_json(resp_body)
            new_keys: set[str] = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())
            sensitive = [
                "password", "secret", "token", "private_key", "ssn",
                "dob", "credit_card", "cvv", "salary", "hash",
            ]
            has_sensitive = any(sf in " ".join(new_keys).lower() for sf in sensitive)
            pkg = self._build_pkg(
                ev, title=f"BOPLA — {list(probe.keys())[0]} param",
                endpoint=url, vuln_type="BOPLA",
                confidence=70 if has_sensitive else 50,
            )
            f = Finding(
                title=f"BOPLA — `{list(probe.keys())[0]}` exposes hidden fields",
                severity=Severity.HIGH if has_sensitive else Severity.MEDIUM,
                category="Business Logic — Object Property Exposure",
                description=(
                    f"Adding `{probe}` at `{url}` returned "
                    f"{len(resp_body) - base_len} extra bytes. "
                    f"New fields: {list(new_keys)[:5]}."
                ),
                request={"method": "GET", "url": url, "params": {**params, **probe}},
                response_summary=f"HTTP {status}, {len(resp_body)} vs {base_len} bytes",
                evidence=f"+{len(resp_body)-base_len} bytes, new keys: {list(new_keys)[:5]}",
                recommendation="Define explicit field allowlists per role.",
                cwe="CWE-213", cvss=7.5 if has_sensitive else 5.3,
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=url,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_workflow_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        path   = parsed.path
        for pattern, label in [(r"/step[_-]?(\d+)", "step"), (r"/stage[_-]?(\d+)", "stage")]:
            match = re.search(pattern, path, re.IGNORECASE)
            if not match:
                continue
            current = match.group(1)
            try:
                for delta in [2, 3]:
                    next_step = str(int(current) + delta)
                    new_path  = re.sub(
                        pattern,
                        match.group(0).replace(current, next_step),
                        path, flags=re.IGNORECASE,
                    )
                    new_url   = urlunparse(parsed._replace(path=new_path))
                    ev = self._new_evidence()
                    await self._req_ev("baseline", ev, method, url, req_body=body)
                    status, _, resp_body, _ = await self._req_ev(
                        "attack", ev, method, new_url, req_body=body
                    )
                    if status not in (200, 201):
                        continue
                    canary_url = urlunparse(parsed._replace(
                        path=re.sub(
                            pattern,
                            match.group(0).replace(current, "999"),
                            path, flags=re.IGNORECASE,
                        )
                    ))
                    cs, _, _, _ = await self._request(method, canary_url, json=body)
                    if cs == 200:
                        continue
                    pkg = self._build_pkg(
                        ev, title=f"Workflow Bypass — {label} {current}→{next_step}",
                        endpoint=new_url, vuln_type="Workflow Bypass", confidence=70,
                    )
                    f = Finding(
                        title=f"Workflow Step Bypass — {label} {current}→{next_step}",
                        severity=Severity.HIGH,
                        category="Business Logic — Workflow Bypass",
                        description=(
                            f"Step {next_step} at `{new_url}` accessible "
                            f"without completing step {current}."
                        ),
                        request={"method": method, "url": new_url, "body": body},
                        response_summary=f"HTTP {status}",
                        evidence=(
                            f"Skip {current}→{next_step}: HTTP {status} "
                            f"(canary step 999 → {cs} ✓)"
                        ),
                        recommendation="Enforce sequential step validation server-side.",
                        cwe="CWE-284", cvss=7.5,
                        owasp="API5:2023 Broken Function Level Authorization",
                        endpoint=new_url,
                    )
                    self._attach(f, pkg)
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
            except (ValueError, TypeError):
                pass

        for key in ["otp", "mfa_token", "verification_token"]:
            if key not in body or method.upper() not in ("POST", "PUT", "PATCH"):
                continue
            test_body = {k: v for k, v in body.items() if k != key}
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, method, url, req_body=body)
            status, _, resp_body, _ = await self._req_ev(
                "attack", ev, method, url, req_body=test_body
            )
            if status in (200, 201) and self._response_indicates_success(resp_body, status):
                pkg = self._build_pkg(
                    ev, title=f"MFA/OTP Omission — {key}",
                    endpoint=url, vuln_type="MFA Bypass", confidence=75,
                )
                f = Finding(
                    title=f"MFA/OTP Token Omission — `{key}` not validated",
                    severity=Severity.HIGH,
                    category="Business Logic — Workflow Bypass",
                    description=f"Removing `{key}` at `{url}` returned success.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Missing `{key}` → HTTP {status}",
                    recommendation="Validate OTP/MFA tokens server-side.",
                    cwe="CWE-284", cvss=8.5,
                    owasp="API5:2023 Broken Function Level Authorization",
                    endpoint=url, parameter=key,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings


    async def _check_mass_assignment(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []





        if not isinstance(body, dict) or method.upper() not in ("POST", "PUT", "PATCH"):
            return findings
        privileged_keys = [
            "is_admin", "admin", "role", "is_premium", "premium",
            "subscription", "plan", "credits", "balance", "is_staff",
            "approved", "email_verified", "kyc_verified",
            "price_override", "tax_exempt", "fee_waiver",
        ]
        for key in privileged_keys:
            test_body = {**body, key: True}
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, method, url, req_body=body)
            status, _, resp_body, _ = await self._req_ev(
                "attack", ev, method, url, req_body=test_body
            )
            if status not in (200, 201):
                continue
            resp_data = self._try_parse_json(resp_body)
            if not isinstance(resp_data, dict):
                continue
            reflected = resp_data.get(key)
            if reflected not in (True, "true", 1, "admin", "premium", "verified"):
                continue
            base_data = self._try_parse_json(base_body)
            if isinstance(base_data, dict) and base_data.get(key) == reflected:
                continue
            pkg = self._build_pkg(
                ev, title=f"Mass Assignment — {key}",
                endpoint=url, vuln_type="Mass Assignment", confidence=90, confirmed=True,
            )
            f = Finding(
                title=f"Mass Assignment — `{key}` reflected as `{reflected}`",
                severity=Severity.CRITICAL,
                category="Business Logic — Mass Assignment",
                description=f"Injecting `{key}: true` at `{url}` reflected as `{reflected}`.",
                request={"method": method, "url": url, "body": test_body},
                response_summary=f"HTTP {status}, `{key}`={reflected}",
                evidence=(
                    f"Injected {key}=True → response {key}={reflected} "
                    f"(absent in baseline)"
                ),
                recommendation="Use an explicit field allowlist.",
                cwe="CWE-915", cvss=9.8,
                owasp="API3:2023 Broken Object Property Level Authorization",
                confirmed=True, endpoint=url, parameter=key,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)

        if findings:
            return findings


        if base_body and base_status in (200, 201):
            for key, inject_val in _discover_dynamic_fields(base_body):
                if key in body:
                    continue
                test_body = {**body, key: inject_val}
                try:
                    status, _, resp_body, _ = await self._request(
                        method, url, json=test_body
                    )
                except Exception:
                    continue
                if status not in (200, 201):
                    continue
                resp_data = self._try_parse_json(resp_body)
                if not isinstance(resp_data, dict):
                    continue
                reflected = resp_data.get(key)
                if reflected is None:
                    continue
                if str(reflected).lower() != str(inject_val).lower():
                    continue
                try:
                    base_data = self._try_parse_json(base_body)
                    if isinstance(base_data, dict) and base_data.get(key) == reflected:
                        continue
                except Exception:
                    pass
                f = Finding(
                    title=f"Mass Assignment (Dynamic) — `{key}` reflected as `{reflected}`",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Mass Assignment (Dynamic Field)",
                    description=(
                        f"Injecting `{key}: {inject_val}` at `{url}` was reflected "
                        f"as `{key}={reflected}`. Field discovered dynamically "
                        f"from the API response — not in the standard allowlist."
                    ),
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}, `{key}`={reflected}",
                    evidence=(
                        f"Injected {key}={inject_val} → response {key}={reflected} "
                        f"(absent in baseline)"
                    ),
                    recommendation=(
                        "Use an explicit field allowlist in your serialiser. "
                        "Never reflect client-supplied privilege fields."
                    ),
                    cwe="CWE-915", cvss=9.8,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    confirmed=True, confidence=88, endpoint=url, parameter=key,
                )
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings


    async def _check_privilege_escalation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"







        if base in self._admin_paths_probed:
            return findings
        self._admin_paths_probed.add(base)

        admin_paths = [
            "/admin", "/api/admin", "/api/v1/admin", "/manage",
            "/api/users/all", "/api/roles", "/api/permissions",
            "/internal", "/api/internal", "/api/metrics", "/api/config",
        ]
        for admin_path in admin_paths:
            test_url = f"{base}{admin_path}"
            for token, label in [(self.config.auth_token, "low-priv"), ("", "no-auth")]:
                ev = self._new_evidence()
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, "GET", test_url, token_override=token
                )
                if status != 200 or len(resp_body) < 50:
                    continue
                if not self._response_indicates_success(resp_body, status):
                    continue
                pkg = self._build_pkg(
                    ev, title=f"BFLA — {admin_path} ({label})",
                    endpoint=test_url, vuln_type="BFLA", confidence=90, confirmed=True,
                )
                f = Finding(
                    title=f"BFLA — `{admin_path}` accessible by {label} user",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=(
                        f"Admin endpoint `{test_url}` returned HTTP 200 "
                        f"+ {len(resp_body)}B with {label} token."
                    ),
                    request={"method": "GET", "url": test_url, "note": f"Token: {label}"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"GET {test_url} with {label} → {status} + {len(resp_body)}B",
                    recommendation="Enforce RBAC on all admin endpoints.",
                    cwe="CWE-269", cvss=9.8,
                    owasp="API5:2023 Broken Function Level Authorization",
                    confirmed=True, endpoint=test_url,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, "", resp_body, 403, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings

    async def _check_function_level_access(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        _s2_sid    = getattr(self.config, "second_api_key_sid", "")
        _s2_secret = getattr(self.config, "second_api_key_secret", "")
        _has_second_identity = bool(self.config.second_user_token) or bool(_s2_sid and _s2_secret)
        if not _has_second_identity:
            return findings
        for test_method in ["DELETE", "PUT", "PATCH"]:
            if test_method == method:
                continue
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, method, url, req_body=body if body else None)
            status, _, resp_body, _ = await self._req_ev(
                "attack", ev, test_method, url,
                req_body=body if body else None,
                token_override=self.config.second_user_token or None,
                api_key_override=(
                    (_s2_sid, _s2_secret)
                    if not self.config.second_user_token else None
                ),
            )
            if status in (200, 201, 204):
                pkg = self._build_pkg(
                    ev, title=f"BFLA — User2 can {test_method} User1 resource",
                    endpoint=url, vuln_type="BFLA", confidence=90, confirmed=True,
                )
                f = Finding(
                    title=f"BFLA — User 2 can {test_method} User 1's resource",
                    severity=Severity.CRITICAL,
                    category="Business Logic — Function Level Access Control",
                    description=f"User 2 performed {test_method} on `{url}` → HTTP {status}.",
                    request={"method": test_method, "url": url, "note": "Second user token"},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=f"User2 + {test_method} {url} → {status}",
                    recommendation="Verify resource ownership on every mutating request.",
                    cwe="CWE-284", cvss=9.1,
                    owasp="API5:2023 Broken Function Level Authorization",
                    confirmed=True, endpoint=url,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings


    async def _check_coupon_stacking(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []




        if not isinstance(body, dict) or method.upper() not in ("POST", "PUT", "PATCH"):
            return findings
        coupon_keys = ["coupon", "coupon_code", "promo_code", "discount_code", "voucher", "promo"]
        for key in coupon_keys:
            if key not in body:
                continue
            original      = body[key]
            if _HAS_FIELD_TYPING and not is_attack_relevant("coupon_stacking", key, original):
                continue
            base_discount = self._extract_discount(base_body)
            for test_body, label in [
                ({**body, key: [original, original]}, "duplicate array"),
                ({**body, key: [original]},           "single-item array"),
            ]:
                ev = self._new_evidence()
                await self._req_ev("baseline", ev, method, url, req_body=body)
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, method, url, req_body=test_body
                )
                if status not in (200, 201):
                    continue
                if not self._response_indicates_success(resp_body, status):
                    continue
                new_discount = self._extract_discount(resp_body)
                confirmed    = bool(
                    new_discount and base_discount
                    and new_discount > base_discount * 1.4
                )
                pkg = self._build_pkg(
                    ev, title=f"Coupon Abuse — {label} for {key}",
                    endpoint=url, vuln_type="Coupon Abuse",
                    confidence=80 if confirmed else 55, confirmed=confirmed,
                )
                f = Finding(
                    title=f"Coupon Abuse — {label} for `{key}`",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    category="Business Logic — Coupon Abuse",
                    description=f"Coupon `{key}` as {label} accepted at `{url}`.",
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}",
                    evidence=f"Coupon as {label}: discount {base_discount}→{new_discount}",
                    recommendation="Normalize coupon inputs. Enforce one-coupon-per-order.",
                    cwe="CWE-20", cvss=8.5 if confirmed else 6.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confirmed=confirmed, endpoint=url, parameter=key,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings


    async def _check_time_logic_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        time_keys = [
            "date", "expiry", "expiry_date", "expires_at", "valid_until",
            "timestamp", "start_date", "end_date", "valid_from",
        ]
        for key in time_keys:
            if key not in body:
                continue
            original = body[key]
            if _HAS_FIELD_TYPING:
                ftype = infer_field_type(key, original)
                if not is_attack_relevant("time_logic_bypass", key, original):
                    continue
                candidates = generate_time_payloads(ftype, original)
            else:
                candidates = [("2099-12-31T23:59:59Z", "far-future"), (-1, "unix-negative")]
            for ts, label in candidates:
                test_body = {**body, key: ts}
                ev = self._new_evidence()
                await self._req_ev("baseline", ev, method, url, req_body=body)
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, method, url, req_body=test_body
                )
                if (
                    status in (200, 201)
                    and self._response_indicates_success(resp_body, status)
                    and self._hash_response(resp_body) != self._hash_response(base_body)
                ):
                    pkg = self._build_pkg(
                        ev, title=f"Time Bypass — {key} ({label})",
                        endpoint=url, vuln_type="Time Logic Bypass", confidence=65,
                    )
                    f = Finding(
                        title=f"Time Bypass — `{key}` accepts {label} timestamp",
                        severity=Severity.HIGH,
                        category="Business Logic — Time Bypass",
                        description=(
                            f"`{key}` = {ts} ({label}) accepted at `{url}` "
                            f"with different response."
                        ),
                        request={"method": method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"`{key}` = {ts} → different response from baseline",
                        recommendation="Validate all timestamps server-side using server time.",
                        cwe="CWE-20", cvss=7.3,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        endpoint=url, parameter=key,
                    )
                    self._attach(f, pkg)
                    f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    break
        return findings


    async def _check_integer_overflow(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        numeric_keys = [
            k for k, v in body.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        ]
        for key in numeric_keys:







            if _HAS_FIELD_TYPING and not is_attack_relevant("integer_overflow", key, body[key]):
                continue
            for val in [2**31 - 1, 2**63 - 1, -2**31, 9999999999]:
                test_body = {**body, key: val}
                try:
                    ev = self._new_evidence()
                    await self._req_ev("baseline", ev, method, url, req_body=body)
                    status, _, resp_body, _ = await self._req_ev(
                        "attack", ev, method, url, req_body=test_body
                    )
                    if status == 500:
                        pkg = self._build_pkg(
                            ev, title=f"Integer Overflow — {key}={val}",
                            endpoint=url, vuln_type="Integer Overflow", confidence=60,
                        )
                        f = Finding(
                            title=f"Integer Overflow — `{key}` = {val} caused 500",
                            severity=Severity.MEDIUM,
                            category="Business Logic — Integer Overflow",
                            description=f"`{key}` = {val} caused HTTP 500 at `{url}`.",
                            request={"method": method, "url": url, "body": test_body},
                            response_summary="HTTP 500",
                            evidence=f"Input {key}={val} → 500",
                            recommendation="Validate numeric ranges.",
                            cwe="CWE-190", cvss=6.5,
                            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                            endpoint=url, parameter=key,
                        )
                        self._attach(f, pkg)
                        f = self._finalize_finding(f, base_body, resp_body, base_status, 500)
                        if f.confidence >= self.config.min_confidence:
                            findings.append(f)
                    elif status in (200, 201):
                        data = self._try_parse_json(resp_body)
                        if isinstance(data, dict):
                            for rk, rv in data.items():
                                if (
                                    isinstance(rv, (int, float))
                                    and not isinstance(rv, bool)
                                    and rv < 0
                                ):
                                    pkg = self._build_pkg(
                                        ev,
                                        title=f"Integer Overflow — {key}={val} → {rk}<0",
                                        endpoint=url, vuln_type="Integer Overflow",
                                        confidence=80, confirmed=True,
                                    )
                                    f = Finding(
                                        title=(
                                            f"Integer Overflow — `{key}`={val} "
                                            f"caused negative `{rk}`"
                                        ),
                                        severity=Severity.HIGH,
                                        category="Business Logic — Integer Overflow",
                                        description=(
                                            f"`{key}`={val} → `{rk}`={rv} "
                                            f"(negative) at `{url}`."
                                        ),
                                        request={"method": method, "url": url, "body": test_body},
                                        response_summary=f"HTTP {status}, {rk}={rv}",
                                        evidence=f"Input {key}={val} → {rk}={rv}",
                                        recommendation="Use 64-bit integers.",
                                        cwe="CWE-190", cvss=7.8,
                                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                                        confirmed=True, endpoint=url, parameter=key,
                                    )
                                    self._attach(f, pkg)
                                    f = self._finalize_finding(
                                        f, base_body, resp_body, base_status, status
                                    )
                                    if f.confidence >= self.config.min_confidence:
                                        findings.append(f)
                except Exception:
                    pass
        return findings


    async def _check_hidden_parameter_disclosure(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []







        if method.upper() not in ("GET", "HEAD"):
            return findings
        probes = {
            "debug": "1", "verbose": "1", "admin": "1", "internal": "1",
            "full": "1", "include_deleted": "1", "show_all": "1", "_debug": "1",
        }
        for param, val in probes.items():
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "GET", url)
            status, _, resp_body, elapsed = await self._request(
                "GET", url, params={**params, param: val}
            )
            if ev:
                ev.record(
                    label="attack", method="GET",
                    url=f"{url}?{param}={val}",
                    req_headers=self._build_headers(), req_body=None,
                    resp_status=status, resp_headers={},
                    resp_body=resp_body, elapsed=elapsed,
                )
            base_len = len(base_body)
            new_len  = len(resp_body)
            if status != 200 or new_len <= base_len * 1.2 or new_len - base_len < 100:
                continue
            base_data = self._try_parse_json(base_body)
            new_data  = self._try_parse_json(resp_body)
            new_keys: set[str] = set()
            if isinstance(new_data, dict) and isinstance(base_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())
            if not new_keys and new_len < base_len * 1.5:
                continue
            pkg = self._build_pkg(
                ev, title=f"Hidden Param — {param}",
                endpoint=url, vuln_type="Information Disclosure", confidence=65,
            )
            f = Finding(
                title=f"Hidden Parameter — `{param}` discloses extra data",
                severity=Severity.HIGH if new_len > base_len * 2 else Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=(
                    f"`{param}={val}` at `{url}` returned "
                    f"{new_len - base_len} extra bytes."
                ),
                request={"method": "GET", "url": url, "params": {**params, param: val}},
                response_summary=f"HTTP {status}, {new_len} vs {base_len} bytes",
                evidence=(
                    f"baseline={base_len}B → with param={new_len}B, "
                    f"new keys: {list(new_keys)[:5]}"
                ),
                recommendation="Remove debug params from production.",
                cwe="CWE-200", cvss=6.5,
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=url, parameter=param,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_state_machine_abuse(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        state_map = {
            "status":              ["completed", "approved", "paid", "shipped"],
            "order_status":        ["completed", "delivered", "paid"],
            "payment_status":      ["paid", "completed", "cleared"],
            "verification_status": ["verified", "approved"],
            "kyc_status":          ["verified", "approved"],
        }
        for key, targets in state_map.items():
            if key not in body:
                continue
            for state in targets:
                if body.get(key) == state:
                    continue
                test_body = {**body, key: state}
                ev = self._new_evidence()
                await self._req_ev("baseline", ev, method, url, req_body=body)
                status, _, resp_body, _ = await self._req_ev(
                    "attack", ev, method, url, req_body=test_body
                )
                if status not in (200, 201):
                    continue
                data = self._try_parse_json(resp_body)
                if not isinstance(data, dict) or data.get(key) != state:
                    continue
                pkg = self._build_pkg(
                    ev, title=f"State Machine Abuse — {key}→{state}",
                    endpoint=url, vuln_type="State Machine Abuse",
                    confidence=90, confirmed=True,
                )
                f = Finding(
                    title=f"State Machine Abuse — `{key}` forced to `{state}`",
                    severity=Severity.CRITICAL,
                    category="Business Logic — State Machine Abuse",
                    description=(
                        f"Forcing `{key}`→`{state}` at `{url}` "
                        f"accepted and confirmed."
                    ),
                    request={"method": method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}, {key}={state}",
                    evidence=(
                        f"Forced {key}={state} → confirmed "
                        f"(was: {body.get(key)})"
                    ),
                    recommendation="Compute state transitions server-side.",
                    cwe="CWE-284", cvss=9.5,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    confirmed=True, endpoint=url, parameter=key,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
                break
        return findings




    async def _burst_request(
        self, method: str, url: str, json_body=None, params=None,
        token_override: str = None,
    ) -> tuple[int, dict, str, float]:
        """
        Low-level request used only for race-condition bursts. Bypasses the
        rate limiter and uses the dedicated high-concurrency burst session
        (see __aenter__) instead of the main rate-limited session, so a
        20-way burst actually reaches the server as 20 near-simultaneous
        requests instead of being serialized by limit_per_host=5.
        """
        req_headers = self._build_headers(None)
        if token_override is not None:
            if token_override == "":
                req_headers.pop("Authorization", None)
            else:
                req_headers["Authorization"] = f"Bearer {token_override}"
        cookies = dict(self.config.cookies)
        if self._session_mgr:
            cookies.update(self._session_mgr.get_cookies())
        start = time.time()
        try:
            async with self._burst_session.request(
                method, url, headers=req_headers, cookies=cookies,
                json=json_body, params=params, allow_redirects=True,
                proxy=self.config.proxy if self.config.proxy else None,
            ) as resp:
                elapsed = time.time() - start
                body = await self._read_body_capped(resp)
                return resp.status, dict(resp.headers), body, elapsed
        except asyncio.TimeoutError:
            return 0, {}, "TIMEOUT", time.time() - start
        except aiohttp.ClientConnectorError as e:
            return 0, {}, f"CONNECTION_ERROR: {str(e)[:100]}", time.time() - start
        except Exception as e:
            return 0, {}, f"ERROR: {str(e)[:100]}", time.time() - start

    async def _warm_connections(self, url: str, count: int):
        """
        Connection warming: pays the TCP + TLS handshake cost for `count`
        connections to the target host *before* the timed burst, using a
        side-effect-free OPTIONS request. When the real burst fires
        immediately after, aiohttp's keep-alive pool can reuse these
        already-established connections instead of negotiating a fresh
        handshake per request — removing the single biggest source of
        client-side jitter (handshake latency routinely dwarfs the actual
        race window). This is NOT a true single-packet/last-byte-sync
        attack (that needs raw HTTP/2 frame control to land writes in the
        same server-side tick) — it's a cheap, honest partial mitigation
        that meaningfully tightens the burst without new dependencies.
        """
        try:
            await asyncio.gather(
                *[self._burst_request("OPTIONS", url) for _ in range(count)],
                return_exceptions=True,
            )
        except Exception:
            pass

    async def _execute_race_burst(
        self, method: str, url: str, body=None, params=None,
        concurrency: int = 15, token_override: str = None, warm: bool = True,
    ) -> list:
        """Fire `concurrency` near-simultaneous requests, warmed beforehand."""
        if warm:
            await self._warm_connections(url, min(concurrency, 20))
        tasks = [
            self._burst_request(method, url, json_body=body, params=params,
                                 token_override=token_override)
            for _ in range(concurrency)
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def _analyze_race_burst(self, responses: list) -> dict:
        """
        Side-effect oracle: don't just count HTTP 200s. Extract resource
        identifiers from each "successful" body and count DISTINCT ones —
        that's proof of N separate mutations, not just N repeated echoes
        of one transaction (idempotency key hit, cache, etc). Also surface
        numeric signals (balance/stock/etc) from each successful body so a
        delta can be reasoned about even without a dedicated read endpoint.
        """
        successes = [
            r for r in responses
            if isinstance(r, tuple) and r[0] in (200, 201)
            and self._response_indicates_success(r[2], r[0])
        ]
        distinct_ids: set = set()
        numeric_samples: list = []
        for r in successes:
            distinct_ids |= _find_identifier_values(r[2])
            nums = _find_numeric_signals(r[2])
            if nums:
                numeric_samples.append(nums)
        return {
            "total": len(responses),
            "success_count": len(successes),
            "distinct_ids": distinct_ids,
            "numeric_samples": numeric_samples,
            "sample_body": successes[0][2][:300] if successes else "",
        }

    async def _check_race_condition(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        if method not in ("POST", "PUT", "PATCH"):
            return findings

        if not _looks_like_mutating_action(url, body, params):
            return findings





        waves = [5, 15, 30]
        analysis = None
        winning_wave = 0
        for wave in waves:
            responses = await self._execute_race_burst(
                method, url, body=body, params=params, concurrency=wave,
            )
            analysis = self._analyze_race_burst(responses)
            if analysis["success_count"] > 1:
                winning_wave = wave
                break

        if not analysis or analysis["success_count"] <= 1:
            return findings

        success_count  = analysis["success_count"]
        total          = analysis["total"]
        distinct_ids   = analysis["distinct_ids"]
        numeric_samples = analysis["numeric_samples"]








        if len(distinct_ids) > 1:
            oracle_note = (
                f"{len(distinct_ids)} DISTINCT resource identifiers were returned "
                f"across successful responses ({', '.join(list(distinct_ids)[:5])}) — "
                "this proves separate mutations were actually committed server-side, "
                "not a repeated/cached response to one transaction."
            )
            oracle_confirmed = True
        elif len(distinct_ids) == 1:
            oracle_note = (
                "All successful responses referenced the SAME resource identifier "
                f"('{next(iter(distinct_ids))}'). This may indicate the server "
                "correctly deduplicated via an idempotency key — treat as lower "
                "confidence unless a balance/stock delta below confirms otherwise."
            )
            oracle_confirmed = False
        elif numeric_samples and len({tuple(sorted(n.items())) for n in numeric_samples}) > 1:
            oracle_note = (
                f"No identifier field was found, but numeric state fields differed "
                f"across successful responses (samples: {numeric_samples[:3]}), "
                "indicating the underlying resource actually changed more than once."
            )
            oracle_confirmed = True
        else:
            oracle_note = (
                "No identifier or numeric field was available to independently "
                "confirm distinct state changes — flagged on HTTP-level evidence "
                "alone. Manually verify actual double-processing before reporting."
            )
            oracle_confirmed = False

        single_status, _, _, _ = await self._request(method, url, json=body)






        cross_account_note = ""
        second_token = getattr(self.config, "second_user_token", "") or ""
        if second_token:
            cross_responses = await self._execute_race_burst(
                method, url, body=body, params=params,
                concurrency=min(winning_wave, 10), token_override=second_token,
                warm=False,
            )
            cross_analysis = self._analyze_race_burst(cross_responses)
            if cross_analysis["success_count"] > 1:
                cross_account_note = (
                    f" A second account also achieved "
                    f"{cross_analysis['success_count']}/{len(cross_responses)} "
                    "concurrent successes, suggesting the lock (if any) is not "
                    "even scoped correctly per-account."
                )

        f = Finding(
            title=(
                f"Race Condition — {success_count}/{total} concurrent requests "
                f"succeeded (window found at concurrency={winning_wave})"
            ),
            severity=Severity.CRITICAL,
            category="Business Logic — Race Condition",
            description=(
                f"{success_count}/{total} simultaneous requests to `{url}` "
                f"succeeded during a connection-warmed burst.{cross_account_note}"
            ),
            request={
                "method": method, "url": url, "body": body,
                "note": f"{total} concurrent requests, connection-warmed",
            },
            response_summary=f"{success_count}/{total} successes",
            evidence=(
                f"Concurrent: {success_count}/{total} at concurrency={winning_wave}. "
                f"Single re-test: HTTP {single_status}. {oracle_note}{cross_account_note}"
            ),
            recommendation=(
                "Use SELECT FOR UPDATE, Redis SETNX, or idempotency keys. "
                "Ensure any limit/lock is scoped to the resource globally, "
                "not just to the caller's session or token."
            ),
            cwe="CWE-362", cvss=9.0 if oracle_confirmed else 7.5,
            owasp="API4:2023 Unrestricted Resource Consumption",
            confirmed=oracle_confirmed, endpoint=url,
        )












        if len(distinct_ids) > 1:
            f.confidence = 90
        elif numeric_samples and len({tuple(sorted(n.items())) for n in numeric_samples}) > 1:
            f.confidence = 80
        elif len(distinct_ids) == 1:
            f.confidence = 45
        else:
            f.confidence = 55
        f.confidence_reasons = [oracle_note.strip()]
        f = severity_from_confidence(f)
        f.poc = self.poc_generator.generate(f)
        if f.confidence >= self.config.min_confidence:
            findings.append(f)
        return findings


    async def _check_jwt_manipulation(self, url, method, body, params, base_status, base_body, resp_headers) -> list[Finding]:
        findings: list[Finding] = []
        token = self.config.auth_token
        if not token or token.count(".") != 2:
            return findings
        parts = token.split(".")

        def b64d(p):
            pad = 4 - len(p) % 4
            try:
                return json.loads(base64.urlsafe_b64decode(p + "=" * pad))
            except Exception:
                return {}

        def b64e(d):
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        header  = b64d(parts[0])
        payload = b64d(parts[1])
        if not header or not payload:
            return findings
        forged = f"{b64e({**header, 'alg': 'none'})}.{parts[1]}."
        ev = self._new_evidence()
        await self._req_ev("baseline", ev, method, url, req_body=body if body else None)
        status, _, resp_body, _ = await self._req_ev(
            "attack", ev, method, url,
            req_body=body if body else None,
            token_override=forged,
        )
        if status in (200, 201) and self._response_indicates_success(resp_body, status):
            random_token = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiZmFrZSJ9."
            ts2, _, _, _ = await self._request(
                method, url,
                json=body if body else None,
                token_override=random_token,
            )
            if ts2 not in (200, 201):
                pkg = self._build_pkg(
                    ev, title="JWT alg:none Bypass",
                    endpoint=url, vuln_type="JWT Vulnerability",
                    confidence=95, confirmed=True,
                )
                f = Finding(
                    title="JWT alg:none Bypass — signature not validated",
                    severity=Severity.CRITICAL,
                    category="Business Logic — JWT Vulnerability",
                    description=f"Server at `{url}` accepted JWT with alg:none.",
                    request={"method": method, "url": url, "note": "JWT alg:none"},
                    response_summary=f"HTTP {status}",
                    evidence=(
                        f"alg:none → HTTP {status} "
                        f"(random invalid token → HTTP {ts2})"
                    ),
                    recommendation="Whitelist allowed algorithms. Reject 'none'.",
                    cwe="CWE-347", cvss=10.0,
                    owasp="API2:2023 Broken Authentication",
                    confirmed=True, endpoint=url,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, base_body, resp_body, base_status, status)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)
        return findings


    async def _check_account_enumeration(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        if method != "POST":
            return findings
        field = next(
            (k for k in ["email", "username", "login"] if k in body), None
        )
        if not field:
            return findings
        ev_results = []
        for test_val in [
            "nonexistent_zzz_9999@nowhere.invalid",
            "admin@example.com",
        ]:
            test_body = {**body, field: test_val}
            s, _, rb, elapsed = await self._request(method, url, json=test_body)
            ev_results.append((test_val, s, rb.lower(), elapsed))
        if len(ev_results) < 2:
            return findings
        r1_body, r2_body = ev_results[0][2], ev_results[1][2]
        not_found  = ["not found", "no account", "doesn't exist", "no user"]
        wrong_pass = ["wrong password", "incorrect password", "invalid password"]
        if (
            (any(s in r1_body for s in not_found) and any(s in r2_body for s in wrong_pass))
            or (any(s in r2_body for s in not_found) and any(s in r1_body for s in wrong_pass))
        ):
            f = Finding(
                title="Account Enumeration — different error messages reveal valid accounts",
                severity=Severity.MEDIUM,
                category="Business Logic — Information Disclosure",
                description=(
                    f"Different error messages for `{field}` at `{url}` "
                    f"enable enumeration."
                ),
                request={"method": method, "url": url},
                response_summary="Different messages for valid vs invalid accounts",
                evidence="'no account' vs 'wrong password' messages differ",
                recommendation="Use generic 'Invalid credentials' for all auth failures.",
                cwe="CWE-204", cvss=5.3,
                owasp="API2:2023 Broken Authentication",
                confirmed=True, endpoint=url, parameter=field,
            )
            f = self._finalize_finding(
                f, base_body, ev_results[0][2], base_status, ev_results[0][1]
            )
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        times        = [r[3] for r in ev_results]
        timing_delta = max(times) - min(times)
        if timing_delta > 0.20:












            confirm_deltas = [timing_delta]
            consistent = True
            first_slower_was_val0 = times[0] > times[1]
            for _ in range(2):
                rerun_times = []
                for test_val in [
                    "nonexistent_zzz_9999@nowhere.invalid", "admin@example.com",
                ]:
                    test_body = {**body, field: test_val}
                    _, _, _, elapsed = await self._request(method, url, json=test_body)
                    rerun_times.append(elapsed)
                confirm_deltas.append(max(rerun_times) - min(rerun_times))
                if (rerun_times[0] > rerun_times[1]) != first_slower_was_val0:
                    consistent = False

            avg_delta = sum(confirm_deltas) / len(confirm_deltas)
            if consistent and avg_delta >= 0.5:
                confidence = 85
            elif consistent and avg_delta >= 0.35:
                confidence = 70
            elif consistent:
                confidence = 55
            else:
                confidence = 30  

            f = Finding(
                title=f"Account Enumeration — timing oracle ({avg_delta:.2f}s avg delta)",
                severity=Severity.LOW,
                category="Business Logic — Information Disclosure",
                description=f"Consistent timing delta of ~{avg_delta:.2f}s at `{url}`.",
                request={"method": method, "url": url, "note": "Timing oracle"},
                response_summary=f"Delta samples (s): {[round(d, 3) for d in confirm_deltas]}",
                evidence=(
                    f"Delta samples across {len(confirm_deltas)} measurements: "
                    f"{[round(d, 3) for d in confirm_deltas]}s (avg {avg_delta:.3f}s). "
                    f"Direction-consistent across repeats: {consistent}."
                ),
                recommendation="Use constant-time comparisons for credential validation.",
                cwe="CWE-203", cvss=3.7 if consistent else 2.0,
                owasp="API2:2023 Broken Authentication",
                endpoint=url, parameter=field,
            )
            f.confidence = confidence
            f.confidence_reasons = [
                f"{len(confirm_deltas)} timing samples, avg {avg_delta:.3f}s, "
                f"direction-consistent={consistent}"
            ]
            f = severity_from_confidence(f)
            f.poc = self.poc_generator.generate(f)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_limit_offset_manipulation(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        if method.upper() not in ("GET", "HEAD"):
            return findings
        if _HAS_FIELD_TYPING and is_non_api_path(url):
            return findings

        def _count(data):
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for k in ("data", "items", "results", "records"):
                    if k in data and isinstance(data[k], list):
                        return len(data[k])
            return 0

        base_data  = self._try_parse_json(base_body)
        base_count = _count(base_data)





        is_collection = isinstance(base_data, list) or base_count > 0
        if not is_collection:
            return findings

        for probe in [
            {"limit": 99999, "offset": 0},
            {"per_page": 99999},
            {"size": 99999},
        ]:
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "GET", url)
            status, _, resp_body, elapsed = await self._request(
                "GET", url, params={**params, **probe}
            )
            if ev:
                ev.record(
                    label="attack", method="GET", url=url,
                    req_headers=self._build_headers(), req_body=None,
                    resp_status=status, resp_headers={},
                    resp_body=resp_body, elapsed=elapsed,
                )
            if status != 200 or len(resp_body) <= len(base_body) * 2:
                continue

            count = _count(self._try_parse_json(resp_body))
            if count <= base_count * 2:
                continue
            pkg = self._build_pkg(
                ev, title=f"Limit Manipulation — {probe}",
                endpoint=url, vuln_type="Excessive Data Exposure", confidence=70,
            )
            f = Finding(
                title=(
                    f"Limit Manipulation — `{probe}` returned "
                    f"{count} vs {base_count} records"
                ),
                severity=Severity.HIGH,
                category="Business Logic — Excessive Data Exposure",
                description=(
                    f"Pagination `{probe}` at `{url}` → "
                    f"{count} vs {base_count} records."
                ),
                request={"method": "GET", "url": url, "params": {**params, **probe}},
                response_summary=f"HTTP {status}, {count} records",
                evidence=f"Baseline: {base_count} → probe: {count} records",
                recommendation="Enforce server-side max page size.",
                cwe="CWE-213", cvss=7.5,
                owasp="API3:2023 Broken Object Property Level Authorization",
                endpoint=url,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_soft_delete_bypass(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        if method.upper() not in ("GET", "HEAD"):
            return findings
        if _HAS_FIELD_TYPING and is_non_api_path(url):
            return findings
        for probe in [
            {"include_deleted": "true"},
            {"show_deleted":    "true"},
            {"archived":        "true"},
        ]:
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "GET", url)
            status, _, resp_body, elapsed = await self._request(
                "GET", url, params={**params, **probe}
            )
            if ev:
                ev.record(
                    label="attack", method="GET", url=url,
                    req_headers=self._build_headers(), req_body=None,
                    resp_status=status, resp_headers={},
                    resp_body=resp_body, elapsed=elapsed,
                )
            if status != 200:
                continue
            if not self._responses_differ_significantly(base_body, resp_body):
                continue
            pkg = self._build_pkg(
                ev, title=f"Soft Delete Bypass — {probe}",
                endpoint=url, vuln_type="Soft Delete Bypass", confidence=65,
            )
            f = Finding(
                title=f"Soft Delete Bypass — `{probe}` exposes deleted records",
                severity=Severity.HIGH,
                category="Business Logic — Soft Delete Bypass",
                description=f"`{probe}` at `{url}` returned a different response.",
                request={"method": "GET", "url": url, "params": {**params, **probe}},
                response_summary=f"HTTP {status}, {len(resp_body)} bytes",
                evidence=f"Response changed with {probe}",
                recommendation="Filter soft-deleted records at the ORM layer.",
                cwe="CWE-284", cvss=6.5,
                owasp="API1:2023 Broken Object Level Authorization",
                endpoint=url,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_http_method_override(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []




        if method.upper() == "DELETE":
            return findings
        if _HAS_FIELD_TYPING and is_non_api_path(url):
            return findings
        for oh in [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Method-Override":      "DELETE"},
            {"_method":                "DELETE"},
        ]:
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "POST", url, req_body=body)
            status, _, resp_body, _ = await self._req_ev(
                "attack", ev, "POST", url, req_body=body, extra_headers=oh
            )
            if status in (405, 404, 400, 403, 401, 0):
                continue
            if status not in (200, 201):
                continue
            if not self._responses_differ_significantly(base_body, resp_body):
                continue
            pkg = self._build_pkg(
                ev, title=f"HTTP Method Override — {list(oh.keys())[0]}",
                endpoint=url, vuln_type="Method Override", confidence=55,
            )
            f = Finding(
                title=(
                    f"HTTP Method Override — `{list(oh.keys())[0]}` "
                    f"caused different response"
                ),
                severity=Severity.MEDIUM,
                category="Business Logic — Method Override",
                description=(
                    f"Override header `{oh}` at `{url}` produced different response."
                ),
                request={"method": "POST", "url": url, "headers": oh},
                response_summary=f"HTTP {status}",
                evidence=f"Override {oh} → {status} + different body",
                recommendation=(
                    "Disable HTTP method override middleware in production."
                ),
                cwe="CWE-436", cvss=5.3,
                owasp="API5:2023 Broken Function Level Authorization",
                endpoint=url,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_parameter_pollution(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        findings: list[Finding] = []
        if not params:
            return findings
        if _HAS_FIELD_TYPING and is_non_api_path(url):
            return findings
        for key, val in list(params.items())[:3]:
            parsed   = urlparse(url)






            dup_val = pollution_probe_value(key, val) if _HAS_FIELD_TYPING else "999999"
            test_url = urlunparse(
                parsed._replace(query=f"{key}={val}&{key}={dup_val}")
            )
            ev = self._new_evidence()
            await self._req_ev("baseline", ev, "GET", url)
            status, _, resp_body, _ = await self._req_ev("attack", ev, "GET", test_url)
            if status != 200:
                continue
            if not self._responses_differ_significantly(base_body, resp_body):
                continue
            pkg = self._build_pkg(
                ev, title=f"Parameter Pollution — {key}",
                endpoint=url, vuln_type="Parameter Pollution", confidence=50,
            )
            f = Finding(
                title=f"HTTP Parameter Pollution — duplicate `{key}` changed response",
                severity=Severity.MEDIUM,
                category="Business Logic — Parameter Pollution",
                description=f"Duplicating `{key}` at `{url}` changed the response.",
                request={"method": "GET", "url": test_url},
                response_summary=f"HTTP {status}",
                evidence=f"Duplicate {key} → significantly different response",
                recommendation="Take only the first value for duplicate parameters.",
                cwe="CWE-20", cvss=5.8,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                endpoint=url, parameter=key,
            )
            self._attach(f, pkg)
            f = self._finalize_finding(f, base_body, resp_body, base_status, status)
            if f.confidence >= self.config.min_confidence:
                findings.append(f)
        return findings


    async def _check_blind_idor(self, url, method, body, params, base_status, base_body) -> list[Finding]:
        if not _HAS_BLIND_IDOR or not self._blind_idor:
            return []
        findings: list[Finding] = []
        path_results = await self._blind_idor.scan_path(
            url=url, method=method,
            body=body if body else None,
            token_owned=self.config.auth_token,
            token_other=self.config.second_user_token,
            samples=3,
        )
        body_results = (
            await self._blind_idor.scan_body(
                url=url, method=method, body=body,
                token_owned=self.config.auth_token,
                token_other=self.config.second_user_token,
                samples=3,
            )
            if body else []
        )
        header_results = await self._blind_idor.scan_header_injection(
            url=url, method=method,
            body=body if body else None,
            token_owned=self.config.auth_token,
        )
        for r in path_results + body_results + header_results:
            if not r.is_idor:
                continue
            f = Finding(
                title=r.title or (
                    f"Blind IDOR — {r.parameter}: "
                    f"{r.owned_id}→{r.tested_id}"
                ),
                severity=Severity.CRITICAL if r.confirmed else Severity.HIGH,
                category="Business Logic — IDOR/BOLA (Blind)",
                description=(
                    f"Blind IDOR at `{r.tested_url or url}` on `{r.parameter}`. "
                    f"{len(r.oracles_triggered)} oracle(s): "
                    f"{', '.join(r.oracles_triggered[:2])}."
                ),
                request={"method": method, "url": r.tested_url or url},
                response_summary=(
                    f"Status: {r.status_owned}→{r.status_tested} | "
                    f"Size delta: {r.size_delta_bytes:+d}B | "
                    f"Timing: {r.timing_delta_ms:+.0f}ms"
                ),
                evidence=r.evidence,
                recommendation=r.recommendation,
                cwe="CWE-639",
                cvss=9.1 if r.confirmed else 8.1,
                owasp="API1:2023 Broken Object Level Authorization",
                confirmed=r.confirmed, confidence=r.confidence,
                false_positive_checks=r.fp_signals,
                endpoint=url, parameter=r.parameter,
            )
            f.poc = self.poc_generator.generate(f)
            findings.append(f)
        return findings


    async def _check_graphql_idor(self) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(self.config.target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for gql_url in [
            f"{base}/graphql",
            f"{base}/api/graphql",
            f"{base}/query",
        ]:
            if _HAS_VALIDATION and self._endpoint_validator:
                val = await self._endpoint_validator.validate(
                    gql_url, "POST", is_graphql=True
                )
                if val.should_skip:
                    if self.config.verbose:
                        print(f"  [SKIP GraphQL] {gql_url} — {val.summary}")
                    continue

            ev = self._new_evidence()
            status, _, resp_body, elapsed = await self._request(
                "POST", gql_url,
                data='{"query": "{ __schema { types { name } } }"}',
            )
            if ev:
                ev.record(
                    label="attack", method="POST", url=gql_url,
                    req_headers=self._build_headers(),
                    req_body={"query": "{ __schema { types { name } } }"},
                    resp_status=status, resp_headers={},
                    resp_body=resp_body, elapsed=elapsed,
                )
            if (
                status == 200
                and "__schema" in resp_body
                and ('"data"' in resp_body or '"errors"' in resp_body)
                and not resp_body.strip().startswith("<")
            ):
                pkg = self._build_pkg(
                    ev, title="GraphQL Introspection",
                    endpoint=gql_url, vuln_type="GraphQL",
                    confidence=90, confirmed=True,
                )
                f = Finding(
                    title="GraphQL Introspection Enabled in Production",
                    severity=Severity.MEDIUM,
                    category="Business Logic — GraphQL",
                    description=(
                        f"GraphQL introspection at `{gql_url}` "
                        f"exposes the full schema."
                    ),
                    request={"method": "POST", "url": gql_url},
                    response_summary=f"HTTP {status}",
                    evidence="__schema returned with JSON GraphQL response",
                    recommendation="Disable introspection in production.",
                    cwe="CWE-200", cvss=5.3,
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    confirmed=True, endpoint=gql_url,
                )
                self._attach(f, pkg)
                f = self._finalize_finding(f, "", resp_body, 403, 200)
                if f.confidence >= self.config.min_confidence:
                    findings.append(f)

            for q in [
                '{"query": "{ users { id email } }"}',
                '{"query": "{ me { id email role } }"}',
            ]:
                ev2 = self._new_evidence()
                status, _, resp_body, elapsed = await self._request(
                    "POST", gql_url, data=q, token_override=""
                )
                if ev2:
                    ev2.record(
                        label="attack", method="POST", url=gql_url,
                        req_headers=self._build_headers(token=""),
                        req_body=q, resp_status=status, resp_headers={},
                        resp_body=resp_body, elapsed=elapsed,
                    )
                if (
                    status == 200
                    and '"data"' in resp_body
                    and "errors" not in resp_body
                    and not resp_body.strip().startswith("<")
                ):
                    pkg2 = self._build_pkg(
                        ev2, title="GraphQL Unauthenticated Access",
                        endpoint=gql_url, vuln_type="GraphQL",
                        confidence=85, confirmed=True,
                    )
                    f = Finding(
                        title="GraphQL Unauthenticated Data Access",
                        severity=Severity.HIGH,
                        category="Business Logic — GraphQL",
                        description=(
                            f"GraphQL query at `{gql_url}` returned "
                            f"data without authentication."
                        ),
                        request={
                            "method": "POST", "url": gql_url,
                            "body": q, "note": "No auth",
                        },
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence="Unauthenticated query returned JSON GraphQL data",
                        recommendation=(
                            "Require authentication for all non-public queries."
                        ),
                        cwe="CWE-306", cvss=8.5,
                        owasp="API2:2023 Broken Authentication",
                        confirmed=True, endpoint=gql_url,
                    )
                    self._attach(f, pkg2)
                    f = self._finalize_finding(f, "", resp_body, 401, 200)
                    if f.confidence >= self.config.min_confidence:
                        findings.append(f)
                    break
        return findings



    async def _run_flow_attacks(self) -> list[Finding]:
        if not _HAS_FLOWS or not self._flow_replayer:
            return []
        findings: list[Finding] = []
        base_url     = self.config.target_url
        flow_configs = getattr(self.config, "flow_configs", [])

        for fc in flow_configs:
            try:
                steps = fc if isinstance(fc, list) else FlowTemplates.from_json(fc)
                findings.extend(
                    await self._flow_replayer.attack(steps, base_url=base_url)
                )
                findings.extend(
                    await self._flow_replayer.attack_workflow_bypass(
                        steps, base_url=base_url
                    )
                )



                findings.extend(
                    await self._flow_replayer.attack_state_transitions(
                        steps, base_url=base_url
                    )
                )


                second_token = getattr(self.config, "second_user_token", "") or None
                findings.extend(
                    await self._flow_replayer.attack_cross_instance_confusion(
                        steps, base_url=base_url, second_token=second_token
                    )
                )
                attack_steps = [s for s in steps if s.attack_here]
                if attack_steps:
                    findings.extend(
                        await self._flow_replayer.attack_race_condition(
                            attack_steps[-1], base_url=base_url
                        )
                    )
            except Exception as e:
                if self.config.verbose:
                    print(f"  [!] Flow attack error: {e}")

        if getattr(self.config, "auto_detect_flows", False):
            await self._auto_run_ecommerce_flow(findings, base_url)

        for f in findings:
            if not getattr(f, "confidence", 0):
                f.confidence = 55
            if not getattr(f, "poc", None):
                f.poc = self.poc_generator.generate(f)
        return findings

    async def _auto_run_ecommerce_flow(self, findings: list, base_url: str):
        checkout_indicators = ["/cart", "/checkout", "/order", "/payment"]
        has_ecommerce = any(
            any(
                ind in ep.get("url", "").lower()
                for ind in checkout_indicators
            )
            for ep in self.discovered_endpoints
        )
        if not has_ecommerce or not _HAS_FLOWS:
            return
        print("  [*] E-commerce endpoints detected — running checkout flow...")
        steps = FlowTemplates.ecommerce_checkout(
            product_id=getattr(self.config, "product_id", 1),
            quantity=1,
            price=getattr(self.config, "product_price", 99.99),
        )
        try:
            findings.extend(
                await self._flow_replayer.attack(steps, base_url=base_url)
            )
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Auto e-commerce flow error: {e}")

    async def _run_oauth_tests(self) -> list[Finding]:
        if not _HAS_OAUTH:
            return []
        oauth_cfg = getattr(self.config, "oauth_config", None)
        if not oauth_cfg:
            return []
        findings: list[Finding] = []
        try:
            handler = OAuthHandler(oauth_cfg, verbose=self.config.verbose)
            token   = await handler.get_token(self.session)
            if token:
                print(
                    f"  [+] OAuth2 token acquired (expires in {token.expires_in}s)"
                )
                self.config.auth_token = token.access_token
                await handler.test_token_endpoint_vulns(self.session)
            sev_map = {
                "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                "MEDIUM":   Severity.MEDIUM,   "LOW":  Severity.LOW,
            }
            for vuln in handler.findings:
                f = Finding(
                    title=vuln.title,
                    severity=sev_map.get(vuln.severity.upper(), Severity.MEDIUM),
                    category="Business Logic — OAuth2 Vulnerability",
                    description=vuln.description,
                    request={"note": "OAuth2 flow test"},
                    response_summary=vuln.evidence,
                    evidence=vuln.evidence,
                    recommendation=vuln.recommendation,
                    cwe=vuln.cwe, owasp=vuln.owasp,
                    confirmed=True, confidence=80,
                    endpoint=oauth_cfg.token_url,
                )
                f.poc = self.poc_generator.generate(f)
                findings.append(f)
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] OAuth test error: {e}")
        return findings




def _url_basename(url: str) -> str:
    path = urlparse(url).path
    return path.split("/")[-1] or url[:40]

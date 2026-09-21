"""
BLFinder Phase 3 — core/recon/js_secret_extractor.py
JavaScript Secret Extractor

Crawls JavaScript files loaded by a target and extracts:
  1. API keys and tokens (AWS, Stripe, Twilio, GitHub, etc.)
  2. Internal API endpoint paths
  3. Hardcoded credentials
  4. Internal hostnames and infrastructure hints
  5. Feature flags and debug mode indicators
  6. JWT tokens left in source

All findings are returned as SecretFinding objects with:
  - The secret value (redacted in reports)
  - Source file URL
  - Line number and surrounding context
  - Confidence score
  - Category and severity

FP reduction:
  - Minimum entropy threshold for "random-looking" secrets
  - Known test/placeholder pattern exclusion
  - Context analysis (near "test", "example", "placeholder" = lower confidence)
  - Deduplication across files
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False




@dataclass
class SecretPattern:
    name:        str
    pattern:     re.Pattern
    category:    str
    severity:    str      
    min_entropy: float = 3.0
    context_keywords: list[str] = field(default_factory=list)
    false_positive_patterns: list[re.Pattern] = field(default_factory=list)


_SECRET_PATTERNS: list[SecretPattern] = [


    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        category="cloud_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?:aws[_\-\s]?secret|secret[_\-\s]?access[_\-\s]?key)["\s:=]+([A-Za-z0-9/+=]{40})', re.I),
        category="cloud_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
        category="cloud_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="Google OAuth Client Secret",
        pattern=re.compile(r'\b(GOCSPX-[0-9A-Za-z\-_]{28})\b'),
        category="cloud_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),


    SecretPattern(
        name="Stripe Live Secret Key",
        pattern=re.compile(r'\b(sk_live_[A-Za-z0-9]{20,})\b'),
        category="payment_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="Stripe Test Secret Key",
        pattern=re.compile(r'\b(sk_test_[A-Za-z0-9]{20,})\b'),
        category="payment_credential",
        severity="MEDIUM",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=re.compile(r'\b(pk_live_[A-Za-z0-9]{20,})\b'),
        category="payment_credential",
        severity="HIGH",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="PayPal Client Secret",
        pattern=re.compile(r'(?:paypal[_\-]?(?:client[_\-]?)?secret)["\s:=]+([A-Za-z0-9_\-]{20,})', re.I),
        category="payment_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),


    SecretPattern(
        name="Twilio Account SID",
        pattern=re.compile(r'\b(AC[a-f0-9]{32})\b'),
        category="communication_credential",
        severity="HIGH",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="Twilio Auth Token",
        pattern=re.compile(r'\b(SK[a-f0-9]{32})\b'),
        category="communication_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r'\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b'),
        category="communication_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="Mailgun API Key",
        pattern=re.compile(r'\b(key-[a-f0-9]{32})\b'),
        category="communication_credential",
        severity="HIGH",
        min_entropy=3.5,
    ),


    SecretPattern(
        name="GitHub Personal Access Token",
        pattern=re.compile(r'\b(ghp_[A-Za-z0-9]{36})\b'),
        category="vcs_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        pattern=re.compile(r'\b(gho_[A-Za-z0-9]{36})\b'),
        category="vcs_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="GitHub Actions Token",
        pattern=re.compile(r'\b(ghs_[A-Za-z0-9]{36})\b'),
        category="vcs_credential",
        severity="CRITICAL",
        min_entropy=4.0,
    ),
    SecretPattern(
        name="GitLab Personal Access Token",
        pattern=re.compile(r'\b(glpat-[A-Za-z0-9\-_]{20})\b'),
        category="vcs_credential",
        severity="CRITICAL",
        min_entropy=3.5,
    ),


    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r'\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b'),
        category="auth_token",
        severity="HIGH",
        min_entropy=4.0,
    ),


    SecretPattern(
        name="Generic API Key",
        pattern=re.compile(
            r'(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?key|app[_\-]?secret)'
            r'["\s:=]+["\']?([A-Za-z0-9_\-]{20,64})["\']?',
            re.I
        ),
        category="generic_credential",
        severity="HIGH",
        min_entropy=3.5,
        false_positive_patterns=[
            re.compile(r'(your|example|placeholder|<|>|{|}|INSERT|REPLACE)', re.I)
        ],
    ),
    SecretPattern(
        name="Generic Secret/Password",
        pattern=re.compile(
            r'(?:password|passwd|secret|private_key|client_secret)'
            r'["\s:=]+["\']([A-Za-z0-9!@#$%^&*_\-]{8,64})["\']',
            re.I
        ),
        category="generic_credential",
        severity="HIGH",
        min_entropy=3.0,
        false_positive_patterns=[
            re.compile(r'(your|example|placeholder|password|secret|changeme|admin|test|demo)', re.I)
        ],
    ),


    SecretPattern(
        name="Internal API Endpoint",
        pattern=re.compile(
            r'["\']'
            r'((?:https?://(?:internal|private|admin|backend|service|api)'
            r'[\w.\-]*(?::\d+)?(?:/[\w/\-]*)?)'
            r'|(?:/(?:internal|private|admin|backend|service)/[\w/\-]{3,}))'
            r'["\']',
            re.I
        ),
        category="internal_endpoint",
        severity="MEDIUM",
        min_entropy=0.0,
    ),


    SecretPattern(
        name="Database Connection String",
        pattern=re.compile(
            r'(?:mongodb|postgresql|mysql|redis|amqp)://[^\s"\'<>]+',
            re.I
        ),
        category="infrastructure",
        severity="CRITICAL",
        min_entropy=2.0,
    ),
    SecretPattern(
        name="Private IP / Internal Hostname",
        pattern=re.compile(
            r'["\']'
            r'((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
            r'|192\.168\.\d{1,3}\.\d{1,3}'
            r'|localhost'
            r'|[\w\-]+\.(?:internal|local|corp|lan))'
            r'(?::\d+)?(?:/[\w/\-]*)?)'
            r'["\']',
            re.I
        ),
        category="infrastructure",
        severity="MEDIUM",
        min_entropy=0.0,
    ),
    SecretPattern(
        name="S3 Bucket",
        pattern=re.compile(
            r'(?:s3://|https?://s3(?:[\.\-][\w\-]+)?\.amazonaws\.com/)'
            r'([\w\-]{3,63})',
            re.I
        ),
        category="infrastructure",
        severity="MEDIUM",
        min_entropy=0.0,
    ),
]


_PLACEHOLDER_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'^(your|example|placeholder|insert|replace|change|todo)_',
        r'<[A-Z_]+>',
        r'\{[A-Z_]+\}',
        r'^(test|demo|sample|fake|dummy)',
        r'xxx+',
        r'^[a-z]+$',   
        r'1234567',
    ]
]


@dataclass
class SecretFinding:
    """A single secret found in a JavaScript file."""
    pattern_name:  str
    category:      str
    severity:      str
    raw_value:     str          
    redacted:      str          
    source_url:    str          
    line_number:   int = 0
    context:       str = ""     
    confidence:    int = 0      
    entropy:       float = 0.0
    is_false_positive: bool = False
    fp_reason:     str = ""


@dataclass
class JSExtractionResult:
    """Full result of JS secret extraction for a target."""
    target_url:    str
    js_files_found:    int = 0
    js_files_scanned:  int = 0
    secrets:       list[SecretFinding] = field(default_factory=list)
    endpoints:     list[str] = field(default_factory=list)   
    elapsed_sec:   float = 0.0

    @property
    def critical_secrets(self) -> list[SecretFinding]:
        return [s for s in self.secrets if s.severity == "CRITICAL" and not s.is_false_positive]

    @property
    def high_secrets(self) -> list[SecretFinding]:
        return [s for s in self.secrets if s.severity == "HIGH" and not s.is_false_positive]

    @property
    def confirmed_secrets(self) -> list[SecretFinding]:
        return [s for s in self.secrets if not s.is_false_positive and s.confidence >= 60]


class JSSecretExtractor:
    """
    Extracts secrets from JavaScript files loaded by a target.

    Usage:
        extractor = JSSecretExtractor(verbose=True)
        result = await extractor.extract("https://app.target.com", session)

        for secret in result.critical_secrets:
            print(f"{secret.pattern_name}: {secret.redacted} in {secret.source_url}")
    """

    _JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts")
    _MAX_JS_SIZE   = 5 * 1024 * 1024    
    _MAX_JS_FILES  = 30                  

    def __init__(self, verbose: bool = False):
        self.verbose   = verbose
        self._seen_secrets: set[str] = set()

    async def extract(
        self,
        target_url: str,
        session: "aiohttp.ClientSession | None" = None,
        extra_js_urls: list[str] | None = None,
    ) -> JSExtractionResult:
        """
        Crawl the target and extract secrets from all JavaScript files.

        Args:
            target_url:    Base URL to crawl for JS files
            session:       aiohttp session
            extra_js_urls: Additional JS URLs to scan directly
        """
        import time as _time
        start  = _time.time()
        result = JSExtractionResult(target_url=target_url)

        own_session = session is None
        if own_session and _HAS_AIOHTTP:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            session   = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=15),
            )

        try:

            js_urls = await self._collect_js_urls(target_url, session)
            if extra_js_urls:
                js_urls.update(extra_js_urls)

            result.js_files_found = len(js_urls)
            if self.verbose:
                print(f"  [*] Found {len(js_urls)} JS files to scan")


            js_url_list = list(js_urls)[: self._MAX_JS_FILES]
            scan_tasks  = [
                self._scan_js_file(url, session)
                for url in js_url_list
            ]
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            for scan in scan_results:
                if isinstance(scan, tuple):
                    file_secrets, file_endpoints = scan
                    result.secrets.extend(file_secrets)
                    result.endpoints.extend(file_endpoints)
                    result.js_files_scanned += 1


            result.secrets   = self._dedupe_secrets(result.secrets)
            result.endpoints = list(set(result.endpoints))

            if self.verbose:
                print(
                    f"  [+] Scanned {result.js_files_scanned} JS files, "
                    f"found {len(result.confirmed_secrets)} confirmed secrets"
                )

        finally:
            if own_session and session:
                await session.close()

        result.elapsed_sec = _time.time() - start
        return result

    async def scan_content(
        self, content: str, source_url: str = ""
    ) -> tuple[list[SecretFinding], list[str]]:
        """
        Scan raw JS content for secrets.
        Returns (secrets, internal_endpoints).
        Can be called directly without network access.
        """
        return self._extract_from_content(content, source_url)



    async def _collect_js_urls(
        self, target_url: str, session
    ) -> set[str]:
        """Collect all JS file URLs from the target page."""
        js_urls: set[str] = set()
        if session is None:
            return js_urls

        try:
            async with session.get(
                target_url,
                headers={"User-Agent": "Mozilla/5.0 BLFinder/3.0"},
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return js_urls
                html = await resp.text(errors="replace")
                parsed = urlparse(target_url)
                base   = f"{parsed.scheme}://{parsed.netloc}"


                for pattern in [
                    r'<script[^>]+src=["\']([^"\']+)["\']',
                    r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
                ]:
                    for match in re.finditer(pattern, html, re.I):
                        src = match.group(1)
                        if self._is_js_url(src):
                            full = urljoin(base, src) if not src.startswith("http") else src
                            js_urls.add(full)


                chunk_patterns = [
                    r'["\']((?:[./\w\-]+)?(?:chunk|bundle|main|vendor|app)'
                    r'[\w.\-]*\.js)["\']',
                    r'src:\s*["\']([^"\']+\.js)["\']',
                ]
                for pattern in chunk_patterns:
                    for match in re.finditer(pattern, html, re.I):
                        src = match.group(1)
                        full = urljoin(base, src) if not src.startswith("http") else src
                        if self._is_js_url(full):
                            js_urls.add(full)

        except Exception as e:
            if self.verbose:
                print(f"  [!] JS URL collection error: {e}")

        return js_urls

    async def _scan_js_file(
        self, url: str, session
    ) -> tuple[list[SecretFinding], list[str]]:
        """Download and scan a single JS file."""
        if session is None:
            return [], []

        try:
            async with session.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 BLFinder/3.0"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    return [], []


                content_length = int(resp.headers.get("content-length", 0))
                if content_length > self._MAX_JS_SIZE:
                    if self.verbose:
                        print(f"  [!] JS file too large ({content_length}B): {url[:60]}")
                    return [], []

                content = await resp.text(errors="replace")
                if len(content) > self._MAX_JS_SIZE:
                    content = content[:self._MAX_JS_SIZE]

                return self._extract_from_content(content, url)

        except asyncio.TimeoutError:
            return [], []
        except Exception as e:
            if self.verbose:
                print(f"  [!] JS scan error {url[:50]}: {e}")
            return [], []

    def _extract_from_content(
        self, content: str, source_url: str
    ) -> tuple[list[SecretFinding], list[str]]:
        """Extract secrets and endpoints from JS content."""
        secrets:   list[SecretFinding] = []
        endpoints: list[str] = []
        lines      = content.split("\n")

        for pattern_def in _SECRET_PATTERNS:
            for match in pattern_def.pattern.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if not value or len(value) < 6:
                    continue


                pos         = match.start()
                line_num    = content[:pos].count("\n") + 1
                context     = self._get_context(lines, line_num - 1)


                is_fp, fp_reason = self._is_false_positive(
                    value, context, pattern_def
                )


                entropy = _shannon_entropy(value)

                confidence = self._compute_confidence(
                    value, context, entropy, pattern_def, is_fp
                )

                finding = SecretFinding(
                    pattern_name=pattern_def.name,
                    category=pattern_def.category,
                    severity=pattern_def.severity,
                    raw_value=value if not is_fp else "",
                    redacted=_redact(value, pattern_def.category),
                    source_url=source_url,
                    line_number=line_num,
                    context=context[:200],
                    confidence=confidence,
                    entropy=entropy,
                    is_false_positive=is_fp,
                    fp_reason=fp_reason,
                )
                secrets.append(finding)


                if pattern_def.category == "internal_endpoint":
                    endpoints.append(value)

        return secrets, endpoints

    def _is_false_positive(
        self, value: str, context: str, pattern_def: SecretPattern
    ) -> tuple[bool, str]:
        """Check if a found value is likely a false positive."""


        for fp_pat in pattern_def.false_positive_patterns:
            if fp_pat.search(value) or fp_pat.search(context):
                return True, f"Matches known FP pattern: {fp_pat.pattern[:30]}"


        for placeholder in _PLACEHOLDER_PATTERNS:
            if placeholder.search(value):
                return True, f"Looks like a placeholder/test value"


        if pattern_def.min_entropy > 0:
            entropy = _shannon_entropy(value)
            if entropy < pattern_def.min_entropy:
                return True, f"Low entropy ({entropy:.1f} < {pattern_def.min_entropy})"


        context_lower = context.lower()
        test_context_words = [
            "test", "example", "mock", "fake", "dummy",
            "placeholder", "sample", "demo", "your_",
        ]
        if sum(1 for w in test_context_words if w in context_lower) >= 2:
            return True, "Context suggests test/example code"

        return False, ""

    def _compute_confidence(
        self,
        value:       str,
        context:     str,
        entropy:     float,
        pattern_def: SecretPattern,
        is_fp:       bool,
    ) -> int:
        if is_fp:
            return 10

        score = 50    


        if entropy >= 4.5:
            score += 25
        elif entropy >= 3.5:
            score += 15
        elif entropy >= 3.0:
            score += 5


        if pattern_def.name.startswith("AWS") or pattern_def.name.startswith("Stripe"):
            score += 20  


        real_context_words = [
            "production", "prod", "live", "config", "env",
            "process.env", "const ", "let ", "var ",
        ]
        context_lower = context.lower()
        if any(w in context_lower for w in real_context_words):
            score += 10

        return min(100, score)

    def _get_context(self, lines: list[str], line_idx: int) -> str:
        """Get surrounding code context for a finding."""
        start = max(0, line_idx - 1)
        end   = min(len(lines), line_idx + 2)
        return " | ".join(lines[start:end]).strip()

    def _is_js_url(self, url: str) -> bool:
        """Check if a URL points to a JavaScript file."""
        url_lower = url.lower().split("?")[0]
        return any(url_lower.endswith(ext) for ext in self._JS_EXTENSIONS)

    def _dedupe_secrets(self, secrets: list[SecretFinding]) -> list[SecretFinding]:
        """Remove duplicate secret findings."""
        seen  : set[str]          = set()
        unique: list[SecretFinding] = []
        for s in secrets:
            key = hashlib.md5(f"{s.pattern_name}:{s.raw_value}".encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(s)
        return unique




def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _redact(value: str, category: str) -> str:
    """Return a safely redacted version of a secret value."""
    if not value:
        return "****"
    if category in ("cloud_credential", "payment_credential", "auth_token"):
        if len(value) > 8:
            return f"{value[:4]}...{value[-2:]} [{len(value)} chars]"
        return "****"
    if len(value) > 12:
        return f"{value[:4]}...{value[-2:]} [{len(value)} chars]"
    return f"{value[:2]}****"

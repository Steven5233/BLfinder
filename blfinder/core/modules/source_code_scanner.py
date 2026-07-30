"""
BLFinder — core/modules/source_code_scanner.py
Source Code Exposure & Static Bug-Pattern Scanner

Every other module in BLFinder attacks the API from the outside (fuzzing
parameters, replaying requests). This module instead goes after cases where
the *source code itself* leaks to the outside — either as raw files
(exposed .git/.env/backup/credential files) or as reconstructable JS via
exposed source maps — and then statically greps that source for
code-level bug patterns that no black-box request would ever surface
(disabled TLS verification, eval/innerHTML sinks, postMessage handlers with
no origin check, hardcoded internal hostnames, commented-out auth checks).

This is deliberately split from `recon/js_secret_extractor.py`, which
already handles credential/API-key pattern matching well. This module's job
is CODE-LOGIC bugs and SOURCE EXPOSURE, not secrets — the two are
complementary and both may fire on the same file.

Two independent phases:

  Phase A — Source exposure sweep (runs once per host)
      Probes a curated list of VCS/config/backup/credential-file paths
      (.git/HEAD, .env, .aws/credentials, .vscode/sftp.json, id_rsa, ...).
      Every candidate has its own content validator — never just "got a
      200" — and every probe is checked against a soft-404/SPA-catch-all
      canary fingerprint first, the same anti-false-positive technique used
      by the wordlist discovery layer. A generic SPA that 200s everything
      will not generate a single finding here.

  Phase B — Source map reconstruction + static bug-pattern scan
      When a response looks like JS (content-type or `.js` URL), the module
      looks for a `sourceMappingURL` comment, fetches the referenced
      `.map` file, and — where the map embeds `sourcesContent` — statically
      scans the *original, unminified* source for dangerous patterns. If no
      map is available, a reduced pattern subset (the patterns that survive
      minification, e.g. `rejectUnauthorized: false`) is still run directly
      against the raw JS.

Resource caps are intentionally conservative (this runs on a phone over
cellular via Termux): map files >2MB are skipped, at most 20 JS files per
host are processed, and the combined reconstructed-source scanned per host
is capped at ~500KB.

Every static-pattern finding is reported as `confirmed=False` with an
explicit "requires manual triage" framing — regex-matched code patterns are
leads, not proof, and this module never inflates a heuristic match into a
false sense of certainty. Only Phase A's file-exposure findings (backed by
a specific content validator, e.g. an actual private-key header or a
parsed git ref) are reported as confirmed.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import string
from urllib.parse import urljoin, urlparse

from ..models import Finding, Severity, ProofOfConcept

_MAX_MAP_BYTES = 2 * 1024 * 1024          # skip source maps bigger than this
_MAX_JS_FILES_PER_HOST = 20                # cap Phase B volume per host
_MAX_RECONSTRUCTED_CHARS = 500_000         # cap total original-source text scanned per host


# ── Phase A: source-exposure candidate paths ─────────────────────────────────
# Each tuple: (path, validator(body, headers) -> bool, title, severity, cwe, recommendation)

def _is_git_ref(body: str, headers: dict) -> bool:
    return bool(re.match(r"^\s*ref:\s*refs/heads/\S+", body)) or bool(re.match(r"^\s*[0-9a-f]{40}\s*$", body.strip()))

def _is_git_config(body: str, headers: dict) -> bool:
    return "[core]" in body and "repositoryformatversion" in body

def _is_env_file(body: str, headers: dict) -> bool:
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    if len(lines) < 2:
        return False
    kv_lines = sum(1 for l in lines if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", l.strip()))
    return kv_lines >= max(2, len(lines) // 2)

def _is_aws_credentials(body: str, headers: dict) -> bool:
    return "[default]" in body and "aws_access_key_id" in body.lower()

def _is_ssh_private_key(body: str, headers: dict) -> bool:
    return bool(re.search(r"-----BEGIN (RSA|OPENSSH|EC|DSA) ?PRIVATE KEY-----", body))

def _is_vscode_sftp(body: str, headers: dict) -> bool:
    try:
        data = json.loads(body)
    except Exception:
        return False
    if isinstance(data, list):
        data = data[0] if data else {}
    return isinstance(data, dict) and "host" in data and ("password" in data or "privateKeyPath" in data)

def _is_npmrc_token(body: str, headers: dict) -> bool:
    return bool(re.search(r"_authToken\s*=\s*\S+", body))

def _is_php_backup(body: str, headers: dict) -> bool:
    return "<?php" in body and bool(re.search(r"DB_(PASSWORD|PASS|HOST)|define\(", body, re.IGNORECASE))

def _is_docker_compose(body: str, headers: dict) -> bool:
    return "services:" in body and ("image:" in body or "build:" in body)

def _is_django_settings(body: str, headers: dict) -> bool:
    return "SECRET_KEY" in body and ("DEBUG" in body or "ALLOWED_HOSTS" in body)

def _is_htpasswd(body: str, headers: dict) -> bool:
    lines = [l for l in body.splitlines() if l.strip()]
    return bool(lines) and all(re.match(r"^[^:]+:\$?\w*\$?[\w./$]+$", l) for l in lines[:5])

_EXPOSURE_CHECKS = [
    (".git/HEAD",              _is_git_ref,          "Exposed .git Repository (HEAD)",       Severity.CRITICAL, "CWE-527"),
    (".git/config",            _is_git_config,       "Exposed .git Repository (config)",     Severity.CRITICAL, "CWE-527"),
    (".env",                   _is_env_file,         "Exposed .env Configuration File",       Severity.CRITICAL, "CWE-200"),
    (".env.local",             _is_env_file,         "Exposed .env.local Configuration File", Severity.CRITICAL, "CWE-200"),
    (".env.production",        _is_env_file,         "Exposed .env.production File",          Severity.CRITICAL, "CWE-200"),
    (".env.backup",            _is_env_file,         "Exposed .env Backup File",              Severity.CRITICAL, "CWE-200"),
    (".aws/credentials",       _is_aws_credentials,  "Exposed AWS Credentials File",          Severity.CRITICAL, "CWE-522"),
    (".ssh/id_rsa",            _is_ssh_private_key,  "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    ("id_rsa",                 _is_ssh_private_key,  "Exposed SSH Private Key",               Severity.CRITICAL, "CWE-522"),
    (".vscode/sftp.json",      _is_vscode_sftp,      "Exposed VS Code SFTP Credentials",      Severity.CRITICAL, "CWE-522"),
    (".npmrc",                 _is_npmrc_token,       "Exposed .npmrc Registry Auth Token",    Severity.HIGH,     "CWE-522"),
    ("config.php.bak",         _is_php_backup,        "Exposed PHP Config Backup File",       Severity.CRITICAL, "CWE-530"),
    ("wp-config.php.bak",      _is_php_backup,        "Exposed WordPress Config Backup File", Severity.CRITICAL, "CWE-530"),
    ("wp-config.php.save",     _is_php_backup,        "Exposed WordPress Config Backup File", Severity.CRITICAL, "CWE-530"),
    ("docker-compose.yml",     _is_docker_compose,    "Exposed docker-compose.yml",           Severity.HIGH,     "CWE-200"),
    ("docker-compose.yml.bak", _is_docker_compose,    "Exposed docker-compose.yml Backup",    Severity.HIGH,     "CWE-200"),
    ("settings.py",            _is_django_settings,   "Exposed Django settings.py",           Severity.CRITICAL, "CWE-200"),
    (".htpasswd",              _is_htpasswd,          "Exposed .htpasswd Credential File",    Severity.HIGH,     "CWE-522"),
]


# ── Phase B: static JS bug patterns ──────────────────────────────────────────
# minified_safe=True patterns are kept in the reduced set run against raw
# (possibly minified) JS when no source map / sourcesContent is available.

class _JSPattern:
    __slots__ = ("id", "regex", "title", "description", "severity", "cwe", "minified_safe")

    def __init__(self, id_, regex, title, description, severity, cwe, minified_safe=False):
        self.id = id_
        self.regex = regex
        self.title = title
        self.description = description
        self.severity = severity
        self.cwe = cwe
        self.minified_safe = minified_safe


_JS_PATTERNS = [
    _JSPattern(
        "disabled_tls_verify",
        re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", re.IGNORECASE),
        "TLS Certificate Verification Disabled in Source",
        "The source disables TLS certificate verification for outbound HTTPS "
        "requests, allowing man-in-the-middle interception of any traffic "
        "this code path sends (e.g. to internal services, webhooks, or "
        "third-party APIs).",
        Severity.HIGH, "CWE-295", minified_safe=True,
    ),
    _JSPattern(
        "eval_dynamic_code",
        re.compile(r"\beval\s*\(|new\s+Function\s*\("),
        "Dynamic Code Execution Sink (eval/Function)",
        "Use of `eval()` or `new Function()` found. If any part of the "
        "argument is influenced by user/URL/query input, this is a direct "
        "path to client-side code execution.",
        Severity.MEDIUM, "CWE-95", minified_safe=True,
    ),
    _JSPattern(
        "dom_xss_sink",
        re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML"),
        "DOM XSS Sink Present",
        "A DOM XSS sink (`innerHTML`/`outerHTML`/`document.write`/"
        "`dangerouslySetInnerHTML`) was found. Requires manual triage to "
        "confirm whether the assigned value is attacker-influenced "
        "(URL params, postMessage data, API responses reflected without "
        "encoding).",
        Severity.MEDIUM, "CWE-79",
    ),
    _JSPattern(
        "postmessage_no_origin_check",
        re.compile(
            r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{"
            r"(?:(?!\.origin).){0,200}\}",
            re.DOTALL,
        ),
        "postMessage Handler Without Origin Validation",
        "A `window.addEventListener('message', ...)` handler was found "
        "whose first ~200 characters of body do not reference `.origin`. "
        "If the handler acts on the message data (writes to the DOM, "
        "navigates, calls an API) without validating `event.origin`, any "
        "page can post messages to it — a common cross-origin data leak / "
        "DOM XSS vector.",
        Severity.MEDIUM, "CWE-346",
    ),
    _JSPattern(
        "hardcoded_internal_host",
        re.compile(
            r"""['"`]https?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"""
            r"""192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"""
            r"""[\w.-]*\.(?:internal|local|corp|intranet))[:/][^'"`]*['"`]""",
        ),
        "Hardcoded Internal Hostname/IP in Client Source",
        "Client-side source references an internal hostname or private IP "
        "range directly. This leaks internal network topology (useful for "
        "chaining into an SSRF target list) and may indicate an internal "
        "API endpoint reachable only from specific network positions.",
        Severity.LOW, "CWE-200", minified_safe=True,
    ),
    _JSPattern(
        "insecure_random_for_security_token",
        re.compile(r"Math\.random\(\)[^;]{0,80}(token|password|otp|reset|secret|session)", re.IGNORECASE),
        "Non-Cryptographic Randomness Used for Security-Sensitive Value",
        "`Math.random()` is used near a security-sensitive identifier "
        "(token/password/OTP/reset/session). `Math.random()` is not "
        "cryptographically secure and its output can be predicted, "
        "potentially allowing token/session prediction. Verify whether "
        "this generates an actual security value or just a UI key.",
        Severity.MEDIUM, "CWE-338",
    ),
    _JSPattern(
        "commented_out_auth_check",
        re.compile(
            r"//\s*(?:if\s*\(.*(?:auth|permission|role|admin|isLoggedIn).*\)|.*(?:return\s+403|return\s+401))",
            re.IGNORECASE,
        ),
        "Commented-Out Authorization/Authentication Check",
        "A commented-out line resembling an authorization/authentication "
        "check was found. This may indicate a security control that was "
        "temporarily disabled for debugging and never re-enabled — worth "
        "manual review to confirm the corresponding server-side check is "
        "still enforced.",
        Severity.LOW, "CWE-489",
    ),
    _JSPattern(
        "debug_bypass_flag",
        re.compile(r"(?:if\s*\(\s*(?:window\.)?(?:DEBUG|debug|__DEV__|isDev|bypassAuth)\b)", re.IGNORECASE),
        "Debug/Bypass Flag Gating Application Logic",
        "A debug/bypass flag (`DEBUG`, `__DEV__`, `bypassAuth`, ...) gates "
        "part of the application logic. If this flag can be influenced "
        "client-side (query param, localStorage, global var) it may allow "
        "toggling debug-only behavior in production. Manual review needed "
        "to confirm what the flag actually gates.",
        Severity.LOW, "CWE-489",
    ),
]

_MINIFIED_SAFE_PATTERNS = [p for p in _JS_PATTERNS if p.minified_safe]


class SourceCodeScanner:
    """
    Usage:
        scs = SourceCodeScanner(scanner)
        findings = await scs.check(url, method, status, headers, body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._exposure_checked_hosts: set[str] = set()
        self._reported: set[tuple] = set()          # (host, kind, key)
        self._js_files_scanned_per_host: dict[str, int] = {}
        self._reconstructed_chars_per_host: dict[str, int] = {}

    # ── Public API ───────────────────────────────────────────────────────────

    async def check(
        self,
        url: str,
        method: str,
        status: int = 0,
        headers: dict | None = None,
        body: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return findings
        headers = headers or {}

        # Phase A — runs once per host, triggered by the first request we see for it.
        if host not in self._exposure_checked_hosts:
            self._exposure_checked_hosts.add(host)
            findings.extend(await self._scan_source_exposure(parsed.scheme, host))

        # Phase B — only for responses that look like JavaScript.
        if self._looks_like_js(url, headers, body):
            budget = self._js_files_scanned_per_host.get(host, 0)
            if budget < _MAX_JS_FILES_PER_HOST:
                self._js_files_scanned_per_host[host] = budget + 1
                findings.extend(await self._scan_js_source(url, host, body))

        return findings

    # ── Phase A ──────────────────────────────────────────────────────────────

    async def _scan_source_exposure(self, scheme: str, host: str) -> list[Finding]:
        findings: list[Finding] = []
        base = f"{scheme}://{host}"

        canary_hash = await self._canary_hash(base)

        for path, validator, title, severity, cwe in _EXPOSURE_CHECKS:
            key = (host, "exposure", path)
            if key in self._reported:
                continue
            probe_url = f"{base}/{path}"
            try:
                pstatus, pheaders, pbody, _ = await self._request("GET", probe_url)
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] SourceCodeScanner exposure probe error {probe_url}: {e}")
                continue
            if pstatus not in (200, 201):
                continue
            if not pbody or len(pbody) < 5:
                continue
            if canary_hash and self._body_hash(pbody) == canary_hash:
                continue  # soft-404 / SPA catch-all — not a real hit
            if not validator(pbody, pheaders or {}):
                continue

            self._reported.add(key)
            findings.append(self._build_exposure_finding(probe_url, path, title, severity, cwe, pbody))

        return findings

    async def _canary_hash(self, base: str) -> str | None:
        nonce = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        canary_url = f"{base}/blfinder_src_canary_{nonce}_does_not_exist"
        try:
            status, _, body, _ = await self._request("GET", canary_url)
        except Exception:
            return None
        if status not in (200, 404) or not body:
            return None
        return self._body_hash(body)

    def _body_hash(self, body: str) -> str:
        return hashlib.md5(body[:500].encode("utf-8", errors="replace")).hexdigest()

    def _build_exposure_finding(self, url, path, title, severity, cwe, body) -> Finding:
        snippet = body[:400].replace("\n", " ")
        recommendation = {
            "CWE-527": (
                "Block access to `.git`/`.svn`/`.hg` directories at the web "
                "server or reverse-proxy layer (deny-by-default for dotfiles), "
                "and rotate any credentials that ever existed in the "
                "repository's history — a partial `.git` exposure is enough "
                "to reconstruct the full history and every secret ever "
                "committed, even if later removed."
            ),
            "CWE-200": (
                "Remove environment/config files from the web root entirely; "
                "they should never be served by the application server. "
                "Rotate every credential contained in the exposed file "
                "immediately, since it must be treated as fully compromised."
            ),
            "CWE-522": (
                "Remove the exposed credential/key file from the web root and "
                "rotate the corresponding credentials immediately. Store "
                "secrets in a secrets manager or environment variables "
                "injected at runtime, never as static files under the "
                "document root."
            ),
            "CWE-530": (
                "Remove editor/deploy backup files (`*.bak`, `*.swp`, `*.save`, "
                "`*~`) from the web root — configure your deploy pipeline to "
                "exclude them, and add a web-server rule denying any request "
                "for a path ending in a backup-file extension."
            ),
        }.get(cwe, "Remove this file from the publicly accessible web root.")

        finding = Finding(
            title=title,
            severity=severity,
            category="Source Code Exposure",
            description=(
                f"`{url}` is publicly accessible and its content matched the "
                f"expected format for this file type (validated beyond a bare "
                f"200 status — confirmed against a soft-404 canary and a "
                f"content-shape check specific to this file)."
            ),
            request={"method": "GET", "url": url},
            response_summary=f"200 OK, content validated as {title.lower()}",
            evidence=f"Response snippet: {snippet}",
            recommendation=recommendation,
            cwe=cwe,
            cvss=9.1 if severity == Severity.CRITICAL else (7.5 if severity == Severity.HIGH else 5.3),
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=True,
            confidence=93,
            confidence_reasons=[
                "Content matched a file-type-specific validator (not just HTTP 200)",
                "Response did not match the soft-404/SPA-catch-all canary fingerprint",
            ],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary=f"Publicly exposed {title.lower()}",
            curl_command=f'curl -sk "{url}" -i',
            python_script=f'import requests\nr = requests.get("{url}")\nprint(r.status_code)\nprint(r.text[:1000])\n',
            burp_request=f"GET /{path} HTTP/1.1\nHost: {urlparse(url).netloc}\nConnection: close\n\n",
            expected_result="The file downloads with content matching the description above.",
            steps=[f"Request `{url}` directly — no authentication required."],
        )
        return finding

    # ── Phase B ──────────────────────────────────────────────────────────────

    def _looks_like_js(self, url: str, headers: dict, body: str) -> bool:
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if "javascript" in ct or "ecmascript" in ct:
            return True
        if urlparse(url).path.endswith((".js", ".mjs", ".cjs")):
            return True
        return False

    async def _scan_js_source(self, url: str, host: str, body: str) -> list[Finding]:
        findings: list[Finding] = []

        map_url, map_content = await self._fetch_source_map(url, body)
        sources_content = self._extract_sources_content(map_content) if map_content else []

        char_budget = _MAX_RECONSTRUCTED_CHARS - self._reconstructed_chars_per_host.get(host, 0)

        if sources_content and char_budget > 0:
            combined = "\n".join(sources_content)[:char_budget]
            self._reconstructed_chars_per_host[host] = (
                self._reconstructed_chars_per_host.get(host, 0) + len(combined)
            )
            findings.extend(
                self._apply_patterns(url, host, combined, _JS_PATTERNS, source_label=f"reconstructed via {map_url}")
            )
        else:
            # No usable source map — fall back to the minification-safe subset
            # run directly against the raw (possibly minified) JS.
            findings.extend(
                self._apply_patterns(url, host, body, _MINIFIED_SAFE_PATTERNS, source_label="raw/minified JS")
            )

        return findings

    async def _fetch_source_map(self, js_url: str, body: str) -> tuple[str, str]:
        m = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", body[-2000:])
        if not m:
            return "", ""
        map_ref = m.group(1)
        if map_ref.startswith("data:"):
            return "", ""  # inline data-URI maps are rare and skipped to keep this cheap
        map_url = urljoin(js_url, map_ref)
        try:
            status, headers, map_body, _ = await self._request("GET", map_url)
        except Exception as e:
            if self._config.verbose:
                print(f"[!] SourceCodeScanner map fetch error {map_url}: {e}")
            return "", ""
        if status != 200 or not map_body:
            return "", ""
        if len(map_body) > _MAX_MAP_BYTES:
            return "", ""
        return map_url, map_body

    def _extract_sources_content(self, map_body: str) -> list[str]:
        try:
            data = json.loads(map_body)
        except Exception:
            return []
        contents = data.get("sourcesContent") or []
        return [c for c in contents if isinstance(c, str) and c.strip()]

    def _apply_patterns(self, url, host, text, patterns, source_label: str) -> list[Finding]:
        findings = []
        for pattern in patterns:
            key = (host, "js_pattern", pattern.id, url)
            if key in self._reported:
                continue
            m = pattern.regex.search(text)
            if not m:
                continue
            self._reported.add(key)
            start = max(0, m.start() - 60)
            snippet = text[start:m.end() + 60].replace("\n", " ")
            findings.append(self._build_js_pattern_finding(url, pattern, snippet, source_label))
        return findings

    def _build_js_pattern_finding(self, url, pattern: "_JSPattern", snippet: str, source_label: str) -> Finding:
        finding = Finding(
            title=f"{pattern.title} — Requires Manual Triage",
            severity=pattern.severity,
            category="Static Source Code Analysis",
            description=(
                f"{pattern.description}\n\nFound in `{url}` ({source_label}). "
                f"This is a static pattern match, not a runtime-confirmed "
                f"vulnerability — verify the surrounding context before "
                f"reporting it as a confirmed bug."
            ),
            request={"method": "GET", "url": url},
            response_summary="Static pattern match in client-side source",
            evidence=f"...{snippet}...",
            recommendation=(
                "Review the surrounding code path manually to confirm "
                "exploitability before reporting; see the pattern-specific "
                "guidance in the description above."
            ),
            cwe=pattern.cwe,
            cvss=0.0,
            owasp="OWASP Top 10 A05:2021 Security Misconfiguration",
            confirmed=False,
            confidence=45,
            confidence_reasons=[f"Static regex match for pattern `{pattern.id}`"],
            false_positive_checks=[
                "Static pattern match only — not confirmed against runtime behavior",
                "Requires manual review of surrounding code to confirm attacker "
                "influence over the relevant value/flag",
            ],
            endpoint=url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary=f"Static match: {pattern.title}",
            curl_command=f'curl -sk "{url}" -o source.js',
            python_script=(
                "import requests\n"
                f'r = requests.get("{url}")\n'
                "open('source.js', 'w').write(r.text)\n"
                "# then search source.js manually around the snippet below\n"
            ),
            burp_request="",
            expected_result="Manually confirm exploitability of the flagged code path.",
            steps=[f"Open `{url}` and locate: ...{snippet}..."],
        )
        return finding

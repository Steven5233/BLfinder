"""
BLFinder — core/modules/numeric_precision.py
Numeric Precision, Integer Overflow & Unit/Currency Scale Scanner

Targets the class of business-logic bugs that live in HOW a number is
processed rather than WHETHER a number is accepted — the gap every
scanner that only checks "is this value rejected?" walks straight past.

Two techniques — deliberately not integer overflow, which scanner.py's
own `_check_integer_overflow` already covers (boundary values across
every numeric field, any-key negative-reflection confirmation):

  1. Sub-cent rounding abuse — a price/rate field set to a value that
     truncates to an effectively-free charge under typical
     floating-point or fixed-2-decimal rounding, while still passing a
     naive `value > 0` guard.

  2. Unit/currency scale confusion — a `*_cents`/`*_minor` field paying
     out 100x on a major-unit value, or a price field whose sibling
     currency code can be swapped to a lower-value currency while the
     numeral is left untouched, exploiting backends that don't re-price
     per currency.

Each technique only reports CONFIRMED when the response itself shows the
distorted number (an echoed total, not just a 2xx) — everything else is
reported at reduced confidence as "accepted, needs manual confirmation"
so false positives don't drown out the real chains.
"""

from __future__ import annotations

import copy
import re
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept
from ..response_heuristics import looks_like_error

try:
    from ..intelligence.field_type_engine import (
        infer_field_type,
        is_minor_unit_field, rescale_minor_unit_payload,
        weaker_currency_candidates,
        generate_precision_payloads,
    )
    _HAS_FIELD_TYPING = True
except ImportError:
    _HAS_FIELD_TYPING = False


_PRICE_KEYS = (
    "price", "amount", "total", "cost", "fee", "charge", "rate",
    "unit_price", "subtotal", "payment_amount", "order_total",
    "grand_total", "final_price", "shipping_cost", "discount_amount",
    "balance",
)
_CURRENCY_KEYS = ("currency", "currency_code", "curr")


class NumericPrecisionScanner:
    """
    Usage:
        numeric = NumericPrecisionScanner(scanner)
        findings = await numeric.check(url, method, req_body, base_status, base_body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._resp_ok = getattr(scanner, "_response_indicates_success", None)
        self._reported: set[tuple] = set()

    async def check(
        self, url: str, method: str, req_body, base_status: int, base_body: str,
    ) -> list[Finding]:
        if not _HAS_FIELD_TYPING or not isinstance(req_body, dict):
            return []

        findings: list[Finding] = []
        fields = self._find_fields(req_body)
        if not fields:
            return findings

        for f in fields:
            key_sig = (self._normalise_path(url), f["path"])
            if key_sig in self._reported:
                continue

            finding = await self._test_precision(url, method, req_body, f)
            if not finding:
                finding = await self._test_scale_confusion(url, method, req_body, f)

            if finding:
                self._reported.add(key_sig)
                findings.append(finding)

        return findings

    async def _test_precision(self, url, method, req_body, f) -> Finding | None:
        ftype = infer_field_type(f["key"], f["value"])
        payloads = generate_precision_payloads(ftype, f["value"])
        for payload in payloads:
            mutated = self._mutate(req_body, f["path"], payload)
            status, resp_body = await self._fire(method, url, mutated)
            if not self._looks_ok(resp_body, status):
                continue

            reflected = self._extract_numeric(resp_body, f["key"])
            confirmed = reflected is not None and 0 <= reflected < 0.01
            confidence = 88 if confirmed else 55

            return self._build(
                url, method, f, payload,
                title=f"Sub-Cent Rounding Abuse — `{f['path']}`",
                severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                confidence=confidence, confirmed=confirmed,
                description=(
                    f"Field `{f['path']}` (original `{f['value']}`) at `{url}` "
                    f"accepted `{payload}` and returned a successful response."
                    + (
                        f" The response echoed `{f['key']}` as `{reflected}` — "
                        "effectively free — confirming the backend trusts the "
                        "submitted precision instead of rounding against a "
                        "server-computed price."
                        if confirmed else
                        " The response did not echo the field back, so the "
                        "actual charged amount needs manual confirmation "
                        "against the order/payment record."
                    )
                ),
                recommendation=(
                    "Compute and round all monetary totals server-side using a "
                    "fixed-point/decimal type at the point of charge, never "
                    "trusting a client-supplied fractional value directly."
                ),
                cwe="CWE-1339", cvss=9.0 if confirmed else 7.2,
                owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                category="Business Logic — Numeric Precision Abuse",
            )
        return None

    async def _test_scale_confusion(self, url, method, req_body, f) -> Finding | None:
        if is_minor_unit_field(f["key"]):
            payload = rescale_minor_unit_payload(f["value"])
            if payload is not None:
                mutated = self._mutate(req_body, f["path"], payload)
                status, resp_body = await self._fire(method, url, mutated)
                if self._looks_ok(resp_body, status):
                    reflected = self._extract_numeric(resp_body, f["key"])
                    confirmed = reflected is not None and abs(reflected - payload) < 0.01
                    return self._build(
                        url, method, f, payload,
                        title=f"Minor-Unit Scale Confusion — `{f['path']}`",
                        severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                        confidence=85 if confirmed else 55, confirmed=confirmed,
                        description=(
                            f"`{f['path']}` at `{url}` looks like a minor-unit "
                            f"(cents) field but accepted a major-unit-scaled "
                            f"value `{payload}` (original `{f['value']}`), "
                            "roughly 100x smaller — the backend appears to "
                            "trust client-asserted scale rather than enforcing "
                            "it server-side."
                        ),
                        recommendation=(
                            "Treat minor-unit amounts as an internal, "
                            "server-derived representation; never accept the "
                            "scale a client happens to submit."
                        ),
                        cwe="CWE-20", cvss=8.1 if confirmed else 6.8,
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        category="Business Logic — Unit/Currency Scale Confusion",
                    )

        sibling = self._find_sibling_currency(req_body, f["path"])
        if sibling:
            candidates = weaker_currency_candidates(sibling["value"])
            for candidate in candidates:
                mutated = self._mutate(req_body, sibling["path"], candidate)
                status, resp_body = await self._fire(method, url, mutated)
                if not self._looks_ok(resp_body, status):
                    continue
                reflected = self._extract_numeric(resp_body, f["key"])
                confirmed = reflected is not None and reflected == f["value"]
                return self._build(
                    url, method, f, f["value"],
                    title=f"Currency-Unit Confusion — `{f['path']}` / `{sibling['path']}`",
                    severity=Severity.CRITICAL if confirmed else Severity.HIGH,
                    confidence=80 if confirmed else 55, confirmed=confirmed,
                    description=(
                        f"Swapping `{sibling['path']}` from `{sibling['value']}` "
                        f"to `{candidate}` while leaving `{f['path']}` = "
                        f"`{f['value']}` unchanged at `{url}` was accepted. "
                        + (
                            f"The response still shows `{f['key']}` = "
                            f"`{reflected}`, meaning the same numeral is now "
                            "charged in a far weaker currency — a direct "
                            "value-loss bug."
                            if confirmed else
                            "Confirm manually whether the charge was actually "
                            "re-priced for the new currency."
                        )
                    ),
                    recommendation=(
                        "Recompute the charge server-side from a trusted price "
                        "list whenever the currency changes; never accept an "
                        "amount and a currency as independently client-supplied."
                    ),
                    cwe="CWE-20", cvss=8.3 if confirmed else 6.6,
                    owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    category="Business Logic — Unit/Currency Scale Confusion",
                )
        return None

    def _find_fields(self, obj, path: str = "") -> list[dict]:
        results: list[dict] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                sub_path = f"{path}.{k}" if path else k
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    if any(pk in k.lower() for pk in _PRICE_KEYS):
                        results.append({"path": sub_path, "key": k, "value": v})
                results.extend(self._find_fields(v, sub_path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                results.extend(self._find_fields(item, f"{path}[{i}]"))
        return results

    def _find_sibling_currency(self, obj, price_path: str) -> dict | None:
        parent_path = price_path.rsplit(".", 1)[0] if "." in price_path else ""
        node = obj
        if parent_path:
            for seg in parent_path.split("."):
                if isinstance(node, dict) and seg in node:
                    node = node[seg]
                else:
                    return None
        if not isinstance(node, dict):
            return None
        for k, v in node.items():
            if isinstance(v, str) and any(ck == k.lower() for ck in _CURRENCY_KEYS):
                full_path = f"{parent_path}.{k}" if parent_path else k
                return {"path": full_path, "key": k, "value": v}
        return None

    def _mutate(self, body: dict, path: str, new_val) -> dict:
        mutated = copy.deepcopy(body)
        node = mutated
        segments = path.split(".")
        for seg in segments[:-1]:
            m = re.match(r"^(.*)\[(\d+)\]$", seg)
            if m:
                node = node[m.group(1)][int(m.group(2))]
            else:
                node = node[seg]
        last = segments[-1]
        m = re.match(r"^(.*)\[(\d+)\]$", last)
        if m:
            node[m.group(1)][int(m.group(2))] = new_val
        else:
            node[last] = new_val
        return mutated

    async def _fire(self, method: str, url: str, mutated_body: dict) -> tuple[int, str]:
        try:
            status, _, resp_body, _ = await self._request(method, url, json=mutated_body)
        except Exception as e:
            if self._config.verbose:
                print(f"[!] NumericPrecisionScanner probe on {url}: {e}")
            return 0, ""
        return status, resp_body

    def _extract_numeric(self, body: str, key: str) -> float | None:
        try:
            import json
            data = json.loads(body)
        except (ValueError, TypeError):
            return None
        return self._dig(data, key)

    def _dig(self, obj, key: str) -> float | None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key and isinstance(v, (int, float)) and not isinstance(v, bool):
                    return float(v)
                found = self._dig(v, key)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = self._dig(item, key)
                if found is not None:
                    return found
        return None

    def _looks_ok(self, body: str, status: int) -> bool:
        if status not in (200, 201):
            return False
        if self._resp_ok:
            return self._resp_ok(body, status)
        return not looks_like_error(body, status)

    def _normalise_path(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc + parsed.path

    def _build(
        self, url, method, f, payload, title, severity, confidence, confirmed,
        description, recommendation, cwe, cvss, owasp, category,
    ) -> Finding:
        host = urlparse(url).netloc
        path = urlparse(url).path or "/"

        curl = (
            f'curl -sk -X {method} "{url}" -H "Authorization: Bearer <TOKEN>" '
            f'-H "Content-Type: application/json" '
            f'-d \'{{"{f["key"]}": {payload!r}}}\''
        )
        python_script = (
            "import requests\n\n"
            f'url = "{url}"\n'
            f'body = {{"{f["key"]}": {payload!r}}}\n'
            f'r = requests.request("{method}", url, json=body, '
            'headers={"Authorization": "Bearer <TOKEN>"})\n'
            "print(r.status_code)\n"
            "print(r.text[:500])\n"
        )
        burp = f"{method} {path} HTTP/1.1\nHost: {host}\nAuthorization: Bearer <TOKEN>\nContent-Type: application/json\nConnection: close\n\n"

        poc = ProofOfConcept(
            summary=title,
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=description,
            steps=[
                f"Send the mutated request above to `{url}`.",
                "Inspect the response for the echoed numeric field and "
                "cross-check it against any resulting order/payment record.",
            ],
        )

        finding = Finding(
            title=title,
            severity=severity,
            category=category,
            description=description,
            request={"method": method, "url": url, "field": f["path"], "payload": payload},
            response_summary=f"Field `{f['path']}` accepted tampered value `{payload}`",
            evidence=f"{f['path']} = {f['value']} → {payload} at {method} {url}",
            recommendation=recommendation,
            cwe=cwe, cvss=cvss, owasp=owasp,
            confirmed=confirmed, confidence=confidence,
            confidence_reasons=[title],
            endpoint=url, parameter=f["path"],
        )
        finding.poc = poc
        return finding

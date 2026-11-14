"""
BLFinder — core/analysis/second_order_tracker.py
Second-Order / Cross-Endpoint State Reflection Tracker

Every existing module tests one endpoint at a time: tamper a field, read
the same endpoint's response, decide. That misses the bug class a manual
hunter finds by "living in the app" — a value tampered at endpoint A that
never shows its effect there, only later, at an entirely different
endpoint B, because the backend trusted and stored the tampered state
instead of re-validating it on every read.

This tracker runs scanner-wide across the whole scan rather than per
endpoint:

  1. record_finding() — whenever any module confirms a tamper was
     accepted (mass assignment, state-machine abuse, price manipulation,
     coupon stacking, ...), the targeted field name and its origin
     endpoint are remembered. No fixed guess-list of "interesting field
     names" — only fields THIS scan already proved tamperable for THIS
     target are tracked, which is what keeps it from being noisy.

  2. observe_response() — called once per endpoint for every response
     the scanner sees for the rest of the scan. If a tracked field
     reappears with a non-trivial value on a DIFFERENT endpoint than the
     one it was tampered at, that is a candidate second-order leak.

  3. flush_findings() — call once, after the full scan's endpoint loop
     completes (observation needs to have seen every endpoint first),
     to turn surviving candidates into Findings.

Confidence is capped at MEDIUM/HIGH, never CRITICAL-by-default: this is
correlation, not a replayed proof. The description says so explicitly so
a reviewer manually confirms causation before treating it as confirmed.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept


_TRIVIAL_VALUES = (None, False, 0, "", "0", "false", "null", "none")


class SecondOrderTracker:
    """
    Usage (once per scan, not per endpoint):
        tracker = SecondOrderTracker()
        ... per confirmed finding:  tracker.record_finding(finding)
        ... per endpoint response:  tracker.observe_response(url, method, status, body)
        ... once, at the end:       findings = tracker.flush_findings()
    """

    def __init__(self):
        self._tracked: dict[str, list[dict]] = {}
        self._candidates: dict[tuple, dict] = {}

    def record_finding(self, finding: Finding) -> None:
        if not finding.confirmed or not finding.parameter or not finding.endpoint:
            return
        field = self._bare_field_name(finding.parameter)
        if not field:
            return
        origin = self._normalise_path(finding.endpoint)
        entries = self._tracked.setdefault(field, [])
        if not any(e["origin"] == origin for e in entries):
            entries.append({"origin": origin, "title": finding.title, "endpoint": finding.endpoint})

    def observe_response(self, url: str, method: str, status: int, body: str) -> None:
        if not self._tracked or status not in (200, 201) or not body:
            return
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return
        this_path = self._normalise_path(url)

        for field, origins in self._tracked.items():
            if any(o["origin"] == this_path for o in origins):
                continue
            value = self._dig(data, field)
            if value is None or value in _TRIVIAL_VALUES:
                continue
            key = (field, this_path)
            if key in self._candidates:
                continue
            self._candidates[key] = {
                "field": field, "endpoint": url, "value": value,
                "method": method, "origins": origins,
            }

    def flush_findings(self) -> list[Finding]:
        findings = [self._build(c) for c in self._candidates.values()]
        self._candidates.clear()
        return findings

    def _bare_field_name(self, parameter: str) -> str:
        last = re.split(r"[.\[]", parameter)[-1]
        return last.rstrip("]").strip()

    def _dig(self, obj, key: str):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key and not isinstance(v, (dict, list)):
                    return v
                found = self._dig(v, key)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = self._dig(item, key)
                if found is not None:
                    return found
        return None

    def _normalise_path(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc + parsed.path

    def _build(self, c: dict) -> Finding:
        origin_list = ", ".join(sorted({o["endpoint"] for o in c["origins"]}))
        origin_titles = "; ".join(sorted({o["title"] for o in c["origins"]}))

        title = f"Second-Order State Reflection — `{c['field']}` Crosses Endpoints"
        description = (
            f"`{c['field']}` was confirmed tamperable at `{origin_list}` "
            f"(via: {origin_titles}). Later in the same scan, `{c['field']}` "
            f"= `{c['value']}` was observed at a different endpoint — "
            f"`{c['method']} {c['endpoint']}` — which never had that value "
            f"tampered directly. This suggests the backend persisted the "
            f"tampered state from the first endpoint and another endpoint "
            f"is trusting it without re-validating on read. Confirm "
            f"manually that the value at the second endpoint is actually "
            f"caused by the first tamper and not a coincidentally similar, "
            f"legitimate value."
        )

        poc = ProofOfConcept(
            summary=title,
            curl_command=(
                f'curl -sk "{c["endpoint"]}" -H "Authorization: Bearer <TOKEN>"'
            ),
            python_script=(
                "import requests\n\n"
                f'r = requests.get("{c["endpoint"]}", '
                'headers={"Authorization": "Bearer <TOKEN>"})\n'
                f'print(r.json().get("{c["field"]}"))\n'
            ),
            burp_request="",
            expected_result=(
                f"`{c['field']}` = `{c['value']}` reappearing at this endpoint "
                "after being tampered elsewhere in the scan."
            ),
            steps=[
                f"Re-run the original tamper at `{origin_list}`.",
                f"Then read `{c['endpoint']}` fresh and confirm `{c['field']}` "
                f"still reflects the tampered value.",
                "If confirmed, this is a stored/second-order business-logic "
                "flaw, not a per-request validation gap.",
            ],
        )

        finding = Finding(
            title=title,
            severity=Severity.HIGH,
            category="Business Logic — Second-Order State Reflection",
            description=description,
            request={"method": c["method"], "url": c["endpoint"], "field": c["field"]},
            response_summary=f"`{c['field']}` = `{c['value']}` at {c['endpoint']}",
            evidence=(
                f"Tampered at {origin_list} → observed `{c['field']}` = "
                f"`{c['value']}` at {c['method']} {c['endpoint']}"
            ),
            recommendation=(
                "Re-validate authorization and business state on every read, "
                "not only at the endpoint where a value was originally set."
            ),
            cwe="CWE-669", cvss=7.4,
            owasp="API1:2023 Broken Object Level Authorization",
            confirmed=False, confidence=58,
            confidence_reasons=["cross-endpoint correlation, not independently replayed"],
            endpoint=c["endpoint"], parameter=c["field"],
        )
        finding.poc = poc
        return finding

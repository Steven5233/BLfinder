"""
BLFinder v3.1 — core/reporting/hackerone_formatter.py
HackerOne-Ready Report Formatter

Generates copy-paste ready markdown for HackerOne (and Bugcrowd) submissions.
Every field uses real data from EvidencePackage — no placeholders.

Output sections match exactly what HackerOne reviewers expect:
  - Title: specific endpoint + vulnerability type
  - Severity: with CVSS string
  - Summary: 2-3 sentence plain English
  - Steps to Reproduce: numbered, with exact curl commands
  - Proof: actual request/response pairs
  - Impact: what data was actually accessed
  - Remediation: specific, actionable
  - References: CWE + OWASP
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import Finding, Severity
from ..evidence.capture import EvidencePackage, RequestResponsePair


class HackerOneFormatter:
    """
    Formats a Finding + EvidencePackage into a HackerOne submission.

    Usage:
        formatter = HackerOneFormatter()
        report = formatter.format(finding, evidence_package)
        print(report.full_markdown)     # Paste into HackerOne
        print(report.title)             # Paste into title field
    """

    def format(self, finding: Finding, pkg: EvidencePackage) -> "H1Report":
        return H1Report(finding=finding, pkg=pkg)


class H1Report:
    """
    A complete HackerOne report for a single Finding.
    All fields are pre-formatted strings ready to paste.
    """

    def __init__(self, finding: Finding, pkg: EvidencePackage):
        self.finding = finding
        self.pkg     = pkg
        self._build()

    def _build(self):
        f   = self.finding
        pkg = self.pkg

        # ── Title ─────────────────────────────────────────────────────────────
        # Use real endpoint URL in title
        endpoint_path = _url_to_path(pkg.endpoint) if pkg.endpoint else f.endpoint
        self.title = f"{f.severity.value}: {_vuln_short(f.category)} on {endpoint_path}"

        # ── Severity ──────────────────────────────────────────────────────────
        self.severity = f.severity.value.lower()
        self.cvss_string = self._build_cvss(f)

        # ── Summary ───────────────────────────────────────────────────────────
        self.summary = self._build_summary(f, pkg)

        # ── Steps to Reproduce ────────────────────────────────────────────────
        self.steps = self._build_steps(f, pkg)

        # ── Proof ─────────────────────────────────────────────────────────────
        self.proof_section = self._build_proof(pkg)

        # ── Impact ────────────────────────────────────────────────────────────
        self.impact_section = self._build_impact(f, pkg)

        # ── Remediation ───────────────────────────────────────────────────────
        self.remediation_section = self._build_remediation(f)

        # ── References ────────────────────────────────────────────────────────
        self.references_section = self._build_references(f)

        # ── Full Markdown ──────────────────────────────────────────────────────
        self.full_markdown = self._assemble()

    def _build_summary(self, f: Finding, pkg: EvidencePackage) -> str:
        endpoint = pkg.endpoint or f.endpoint or "[endpoint]"
        vuln_type = _vuln_long(f.category)
        impact_hint = ""

        if pkg.impact_report and pkg.impact_report.sensitive_items:
            top = pkg.impact_report.sensitive_items[0]
            impact_hint = f" The response contained {top.description.lower()}."

        confirmed_str = (
            " Cross-user confirmation verified the vulnerability is exploitable by any authenticated user."
            if pkg.confirmed else ""
        )

        return (
            f"A {vuln_type} vulnerability exists at `{endpoint}`. "
            f"An authenticated user can access resources or functionality they should not have access to "
            f"by modifying {_parameter_hint(f.parameter)}.{impact_hint}{confirmed_str}"
        )

    def _build_steps(self, f: Finding, pkg: EvidencePackage) -> str:
        lines = []
        step = 1

        lines.append(f"{step}. **Authenticate** and obtain a valid session token for a regular (non-admin) user account.")
        step += 1

        if pkg.baseline:
            lines.append(f"{step}. **Send the baseline request** to confirm normal behavior:")
            lines.append("```bash")
            lines.append(pkg.baseline.request.to_curl())
            lines.append("```")
            lines.append(f"   _Expected response: HTTP {pkg.baseline.response.status}_")
            lines.append("")
            step += 1

        if pkg.attack:
            attack_note = f.request.get("note", "") if isinstance(f.request, dict) else ""
            lines.append(f"{step}. **Send the exploit request** ({attack_note or 'modified request'}):")
            lines.append("```bash")
            lines.append(pkg.attack.request.to_curl())
            lines.append("```")
            lines.append(f"   _Expected response: HTTP {pkg.attack.response.status} — observe the difference_")
            lines.append("")
            step += 1

        if pkg.cross_user:
            lines.append(f"{step}. **Cross-user confirmation** (optional — requires second account):")
            lines.append("```bash")
            lines.append(pkg.cross_user.request.to_curl())
            lines.append("```")
            lines.append("")
            step += 1

        if pkg.diff_report and pkg.diff_report.field_diffs:
            lines.append(
                f"{step}. **Observe** the difference in the response — "
                f"see the field-level diff in the Proof section below."
            )
        else:
            lines.append(f"{step}. **Observe** that the attack response differs from the baseline.")

        return "\n".join(lines)

    def _build_proof(self, pkg: EvidencePackage) -> str:
        lines = []

        # Baseline pair
        if pkg.baseline:
            lines.append("### Baseline Request (Normal Behavior)")
            lines.append("```http")
            lines.append(pkg.baseline.request.to_burp_format())
            lines.append("```")
            lines.append("")
            lines.append("**Baseline Response:**")
            lines.append("```http")
            resp_preview = pkg.baseline.response.body.strip()[:500]
            lines.append(pkg.baseline.response.to_burp_format()[:800])
            lines.append("```")
            lines.append("")

        # Attack pair
        if pkg.attack:
            lines.append("### Attack Request (Exploit)")
            lines.append("```http")
            lines.append(pkg.attack.request.to_burp_format())
            lines.append("```")
            lines.append("")
            lines.append("**Attack Response:**")
            lines.append("```http")
            lines.append(pkg.attack.response.to_burp_format()[:800])
            lines.append("```")
            lines.append("")

        # Field-level diff
        if pkg.diff_report and pkg.diff_report.is_meaningfully_different:
            lines.append("### Response Difference (Field-Level)")
            lines.append("")
            lines.append(pkg.diff_report.markdown_table)
            lines.append("")

        # Cross-user confirmation
        if pkg.cross_user:
            lines.append("### Cross-User Confirmation")
            lines.append(
                f"User 2's token was used to access a resource belonging to User 1. "
                f"The server returned HTTP {pkg.cross_user.response.status}."
            )
            lines.append("```http")
            lines.append(pkg.cross_user.request.to_burp_format())
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def _build_impact(self, f: Finding, pkg: EvidencePackage) -> str:
        lines = []

        if pkg.impact_report and pkg.impact_report.h1_impact_section:
            lines.append(pkg.impact_report.h1_impact_section)
            lines.append("")

        # Generic impact based on category
        cat = f.category.lower()
        if "idor" in cat or "bola" in cat:
            lines.append(
                "An attacker with a standard user account can access, modify, or delete "
                "resources belonging to any other user by enumerating object IDs. "
                "This affects all users of the application."
            )
        elif "price" in cat or "quantity" in cat:
            lines.append(
                "An attacker can purchase items at arbitrary prices (including free or negative cost), "
                "potentially causing direct financial loss to the company."
            )
        elif "race" in cat:
            lines.append(
                "An attacker can exploit the race condition to redeem single-use vouchers or credits "
                "multiple times, causing financial loss or unauthorized resource acquisition."
            )
        elif "privilege" in cat or "bfla" in cat or "mass" in cat:
            lines.append(
                "An attacker can escalate their own privileges to administrator level, "
                "gaining access to all administrative functionality and all user data."
            )
        elif "jwt" in cat:
            lines.append(
                "An attacker can forge arbitrary JWT claims and impersonate any user, "
                "including administrators, without knowing the signing secret."
            )

        if f.confirmed:
            lines.append("")
            lines.append(
                "**This vulnerability has been independently confirmed** with two separate user accounts. "
                "Exploitation requires only a valid user account — no special privileges."
            )

        return "\n".join(lines)

    def _build_remediation(self, f: Finding) -> str:
        specific = f.recommendation if f.recommendation else ""
        category = f.category.lower()

        general = ""
        if "idor" in category or "bola" in category:
            general = (
                "Implement object-level authorization checks that verify the requesting user "
                "owns or has been explicitly granted access to the requested resource. "
                "These checks must occur server-side on every request, not just at login."
            )
        elif "mass" in category:
            general = (
                "Use an explicit allowlist of fields that users are permitted to set. "
                "Never pass raw request bodies directly to ORM update methods (e.g. `update(params)`)."
            )
        elif "price" in category:
            general = (
                "All prices must be computed server-side from a trusted product catalog. "
                "Client-submitted price values must never be accepted or used in calculations."
            )
        elif "jwt" in category:
            general = (
                "Explicitly configure the JWT library to only accept a specific list of algorithms. "
                "Never accept `alg: none`. Verify signatures using a strong, server-stored secret."
            )

        parts = []
        if specific:
            parts.append(f"**Specific Fix:** {specific}")
        if general:
            parts.append(f"**General Guidance:** {general}")

        return "\n\n".join(parts)

    def _build_references(self, f: Finding) -> str:
        refs = []
        if f.cwe:
            cwe_num = f.cwe.replace("CWE-", "")
            refs.append(f"- [{f.cwe}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)")
        if f.owasp:
            refs.append(f"- [OWASP API Security — {f.owasp}](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)")
        refs.append("- [PortSwigger Web Security Academy](https://portswigger.net/web-security)")
        return "\n".join(refs)

    def _build_cvss(self, f: Finding) -> str:
        sev_scores = {
            Severity.CRITICAL: "9.1",
            Severity.HIGH:     "8.1",
            Severity.MEDIUM:   "5.3",
            Severity.LOW:      "3.7",
            Severity.INFO:     "0.0",
        }
        return sev_scores.get(f.severity, str(f.cvss))

    def _assemble(self) -> str:
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        return f"""# {self.title}

**Severity:** {self.severity.title()} ({self.cvss_string})
**Date Found:** {scan_date}
**Endpoint:** `{self.pkg.endpoint}`
**Confidence:** {self.pkg.confidence}%{' ✓ CONFIRMED' if self.pkg.confirmed else ''}

---

## Summary

{self.summary}

---

## Steps to Reproduce

{self.steps}

---

## Proof

{self.proof_section}

---

## Impact

{self.impact_section}

---

## Remediation

{self.remediation_section}

---

## References

{self.references_section}

---
_Report generated by BLFinder v3.1 — {scan_date}_
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _url_to_path(url: str) -> str:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.path or url


def _vuln_short(category: str) -> str:
    mapping = {
        "idor": "IDOR", "bola": "BOLA", "price": "Price Manipulation",
        "race": "Race Condition", "mass": "Mass Assignment",
        "jwt": "JWT Bypass", "privilege": "Privilege Escalation",
        "workflow": "Workflow Bypass", "state": "State Machine Abuse",
        "coupon": "Coupon Abuse", "graphql": "GraphQL Vulnerability",
    }
    cat_lower = category.lower()
    for key, val in mapping.items():
        if key in cat_lower:
            return val
    return "Business Logic Flaw"


def _vuln_long(category: str) -> str:
    mapping = {
        "idor": "Broken Object Level Authorization (IDOR/BOLA)",
        "bola": "Broken Object Level Authorization (IDOR/BOLA)",
        "price": "price manipulation",
        "race": "race condition",
        "mass": "mass assignment",
        "jwt": "JWT authentication bypass",
        "privilege": "privilege escalation",
        "workflow": "workflow bypass",
        "state": "state machine abuse",
        "coupon": "coupon/discount abuse",
        "graphql": "GraphQL security",
    }
    cat_lower = category.lower()
    for key, val in mapping.items():
        if key in cat_lower:
            return val
    return "business logic"


def _parameter_hint(parameter: str) -> str:
    if not parameter:
        return "request parameters"
    if "path" in parameter:
        return f"the ID in the URL path (`{parameter}`)"
    if "body" in parameter:
        return f"the `{parameter.replace('body.', '')}` field in the request body"
    if "header" in parameter:
        return f"the `{parameter.replace('header:', '')}` request header"
    return f"the `{parameter}` parameter"

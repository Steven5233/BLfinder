"""
BLFinder v3.1 — core/evidence/diff_engine.py
Response Differential Analysis — Field-Level Diff

Produces a structured diff between two HTTP responses that:
  1. Shows exactly which JSON fields changed
  2. Identifies newly exposed fields (key in attack, absent in baseline)
  3. Generates a human-readable table for reports
  4. Provides a one-line summary for the Finding.evidence field
  5. Flags sensitive field changes with higher importance

This replaces the naive difflib string comparison that caused false positives
by understanding JSON structure rather than treating responses as opaque strings.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .capture import ResponseRecord


class ChangeType(str, Enum):
    ADDED   = "ADDED"       
    REMOVED = "REMOVED"     
    CHANGED = "CHANGED"     
    SAME    = "SAME"        


@dataclass
class FieldDiff:
    """Diff result for a single field."""
    field_path: str                     
    change_type: ChangeType
    baseline_value: Any = None
    attack_value: Any = None
    is_sensitive: bool = False          
    is_privileged: bool = False         
    security_impact: str = ""          

    @property
    def display_baseline(self) -> str:
        return _format_value(self.baseline_value)

    @property
    def display_attack(self) -> str:
        return _format_value(self.attack_value)


@dataclass
class DiffReport:
    """
    Complete diff between baseline and attack responses.
    The main output of DiffEngine.compare().
    """

    field_diffs: list[FieldDiff] = field(default_factory=list)


    added_fields: list[FieldDiff] = field(default_factory=list)
    removed_fields: list[FieldDiff] = field(default_factory=list)
    changed_fields: list[FieldDiff] = field(default_factory=list)
    sensitive_changes: list[FieldDiff] = field(default_factory=list)
    privileged_changes: list[FieldDiff] = field(default_factory=list)


    baseline_size: int = 0
    attack_size: int = 0
    size_delta: int = 0
    size_delta_pct: float = 0.0


    baseline_status: int = 0
    attack_status: int = 0
    status_changed: bool = False


    baseline_count: int = 0
    attack_count: int = 0
    count_delta: int = 0


    raw_diff_lines: list[str] = field(default_factory=list)


    baseline_is_json: bool = False
    attack_is_json: bool = False


    is_meaningfully_different: bool = False
    similarity_score: float = 1.0       

    @property
    def one_line_summary(self) -> str:
        """
        Single-line summary for the Finding.evidence field.
        Uses real field names and values, not placeholders.
        """
        parts = []

        if self.status_changed:
            parts.append(f"Status {self.baseline_status}→{self.attack_status}")

        if self.size_delta != 0:
            direction = "larger" if self.size_delta > 0 else "smaller"
            parts.append(f"Response {abs(self.size_delta)}B {direction}")

        if self.count_delta != 0:
            parts.append(f"Record count {self.baseline_count}→{self.attack_count}")

        if self.privileged_changes:
            top = self.privileged_changes[0]
            parts.append(
                f"Privilege field `{top.field_path}`: "
                f"{top.display_baseline}→{top.display_attack}"
            )
        elif self.sensitive_changes:
            top = self.sensitive_changes[0]
            parts.append(f"Sensitive field `{top.field_path}` newly exposed")

        if self.added_fields:
            field_names = [d.field_path for d in self.added_fields[:3]]
            parts.append(f"New fields: {', '.join(field_names)}")

        if self.changed_fields and not self.privileged_changes:
            top = self.changed_fields[0]
            parts.append(
                f"`{top.field_path}`: {top.display_baseline}→{top.display_attack}"
            )

        return " | ".join(parts) if parts else "Responses differ (structural)"

    @property
    def markdown_table(self) -> str:
        """
        Generate a markdown table showing all changed fields.
        Ready to paste into HackerOne report.
        """
        if not self.field_diffs:
            return "_No field-level differences detected (non-JSON response)_"

        rows = [
            "| Field | Baseline | Attack | Change | Impact |",
            "|-------|----------|--------|--------|--------|",
        ]
        for d in self.field_diffs:
            if d.change_type == ChangeType.SAME:
                continue
            impact_icon = "🔴" if d.is_privileged else "🟠" if d.is_sensitive else "🟡"
            impact = d.security_impact or d.change_type.value
            rows.append(
                f"| `{d.field_path}` "
                f"| `{d.display_baseline[:30]}` "
                f"| `{d.display_attack[:30]}` "
                f"| {d.change_type.value} "
                f"| {impact_icon} {impact} |"
            )
        return "\n".join(rows)

    @property
    def html_table(self) -> str:
        """Generate an HTML table for the evidence report."""
        if not self.field_diffs:
            return "<p><em>No field-level differences (non-JSON response)</em></p>"

        rows = []
        for d in self.field_diffs:
            if d.change_type == ChangeType.SAME:
                continue
            color = (
                "#ff2d55" if d.is_privileged
                else "#ff9f0a" if d.is_sensitive
                else "#ffd60a"
            )
            rows.append(
                f"<tr>"
                f"<td><code>{_esc(d.field_path)}</code></td>"
                f"<td><code>{_esc(d.display_baseline[:40])}</code></td>"
                f"<td><code style='color:{color}'>{_esc(d.display_attack[:40])}</code></td>"
                f"<td>{d.change_type.value}</td>"
                f"<td>{_esc(d.security_impact or '')}</td>"
                f"</tr>"
            )

        if not rows:
            return "<p><em>All differing fields are volatile (timestamps/nonces)</em></p>"

        return (
            "<table>"
            "<thead><tr>"
            "<th>Field</th><th>Baseline</th><th>Attack</th>"
            "<th>Change</th><th>Impact</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
        )




_SENSITIVE_KEYWORDS = {
    "password", "secret", "token", "key", "hash", "salt",
    "ssn", "social_security", "national_id", "passport",
    "credit_card", "card_number", "cvv", "bank", "account_number", "routing",
    "salary", "income", "revenue",
    "dob", "date_of_birth", "birthdate",
    "phone", "mobile", "address", "zip", "postal",
    "ip_address", "location", "lat", "lng", "coordinates",
    "private", "internal", "confidential",
}

_PRIVILEGED_KEYWORDS = {
    "role", "roles", "admin", "is_admin", "is_staff", "is_superuser",
    "permissions", "scopes", "permission",
    "account_type", "tier", "plan", "subscription",
    "verified", "approved", "kyc",
    "access_level", "trust_level", "group",
}

_VOLATILE_KEYWORDS = {
    "timestamp", "created_at", "updated_at", "expires_at",
    "last_seen", "modified_at", "date", "_at", "_time",
    "request_id", "trace_id", "nonce", "jti", "session_id",
    "etag", "age", "cache",
}


def _is_volatile(field_name: str) -> bool:
    name_lower = field_name.lower()
    return (
        any(name_lower.endswith(v) for v in ("_at", "_time", "_date", "_id"))
        or any(v in name_lower for v in _VOLATILE_KEYWORDS)
    )


def _is_sensitive(field_name: str) -> bool:
    name_lower = field_name.lower()
    return any(kw in name_lower for kw in _SENSITIVE_KEYWORDS)


def _is_privileged(field_name: str) -> bool:
    name_lower = field_name.lower()
    return any(kw in name_lower for kw in _PRIVILEGED_KEYWORDS)


def _security_impact(fd: FieldDiff) -> str:
    if fd.is_privileged:
        if fd.change_type == ChangeType.CHANGED:
            return f"PRIVILEGE ESCALATION: {fd.display_baseline}→{fd.display_attack}"
        if fd.change_type == ChangeType.ADDED:
            return "PRIVILEGE FIELD EXPOSED"
    if fd.is_sensitive:
        if fd.change_type == ChangeType.ADDED:
            return "SENSITIVE DATA EXPOSURE"
        if fd.change_type == ChangeType.CHANGED:
            return "SENSITIVE DATA CHANGED"
    if fd.change_type == ChangeType.ADDED:
        return "NEW FIELD EXPOSED"
    if fd.change_type == ChangeType.CHANGED:
        return "VALUE CHANGED"
    return ""


class DiffEngine:
    """
    JSON-aware differential analysis between two HTTP responses.

    Usage:
        report = DiffEngine.compare(baseline_response, attack_response)
        print(report.one_line_summary)
        print(report.markdown_table)
    """

    @classmethod
    def compare(
        cls,
        baseline: ResponseRecord,
        attack: ResponseRecord,
    ) -> DiffReport:
        """
        Main entry point. Compare two responses and return a DiffReport.
        """
        report = DiffReport()
        report.baseline_status = baseline.status
        report.attack_status   = attack.status
        report.status_changed  = baseline.status != attack.status
        report.baseline_size   = len(baseline.body)
        report.attack_size     = len(attack.body)
        report.size_delta      = report.attack_size - report.baseline_size
        report.size_delta_pct  = (
            abs(report.size_delta) / max(report.baseline_size, 1)
        )


        base_data   = _safe_parse(baseline.body)
        attack_data = _safe_parse(attack.body)
        report.baseline_is_json = base_data is not None
        report.attack_is_json   = attack_data is not None

        if base_data is not None and attack_data is not None:

            cls._deep_compare(report, base_data, attack_data, prefix="")
            cls._categorise(report)


            if isinstance(base_data, list) and isinstance(attack_data, list):
                report.baseline_count = len(base_data)
                report.attack_count   = len(attack_data)
                report.count_delta    = report.attack_count - report.baseline_count

        else:

            report.raw_diff_lines = list(
                difflib.unified_diff(
                    baseline.body.splitlines(),
                    attack.body.splitlines(),
                    fromfile="baseline",
                    tofile="attack",
                    lineterm="",
                    n=3,
                )
            )


        report.similarity_score = difflib.SequenceMatcher(
            None, baseline.body[:3000], attack.body[:3000]
        ).ratio()


        report.is_meaningfully_different = (
            report.status_changed
            or bool(report.added_fields)
            or bool(report.changed_fields)
            or bool(report.privileged_changes)
            or report.count_delta != 0
            or (report.size_delta_pct > 0.15 and abs(report.size_delta) > 50)
        )

        return report

    @classmethod
    def _deep_compare(
        cls,
        report: DiffReport,
        base: Any,
        attack: Any,
        prefix: str,
        depth: int = 0,
    ):
        """Recursively compare two JSON structures."""
        if depth > 6:
            return


        if isinstance(base, dict) and isinstance(attack, dict):
            for envelope in ("data", "result", "response", "payload"):
                if envelope in base and envelope in attack and len(base) <= 3:
                    base   = base[envelope]
                    attack = attack[envelope]
                    break

        if isinstance(base, dict) and isinstance(attack, dict):
            all_keys = set(base.keys()) | set(attack.keys())
            for key in sorted(all_keys):
                path = f"{prefix}.{key}" if prefix else key

                if _is_volatile(key):
                    continue    

                if key in base and key in attack:
                    if base[key] == attack[key]:
                        report.field_diffs.append(FieldDiff(
                            field_path=path,
                            change_type=ChangeType.SAME,
                            baseline_value=base[key],
                            attack_value=attack[key],
                        ))
                    elif isinstance(base[key], dict) and isinstance(attack[key], dict):
                        cls._deep_compare(report, base[key], attack[key], path, depth + 1)
                    elif isinstance(base[key], list) and isinstance(attack[key], list):
                        cls._compare_lists(report, base[key], attack[key], path, depth)
                    else:
                        fd = FieldDiff(
                            field_path=path,
                            change_type=ChangeType.CHANGED,
                            baseline_value=base[key],
                            attack_value=attack[key],
                            is_sensitive=_is_sensitive(key),
                            is_privileged=_is_privileged(key),
                        )
                        fd.security_impact = _security_impact(fd)
                        report.field_diffs.append(fd)

                elif key in attack:
                    fd = FieldDiff(
                        field_path=path,
                        change_type=ChangeType.ADDED,
                        baseline_value=None,
                        attack_value=attack[key],
                        is_sensitive=_is_sensitive(key),
                        is_privileged=_is_privileged(key),
                    )
                    fd.security_impact = _security_impact(fd)
                    report.field_diffs.append(fd)

                else:   
                    fd = FieldDiff(
                        field_path=path,
                        change_type=ChangeType.REMOVED,
                        baseline_value=base[key],
                        attack_value=None,
                    )
                    report.field_diffs.append(fd)

        elif isinstance(base, list) and isinstance(attack, list):
            cls._compare_lists(report, base, attack, prefix, depth)

        else:

            if base != attack:
                fd = FieldDiff(
                    field_path=prefix or "root",
                    change_type=ChangeType.CHANGED,
                    baseline_value=base,
                    attack_value=attack,
                )
                report.field_diffs.append(fd)

    @classmethod
    def _compare_lists(
        cls,
        report: DiffReport,
        base: list,
        attack: list,
        prefix: str,
        depth: int,
    ):
        """Compare two lists — note count difference and compare first items."""
        if len(base) != len(attack):
            fd = FieldDiff(
                field_path=prefix,
                change_type=ChangeType.CHANGED,
                baseline_value=f"[{len(base)} items]",
                attack_value=f"[{len(attack)} items]",
                is_sensitive=_is_sensitive(prefix),
            )
            fd.security_impact = (
                f"List grew from {len(base)} to {len(attack)} items"
                if len(attack) > len(base)
                else f"List shrank from {len(base)} to {len(attack)} items"
            )
            report.field_diffs.append(fd)


        if base and attack and isinstance(base[0], dict) and isinstance(attack[0], dict):
            cls._deep_compare(report, base[0], attack[0], f"{prefix}[0]", depth + 1)

    @classmethod
    def _categorise(cls, report: DiffReport):
        """Populate the categorised lists from field_diffs."""
        for fd in report.field_diffs:
            if fd.change_type == ChangeType.SAME:
                continue
            if fd.change_type == ChangeType.ADDED:
                report.added_fields.append(fd)
            elif fd.change_type == ChangeType.REMOVED:
                report.removed_fields.append(fd)
            elif fd.change_type == ChangeType.CHANGED:
                report.changed_fields.append(fd)
            if fd.is_sensitive:
                report.sensitive_changes.append(fd)
            if fd.is_privileged:
                report.privileged_changes.append(fd)




def _safe_parse(body: str) -> Any:
    if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
        return None
    body = body.strip()

    import re
    jsonp = re.match(r'^\w+\((.*)\);?$', body, re.DOTALL)
    if jsonp:
        body = jsonp.group(1)
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def _format_value(val: Any) -> str:
    if val is None:
        return "[absent]"
    if isinstance(val, str):
        return f'"{val[:40]}"' if len(val) <= 40 else f'"{val[:37]}..."'
    if isinstance(val, (dict, list)):
        preview = json.dumps(val, separators=(",", ":"))
        return preview[:40] + "..." if len(preview) > 40 else preview
    return str(val)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

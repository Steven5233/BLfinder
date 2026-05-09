"""
BLFinder v3.1 — core/reporter.py
Report Generator — delegates to evidence_report.py for HTML
"""

import json
from datetime import datetime
from dataclasses import asdict
from .models import Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

ANSI = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[1;33m",
    "MEDIUM":   "\033[1;34m", "LOW":  "\033[1;32m",
    "INFO":     "\033[1;36m", "RESET": "\033[0m",
    "BOLD":     "\033[1m",    "DIM":   "\033[2m",
    "GREEN":    "\033[1;32m",
}


def print_terminal_summary(findings: list[Finding], config: dict):
    total  = len(findings)
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    print(f"\n{ANSI['BOLD']}{'─'*65}{ANSI['RESET']}")
    print(f"{ANSI['BOLD']} BLFinder v3.1 — Scan Complete{ANSI['RESET']}")
    print(f" Target     : {config.get('target_url', 'N/A')}")
    print(f" Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*65}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        if count > 0:
            print(f"  {ANSI[sev]}{sev:<10}{ANSI['RESET']} {count}")
    print(f"  {'TOTAL':<10} {total}")
    print(f"{'─'*65}\n")

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity))
    for i, f in enumerate(sorted_findings, 1):
        color     = ANSI[f.severity.value]
        confirmed = f" {ANSI['GREEN']}✓ CONFIRMED{ANSI['RESET']}" if f.confirmed else ""
        confidence = getattr(f, "confidence", 0)
        endpoint  = getattr(f, "endpoint", "") or ""

        print(f"{color}[{f.severity.value}]{ANSI['RESET']} {i}. {f.title}{confirmed}")
        if endpoint:
            print(f"  {ANSI['DIM']}Endpoint   : {endpoint}{ANSI['RESET']}")
        print(f"  {ANSI['DIM']}Category   : {f.category}{ANSI['RESET']}")
        print(f"  {ANSI['DIM']}CWE/OWASP  : {f.cwe} / {f.owasp}{ANSI['RESET']}")
        print(f"  {ANSI['DIM']}Confidence : {confidence}%{ANSI['RESET']}")
        print(f"  Evidence   : {f.evidence[:120]}")

        # Show if evidence package is attached
        pkg = getattr(f, "evidence_package", None)
        if pkg and pkg.has_sensitive_data:
            print(f"  {ANSI['GREEN']}Sensitive  : {pkg.sensitive_data_preview}{ANSI['RESET']}")

        if getattr(f, "poc", None) and f.poc.summary:
            print(f"  PoC        : {ANSI['GREEN']}{f.poc.summary}{ANSI['RESET']}")
        print()


def generate_html_report(findings: list[Finding], config: dict, output_path: str = "report.html") -> str:
    """
    v3.1: Delegates to EvidenceReportGenerator for full evidence tabs.
    """
    try:
        from .reporting.evidence_report import EvidenceReportGenerator
        return EvidenceReportGenerator().generate(findings, output_path, config)
    except ImportError:
        # Fallback to basic HTML if reporting module not available
        return _basic_html_report(findings, config, output_path)


def generate_json_report(findings: list[Finding], config: dict, output_path: str = "report.json") -> str:
    data = {
        "meta": {
            "tool":       "BLFinder",
            "version":    "3.1",
            "target":     config.get("target_url", ""),
            "scan_date":  datetime.now().isoformat(),
        },
        "summary": _build_summary(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    with open(output_path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"[+] JSON report → {output_path}")
    return output_path


def generate_markdown_report(findings: list[Finding], config: dict, output_path: str = "report.md") -> str:
    """
    v3.1: Each finding generates a HackerOne-ready section if evidence package is attached.
    """
    summary = _build_summary(findings)
    lines   = [
        "# BLFinder v3.1 — Business Logic Flaw Report",
        f"**Target:** {config.get('target_url', 'N/A')}  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {summary.get(sev, 0)} |")
    lines += ["", f"**Total:** {summary['total']}", "", "---", "## Findings", ""]

    for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)), 1):
        confirmed = " ✓ CONFIRMED" if f.confirmed else ""
        confidence = getattr(f, "confidence", 0)
        endpoint   = getattr(f, "endpoint", "") or f.request.get("url", "")

        lines += [
            f"### {i}. [{f.severity.value}]{confirmed} {f.title}",
            f"**Endpoint:** `{endpoint}`  ",
            f"**Category:** {f.category}  ",
            f"**CWE:** {f.cwe} | **CVSS:** {f.cvss} | **OWASP:** {f.owasp}  ",
            f"**Confidence:** {confidence}%  ",
            "",
        ]

        # Use HackerOne formatter if evidence package is available
        pkg = getattr(f, "evidence_package", None)
        if pkg:
            try:
                from .reporting.hackerone_formatter import HackerOneFormatter
                h1 = HackerOneFormatter().format(f, pkg)
                lines.append(h1.full_markdown)
            except ImportError:
                lines += [
                    f"**Description:** {f.description}",
                    "",
                    "**Evidence:**",
                    f"```\n{f.evidence}\n```",
                    "",
                    f"**Recommendation:** {f.recommendation}",
                ]
        else:
            lines += [
                f"**Description:** {f.description}",
                "",
                "**Evidence:**",
                f"```\n{f.evidence}\n```",
                "",
                f"**Recommendation:** {f.recommendation}",
            ]

        lines += ["", "---", ""]

    with open(output_path, "w") as fh:
        fh.write("\n".join(lines))
    print(f"[+] Markdown report → {output_path}")
    return output_path


def generate_hackerone_report(
    finding: Finding,
    output_path: str,
) -> str:
    """
    NEW in v3.1: Generate a single-finding HackerOne submission file.
    """
    pkg = getattr(finding, "evidence_package", None)
    if not pkg:
        print(f"[!] No evidence package on finding — cannot generate HackerOne report")
        return ""

    try:
        from .reporting.hackerone_formatter import HackerOneFormatter
        h1 = HackerOneFormatter().format(finding, pkg)
        with open(output_path, "w") as fh:
            fh.write(h1.full_markdown)
        print(f"[+] HackerOne report → {output_path}")
        return output_path
    except ImportError as e:
        print(f"[!] HackerOne formatter not available: {e}")
        return ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_summary(findings: list[Finding]) -> dict:
    s = {"total": len(findings)}
    for f in findings:
        s[f.severity.value] = s.get(f.severity.value, 0) + 1
    return s


def _finding_to_dict(f: Finding) -> dict:
    d = {}
    for field_name in [
        "title", "severity", "category", "description",
        "request", "response_summary", "evidence", "recommendation",
        "cwe", "cvss", "owasp", "confirmed",
    ]:
        val = getattr(f, field_name, None)
        d[field_name] = val.value if hasattr(val, "value") else val

    d["confidence"]  = getattr(f, "confidence", 0)
    d["endpoint"]    = getattr(f, "endpoint", "")
    d["parameter"]   = getattr(f, "parameter", "")

    # Include evidence package summary if available
    pkg = getattr(f, "evidence_package", None)
    if pkg:
        d["evidence_package"] = {
            "endpoint":        pkg.endpoint,
            "scan_timestamp":  pkg.scan_timestamp,
            "confirmed":       pkg.confirmed,
            "has_sensitive":   pkg.has_sensitive_data,
            "sensitive_data":  pkg.sensitive_data_preview,
            "verified_curl":   pkg.verified_curl,
            "diff_summary":    pkg.diff_report.one_line_summary if pkg.diff_report else "",
            "impact_score":    pkg.impact_report.impact_score if pkg.impact_report else 0,
            "impact_statement": pkg.impact_report.impact_statement if pkg.impact_report else "",
        }

    return d


def _basic_html_report(findings: list[Finding], config: dict, output_path: str) -> str:
    """Minimal fallback HTML report if evidence_report.py is not available."""
    lines = [
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>",
        "<title>BLFinder v3.1</title>",
        "<style>body{background:#0a0a0f;color:#e8e8f0;font-family:monospace;padding:2rem}</style>",
        "</head><body>",
        f"<h1>BLFinder v3.1 — {config.get('target_url', '')}</h1>",
        f"<p>{len(findings)} findings</p>",
    ]
    for f in findings:
        lines.append(f"<h2>[{f.severity.value}] {f.title}</h2>")
        lines.append(f"<p>{f.evidence}</p>")
        lines.append(f"<pre>{f.recommendation}</pre>")
    lines.append("</body></html>")
    with open(output_path, "w") as fh:
        fh.write("\n".join(lines))
    return output_path

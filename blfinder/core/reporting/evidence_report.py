"""
BLFinder v3.1 — core/reporting/evidence_report.py
HTML Evidence Report with Live Evidence Tabs

Replaces the v2.1 HTML report with a version that shows:
  - Real captured HTTP request/response pairs (not templates)
  - Visual field-level diff between baseline and attack
  - Impact summary with actual sensitive data found
  - Side-by-side request comparison
  - Burp Suite importable raw HTTP
  - HackerOne-ready markdown for each finding
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from ..models import Finding, Severity
from ..evidence.capture import EvidencePackage
from .hackerone_formatter import H1Report, HackerOneFormatter


SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff2d55",
    Severity.HIGH:     "#ff9f0a",
    Severity.MEDIUM:   "#ffd60a",
    Severity.LOW:      "#30d158",
    Severity.INFO:     "#0a84ff",
}
SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH,
    Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


class EvidenceReportGenerator:
    """
    Generates the v3.1 HTML evidence report.

    Usage:
        gen = EvidenceReportGenerator()
        gen.generate(findings, output_path="report.html", config={"target_url": "..."})
    """

    def __init__(self):
        self._h1_formatter = HackerOneFormatter()

    def generate(
        self,
        findings: list[Finding],
        output_path: str = "report.html",
        config: dict | None = None,
    ) -> str:
        config = config or {}
        target = config.get("target_url", "N/A")
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity))
        summary = self._build_summary(findings)
        findings_html = self._build_all_findings(sorted_findings)

        html = _HTML_TEMPLATE.format(
            target=_esc(target),
            scan_date=_esc(scan_date),
            total=summary["total"],
            critical=summary.get("CRITICAL", 0),
            high=summary.get("HIGH", 0),
            medium=summary.get("MEDIUM", 0),
            low=summary.get("LOW", 0),
            findings_html=findings_html,
            empty_msg=(
                ""
                if findings
                else '<div class="empty">// No findings above confidence threshold</div>'
            ),
        )

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        print(f"[+] Evidence HTML report → {output_path}")
        return output_path

    def _build_summary(self, findings: list[Finding]) -> dict:
        s = {"total": len(findings)}
        for f in findings:
            s[f.severity.value] = s.get(f.severity.value, 0) + 1
        return s

    def _build_all_findings(self, findings: list[Finding]) -> str:
        return "\n".join(self._build_finding_card(f, i) for i, f in enumerate(findings))

    def _build_finding_card(self, f: Finding, idx: int) -> str:
        fid     = f"finding-{idx}"
        color   = SEVERITY_COLORS[f.severity]
        pkg     = getattr(f, "evidence_package", None)
        confirmed_badge = '<span class="confirmed-badge">✓ CONFIRMED</span>' if f.confirmed else ""

        confidence_pct  = getattr(f, "confidence", 0)
        conf_color      = (
            "#00ff88" if confidence_pct >= 70
            else "#ffd60a" if confidence_pct >= 40
            else "#ff2d55"
        )


        tabs_html   = self._build_tabs(fid)
        tab_content = self._build_tab_contents(fid, f, pkg)

        endpoint_display = _esc(getattr(f, "endpoint", "") or f.request.get("url", ""))

        return f"""
<div class="finding {'open' if f.severity in (Severity.CRITICAL, Severity.HIGH) else ''}" id="{fid}">
  <div class="finding-header" style="border-left:4px solid {color}" onclick="toggleFinding('{fid}')">
    <span class="badge" style="background:{color}">{f.severity.value}</span>
    <div class="finding-title-block">
      <span class="finding-title">{_esc(f.title)}{confirmed_badge}</span>
      <span class="endpoint-tag">{endpoint_display}</span>
    </div>
    <div class="finding-meta">
      <span class="conf-badge" style="border-color:{conf_color};color:{conf_color}">{confidence_pct}%</span>
      <span class="category-tag">{_esc(f.category)}</span>
    </div>
  </div>
  <div class="finding-body">
    <div class="meta-strip">
      <span>CWE: {_esc(f.cwe)}</span>
      <span>CVSS: {f.cvss}</span>
      <span>OWASP: {_esc(f.owasp)}</span>
    </div>
    <div class="confidence-bar-wrap">
      <div class="confidence-bar-fill" style="width:{confidence_pct}%;background:{conf_color}"></div>
      <span class="confidence-bar-label">{confidence_pct}% confidence</span>
    </div>
    {tabs_html}
    <div class="tab-body">
      {tab_content}
    </div>
  </div>
</div>"""

    def _build_tabs(self, fid: str) -> str:
        tab_names = ["Overview", "Evidence", "Diff", "Impact", "Reproduce", "Raw HTTP", "HackerOne"]
        tabs = []
        for i, name in enumerate(tab_names):
            active = "active" if i == 0 else ""
            tabs.append(
                f'<button class="tab-btn {active}" '
                f'onclick="showTab(\'{fid}\', \'{name.lower().replace(" ", "_")}\', this)">'
                f'{name}</button>'
            )
        return f'<div class="tab-bar">{"".join(tabs)}</div>'

    def _build_tab_contents(self, fid: str, f: Finding, pkg: EvidencePackage | None) -> str:
        sections = {
            "overview":   self._tab_overview(f, pkg),
            "evidence":   self._tab_evidence(f, pkg),
            "diff":       self._tab_diff(f, pkg),
            "impact":     self._tab_impact(f, pkg),
            "reproduce":  self._tab_reproduce(f, pkg),
            "raw_http":   self._tab_raw_http(f, pkg),
            "hackerone":  self._tab_hackerone(f, pkg),
        }
        html_parts = []
        for tab_id, content in sections.items():
            active = "active" if tab_id == "overview" else ""
            html_parts.append(
                f'<div class="tab-content {active}" data-tab="{tab_id}" data-finding="{fid}">'
                f'{content}'
                f'</div>'
            )
        return "\n".join(html_parts)

    def _tab_overview(self, f: Finding, pkg: EvidencePackage | None) -> str:
        fp_html = ""
        fp_checks = getattr(f, "false_positive_checks", [])
        if fp_checks:
            fp_items = "".join(f"<li>{_esc(c)}</li>" for c in fp_checks)
            fp_html = f'<div class="section-label">False Positive Analysis</div><ul class="fp-list">{fp_items}</ul>'

        conf_reasons = getattr(f, "confidence_reasons", [])
        cr_html = ""
        if conf_reasons:
            cr_items = "".join(f"<li>{_esc(c)}</li>" for c in conf_reasons[:3])
            cr_html = f'<div class="section-label">Confidence Reasoning</div><ul class="cr-list">{cr_items}</ul>'

        endpoint = _esc(getattr(f, "endpoint", "") or "")
        return f"""
<div class="section-label">Description</div>
<p>{_esc(f.description)}</p>
{f'<div class="section-label">Endpoint</div><code class="endpoint-code">{endpoint}</code>' if endpoint else ''}
<div class="section-label">Evidence Summary</div>
<pre class="code-block evidence-summary">{_esc(f.evidence)}</pre>
{cr_html}
{fp_html}
<div class="section-label">Recommendation</div>
<p class="recommendation">{_esc(f.recommendation)}</p>
"""

    def _tab_evidence(self, f: Finding, pkg: EvidencePackage | None) -> str:
        if not pkg or not pkg.baseline or not pkg.attack:
            req_str = json.dumps(f.request, indent=2) if f.request else "{}"
            return f"""
<p class="muted">No live evidence captured. Showing generated request:</p>
<div class="section-label">Request</div>
<pre class="code-block">{_esc(req_str)}</pre>
<div class="section-label">Response Summary</div>
<pre class="code-block">{_esc(f.response_summary)}</pre>
"""
        baseline = pkg.baseline
        attack   = pkg.attack

        return f"""
<div class="evidence-split">
  <div class="evidence-col">
    <div class="evidence-col-header baseline-header">BASELINE REQUEST</div>
    <pre class="code-block evidence-code">{_esc(baseline.request.to_burp_format())}</pre>
    <div class="evidence-col-header baseline-header">BASELINE RESPONSE — HTTP {baseline.response.status}</div>
    <pre class="code-block evidence-code">{_esc(baseline.response.body[:800])}</pre>
  </div>
  <div class="evidence-col">
    <div class="evidence-col-header attack-header">ATTACK REQUEST</div>
    <pre class="code-block evidence-code">{_esc(attack.request.to_burp_format())}</pre>
    <div class="evidence-col-header attack-header">ATTACK RESPONSE — HTTP {attack.response.status}</div>
    <pre class="code-block evidence-code">{_esc(attack.response.body[:800])}</pre>
  </div>
</div>
{self._cross_user_block(pkg)}
"""

    def _cross_user_block(self, pkg: EvidencePackage) -> str:
        if not pkg.cross_user:
            return ""
        cu = pkg.cross_user
        return f"""
<div class="section-label" style="color:var(--confirmed)">Cross-User Confirmation</div>
<pre class="code-block">{_esc(cu.request.to_burp_format())}</pre>
<p style="color:var(--confirmed)">User 2 received HTTP {cu.response.status} ({len(cu.response.body)}B)</p>
"""

    def _tab_diff(self, f: Finding, pkg: EvidencePackage | None) -> str:
        if not pkg or not pkg.diff_report:
            return "<p class='muted'>Diff not available — evidence package required.</p>"

        dr = pkg.diff_report
        summary = _esc(dr.one_line_summary)
        table   = dr.html_table

        stats_parts = []
        if dr.status_changed:
            stats_parts.append(f"<span class='diff-stat critical'>Status: {dr.baseline_status}→{dr.attack_status}</span>")
        if dr.size_delta:
            color = "critical" if abs(dr.size_delta) > 500 else "high"
            stats_parts.append(f"<span class='diff-stat {color}'>Size: {dr.size_delta:+d}B</span>")
        if dr.count_delta:
            stats_parts.append(f"<span class='diff-stat critical'>Records: {dr.baseline_count}→{dr.attack_count}</span>")
        if dr.privileged_changes:
            stats_parts.append(f"<span class='diff-stat critical'>{len(dr.privileged_changes)} privilege field(s) changed</span>")
        if dr.sensitive_changes:
            stats_parts.append(f"<span class='diff-stat high'>{len(dr.sensitive_changes)} sensitive field(s) exposed</span>")

        stats_html = f'<div class="diff-stats">{"".join(stats_parts)}</div>' if stats_parts else ""

        return f"""
{stats_html}
<div class="section-label">Field-Level Diff</div>
<p class="diff-summary">{summary}</p>
{table}
"""

    def _tab_impact(self, f: Finding, pkg: EvidencePackage | None) -> str:
        if not pkg or not pkg.impact_report:
            return f"<p>{_esc(f.recommendation)}</p>"

        ir = pkg.impact_report

        flag_html = ""
        flags = []
        if ir.has_credentials:
            flags.append('<span class="impact-flag critical">🔑 Credentials Exposed</span>')
        if ir.has_pii:
            flags.append('<span class="impact-flag high">👤 PII Exposed</span>')
        if ir.has_financial:
            flags.append('<span class="impact-flag critical">💳 Financial Data Exposed</span>')
        if ir.has_internal:
            flags.append('<span class="impact-flag high">🔒 Internal Data Exposed</span>')
        if flags:
            flag_html = f'<div class="impact-flags">{"".join(flags)}</div>'

        items_html = ""
        if ir.sensitive_items:
            rows = "".join(
                f"<tr>"
                f"<td><code>{_esc(i.field_name)}</code></td>"
                f"<td>{_esc(i.sensitivity.value)}</td>"
                f"<td>{_esc(i.category)}</td>"
                f"<td><code>{_esc(i.sample_value)}</code></td>"
                f"<td>{i.count}</td>"
                f"<td>{_esc(i.description)}</td>"
                f"</tr>"
                for i in ir.sensitive_items[:15]
            )
            items_html = f"""
<div class="section-label">Sensitive Data Found</div>
<table>
<thead><tr>
  <th>Field</th><th>Severity</th><th>Category</th>
  <th>Sample</th><th>Count</th><th>Description</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""

        return f"""
{flag_html}
<div class="section-label">Impact Statement</div>
<p class="impact-statement">{_esc(ir.impact_statement)}</p>
{items_html}
<div class="section-label">Records Exposed</div>
<p>{ir.total_records_exposed} records accessible through this vulnerability.</p>
"""

    def _tab_reproduce(self, f: Finding, pkg: EvidencePackage | None) -> str:








        poc = getattr(f, "poc", None)

        verified_html = ""
        if pkg and pkg.verified_curl:
            verified_html = f"""
<div class="section-label">✓ Curl Verified During Scan</div>
<pre class="code-block reproduce-cmd">{_esc(pkg.verified_curl)}</pre>
"""

        if not poc:
            if f.request:
                from ..evidence.http_recorder import HTTPRecorder
                from ..evidence.capture import RequestRecord
                url  = f.request.get("url", "")
                meth = f.request.get("method", "GET")
                body = f.request.get("body")
                hdrs = f.request.get("headers", {})
                rec  = RequestRecord(method=meth, url=url, headers=hdrs, body=body)
                curl_cmd = rec.to_curl()
                return f"""
{verified_html}
<div class="section-label">Generated Curl Command</div>
<p class="muted">⚠ No PoC was generated for this finding — showing a bare request derived from the finding data. Verify manually.</p>
<pre class="code-block reproduce-cmd">{_esc(curl_cmd)}</pre>
"""
            return verified_html or "<p class='muted'>No reproduction steps available.</p>"

        steps_html = ""
        if poc.steps:
            steps_items = "".join(f"<li>{_esc(s)}</li>" for s in poc.steps)
            steps_html = f'<div class="section-label">Reproduction Steps</div><ol class="steps-list">{steps_items}</ol>'

        expected_html = (
            f'<div class="section-label">Expected Result</div><p class="impact-statement">{_esc(poc.expected_result)}</p>'
            if poc.expected_result else ""
        )

        curl_html = (
            f'<div class="section-label">Curl Command</div><pre class="code-block reproduce-cmd">{_esc(poc.curl_command)}</pre>'
            if poc.curl_command else ""
        )

        python_html = (
            f'<div class="section-label">Standalone Python PoC</div><pre class="code-block reproduce-cmd">{_esc(poc.python_script)}</pre>'
            if poc.python_script else ""
        )

        burp_html = (
            f'<div class="section-label">Raw HTTP (Burp Repeater)</div><pre class="code-block reproduce-cmd">{_esc(poc.burp_request)}</pre>'
            if poc.burp_request else ""
        )

        video_html = (
            f'<div class="section-label">Recording Notes</div><p class="muted">{_esc(poc.video_note)}</p>'
            if poc.video_note else ""
        )

        return f"""
<p class="impact-statement">{_esc(poc.summary)}</p>
{verified_html}
{curl_html}
{steps_html}
{expected_html}
{python_html}
{burp_html}
{video_html}
"""

    def _tab_raw_http(self, f: Finding, pkg: EvidencePackage | None) -> str:
        if not pkg:
            return "<p class='muted'>No raw HTTP captured.</p>"

        sections = []
        for pair in pkg.all_pairs():
            sections.append(f"""
<div class="section-label">{_esc(pair.label.upper())} — {_esc(pair.note)}</div>
<pre class="code-block">{_esc(pair.to_burp_format())}</pre>
""")

        return "\n".join(sections) if sections else "<p class='muted'>No HTTP pairs captured.</p>"

    def _tab_hackerone(self, f: Finding, pkg: EvidencePackage | None) -> str:
        if not pkg:
            return "<p class='muted'>Evidence package required for HackerOne report generation.</p>"

        try:
            h1 = self._h1_formatter.format(f, pkg)
            return f"""
<p class="muted">Copy the content below and paste it into your HackerOne report.</p>
<div class="h1-title-block">
  <div class="section-label">Title</div>
  <pre class="code-block">{_esc(h1.title)}</pre>
</div>
<div class="section-label">Full Report (Markdown)</div>
<pre class="code-block h1-report">{_esc(h1.full_markdown)}</pre>
"""
        except Exception as e:
            return f"<p class='muted'>Report generation error: {_esc(str(e))}</p>"


def _esc(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html_report(
    findings: list[Finding],
    config: dict,
    output_path: str = "report.html",
) -> str:
    return EvidenceReportGenerator().generate(findings, output_path, config)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>BLFinder v3.1 Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
:root{{--bg:#0a0a0f;--surface:#111118;--surface2:#1a1a24;--border:#2a2a3a;--text:#e8e8f0;--muted:#666680;--critical:#ff2d55;--high:#ff9f0a;--medium:#ffd60a;--low:#30d158;--info:#0a84ff;--accent:#bf5af2;--confirmed:#00ff88;--baseline:#1a2a3a;--attack:#2a1a1a}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;min-height:100vh}}
.header{{background:linear-gradient(135deg,#0d0d1a,#1a0a2e 50%,#0d1a0d);border-bottom:1px solid var(--border);padding:2rem 2.5rem}}
.logo{{font-family:'JetBrains Mono',monospace;font-size:1.6rem;font-weight:700;color:var(--accent)}}
.logo span{{color:var(--critical)}}
h1{{font-size:.9rem;color:var(--muted);font-weight:400;font-family:'JetBrains Mono',monospace;margin-top:.3rem}}
.meta{{display:flex;gap:2rem;margin-top:1.2rem;flex-wrap:wrap}}
.meta-item{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--muted)}}
.meta-item strong{{color:var(--text)}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1px;background:var(--border);border-bottom:1px solid var(--border)}}
.stat{{background:var(--surface);padding:1.2rem 1.5rem;text-align:center}}
.stat-num{{font-size:2.2rem;font-weight:800;font-family:'JetBrains Mono',monospace;line-height:1}}
.stat-label{{font-size:.65rem;color:var(--muted);margin-top:.3rem;letter-spacing:.1em;text-transform:uppercase}}
.stat.critical .stat-num{{color:var(--critical)}} .stat.high .stat-num{{color:var(--high)}} .stat.medium .stat-num{{color:var(--medium)}} .stat.low .stat-num{{color:var(--low)}}
.findings-container{{padding:1.5rem 2.5rem;max-width:1400px;margin:0 auto}}
.section-heading{{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--muted);letter-spacing:.2em;text-transform:uppercase;margin:1.5rem 0 1rem}}
.finding{{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:.8rem;overflow:hidden}}
.finding-header{{padding:.9rem 1.2rem;display:flex;align-items:center;gap:.8rem;cursor:pointer;background:var(--surface2);user-select:none}}
.badge{{font-family:'JetBrains Mono',monospace;font-size:.6rem;font-weight:700;padding:.2rem .5rem;border-radius:3px;color:#000;flex-shrink:0}}
.confirmed-badge{{font-family:'JetBrains Mono',monospace;font-size:.58rem;color:var(--confirmed);margin-left:.4rem;border:1px solid var(--confirmed);padding:.1rem .35rem;border-radius:3px}}
.finding-title-block{{flex:1;min-width:0}}
.finding-title{{font-weight:700;font-size:.9rem;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.endpoint-tag{{font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--info);display:block;margin-top:.15rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.finding-meta{{display:flex;align-items:center;gap:.5rem;flex-shrink:0}}
.conf-badge{{font-family:'JetBrains Mono',monospace;font-size:.65rem;border:1px solid;padding:.1rem .4rem;border-radius:3px}}
.category-tag{{font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--muted);background:var(--bg);padding:.15rem .5rem;border-radius:3px}}
.finding-body{{display:none;padding:1.2rem;border-top:1px solid var(--border)}}
.finding.open .finding-body{{display:block}}
.meta-strip{{display:flex;gap:2rem;margin-bottom:.8rem;font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--muted);flex-wrap:wrap}}
.confidence-bar-wrap{{height:4px;background:var(--border);border-radius:2px;margin-bottom:1rem;position:relative}}
.confidence-bar-fill{{height:100%;border-radius:2px}}
.confidence-bar-label{{font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--muted);position:absolute;right:0;top:-16px}}
.section-label{{font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--accent);letter-spacing:.12em;text-transform:uppercase;margin:1rem 0 .4rem}}
.section-label:first-child{{margin-top:0}}
p{{color:#b0b0c8;line-height:1.7;font-size:.88rem}}
.muted{{color:var(--muted)!important}}
.code-block{{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:.8rem;font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#c0c0d8;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto;line-height:1.5}}
.evidence-code{{max-height:300px}}
.endpoint-code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--info);background:var(--bg);padding:.3rem .6rem;border-radius:3px;display:inline-block;margin-bottom:.5rem}}
.recommendation{{color:#80d8a0!important}}
.tab-bar{{display:flex;gap:.3rem;margin-bottom:0;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:0}}
.tab-btn{{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--muted);padding:.5rem .9rem;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:.72rem;transition:color .2s,border-color .2s}}
.tab-btn.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.tab-btn:hover{{color:var(--text)}}
.tab-body{{margin-top:1rem}}
.tab-content{{display:none}}
.tab-content.active{{display:block}}
.evidence-split{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}
.evidence-col{{min-width:0}}
.evidence-col-header{{font-family:'JetBrains Mono',monospace;font-size:.68rem;padding:.3rem .6rem;border-radius:3px 3px 0 0;margin-bottom:0;font-weight:700}}
.baseline-header{{background:var(--baseline);color:#7ab8e0}}
.attack-header{{background:var(--attack);color:#ff9090}}
.diff-stats{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.8rem}}
.diff-stat{{font-family:'JetBrains Mono',monospace;font-size:.7rem;padding:.2rem .6rem;border-radius:3px}}
.diff-stat.critical{{background:rgba(255,45,85,.15);color:var(--critical);border:1px solid rgba(255,45,85,.3)}}
.diff-stat.high{{background:rgba(255,159,10,.1);color:var(--high);border:1px solid rgba(255,159,10,.2)}}
.diff-summary{{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--text);background:var(--bg);padding:.5rem .8rem;border-radius:4px;margin-bottom:.8rem}}
table{{width:100%;border-collapse:collapse;font-size:.8rem;margin:.5rem 0}}
th{{text-align:left;padding:.4rem .6rem;background:var(--surface2);color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.68rem;font-weight:400;border-bottom:1px solid var(--border)}}
td{{padding:.35rem .6rem;border-bottom:1px solid rgba(42,42,58,.5);color:#c0c0d8;vertical-align:top}}
td code{{font-family:'JetBrains Mono',monospace;font-size:.75rem}}
.impact-flags{{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.8rem}}
.impact-flag{{font-family:'JetBrains Mono',monospace;font-size:.72rem;padding:.25rem .6rem;border-radius:3px}}
.impact-flag.critical{{background:rgba(255,45,85,.15);color:var(--critical);border:1px solid rgba(255,45,85,.3)}}
.impact-flag.high{{background:rgba(255,159,10,.1);color:var(--high);border:1px solid rgba(255,159,10,.2)}}
.impact-statement{{color:#80d8a0!important;font-family:'JetBrains Mono',monospace;font-size:.8rem}}
.reproduce-cmd{{border-color:var(--confirmed)!important;color:var(--confirmed)!important}}
.steps-list{{color:#b0b0c8;margin-left:1.2rem;font-size:.85rem;line-height:2}}
.h1-report{{max-height:600px}}
.fp-list,.cr-list{{margin:.3rem 0 0 1rem;font-size:.8rem;color:var(--muted)}}
.fp-list li,.cr-list li{{margin-bottom:.25rem}}
.empty{{text-align:center;padding:3rem;color:var(--muted);font-family:'JetBrains Mono',monospace}}
@media(max-width:768px){{.header{{padding:1.2rem}}.findings-container{{padding:.8rem}}.category-tag{{display:none}}.evidence-split{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <div class="logo">BL<span>F</span>inder <span style="font-size:.8rem;color:var(--muted)">v3.1</span></div>
  <h1>Business Logic Flaw Report — Evidence Edition</h1>
  <div class="meta">
    <div class="meta-item"><strong>Target:</strong> {target}</div>
    <div class="meta-item"><strong>Date:</strong> {scan_date}</div>
    <div class="meta-item"><strong>Total:</strong> {total} findings</div>
  </div>
</div>
<div class="summary">
  <div class="stat critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
</div>
<div class="findings-container">
  <div class="section-heading">// Findings ({total} total)</div>
  {findings_html}
  {empty_msg}
</div>
<script>
function toggleFinding(id){{document.getElementById(id).classList.toggle('open')}}
function showTab(fid,tab,btn){{
  const body=document.querySelector(`#${{fid}} .finding-body`);
  body.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
  body.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const el=body.querySelector(`.tab-content[data-tab="${{tab}}"][data-finding="${{fid}}"]`);
  if(el)el.classList.add('active');
  if(btn)btn.classList.add('active');
}}
</script>
</body>
</html>"""

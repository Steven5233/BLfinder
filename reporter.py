"""
BLFinder - Report Generator
Produces HTML, JSON, and Markdown reports
"""

import json
import time
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from core.scanner import Finding, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff2d55",
    Severity.HIGH: "#ff9f0a",
    Severity.MEDIUM: "#ffd60a",
    Severity.LOW: "#30d158",
    Severity.INFO: "#0a84ff",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def generate_html_report(findings: list[Finding], config: dict, output_path: str = "report.html"):
    summary = _build_summary(findings)
    findings_html = ""

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
        color = SEVERITY_COLORS[f.severity]
        req_str = json.dumps(f.request, indent=2)
        findings_html += f"""
        <div class="finding" id="f-{id(f)}">
            <div class="finding-header" style="border-left: 4px solid {color}">
                <span class="badge" style="background:{color}">{f.severity.value}</span>
                <span class="finding-title">{_esc(f.title)}</span>
                <span class="category-tag">{_esc(f.category)}</span>
            </div>
            <div class="finding-body">
                <div class="meta-row">
                    <span>CWE: {f.cwe}</span>
                    <span>CVSS: {f.cvss}</span>
                </div>
                <div class="section-label">Description</div>
                <p>{_esc(f.description)}</p>
                <div class="section-label">Evidence</div>
                <pre class="code-block">{_esc(f.evidence)}</pre>
                <div class="section-label">Request</div>
                <pre class="code-block">{_esc(req_str)}</pre>
                <div class="section-label">Response Summary</div>
                <pre class="code-block">{_esc(f.response_summary)}</pre>
                <div class="section-label">Recommendation</div>
                <p class="recommendation">{_esc(f.recommendation)}</p>
            </div>
        </div>
        """

    html = HTML_TEMPLATE.format(
        target=_esc(config.get("target_url", "N/A")),
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        total=summary["total"],
        critical=summary.get(Severity.CRITICAL, 0),
        high=summary.get(Severity.HIGH, 0),
        medium=summary.get(Severity.MEDIUM, 0),
        low=summary.get(Severity.LOW, 0),
        findings_html=findings_html,
    )

    with open(output_path, "w") as f:
        f.write(html)

    print(f"[+] HTML report saved → {output_path}")
    return output_path


def generate_json_report(findings: list[Finding], config: dict, output_path: str = "report.json"):
    data = {
        "meta": {
            "tool": "BLFinder",
            "version": "1.0.0",
            "target": config.get("target_url", ""),
            "scan_date": datetime.now().isoformat(),
        },
        "summary": _build_summary_serializable(findings),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON report saved → {output_path}")
    return output_path


def generate_markdown_report(findings: list[Finding], config: dict, output_path: str = "report.md"):
    lines = [
        "# BLFinder — Business Logic Flaw Report",
        f"**Target:** {config.get('target_url', 'N/A')}  ",
        f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    summary = _build_summary_serializable(findings)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {summary.get(sev, 0)} |")

    lines += ["", f"**Total Findings:** {summary['total']}", "", "---", "## Findings", ""]

    for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)), 1):
        lines += [
            f"### {i}. [{f.severity.value}] {f.title}",
            f"**Category:** {f.category}  ",
            f"**CWE:** {f.cwe} | **CVSS:** {f.cvss}",
            "",
            f"**Description:** {f.description}",
            "",
            "**Evidence:**",
            f"```\n{f.evidence}\n```",
            "",
            "**Request:**",
            f"```json\n{json.dumps(f.request, indent=2)}\n```",
            "",
            f"**Recommendation:** {f.recommendation}",
            "",
            "---",
            "",
        ]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved → {output_path}")
    return output_path


def _build_summary(findings):
    s = {"total": len(findings)}
    for f in findings:
        s[f.severity] = s.get(f.severity, 0) + 1
    return s


def _build_summary_serializable(findings):
    s = {"total": len(findings)}
    for f in findings:
        s[f.severity.value] = s.get(f.severity.value, 0) + 1
    return s


def _finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d


def _esc(s) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLFinder Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{
    --bg: #0a0a0f;
    --surface: #111118;
    --surface2: #1a1a24;
    --border: #2a2a3a;
    --text: #e8e8f0;
    --muted: #666680;
    --critical: #ff2d55;
    --high: #ff9f0a;
    --medium: #ffd60a;
    --low: #30d158;
    --info: #0a84ff;
    --accent: #bf5af2;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; min-height: 100vh; }}
  .header {{
    background: linear-gradient(135deg, #0d0d1a 0%, #1a0a2e 50%, #0d1a0d 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: repeating-linear-gradient(90deg, transparent, transparent 60px, rgba(191,90,242,0.03) 60px, rgba(191,90,242,0.03) 61px);
  }}
  .header-top {{ display: flex; align-items: center; gap: 1.5rem; margin-bottom: 0.5rem; }}
  .logo {{ font-family: 'JetBrains Mono', monospace; font-size: 1.8rem; font-weight: 700; color: var(--accent); letter-spacing: -0.05em; }}
  .logo span {{ color: var(--critical); }}
  h1 {{ font-size: 1rem; color: var(--muted); font-weight: 400; font-family: 'JetBrains Mono', monospace; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1.5rem; flex-wrap: wrap; }}
  .meta-item {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--muted); }}
  .meta-item strong {{ color: var(--text); }}
  .summary {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 1px; background: var(--border);
    margin: 0; border-bottom: 1px solid var(--border);
  }}
  .stat {{ background: var(--surface); padding: 1.5rem 2rem; text-align: center; }}
  .stat-num {{ font-size: 2.5rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; line-height: 1; }}
  .stat-label {{ font-size: 0.7rem; color: var(--muted); margin-top: 0.4rem; letter-spacing: 0.1em; text-transform: uppercase; }}
  .stat.critical .stat-num {{ color: var(--critical); }}
  .stat.high .stat-num {{ color: var(--high); }}
  .stat.medium .stat-num {{ color: var(--medium); }}
  .stat.low .stat-num {{ color: var(--low); }}
  .findings-container {{ padding: 2rem 3rem; max-width: 1200px; margin: 0 auto; }}
  .section-title {{ font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--muted); letter-spacing: 0.2em; text-transform: uppercase; margin-bottom: 1.5rem; margin-top: 2rem; }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem; cursor: pointer; background: var(--surface2); }}
  .badge {{ font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; font-weight: 700; padding: 0.2rem 0.6rem; border-radius: 3px; color: #000; letter-spacing: 0.05em; flex-shrink: 0; }}
  .finding-title {{ font-weight: 700; font-size: 0.95rem; flex: 1; }}
  .category-tag {{ font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--muted); background: var(--bg); padding: 0.2rem 0.6rem; border-radius: 3px; flex-shrink: 0; }}
  .finding-body {{ padding: 1.5rem; border-top: 1px solid var(--border); display: none; }}
  .finding.open .finding-body {{ display: block; }}
  .section-label {{ font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: var(--accent); letter-spacing: 0.15em; text-transform: uppercase; margin: 1.2rem 0 0.5rem; }}
  .section-label:first-child {{ margin-top: 0; }}
  p {{ color: #b0b0c8; line-height: 1.7; font-size: 0.9rem; }}
  .code-block {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #c0c0d8; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }}
  .meta-row {{ display: flex; gap: 2rem; margin-bottom: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--muted); }}
  .recommendation {{ color: #80d8a0 !important; }}
  .empty {{ text-align: center; padding: 4rem; color: var(--muted); font-family: 'JetBrains Mono', monospace; }}
  @media (max-width: 768px) {{
    .header {{ padding: 1.5rem; }}
    .findings-container {{ padding: 1rem; }}
    .finding-header {{ flex-wrap: wrap; gap: 0.5rem; }}
    .category-tag {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div class="header-top">
    <div class="logo">BL<span>F</span>inder</div>
  </div>
  <h1>Business Logic Flaw Detection Report</h1>
  <div class="meta">
    <div class="meta-item"><strong>Target:</strong> {target}</div>
    <div class="meta-item"><strong>Scan Date:</strong> {scan_date}</div>
    <div class="meta-item"><strong>Total Findings:</strong> {total}</div>
  </div>
</div>
<div class="summary">
  <div class="stat critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
  <div class="stat medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
</div>
<div class="findings-container">
  <div class="section-title">// Findings ({total} total)</div>
  {findings_html}
  {'<div class="empty">// No findings detected — consider expanding endpoint coverage</div>' if not {total} else ''}
</div>
<script>
  document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => h.closest('.finding').classList.toggle('open'));
  }});
  // Auto-open critical findings
  document.querySelectorAll('.finding').forEach(f => {{
    if (f.querySelector('.badge') && f.querySelector('.badge').textContent.trim() === 'CRITICAL') {{
      f.classList.add('open');
    }}
  }});
</script>
</body>
</html>"""

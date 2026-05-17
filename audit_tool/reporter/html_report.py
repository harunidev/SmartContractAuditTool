"""Generates a self-contained HTML audit report."""
from datetime import datetime, timezone
from typing import Optional

from ..analyzer.static import Finding


SEVERITY_COLORS = {
    "CRITICAL": ("#dc2626", "#fef2f2"),
    "HIGH": ("#ea580c", "#fff7ed"),
    "MEDIUM": ("#d97706", "#fffbeb"),
    "LOW": ("#2563eb", "#eff6ff"),
    "INFO": ("#6b7280", "#f9fafb"),
}


def _badge(severity: str) -> str:
    color, _ = SEVERITY_COLORS.get(severity, ("#6b7280", "#f9fafb"))
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:12px;font-size:11px;font-weight:700;">{severity}</span>'
    )


def _finding_html(f: Finding, idx: int) -> str:
    _, bg = SEVERITY_COLORS.get(f.severity, ("#6b7280", "#f9fafb"))
    line_info = f" &nbsp;·&nbsp; Line {f.line}" if f.line else ""
    snippet_html = (
        f'<pre style="background:#1e293b;color:#e2e8f0;padding:10px 14px;'
        f'border-radius:6px;font-size:12px;overflow-x:auto;margin-top:8px;">'
        f"{f.snippet}</pre>"
        if f.snippet
        else ""
    )
    return f"""
    <div style="background:{bg};border-radius:8px;padding:16px 20px;margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        <span style="font-weight:700;font-size:15px;">#{idx} {f.title}</span>
        {_badge(f.severity)}
        <span style="color:#64748b;font-size:12px;">{f.category}{line_info}</span>
      </div>
      <p style="margin:0 0 6px;font-size:13px;color:#374151;">{f.description}</p>
      {snippet_html}
      <p style="margin:8px 0 0;font-size:12px;color:#374151;">
        <strong>Recommendation:</strong> {f.recommendation}
      </p>
    </div>"""


def _section(title: str, findings: list[Finding], start_idx: int) -> str:
    if not findings:
        return (
            f'<h2 style="color:#1e293b;margin:28px 0 8px;">{title}</h2>'
            '<p style="color:#64748b;font-size:13px;">No findings detected.</p>'
        )

    items = "".join(
        _finding_html(f, start_idx + i) for i, f in enumerate(findings)
    )
    return f'<h2 style="color:#1e293b;margin:28px 0 8px;">{title}</h2>{items}'


class HTMLReporter:
    def generate(
        self,
        contract_name: str,
        source_code: str,
        static_findings: list[Finding],
        ai_findings: list[Finding],
        output_path: Optional[str] = None,
    ) -> str:
        all_findings = static_findings + ai_findings
        counts: dict[str, int] = {}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        summary_badges = " ".join(
            f'<span style="background:{SEVERITY_COLORS[s][0]};color:#fff;'
            f'padding:4px 12px;border-radius:14px;font-size:13px;font-weight:700;">'
            f'{s}: {counts.get(s, 0)}</span>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )

        static_section = _section("Static Analysis Findings", static_findings, 1)
        ai_section = _section(
            "AI (Claude) Analysis Findings", ai_findings, len(static_findings) + 1
        )

        source_escaped = (
            source_code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit Report — {contract_name}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background:#f1f5f9;color:#1e293b;margin:0;padding:0; }}
  .container {{ max-width:900px;margin:0 auto;padding:32px 20px; }}
  header {{ background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);
            color:#fff;padding:32px;border-radius:12px;margin-bottom:28px; }}
  header h1 {{ margin:0 0 6px;font-size:24px; }}
  header p {{ margin:0;opacity:.7;font-size:14px; }}
  .card {{ background:#fff;border-radius:12px;padding:24px;
           box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:24px; }}
  details summary {{ cursor:pointer;font-weight:600;font-size:14px;color:#475569; }}
  pre {{ white-space:pre-wrap;word-break:break-all; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Smart Contract Audit Report</h1>
    <p>{contract_name} &nbsp;·&nbsp; {now} &nbsp;·&nbsp; SmartContractAuditTool v1.0.0</p>
  </header>

  <div class="card">
    <h2 style="margin:0 0 12px;font-size:16px;">Summary</h2>
    <p style="margin:0 0 12px;font-size:13px;color:#64748b;">
      Total findings: <strong>{len(all_findings)}</strong>
    </p>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">{summary_badges}</div>
  </div>

  <div class="card">
    {static_section}
    {ai_section}
  </div>

  <div class="card">
    <details>
      <summary>Contract Source Code</summary>
      <pre style="background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;
                  font-size:12px;margin-top:12px;overflow-x:auto;">{source_escaped}</pre>
    </details>
  </div>
</div>
</body>
</html>"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(html)

        return html

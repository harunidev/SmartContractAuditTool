"""Generates a self-contained, standalone HTML audit report."""
from datetime import datetime, timezone
from typing import Optional

from ..analyzer.static import Finding

SEVERITY_META = {
    "CRITICAL": ("#dc2626", "#fef2f2", "🔴"),
    "HIGH":     ("#ea580c", "#fff7ed", "🟠"),
    "MEDIUM":   ("#d97706", "#fffbeb", "🟡"),
    "LOW":      ("#2563eb", "#eff6ff", "🔵"),
    "INFO":     ("#6b7280", "#f9fafb", "⚪"),
}


def _badge(severity: str) -> str:
    color, _, _ = SEVERITY_META.get(severity, ("#6b7280", "#f9fafb", ""))
    return (
        f'<span style="background:{color};color:#fff;padding:2px 9px;'
        f'border-radius:12px;font-size:11px;font-weight:700;letter-spacing:.3px;">'
        f'{severity}</span>'
    )


def _finding_card(f: Finding, idx: int, source: str = "") -> str:
    color, bg, icon = SEVERITY_META.get(f.severity, ("#6b7280", "#f9fafb", ""))
    line_info = f" &nbsp;·&nbsp; Line&nbsp;{f.line}" if f.line else ""
    src_tag   = f" &nbsp;·&nbsp; {source.title()}" if source else ""

    snippet_html = ""
    if f.snippet:
        esc = f.snippet.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        snippet_html = (
            f'<pre style="background:#1e293b;color:#e2e8f0;padding:10px 14px;'
            f'border-radius:6px;font-size:12px;overflow-x:auto;margin:10px 0;'
            f'white-space:pre-wrap;word-break:break-all;">{esc}</pre>'
        )

    swc_html = ""
    swc_id = getattr(f, "swc_id", None)
    if swc_id and swc_id.startswith("SWC-"):
        swc_html = (
            f'<a href="https://swcregistry.io/docs/{swc_id}" target="_blank" '
            f'rel="noopener" style="font-size:11px;color:#6366f1;">'
            f'{swc_id} ↗</a>'
        )

    rec_text = f.recommendation.replace("\n", "<br>")

    return f"""
<details style="background:{bg};border-radius:9px;padding:0;margin-bottom:12px;
                border-left:4px solid {color};">
  <summary style="list-style:none;padding:14px 18px;cursor:pointer;display:flex;
                  align-items:center;gap:10px;font-weight:600;font-size:14px;">
    <span style="min-width:20px;">{icon}</span>
    <span style="flex:1;">#{idx} {f.title}</span>
    {_badge(f.severity)}
    <span style="color:#64748b;font-size:11px;white-space:nowrap;">{f.category}{line_info}{src_tag}</span>
  </summary>
  <div style="padding:0 18px 16px;">
    <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 12px;">
    <p style="font-size:13px;color:#374151;line-height:1.6;margin:0 0 8px;">
      {f.description}
    </p>
    {snippet_html}
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:7px;
                padding:10px 14px;margin-top:8px;">
      <strong style="font-size:12px;color:#374151;">Recommendation</strong>
      <p style="font-size:12px;color:#374151;margin:6px 0 0;line-height:1.6;">
        {rec_text}
      </p>
    </div>
    {('<div style="margin-top:8px;">' + swc_html + '</div>') if swc_html else ''}
  </div>
</details>"""


def _section(title: str, findings: list[Finding], start: int, source: str = "") -> str:
    header = (
        f'<h2 style="color:#1e293b;margin:28px 0 12px;font-size:17px;">'
        f'{title}</h2>'
    )
    if not findings:
        return header + '<p style="color:#64748b;font-size:13px;">No findings.</p>'
    body = "".join(_finding_card(f, start + i, source) for i, f in enumerate(findings))
    return header + body


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

        # Summary pills
        pills = " ".join(
            f'<span style="background:{SEVERITY_META[s][0]};color:#fff;padding:5px 14px;'
            f'border-radius:20px;font-size:12px;font-weight:700;">'
            f'{SEVERITY_META[s][2]} {s}: {counts.get(s, 0)}</span>'
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        )

        static_sec = _section("Static Analysis Findings", static_findings, 1, "static")
        ai_sec = _section(
            "AI Analysis Findings (Claude)",
            ai_findings,
            len(static_findings) + 1,
            "AI",
        )

        src_esc = (
            source_code
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk = "CRITICAL" if counts.get("CRITICAL", 0) else (
               "HIGH"     if counts.get("HIGH", 0)     else (
               "MEDIUM"   if counts.get("MEDIUM", 0)   else (
               "LOW"      if counts.get("LOW", 0)       else "CLEAN"
        )))
        risk_color = SEVERITY_META.get(risk, ("#10b981", "#f0fdf4", "✅"))[0]
        if risk == "CLEAN":
            risk_color = "#10b981"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit Report — {contract_name}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f1f5f9; color: #1e293b; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 32px 20px 60px; }}
  .card {{ background: #fff; border-radius: 12px; padding: 24px;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 24px; }}
  details summary::-webkit-details-marker {{ display: none; }}
  pre {{ white-space: pre-wrap; word-break: break-all; }}
  a {{ color: #6366f1; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);
              color:#fff;padding:30px 32px;border-radius:14px;margin-bottom:24px;">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div>
        <h1 style="font-size:22px;font-weight:800;margin-bottom:4px;">
          Smart Contract Audit Report
        </h1>
        <p style="opacity:.65;font-size:13px;">{contract_name} &nbsp;·&nbsp; {now}</p>
        <p style="opacity:.5;font-size:11px;margin-top:2px;">SmartContractAuditTool v1.0.0</p>
      </div>
      <div style="background:{risk_color};padding:8px 20px;border-radius:24px;
                  font-weight:800;font-size:14px;">
        RISK: {risk}
      </div>
    </div>
  </div>

  <!-- Summary -->
  <div class="card">
    <h2 style="font-size:15px;margin-bottom:14px;">Findings Summary</h2>
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;">{pills}</div>
    <p style="font-size:13px;color:#64748b;">
      Total: <strong>{len(all_findings)}</strong> finding(s) &nbsp;·&nbsp;
      Static: {len(static_findings)} &nbsp;·&nbsp; AI: {len(ai_findings)}
    </p>
  </div>

  <!-- Findings -->
  <div class="card">
    {static_sec}
    {ai_sec}
  </div>

  <!-- Source code -->
  <div class="card">
    <details>
      <summary style="cursor:pointer;font-weight:600;font-size:14px;
                      list-style:none;color:#475569;">
        📄 Contract Source Code
      </summary>
      <pre style="background:#1e293b;color:#e2e8f0;padding:16px;
                  border-radius:9px;font-size:12px;margin-top:14px;
                  overflow-x:auto;">{src_esc}</pre>
    </details>
  </div>

</div>
</body>
</html>"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(html)

        return html

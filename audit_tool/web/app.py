"""Flask web interface for SmartContractAuditTool."""
import os
import time

from flask import Flask, jsonify, render_template, request

from ..analyzer.static import StaticAnalyzer
from ..config import AuditConfig
from ..reporter.html_report import HTMLReporter
from ..reporter.json_report import JSONReporter

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = AuditConfig.max_upload_kb * 1024


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "ai_available": bool(os.environ.get("ANTHROPIC_API_KEY"))})


# ── Main UI ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Audit API ─────────────────────────────────────────────────────────────────

@app.route("/api/audit", methods=["POST"])
def audit():
    t0 = time.monotonic()

    source_code: str | None = None
    contract_name = "contract.sol"

    # Accept multipart file upload OR JSON body
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        contract_name = f.filename or contract_name
        source_code = f.read().decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        source_code = data.get("source_code", "").strip()
        contract_name = data.get("contract_name", contract_name) or contract_name

    if not source_code:
        return jsonify({"error": "No source code provided"}), 400

    # Query params
    use_ai: bool = request.args.get("ai", "true").lower() != "false"
    output_format: str = request.args.get("format", "html")
    min_severity: str = request.args.get("min_severity", "INFO").upper()

    # ── Static analysis ──────────────────────────────────────────────────────
    static_findings = StaticAnalyzer().analyze(source_code, min_severity=min_severity)

    # ── AI analysis ──────────────────────────────────────────────────────────
    ai_findings = []
    ai_error: str | None = None
    if use_ai:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                from ..analyzer.ai_auditor import AIAuditor
                ai_findings, _ = AIAuditor(
                    api_key=api_key, model=AuditConfig.model
                ).analyze(source_code)
                ai_findings = AuditConfig.filter_by_min_severity(ai_findings, min_severity)
            except Exception as exc:  # noqa: BLE001
                ai_error = str(exc)
        else:
            ai_error = "ANTHROPIC_API_KEY not configured on server"

    elapsed = round(time.monotonic() - t0, 2)

    # ── JSON download ────────────────────────────────────────────────────────
    if output_format == "json":
        result = JSONReporter().generate(
            contract_name, source_code, static_findings, ai_findings
        )
        response = app.response_class(result, mimetype="application/json")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{contract_name}_audit.json"'
        )
        return response

    # ── HTML report + JSON envelope ──────────────────────────────────────────
    report_html = HTMLReporter().generate(
        contract_name, source_code, static_findings, ai_findings
    )

    def _serialise(f, source: str) -> dict:
        return {
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "recommendation": f.recommendation,
            "line": f.line,
            "snippet": f.snippet,
            "swc_id": getattr(f, "swc_id", None),
            "source": source,
        }

    findings_data = [
        _serialise(f, "static") for f in static_findings
    ] + [
        _serialise(f, "ai") for f in ai_findings
    ]

    return jsonify(
        {
            "contract_name": contract_name,
            "static_count": len(static_findings),
            "ai_count": len(ai_findings),
            "ai_error": ai_error,
            "elapsed_s": elapsed,
            "report_html": report_html,
            "findings": findings_data,
        }
    )


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> None:
    app.run(host=host, port=port, debug=debug)

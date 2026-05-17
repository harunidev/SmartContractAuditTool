"""Flask web interface for SmartContractAuditTool."""
import os
import tempfile

from flask import Flask, jsonify, render_template, request

from ..analyzer.static import StaticAnalyzer
from ..reporter.html_report import HTMLReporter
from ..reporter.json_report import JSONReporter

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB max upload


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/audit", methods=["POST"])
def audit():
    source_code: str | None = None
    contract_name = "contract.sol"

    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        contract_name = f.filename or contract_name
        source_code = f.read().decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        source_code = data.get("source_code", "").strip()
        contract_name = data.get("contract_name", contract_name)

    if not source_code:
        return jsonify({"error": "No source code provided"}), 400

    use_ai: bool = request.args.get("ai", "true").lower() != "false"
    output_format: str = request.args.get("format", "html")

    # Static analysis (always)
    static_findings = StaticAnalyzer().analyze(source_code)

    # AI analysis (optional — requires env var)
    ai_findings = []
    ai_error: str | None = None
    if use_ai:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if api_key:
            try:
                from ..analyzer.ai_auditor import AIAuditor
                ai_findings, _ = AIAuditor(api_key=api_key).analyze(source_code)
            except Exception as exc:  # noqa: BLE001
                ai_error = str(exc)
        else:
            ai_error = "ANTHROPIC_API_KEY not set on server"

    if output_format == "json":
        reporter = JSONReporter()
        result = reporter.generate(contract_name, source_code, static_findings, ai_findings)
        response = app.response_class(result, mimetype="application/json")
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{contract_name}_audit.json"'
        )
        return response

    # HTML report (default)
    reporter = HTMLReporter()
    html = reporter.generate(contract_name, source_code, static_findings, ai_findings)

    # Return JSON envelope with embedded HTML for the SPA to inject
    return jsonify(
        {
            "contract_name": contract_name,
            "static_count": len(static_findings),
            "ai_count": len(ai_findings),
            "ai_error": ai_error,
            "report_html": html,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "line": f.line,
                    "source": "static" if i < len(static_findings) else "ai",
                }
                for i, f in enumerate(static_findings + ai_findings)
            ],
        }
    )


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> None:
    app.run(host=host, port=port, debug=debug)

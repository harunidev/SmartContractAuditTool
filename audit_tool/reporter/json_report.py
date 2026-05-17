import json
from datetime import datetime, timezone
from typing import Optional

from ..analyzer.static import Finding


def _finding_to_dict(f: Finding) -> dict:
    return {
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "line": f.line,
        "snippet": f.snippet,
    }


class JSONReporter:
    def generate(
        self,
        contract_name: str,
        source_code: str,
        static_findings: list[Finding],
        ai_findings: list[Finding],
        output_path: Optional[str] = None,
    ) -> str:
        counts: dict[str, int] = {}
        for f in static_findings + ai_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        report = {
            "tool": "SmartContractAuditTool",
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "contract": contract_name,
            "summary": {
                "total_findings": len(static_findings) + len(ai_findings),
                "by_severity": counts,
            },
            "static_analysis": [_finding_to_dict(f) for f in static_findings],
            "ai_analysis": [_finding_to_dict(f) for f in ai_findings],
        }

        output = json.dumps(report, indent=2, ensure_ascii=False)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(output)

        return output

"""Tests for HTML and JSON reporters."""
import json
import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_tool.analyzer.static import Finding, StaticAnalyzer
from audit_tool.reporter.html_report import HTMLReporter
from audit_tool.reporter.json_report import JSONReporter

SOURCE = """pragma solidity ^0.7.0;
contract Test {
    function drain() public { (bool ok,) = msg.sender.call{value: 1}(""); }
}"""

def _findings():
    return StaticAnalyzer().analyze(SOURCE)


# ── JSON reporter ─────────────────────────────────────────────────────────────

def test_json_is_valid():
    out = JSONReporter().generate("test.sol", SOURCE, _findings(), [])
    data = json.loads(out)
    assert isinstance(data, dict)

def test_json_schema():
    data = json.loads(JSONReporter().generate("test.sol", SOURCE, _findings(), []))
    for key in ("tool", "version", "generated_at", "contract", "summary",
                "static_analysis", "ai_analysis"):
        assert key in data, f"Missing key: {key}"

def test_json_summary_counts():
    findings = _findings()
    data = json.loads(JSONReporter().generate("test.sol", SOURCE, findings, []))
    assert data["summary"]["total_findings"] == len(findings)

def test_json_static_list():
    findings = _findings()
    data = json.loads(JSONReporter().generate("test.sol", SOURCE, findings, []))
    assert len(data["static_analysis"]) == len(findings)

def test_json_finding_fields():
    data = json.loads(JSONReporter().generate("test.sol", SOURCE, _findings(), []))
    for item in data["static_analysis"]:
        for field in ("severity", "category", "title", "description", "recommendation"):
            assert field in item, f"Missing field: {field}"

def test_json_write_to_file():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        path = fh.name
    try:
        JSONReporter().generate("test.sol", SOURCE, _findings(), [], output_path=path)
        with open(path) as f:
            data = json.load(f)
        assert data["contract"] == "test.sol"
    finally:
        os.unlink(path)


# ── HTML reporter ─────────────────────────────────────────────────────────────

def test_html_is_string():
    out = HTMLReporter().generate("test.sol", SOURCE, _findings(), [])
    assert isinstance(out, str)

def test_html_is_valid_html():
    out = HTMLReporter().generate("test.sol", SOURCE, _findings(), [])
    assert out.strip().startswith("<!DOCTYPE html")
    assert "</html>" in out

def test_html_contains_contract_name():
    out = HTMLReporter().generate("MyContract.sol", SOURCE, _findings(), [])
    assert "MyContract.sol" in out

def test_html_contains_severities():
    out = HTMLReporter().generate("test.sol", SOURCE, _findings(), [])
    # At least CRITICAL or HIGH should appear for our vulnerable snippet
    assert "CRITICAL" in out or "HIGH" in out

def test_html_no_raw_source_leak():
    """Source is HTML-escaped — raw < chars must not appear."""
    src = "pragma solidity 0.8.0;\ncontract A { function f() external {} }"
    out = HTMLReporter().generate("a.sol", src, [], [])
    # The source is embedded as escaped HTML, check no unescaped tags
    import re
    # srcdoc won't have bare script or style from source (we escape it)
    assert "<script" not in out.split("Contract Source Code")[1].split("</details")[0]

def test_html_write_to_file():
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
        path = fh.name
    try:
        HTMLReporter().generate("test.sol", SOURCE, _findings(), [], output_path=path)
        with open(path) as f:
            content = f.read()
        assert "<!DOCTYPE html" in content
    finally:
        os.unlink(path)

def test_html_ai_findings_section():
    ai_f = Finding(
        severity="HIGH", category="Test", title="AI Finding",
        description="desc", recommendation="rec"
    )
    out = HTMLReporter().generate("test.sol", SOURCE, [], [ai_f])
    assert "AI Analysis Findings" in out
    assert "AI Finding" in out


# ── Runner ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)

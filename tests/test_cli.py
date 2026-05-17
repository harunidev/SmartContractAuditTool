"""Tests for the CLI module."""
import os
import sys
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_tool.cli import main

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(HERE)
VULNERABLE = os.path.join(REPO_ROOT, "contracts", "vulnerable.sol")
SAFE       = os.path.join(REPO_ROOT, "contracts", "safe_example.sol")


# ── Basic invocation ──────────────────────────────────────────────────────────

def test_console_format_exits_zero():
    rc = main(["--file", VULNERABLE, "--no-ai", "--format", "console"])
    assert rc == 0

def test_missing_file_exits_nonzero():
    rc = main(["--file", "/nonexistent/contract.sol", "--no-ai", "--format", "console"])
    assert rc != 0

def test_no_args_exits_nonzero():
    # No --file or --dir → print help → return 1
    rc = main([])
    assert rc == 1


# ── HTML report generation ────────────────────────────────────────────────────

def test_generates_html_report():
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
        out = fh.name
    try:
        rc = main(["--file", VULNERABLE, "--no-ai", "--format", "html", "--output", out])
        assert rc == 0
        with open(out) as f:
            content = f.read()
        assert "<!DOCTYPE html" in content
        assert "SmartContractAuditTool" in content
    finally:
        if os.path.exists(out):
            os.unlink(out)


# ── JSON report generation ────────────────────────────────────────────────────

def test_generates_json_report():
    import json
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = fh.name
    try:
        rc = main(["--file", VULNERABLE, "--no-ai", "--format", "json", "--output", out])
        assert rc == 0
        with open(out) as f:
            data = json.load(f)
        assert data["contract"] == "vulnerable.sol"
        assert data["summary"]["total_findings"] > 0
    finally:
        if os.path.exists(out):
            os.unlink(out)


# ── Severity filter ───────────────────────────────────────────────────────────

def test_min_severity_critical_only():
    import json
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        out = fh.name
    try:
        main(["--file", VULNERABLE, "--no-ai", "--format", "json",
              "--output", out, "--min-severity", "CRITICAL"])
        with open(out) as f:
            data = json.load(f)
        for item in data["static_analysis"]:
            assert item["severity"] == "CRITICAL"
    finally:
        if os.path.exists(out):
            os.unlink(out)


# ── Batch / dir mode ──────────────────────────────────────────────────────────

def test_batch_dir_mode():
    contracts_dir = os.path.join(REPO_ROOT, "contracts")
    rc = main(["--dir", contracts_dir, "--no-ai", "--format", "console"])
    assert rc == 0

def test_dir_not_found_exits_nonzero():
    rc = main(["--dir", "/tmp/no_sol_here_xyz", "--no-ai", "--format", "console"])
    assert rc != 0


# ── Demo sub-command ──────────────────────────────────────────────────────────

def test_demo_generates_file():
    # Change to tmp dir so the demo report lands somewhere writable
    orig = os.getcwd()
    try:
        os.chdir(tempfile.gettempdir())
        rc = main(["demo"])
        assert rc == 0
        assert os.path.exists("demo_audit_report.html")
    finally:
        demo = os.path.join(tempfile.gettempdir(), "demo_audit_report.html")
        if os.path.exists(demo):
            os.unlink(demo)
        os.chdir(orig)


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

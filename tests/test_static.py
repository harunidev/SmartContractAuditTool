"""Tests for the static vulnerability analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_tool.analyzer.static import StaticAnalyzer, Finding

VULNERABLE = """
pragma solidity ^0.7.6;
contract Vuln {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    function auth() public { require(tx.origin == msg.sender); }
    function ts() public view returns (bool) { return block.timestamp > 0; }
    function kill() public { selfdestruct(payable(msg.sender)); }
    function proxy(address impl, bytes calldata d) public { impl.delegatecall(d); }
    function loop(address[] calldata users) public {
        for (uint i = 0; i < users.length; i++) {}
    }
    function initialize() public { }
}
"""

CLEAN = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Safe {
    uint256 private _value;
    event ValueSet(address indexed caller, uint256 v);
    function setValue(uint256 v) external { _value = v; emit ValueSet(msg.sender, v); }
    function getValue() external view returns (uint256) { return _value; }
}
"""


def _run(code: str, min_sev: str = "INFO") -> list[Finding]:
    return StaticAnalyzer().analyze(code, min_severity=min_sev)


# ── Individual pattern tests ───────────────────────────────────────────────────

def test_detects_reentrancy():
    cats = [f.category for f in _run(VULNERABLE)]
    assert "Reentrancy" in cats

def test_detects_tx_origin():
    titles = [f.title for f in _run(VULNERABLE)]
    assert any("tx.origin" in t for t in titles)

def test_detects_selfdestruct():
    titles = [f.title for f in _run(VULNERABLE)]
    assert any("selfdestruct" in t.lower() for t in titles)

def test_detects_delegatecall():
    cats = [f.category for f in _run(VULNERABLE)]
    assert "Delegatecall" in cats

def test_detects_floating_pragma():
    titles = [f.title for f in _run(VULNERABLE)]
    assert any("pragma" in t.lower() or "Floating" in t for t in titles)

def test_detects_old_version_overflow():
    sevs = [f.severity for f in _run(VULNERABLE)]
    assert "HIGH" in sevs  # SWC-101 fires on 0.7.x pragma

def test_detects_unbounded_loop():
    cats = [f.category for f in _run(VULNERABLE)]
    assert "DoS" in cats

def test_detects_unprotected_initializer():
    titles = [f.title for f in _run(VULNERABLE)]
    assert any("initializer" in t.lower() or "Initializer" in t for t in titles)

# ── Ordering ──────────────────────────────────────────────────────────────────

def test_severity_order():
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = _run(VULNERABLE)
    for a, b in zip(findings, findings[1:]):
        assert sev_rank[a.severity] <= sev_rank[b.severity], \
            f"Order violated: {a.severity} before {b.severity}"

# ── Min-severity filter ───────────────────────────────────────────────────────

def test_min_severity_critical():
    findings = _run(VULNERABLE, min_sev="CRITICAL")
    assert all(f.severity == "CRITICAL" for f in findings)
    assert len(findings) > 0

def test_min_severity_high():
    all_f  = _run(VULNERABLE)
    high_f = _run(VULNERABLE, min_sev="HIGH")
    assert all(f.severity in ("CRITICAL", "HIGH") for f in high_f)
    assert len(high_f) <= len(all_f)

# ── Clean contract ────────────────────────────────────────────────────────────

def test_clean_has_fewer_findings():
    assert len(_run(CLEAN)) < len(_run(VULNERABLE))

def test_clean_no_critical():
    crits = [f for f in _run(CLEAN) if f.severity == "CRITICAL"]
    assert len(crits) == 0

# ── Finding fields ────────────────────────────────────────────────────────────

def test_finding_has_required_fields():
    findings = _run(VULNERABLE)
    for f in findings:
        assert f.severity
        assert f.category
        assert f.title
        assert f.description
        assert f.recommendation
        assert f.line is not None and f.line > 0
        assert f.snippet

def test_snippet_matches_line():
    """Verify that the snippet corresponds to content near the given line."""
    findings = _run(VULNERABLE)
    lines = VULNERABLE.splitlines()
    for f in findings:
        if f.line and f.snippet:
            actual = lines[f.line - 1].strip()
            assert f.snippet == actual, \
                f"Snippet mismatch at line {f.line}: {f.snippet!r} vs {actual!r}"


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

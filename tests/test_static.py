"""Basic unit tests for the static analyzer."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_tool.analyzer.static import StaticAnalyzer

VULNERABLE_CODE = """
pragma solidity ^0.7.6;
contract Vuln {
    function drain() public {
        (bool ok,) = msg.sender.call{value: 1 ether}("");
        balances[msg.sender] = 0;
    }
    function auth() public { require(tx.origin == msg.sender); }
    function ts() public view returns (bool) { return block.timestamp > 0; }
    function kill() public { selfdestruct(payable(msg.sender)); }
}
"""

CLEAN_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract Safe {
    uint256 private value;
    function set(uint256 v) external { value = v; }
    function get() external view returns (uint256) { return value; }
}
"""


def test_detects_reentrancy():
    findings = StaticAnalyzer().analyze(VULNERABLE_CODE)
    categories = [f.category for f in findings]
    assert "Reentrancy" in categories, "Should detect reentrancy"


def test_detects_tx_origin():
    findings = StaticAnalyzer().analyze(VULNERABLE_CODE)
    titles = [f.title for f in findings]
    assert any("tx.origin" in t for t in titles), "Should detect tx.origin"


def test_detects_selfdestruct():
    findings = StaticAnalyzer().analyze(VULNERABLE_CODE)
    titles = [f.title for f in findings]
    assert any("selfdestruct" in t.lower() for t in titles), "Should detect selfdestruct"


def test_detects_floating_pragma():
    findings = StaticAnalyzer().analyze(VULNERABLE_CODE)
    titles = [f.title for f in findings]
    assert any("pragma" in t.lower() for t in titles), "Should detect floating pragma"


def test_severity_order():
    findings = StaticAnalyzer().analyze(VULNERABLE_CODE)
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for a, b in zip(findings, findings[1:]):
        assert severity_rank[a.severity] <= severity_rank[b.severity], \
            "Findings should be sorted by severity"


def test_clean_contract_fewer_findings():
    vuln = StaticAnalyzer().analyze(VULNERABLE_CODE)
    clean = StaticAnalyzer().analyze(CLEAN_CODE)
    assert len(clean) < len(vuln), "Clean contract should have fewer findings"


if __name__ == "__main__":
    tests = [test_detects_reentrancy, test_detects_tx_origin, test_detects_selfdestruct,
             test_detects_floating_pragma, test_severity_order, test_clean_contract_fewer_findings]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")

"""
Static pattern-based vulnerability detector for Solidity contracts.
Covers the most common EVM security pitfalls without external dependencies.
"""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    title: str
    description: str
    recommendation: str
    line: Optional[int] = None
    snippet: Optional[str] = None


PATTERNS = [
    # ── Reentrancy ────────────────────────────────────────────────────────────
    {
        "id": "SWC-107",
        "severity": "CRITICAL",
        "category": "Reentrancy",
        "title": "Potential Reentrancy Vulnerability",
        "description": (
            "External call detected before state variable update. "
            "An attacker may re-enter the function before balances are zeroed."
        ),
        "recommendation": (
            "Apply the Checks-Effects-Interactions pattern: update state "
            "before making external calls. Consider using ReentrancyGuard."
        ),
        "pattern": re.compile(
            r"\.call\s*\{[^}]*\}\s*\([^)]*\)|\.call\.value\s*\([^)]*\)\s*\(\)",
            re.IGNORECASE,
        ),
    },
    # ── tx.origin auth ────────────────────────────────────────────────────────
    {
        "id": "SWC-115",
        "severity": "HIGH",
        "category": "Access Control",
        "title": "Use of tx.origin for Authentication",
        "description": (
            "tx.origin refers to the original EOA that started the transaction, "
            "not the immediate caller. A malicious intermediary contract can "
            "impersonate the user."
        ),
        "recommendation": "Replace tx.origin with msg.sender for access control checks.",
        "pattern": re.compile(r"\btx\.origin\b"),
    },
    # ── Unchecked low-level call return ───────────────────────────────────────
    {
        "id": "SWC-104",
        "severity": "HIGH",
        "category": "Unchecked Return",
        "title": "Unchecked Low-Level Call Return Value",
        "description": (
            "The return value of a low-level call (send/call) is not checked. "
            "Failures will be silently swallowed."
        ),
        "recommendation": (
            "Always check the boolean return value of send/call, or prefer "
            "transfer() which reverts on failure."
        ),
        "pattern": re.compile(
            r"(?<!\(bool\s)\b(?:\.send|\.call)\b(?!\s*\(bool)",
            re.IGNORECASE,
        ),
    },
    # ── Integer overflow (pre-0.8) ────────────────────────────────────────────
    {
        "id": "SWC-101",
        "severity": "HIGH",
        "category": "Arithmetic",
        "title": "Potential Integer Overflow/Underflow",
        "description": (
            "Arithmetic operations without SafeMath or Solidity >=0.8 "
            "overflow checks can wrap silently."
        ),
        "recommendation": (
            "Use Solidity ^0.8.0 (built-in overflow checks) or OpenZeppelin "
            "SafeMath for earlier versions."
        ),
        "pattern": re.compile(
            r"pragma\s+solidity\s+[^;]*0\.[1-7]\.[0-9]",
            re.IGNORECASE,
        ),
    },
    # ── Block timestamp dependence ────────────────────────────────────────────
    {
        "id": "SWC-116",
        "severity": "MEDIUM",
        "category": "Timestamp Dependence",
        "title": "Block Timestamp Dependence",
        "description": (
            "block.timestamp can be manipulated by miners within ~15 seconds, "
            "making it unreliable for time-sensitive logic."
        ),
        "recommendation": (
            "Avoid using block.timestamp for critical decisions. "
            "Use block.number or Chainlink VRF for randomness."
        ),
        "pattern": re.compile(r"\bblock\.timestamp\b"),
    },
    # ── Selfdestruct ──────────────────────────────────────────────────────────
    {
        "id": "SWC-106",
        "severity": "HIGH",
        "category": "Dangerous Function",
        "title": "Use of selfdestruct",
        "description": (
            "selfdestruct sends all Ether to a target and destroys the contract. "
            "If callable by unauthorized parties, this is catastrophic."
        ),
        "recommendation": (
            "Remove selfdestruct or protect it with strict access control. "
            "Consider using a pause/upgrade pattern instead."
        ),
        "pattern": re.compile(r"\bselfdestruct\s*\("),
    },
    # ── Delegatecall to user-controlled address ───────────────────────────────
    {
        "id": "SWC-112",
        "severity": "CRITICAL",
        "category": "Delegatecall",
        "title": "Delegatecall to User-Controlled Address",
        "description": (
            "delegatecall executes code from another contract in the caller's "
            "storage context. Calling an attacker-supplied address gives full "
            "storage write access."
        ),
        "recommendation": (
            "Never delegatecall to an address derived from user input. "
            "Whitelist allowed implementation addresses."
        ),
        "pattern": re.compile(r"\bdelegatecall\s*\("),
    },
    # ── Floating pragma ───────────────────────────────────────────────────────
    {
        "id": "SWC-103",
        "severity": "LOW",
        "category": "Best Practice",
        "title": "Floating Pragma",
        "description": (
            "Using ^ or >= in pragma allows the contract to be compiled with "
            "multiple compiler versions, some of which may have known bugs."
        ),
        "recommendation": "Pin the compiler version: pragma solidity 0.8.20;",
        "pattern": re.compile(
            r"pragma\s+solidity\s+[\^>=~]",
            re.IGNORECASE,
        ),
    },
    # ── Uninitialized storage pointer ─────────────────────────────────────────
    {
        "id": "SWC-109",
        "severity": "HIGH",
        "category": "Storage",
        "title": "Uninitialized Local Storage Variable",
        "description": (
            "Local storage variables that are not explicitly assigned point to "
            "slot 0 by default, which can corrupt contract state."
        ),
        "recommendation": (
            "Always initialize storage pointers or use memory keyword "
            "where a copy is intended."
        ),
        "pattern": re.compile(
            r"\bstorage\b[^;=\n]+(;)(?!=)",
            re.IGNORECASE,
        ),
    },
    # ── Arbitrary jump / assembly ─────────────────────────────────────────────
    {
        "id": "SWC-127",
        "severity": "MEDIUM",
        "category": "Assembly",
        "title": "Use of Inline Assembly",
        "description": (
            "Inline assembly bypasses Solidity's safety checks. "
            "Errors here can corrupt memory or storage."
        ),
        "recommendation": (
            "Avoid assembly unless strictly necessary. "
            "Document and test all assembly blocks thoroughly."
        ),
        "pattern": re.compile(r"\bassembly\s*\{"),
    },
    # ── Hardcoded ETH transfer ─────────────────────────────────────────────────
    {
        "id": "SWC-132",
        "severity": "MEDIUM",
        "category": "Gas",
        "title": "Hardcoded Gas in Transfer",
        "description": (
            ".transfer() and .send() forward only 2300 gas which may be "
            "insufficient after EIP-1884 repricing."
        ),
        "recommendation": (
            "Use .call{value: amount}('') with reentrancy guard, "
            "or use OpenZeppelin Address.sendValue."
        ),
        "pattern": re.compile(r"\.\s*transfer\s*\("),
    },
    # ── Missing zero-address check ─────────────────────────────────────────────
    {
        "id": "SWC-020",
        "severity": "LOW",
        "category": "Validation",
        "title": "Missing Zero-Address Validation",
        "description": (
            "Address parameters are not validated against address(0). "
            "Funds or ownership could be sent to the burn address."
        ),
        "recommendation": (
            "Add require(addr != address(0), 'zero address') for all "
            "address parameters that affect state."
        ),
        "pattern": re.compile(
            r"function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)(?![^{]*require\s*\([^)]*address\(0\))",
            re.IGNORECASE | re.DOTALL,
        ),
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class StaticAnalyzer:
    def analyze(self, source_code: str) -> list[Finding]:
        lines = source_code.splitlines()
        findings: list[Finding] = []
        seen: set[str] = set()

        for rule in PATTERNS:
            for lineno, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    key = f"{rule['id']}:{lineno}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            severity=rule["severity"],
                            category=rule["category"],
                            title=rule["title"],
                            description=rule["description"],
                            recommendation=rule["recommendation"],
                            line=lineno,
                            snippet=line.strip(),
                        )
                    )

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        return findings

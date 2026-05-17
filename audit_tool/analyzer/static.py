"""
Static pattern-based vulnerability detector for Solidity contracts.
Covers the most common EVM security pitfalls without external dependencies.
References: SWC Registry (https://swcregistry.io/), OpenZeppelin, ConsenSys
"""
import re
from dataclasses import dataclass
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
    swc_id: Optional[str] = None


# ── Vulnerability patterns ────────────────────────────────────────────────────
# Each rule matches line-by-line. The first match on a line triggers one finding.

PATTERNS = [
    # ── Reentrancy (SWC-107) ──────────────────────────────────────────────────
    {
        "id": "SWC-107",
        "severity": "CRITICAL",
        "category": "Reentrancy",
        "title": "Potential Reentrancy Vulnerability",
        "description": (
            "An external .call{value:...}() is made without the ReentrancyGuard or "
            "the Checks-Effects-Interactions pattern. An attacker contract can re-enter "
            "this function before state is updated, draining funds (classic DAO attack)."
        ),
        "recommendation": (
            "1) Apply Checks-Effects-Interactions: update all state before the external call.\n"
            "2) Or use OpenZeppelin's ReentrancyGuard and add the nonReentrant modifier.\n"
            "3) Consider using a pull-payment pattern instead of push payments."
        ),
        "pattern": re.compile(
            r"\.call\s*\{[^}]*value[^}]*\}\s*\(",
            re.IGNORECASE,
        ),
    },
    # ── tx.origin auth (SWC-115) ──────────────────────────────────────────────
    {
        "id": "SWC-115",
        "severity": "HIGH",
        "category": "Access Control",
        "title": "Authentication via tx.origin",
        "description": (
            "tx.origin is the original EOA that started the transaction chain, not the "
            "immediate caller. A malicious intermediary contract can forward a call and "
            "impersonate the victim (phishing attack)."
        ),
        "recommendation": (
            "Replace tx.origin with msg.sender for all access control checks. "
            "tx.origin is only safe for distinguishing EOAs from contracts, not for auth."
        ),
        "pattern": re.compile(r"\btx\.origin\b"),
    },
    # ── Unchecked low-level call return (SWC-104) ─────────────────────────────
    {
        "id": "SWC-104",
        "severity": "HIGH",
        "category": "Unchecked Return",
        "title": "Unchecked Low-Level Call Return Value",
        "description": (
            "The return value of .send() or .call() is a boolean indicating success. "
            "If not checked, failed transfers are silently swallowed and execution continues."
        ),
        "recommendation": (
            "Always check the bool return: (bool ok,) = addr.call{...}('');\n"
            "require(ok, 'transfer failed');\n"
            "Or use OpenZeppelin's Address.sendValue() which reverts on failure."
        ),
        "pattern": re.compile(
            r"\.\s*(send|call)\s*[\({]",
            re.IGNORECASE,
        ),
    },
    # ── Integer overflow — old pragma (SWC-101) ───────────────────────────────
    {
        "id": "SWC-101",
        "severity": "HIGH",
        "category": "Arithmetic",
        "title": "Integer Overflow/Underflow Risk (Solidity <0.8)",
        "description": (
            "Solidity versions before 0.8.0 do not revert on arithmetic overflow or "
            "underflow — the value wraps silently. This can corrupt balances and bypass "
            "access controls (e.g., underflowing a balance check)."
        ),
        "recommendation": (
            "Upgrade to Solidity ^0.8.0 (overflow checks built in) or use "
            "OpenZeppelin SafeMath for all arithmetic on older versions."
        ),
        "pattern": re.compile(
            r"pragma\s+solidity\s+[^;]*0\.[1-7]\.",
            re.IGNORECASE,
        ),
    },
    # ── Block timestamp dependence (SWC-116) ─────────────────────────────────
    {
        "id": "SWC-116",
        "severity": "MEDIUM",
        "category": "Timestamp Dependence",
        "title": "Block Timestamp Dependence",
        "description": (
            "block.timestamp can be manipulated by validators/miners within a ~15-second "
            "window. Using it for random seeds, time-locks, or auction deadlines creates "
            "exploitable predictability."
        ),
        "recommendation": (
            "Avoid block.timestamp for randomness — use Chainlink VRF instead. "
            "For time-locks, use block.number with a known block time, or accept "
            "the ±15s miner wiggle room as acceptable risk."
        ),
        "pattern": re.compile(r"\bblock\.timestamp\b"),
    },
    # ── Selfdestruct (SWC-106) ────────────────────────────────────────────────
    {
        "id": "SWC-106",
        "severity": "HIGH",
        "category": "Dangerous Function",
        "title": "Use of selfdestruct",
        "description": (
            "selfdestruct permanently destroys the contract, sends all ETH to the target, "
            "and bypasses receive/fallback. If callable by untrusted parties, it can drain "
            "all funds or break dependent contracts. Note: EIP-6780 limits selfdestruct "
            "behavior in Cancun+ but it's still dangerous."
        ),
        "recommendation": (
            "Remove selfdestruct unless absolutely necessary. Protect with strict "
            "onlyOwner or multisig access control. Consider a pausable/upgradeable "
            "pattern instead of contract destruction."
        ),
        "pattern": re.compile(r"\bselfdestruct\s*\("),
    },
    # ── Delegatecall (SWC-112) ────────────────────────────────────────────────
    {
        "id": "SWC-112",
        "severity": "CRITICAL",
        "category": "Delegatecall",
        "title": "Uncontrolled Delegatecall",
        "description": (
            "delegatecall executes code from another address in the calling contract's "
            "storage context. If the target address is user-supplied or unvalidated, an "
            "attacker can execute arbitrary logic — including draining all funds or "
            "changing ownership."
        ),
        "recommendation": (
            "Never delegatecall to user-supplied addresses. Maintain a whitelist of "
            "trusted implementation addresses. Use OpenZeppelin's transparent or UUPS "
            "proxy pattern with strict access controls."
        ),
        "pattern": re.compile(r"\bdelegatecall\s*\("),
    },
    # ── Floating pragma (SWC-103) ─────────────────────────────────────────────
    {
        "id": "SWC-103",
        "severity": "LOW",
        "category": "Best Practice",
        "title": "Floating Pragma Version",
        "description": (
            "Using ^, >=, or ~ in pragma solidity allows the contract to be compiled "
            "with different compiler versions, some of which may have known bugs or "
            "breaking behavior changes."
        ),
        "recommendation": (
            "Pin the exact compiler version: pragma solidity 0.8.24;\n"
            "Ensure your CI locks the same version via solc-select or hardhat settings."
        ),
        "pattern": re.compile(
            r"pragma\s+solidity\s+[\^>=~]",
            re.IGNORECASE,
        ),
    },
    # ── Inline assembly (SWC-127) ─────────────────────────────────────────────
    {
        "id": "SWC-127",
        "severity": "MEDIUM",
        "category": "Assembly",
        "title": "Use of Inline Assembly",
        "description": (
            "Inline assembly bypasses Solidity's type system, bounds checks, and "
            "safety guarantees. Errors in assembly can silently corrupt memory or storage, "
            "and assembly code is harder to audit."
        ),
        "recommendation": (
            "Avoid assembly unless strictly necessary for gas optimization or low-level "
            "operations unavailable in Solidity. Document every assembly block extensively "
            "and add invariant tests."
        ),
        "pattern": re.compile(r"\bassembly\s*\{"),
    },
    # ── .transfer() gas limit (SWC-132) ──────────────────────────────────────
    {
        "id": "SWC-132",
        "severity": "MEDIUM",
        "category": "Gas",
        "title": "Hardcoded Gas via .transfer()",
        "description": (
            ".transfer() and .send() forward exactly 2300 gas. After EIP-1884 "
            "(Istanbul), several SLOAD/SSTORE costs increased, making 2300 gas "
            "insufficient for recipients that do more than emit an event — causing "
            "unexpected reverts."
        ),
        "recommendation": (
            "Replace .transfer(amount) with:\n"
            "(bool ok,) = recipient.call{value: amount}('');\n"
            "require(ok, 'ETH transfer failed');\n"
            "Pair with ReentrancyGuard to mitigate reentrancy risk."
        ),
        "pattern": re.compile(r"\.\s*transfer\s*\("),
    },
    # ── Missing zero-address check (SWC-020) ─────────────────────────────────
    {
        "id": "SWC-020",
        "severity": "LOW",
        "category": "Validation",
        "title": "Missing Zero-Address Validation",
        "description": (
            "An address parameter is not checked against address(0). Sending funds or "
            "assigning critical roles to address(0) permanently locks them — the zero "
            "address has no private key."
        ),
        "recommendation": (
            "Add: require(addr != address(0), 'zero address');\n"
            "for every address parameter that writes to storage or transfers value."
        ),
        "pattern": re.compile(
            r"function\s+\w+\s*\([^)]*\baddress\b[^)]*\)",
            re.IGNORECASE,
        ),
    },
    # ── block.difficulty / randomness (SWC-120) ───────────────────────────────
    {
        "id": "SWC-120",
        "severity": "HIGH",
        "category": "Bad Randomness",
        "title": "Weak On-Chain Randomness Source",
        "description": (
            "block.difficulty (now block.prevrandao post-Merge), blockhash, and "
            "block.number are not secure randomness sources. Validators/miners can "
            "influence these values, and anyone can predict blockhash for past blocks."
        ),
        "recommendation": (
            "Use Chainlink VRF (Verifiable Random Function) for any randomness that "
            "affects economic outcomes (lotteries, NFT traits, game outcomes)."
        ),
        "pattern": re.compile(
            r"\bblock\.(difficulty|prevrandao|blockhash)\b|\bblockhash\s*\(",
            re.IGNORECASE,
        ),
    },
    # ── Unbounded loop (SWC-128) ──────────────────────────────────────────────
    {
        "id": "SWC-128",
        "severity": "MEDIUM",
        "category": "DoS",
        "title": "Potentially Unbounded Loop",
        "description": (
            "A loop iterates over a storage array or mapping whose length is controlled "
            "by users. A large enough array can exceed the block gas limit, permanently "
            "bricking the function (DoS)."
        ),
        "recommendation": (
            "1) Use a pull-payment pattern instead of looping to push funds.\n"
            "2) If iteration is required, add a per-call limit and a cursor for batching.\n"
            "3) Store length in a variable to avoid repeated SLOAD."
        ),
        "pattern": re.compile(
            r"\bfor\s*\([^;]*;\s*[^;]*\.length\b",
            re.IGNORECASE,
        ),
    },
    # ── Hardcoded address ─────────────────────────────────────────────────────
    {
        "id": "SWC-134",
        "severity": "LOW",
        "category": "Maintainability",
        "title": "Hardcoded Ethereum Address",
        "description": (
            "A literal Ethereum address is embedded in the contract. Hardcoded addresses "
            "cannot be updated if a dependency is upgraded, compromised, or redeployed on "
            "another network, breaking multi-chain deployments."
        ),
        "recommendation": (
            "Pass addresses as constructor arguments or use immutable/constant variables "
            "that are set at deploy time. For upgradeable contracts use a registry pattern."
        ),
        "pattern": re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    },
    # ── Unprotected initializer ───────────────────────────────────────────────
    {
        "id": "SWC-118",
        "severity": "CRITICAL",
        "category": "Access Control",
        "title": "Unprotected Initializer Function",
        "description": (
            "A function named initialize() exists but does not appear to use the "
            "initializer modifier (common in OpenZeppelin upgradeable contracts). "
            "Anyone can call an unprotected initializer to take ownership of the contract."
        ),
        "recommendation": (
            "Add the initializer modifier from OpenZeppelin Initializable:\n"
            "function initialize(...) public initializer { ... }\n"
            "Or restrict with onlyOwner / a one-time flag."
        ),
        "pattern": re.compile(
            r"function\s+initialize\s*\([^)]*\)\s*(public|external)(?!\s*initializer)",
            re.IGNORECASE,
        ),
    },
    # ── ERC20 approve race condition ──────────────────────────────────────────
    {
        "id": "SWC-114",
        "severity": "MEDIUM",
        "category": "ERC20",
        "title": "ERC20 approve() Race Condition",
        "description": (
            "The standard ERC20 approve() function is vulnerable to a front-running race: "
            "when changing an allowance from N to M, an attacker can spend the original N "
            "tokens before the new M allowance is set, spending N+M total."
        ),
        "recommendation": (
            "Use increaseAllowance()/decreaseAllowance() from OpenZeppelin ERC20 instead. "
            "Alternatively require the current allowance be zero before setting a new value: "
            "require(allowance[owner][spender] == 0 || amount == 0)."
        ),
        "pattern": re.compile(
            r"function\s+approve\s*\(\s*address[^)]*uint\d*[^)]*\)\s*(public|external)",
            re.IGNORECASE,
        ),
    },
    # ── Missing event on state change ────────────────────────────────────────
    {
        "id": "SWC-EVENT",
        "severity": "INFO",
        "category": "Best Practice",
        "title": "Setter Function Without Event Emission",
        "description": (
            "A public/external function that appears to change state does not emit an "
            "event. Without events, off-chain indexers, explorers, and monitoring tools "
            "cannot track state changes, making auditing and incident response harder."
        ),
        "recommendation": (
            "Define an event for every significant state change and emit it.\n"
            "Example: event ValueSet(address indexed caller, uint256 newValue);\n"
            "emit ValueSet(msg.sender, newValue);"
        ),
        "pattern": re.compile(
            r"function\s+set\w*\s*\([^)]*\)\s*(public|external)(?![^{]*emit\b)",
            re.IGNORECASE,
        ),
    },
    # ── Visibility not specified (SWC-100) ────────────────────────────────────
    {
        "id": "SWC-100",
        "severity": "LOW",
        "category": "Best Practice",
        "title": "Function Visibility Not Explicitly Stated",
        "description": (
            "Solidity <0.5.0 defaults to public for functions without explicit visibility. "
            "Missing visibility specifiers make intent unclear and can accidentally expose "
            "internal logic."
        ),
        "recommendation": (
            "Always explicitly mark function visibility: public, external, internal, or private. "
            "Use external for functions not called internally (saves gas)."
        ),
        "pattern": re.compile(
            r"function\s+\w+\s*\([^)]*\)\s*(?:view|pure|payable)?\s*\{",
            re.IGNORECASE,
        ),
    },
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class StaticAnalyzer:
    """
    Line-by-line pattern scanner.
    Each rule fires at most once per unique (rule_id, line_number) pair.
    Results are sorted: CRITICAL → INFO.
    """

    def analyze(self, source_code: str, min_severity: str = "INFO") -> list[Finding]:
        threshold = SEVERITY_ORDER.get(min_severity.upper(), 4)
        lines = source_code.splitlines()
        findings: list[Finding] = []
        seen: set[str] = set()

        for rule in PATTERNS:
            # Skip rules below threshold
            if SEVERITY_ORDER.get(rule["severity"], 99) > threshold:
                continue

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
                            swc_id=rule["id"],
                        )
                    )

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        return findings

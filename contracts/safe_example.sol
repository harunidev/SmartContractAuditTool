// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * SafeBank — demonstrates security best practices for comparison.
 * This contract is intentionally clean to contrast with vulnerable.sol.
 *
 * Best practices applied:
 *  - Pinned compiler version (0.8.24)
 *  - ReentrancyGuard on all ETH-transferring functions
 *  - Checks-Effects-Interactions pattern
 *  - msg.sender instead of tx.origin
 *  - Zero-address validation
 *  - Events emitted on all state changes
 *  - No selfdestruct
 *  - No user-controlled delegatecall
 *  - Address.sendValue instead of .transfer()
 */
contract SafeBank is ReentrancyGuard, Ownable {
    using Address for address payable;

    mapping(address => uint256) private _balances;
    uint256 public constant MAX_DEPOSIT = 100 ether;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    address public feeRecipient;

    constructor(address _feeRecipient) Ownable(msg.sender) {
        require(_feeRecipient != address(0), "SafeBank: zero address");
        feeRecipient = _feeRecipient;
    }

    // ── Deposit ──────────────────────────────────────────────────────────────

    function deposit() external payable {
        require(msg.value > 0, "SafeBank: zero deposit");
        require(msg.value <= MAX_DEPOSIT, "SafeBank: exceeds max deposit");

        // Effects before interactions
        _balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // ── Withdraw (ReentrancyGuard + CEI) ────────────────────────────────────

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "SafeBank: zero amount");
        require(_balances[msg.sender] >= amount, "SafeBank: insufficient balance");

        // Effects BEFORE external call
        _balances[msg.sender] -= amount;
        emit Withdrawn(msg.sender, amount);

        // Interaction last
        payable(msg.sender).sendValue(amount);
    }

    // ── Admin ────────────────────────────────────────────────────────────────

    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "SafeBank: zero address");
        emit RecipientUpdated(feeRecipient, newRecipient);
        feeRecipient = newRecipient;
    }

    // ── View ─────────────────────────────────────────────────────────────────

    function balanceOf(address user) external view returns (uint256) {
        return _balances[user];
    }
}

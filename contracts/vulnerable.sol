// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * Intentionally vulnerable contract for testing SmartContractAuditTool.
 * DO NOT DEPLOY.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    // SWC-107: Reentrancy — state updated AFTER external call
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;   // too late!
    }

    // SWC-115: tx.origin auth
    function onlyOwnerAction() public {
        require(tx.origin == msg.sender, "Not owner");
        // privileged action
    }

    // SWC-116: Block timestamp dependence
    function isLucky() public view returns (bool) {
        return block.timestamp % 15 == 0;
    }

    // SWC-106: Selfdestruct
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // SWC-112: Delegatecall to arbitrary address
    function proxyCall(address impl, bytes calldata data) public {
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // Assembly usage
    function getBalance() public view returns (uint256 bal) {
        assembly {
            bal := selfbalance()
        }
    }

    // Missing zero-address check
    function setRecipient(address recipient) public {
        balances[recipient] = 100;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * DeFiVault — realistic DeFi contract with subtle vulnerabilities.
 * Use this as a more challenging audit target than vulnerable.sol.
 *
 * Intentional issues (find them!):
 *  1. Price oracle manipulation via spot price
 *  2. Missing slippage protection
 *  3. Reward calculation rounding error
 *  4. Front-running risk on deposit
 *  5. Uncapped loop over depositors
 */
contract DeFiVault {
    address public token;
    address public priceOracle;

    mapping(address => uint256) public shares;
    mapping(address => uint256) public lastDepositBlock;
    address[] public depositors;

    uint256 public totalShares;
    uint256 public rewardPool;

    constructor(address _token, address _oracle) {
        require(_token != address(0));
        token = _token;
        priceOracle = _oracle;
    }

    // Issue 1: spot-price oracle — manipulable via flash loan
    function getPrice() public view returns (uint256) {
        (bool ok, bytes memory data) = priceOracle.staticcall(
            abi.encodeWithSignature("getSpotPrice(address)", token)
        );
        require(ok);
        return abi.decode(data, (uint256));
    }

    // Issue 2: no slippage check
    function deposit(uint256 tokenAmount) external {
        uint256 price = getPrice();
        uint256 newShares = tokenAmount * price / 1e18;

        if (shares[msg.sender] == 0) {
            depositors.push(msg.sender);
        }

        shares[msg.sender] += newShares;
        totalShares += newShares;
        lastDepositBlock[msg.sender] = block.number;
    }

    // Issue 3: integer division truncation causes dust loss
    function claimReward() external {
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "No shares");
        uint256 reward = rewardPool * userShares / totalShares;
        rewardPool -= reward;
        // transfer reward ...
    }

    // Issue 4: front-running — attacker sees pending tx and sandwiches
    function swap(uint256 amountIn, uint256 minOut) external {
        uint256 price = getPrice();
        uint256 amountOut = amountIn * price / 1e18;
        require(amountOut >= minOut, "Slippage");
        // execute swap ...
    }

    // Issue 5: unbounded loop — DoS if depositors list grows large
    function distributeRewards(uint256 amount) external {
        rewardPool += amount;
        for (uint256 i = 0; i < depositors.length; i++) {
            address dep = depositors[i];
            uint256 share = shares[dep] * amount / totalShares;
            // send share to dep ...
            (bool ok,) = dep.call{value: share}("");
            require(ok);
        }
    }

    receive() external payable {}
}

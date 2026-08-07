// SPDX-License-Identifier: MIT
// SYNTHETIC deliberately-vulnerable contract — the fixture the `evm-external-flow` playbook maps.
// This is NOT a real protocol. It exists only so the /code-scan web3 audit demo has a small,
// public, synthetic Solidity target to fan out over (never a real client's private source in a
// screenshot). Each external function carries one classic, attacker-reachable loss-of-funds bug so
// the enumerate -> flows -> verify pipeline has something concrete to find. Do not deploy this.
pragma solidity ^0.8.19;

interface IPriceFeed {
    function latestAnswer() external view returns (int256);
}

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;
    IPriceFeed public feed;
    IPair public pair;

    // ACCESS CONTROL: privileged initializer is external with no owner/role guard. Anyone can
    // call it after deploy (or re-call it) to seize ownership of the vault.
    function initialize(address _owner) external {
        owner = _owner;
        feed = IPriceFeed(address(0));
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // REENTRANCY: sends value with a low-level call BEFORE zeroing the caller's balance
    // (checks-effects-interactions violated). A malicious receive() re-enters and drains the pool.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // ORACLE: consumes the feed price with no staleness / round check, then pays out against it.
    function borrowAgainstPrice(uint256 collateral) external {
        int256 price = feed.latestAnswer();
        uint256 credit = collateral * uint256(price);
        balances[msg.sender] += credit;
    }

    // FLASH-LOAN ORACLE: derives the exchange rate from AMM spot reserves in-transaction.
    function swapUsingSpot(uint256 amountIn) external returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 out = (amountIn * r1) / r0;
        balances[msg.sender] += out;
        return out;
    }

    // UNCHECKED MATH: reward math runs in an unchecked block; a large multiplier wraps the total.
    function accrue(uint256 rate, uint256 units) external {
        unchecked {
            balances[msg.sender] += rate * units;
        }
    }

    // DELEGATECALL: forwards to an attacker-influenced target in this contract's storage context.
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // tx.origin AUTH: a phished victim calling a malicious contract still passes this check.
    function rescue(address to) external {
        require(tx.origin == owner, "not owner");
        payable(to).transfer(address(this).balance);
    }
}

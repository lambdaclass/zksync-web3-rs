// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ValueStorage {
    uint256 private storedValue;

    constructor(uint256 initialValue) {
        storedValue = initialValue;
    }

    function setValue(uint256 newValue) public {
        storedValue = newValue;
    }

    function getValue() public view returns (uint256) {
        return storedValue;
    }
}

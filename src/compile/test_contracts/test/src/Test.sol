
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.6 <0.9.0; 
contract Test {
    // Declaring variable
    string str = "Hello World!";
 
    // Defining a function to return value of variable 'str'
    function str_out() public view returns(string memory){
        return str;
    }

    function plus_one(uint256 value) public view returns(uint256) {
        return value + 1;
    }
}

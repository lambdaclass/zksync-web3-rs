use ethers_contract::abigen;

abigen!(ERC20, "abi/IERC20.json");

abigen!(
    MINT_IERC20,
    "[function mint(address _to, uint256 _amount) public returns (bool)]"
);

# zksync-web3-rs

## CLI
### Installation

```
git clone git@github.com:lambdaclass/zksync-web3-rs.git
cd zksync-web3-rs
make cli
```

### Usage

Running `zksync-web3-cli` outputs the following:

```
Usage: zksync-web3-cli [OPTIONS] <COMMAND>

Commands:
  deploy
  call
  get-contract
  get-transaction
  help             Print this message or the help of the given subcommand(s)

Options:
      --host <HOST>  [default: 65.108.204.116]
  -p, --port <PORT>  [default: 8545]
  -h, --help         Print help
  -V, --version      Print version
```

#### `zksync-web3-cli deploy`

Deploys the contract located in `CONTRACT_PATH/src` signing the transaction with `PRIVATE_KEY`.

```
zksync-web3-cli deploy --contract <CONTRACT_PATH> --private-key <PRIVATE_KEY>
```

#### `zksync-web3-cli call`

Calls `FUNCTION_SIGNATURE` of `CONTRACT_ADDRESS` with args `FUNCTION_ARGS`. If you want o call a `public view` contract function then you don't need to provide your `PRIVATE_KEY`. You must provide the latter only if you want to call a contract function that performs a state change.

```
zksync-web3-cli call --contract <CONTRACT_ADDRESS> --function <FUNCTION_SIGNATURE> --args <FUNCTION_ARGS> --private-key <PRIVATE_KEY>
```

#### `zksync-web3-cli get-contract`

Gets `CONTRACT_ADDRESS`'s bytecode.

```
zksync-web3-cli get-contract --contract <CONTRACT_ADDRESS>
```

#### `zksync-web3-cli get-transaction`

Get the transaction corresponding to `TRANSACTION_HASH`.

```
zksync-web3-cli get-transaction --transaction <TRANSACTION_HASH>
```

#### `zksync-web3-cli balance`

Gets the balance of the `ACCOUNT_ADDRESS`.

```
zksync-web3-cli balance --account <ACCOUNT_ADDRESS>
```

#### `zksync-web3-cli pay`

Pays `AMOUNT` from `SENDER_ADDRESS` to `RECEIVER_ADDRESS` signing the transaction with `SENDER_PRIVATE_KEY`.

```
zksync-web3-cli pay --amount <AMOUNT_TO_TRANSFER> --from <SENDER_ADDRESS> --to <RECEIVER_ADDRESS> --private-key <SENDER_PRIVATE_KEY>
```

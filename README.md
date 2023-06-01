# zksync-web3-rs

## EIP712 on zkSync Era

The Ethereum Improvement Proposal [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712) introduces hashing and signing of typed-structured data as well as bytestrings.

In the following sections we'll explain how to build, sign, encode and send a well-formed EIP712 transaction request to the network.

The steps:

1. Create a base request and fill it with sufficient data for estimating the fee.
2. Estimate the fee and add it the request.
3. Derive the EIP712 signable transaction from the request and sign it and add the signature to the request.
5. RLP-encode the request and concatenate the transaction type at the beginning.
6. Send the transaction using the `sendRawTransaction` method.

### Building an EIP712 transaction request

These transactions have the same fields as standard Ethereum transactions, but they also have fields that contain additional L2-specific data that should be set in the `customData` field.

In the case of zkSync Era, this fields are the following:

- `gasPerPubdata`: A field denoting the maximum amount of gas the user is willing to pay for a single byte of pubdata.
- `customSignature`: A field with a custom signature for the cases in which the signer's account is not an EOA.
- `paymasterParams`: A field with parameters for configuring the custom paymaster for the transaction. Parameters include the address of the paymaster and the encoded input (you could find a tutorial on building a custom paymaster in the [zkSync Era docs](https://era.zksync.io/docs/dev/tutorials/custom-paymaster-tutorial.html)).
- `factory_deps`: A non-empty array of bytes. For deployment transactions, it should contain the bytecode of the contract being deployed. If the contract is a factory contract, i.e. it can deploy other contracts, the array should also contain the bytecodes of the contracts which it can deploy.

This is how a noop `customData` object looks like:

```json
"customData": {
  "gasPerPubdata": "0xc350",
  "factoryDeps": [],
  "customSignature": "0x",
  "paymasterParams": {
    "paymaster": "0x0000000000000000000000000000000000000000",
    "paymasterInput": "0x"
  }
}
```

We call the representation of this structure `Eip712Meta` and its definition and implementation is located in the [`src/eip712/meta.rs`](/src/eip712/meta.rs) module.

The transaction request is built in three stages being the final the one being encoded and sent to the network. 

In the first stage you fill the request with *input data* (i.e. this could be `from`, `to`, `nonce`, `gasPrice`, `value`, `chainId`, `type` in the case of a transfer transaction). In the second stage the request is filled with fee data obtained from the network given the first stage's result (i.e. `maxFeePerGas`, `maxPriorityFeePerGas`, `gasPerPubdata`, `gasLimit`). Finally, the last stage consists on adding the EIP712 signature to the `customSignature` field of the `customData` object.

This is how a noop EIP712 transaction request looks like:

```json
{
  "to": "0x0000000000000000000000000000000000000000",
  "from": "0x0000000000000000000000000000000000000000",
  "nonce": "0x0",
  "gasLimit": "0x0",
  "gasPrice": "0x0",
  "data": "0x",
  "value": "0x0",
  "chainId": "0x10e",
  "type": "0x71",
  "accessList": [],
  "maxPriorityFeePerGas": "0x0",
  "maxFeePerGas": "0x0",
  "customData": {
    "gasPerPubdata": "0xc350",
    "factoryDeps": [],
    "customSignature": "0x",
    "paymasterParams": {
      "paymaster": "0x0000000000000000000000000000000000000000",
      "paymasterInput": "0x"
    }
  },
  "ccipReadEnabled": false
}
```

### Building an EIP712 signable transaction

Instead of signing the RLP-encoded transaction, the user signs the a typed EIP712 structure which we called `Eip712Transaction`. This structure is built from the transaction request as it contains a subset of its fields. The `Eip712Transaction` structure is defined in the [`src/eip712/transaction.rs`](/src/eip712/transaction.rs) module and a noop one looks like the following:

```json
{
  "txType": "0x71",
  "from": "0x0000000000000000000000000000000000000000",
  "to": "0x0000000000000000000000000000000000000000",
  "gasLimit": "0x0",
  "gasPerPubdataByteLimit": "0xc350",
  "maxFeePerGas": "0x0",
  "maxPriorityFeePerGas": "0x0",
  "paymaster": "0x0000000000000000000000000000000000000000",
  "nonce": "0x0",
  "value": "0x0",
  "data": "0x",
  "factoryDeps": [],
  "paymasterInput": "0x"
}
```

### Encoding an EIP712 transaction

### Signing an EIP712 transaction

### Sending an EIP712 transaction request

What is sent to the network is the concatenation of the transaction type with the RLP-encoding of the transaction request containing the signed message.

## zkSync Era’s JSON-RPC methods

### The `ZKSProvider` trait

zkSync Era fully supports the standard [Ethereum JSON-RPC API](https://ethereum.org/en/developers/docs/apis/json-rpc/) and adds some L2-specific features.

> As long as code does not involve deploying new smart contracts, which can only be deployed using [EIP712 transactions](https://era.zksync.io/docs/api/api.html#eip712), *no changes to the codebase are needed*.

zkSync Era The `ZKSProvider` trait defines the methods that can be used to interact with [zkSync Era's JSON-RPC API](https://era.zksync.io/docs/api/api.html#zksync-era-json-rpc-methods) (the previously L2-specific features mentioned above).
### Status (for full compatibility)

| RPC Method                        | Description                                                                                                                                                                                                                                                                                                                                         | Supported | Tested |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------ |
| `debug_traceBlockByHash`      | Returns debug trace of all executed calls contained in a block given by its L2 hash.                                                                                                                                                                                                                                                                | ✅        | ❌     |
| `debug_traceBlockByNumber`    | Returns debug trace of all executed calls contained in a block given by its L2 block number.                                                                                                                                                                                                                                                        | ✅        | ❌     |
| `debug_traceCall`             | Returns debug trace containing information on a specific calls given by the call request.                                                                                                                                                                                                                                                           | ✅        | ❌     |
| `debug_traceTransaction`      | Uses the [EVM's `callTracer`](https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers#call-tracer) to return a debug trace of a specific transaction given by its transaction hash.                                                                                                                                                  | ✅        | ❌     |
| `zks_estimateFee`             | Returns the fee for the transaction.                                                                                                                                                                                                                                                                                                                | ✅        | ✅     |
| `zks_estimateGasL1ToL2`       | Returns an estimate of the gas required for a L1 to L2 transaction.                                                                                                                                                                                                                                                                                 | ✅        | ✅     |
| `zks_getAllAccountBalances`   | Returns all balances for confirmed tokens given by an account address.                                                                                                                                                                                                                                                                              | ✅        | ✅     |
| `zks_getBlockDetails`         | Returns additional zkSync-specific information about the L2 block. `committed`: The batch is closed and the state transition it creates exists on layer 1. `proven`: The batch proof has been created, submitted, and accepted on layer 1. `executed`: The batch state transition has been executed on L1; meaning the root state has been updated. | ✅        | ✅     |
| `zks_getBridgeContracts`      | Returns L1/L2 addresses of default bridges.                                                                                                                                                                                                                                                                                                         | ✅        | ✅     |
| `zks_getBytecodeByHash`       | Returns bytecode of a transaction given by its hash.                                                                                                                                                                                                                                                                                                | ✅        | ✅     |
| `zks_getConfirmedTokens`      | Returns [address, symbol, name, and decimal] information of all tokens within a range of ids given by parameters from and limit. **Confirmed** in the method name means the method returns any token bridged to zkSync via the official bridge.                                                                                                     | ✅        | 🏗      |
| `zks_getL1BatchBlockRange`    | Returns the range of blocks contained within a batch given by batch number. The range is given by beginning/end block numbers in hexadecimal.                                                                                                                                                                                                       | ✅        | ✅     |
| `zks_getL1BatchDetails`       | Returns data pertaining to a given batch.                                                                                                                                                                                                                                                                                                           | ✅        | ✅     |
| `zks_getL2ToL1LogProof`       | Given a transaction hash, and an index of the L2 to L1 log produced within the transaction, it returns the proof for the corresponding L2 to L1 log. The index of the log that can be obtained from the transaction receipt (it includes a list of every log produced by the transaction).                                                          | ✅        | ✅     |
| `zks_getL2ToL1MsgProof`       | Given a block, a sender, a message, and an optional message log index in the block containing the L1->L2 message, it returns the proof for the message sent via the L1Messenger system contract.                                                                                                                                                    | ✅        | ❌     |
| `zks_getMainContract`         | Returns the address of the zkSync Era contract.                                                                                                                                                                                                                                                                                                     | ✅        | ✅     |
| `zks_getRawBlockTransactions` | Returns data of transactions in a block.                                                                                                                                                                                                                                                                                                            | ✅        | ✅     |
| `zks_getTestnetPaymaster`     | Returns the address of the [testnet paymaster](https://era.zksync.io/docs/dev/developer-guides/aa.html#testnet-paymaster): the paymaster that is available on testnets and enables paying fees in ERC-20 compatible tokens.                                                                                                                         | ✅        | ✅     |
| `zks_getTokenPrice`           | Returns the price of a given token in USD.                                                                                                                                                                                                                                                                                                          | ✅        | ✅     |
| `zks_getTransactionDetails`   | Returns data from a specific transaction given by the transaction hash.                                                                                                                                                                                                                                                                             | ✅        | ✅     |
| `zks_L1BatchNumber`           | Returns the latest L1 batch number.                                                                                                                                                                                                                                                                                                                 | ✅        | ✅     |
| `zks_L1ChainId`               | Returns the chain id of the underlying L1.                                                                                                                                                                                                                                                                                                          | ✅        | ✅     |

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

#### `zksync-web3-cli compile`

> This command is a wrapper for the zksolc compiler.

Compiles the contract located in `PATH_TO_CONTRACT` using the zksolc compiler.

```
zksync-web3-cli compile --solc <PATH_TO_SOLC> --standard-json -- <PATH_TO_CONTRACT>
```

##### Status (for full compatibility)

| Flags                      | Description                                                                                                                                                                                                                                                 | Supported | State |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----- |
| `--disable-solc-optimizer` | Disable the `solc` optimizer. Use it if your project uses the `MSIZE` instruction, or in other cases. Beware that it will prevent libraries from being inlined                                                                                              | ❌        | ❌    |
| `--force-evmla`            | Forcibly switch to the EVM legacy assembly pipeline. It is useful for older revisions of `solc` 0.8, where Yul was considered highly experimental and contained more bugs than today                                                                        | ❌        | ❌    |
| `-h, --help`               | Prints help information                                                                                                                                                                                                                                     | ✅        | ✅    |
| `--system-mode`            | Enable the system contract compilation mode. In this mode zkEVM extensions are enabled. For example, calls to addresses `0xFFFF` and below are substituted by special zkEVM instructions. In the Yul mode, the `verbatim_*` instruction family is available | ❌        | ❌    |
| `--llvm-debug-logging`     | Set the debug-logging option in LLVM. Only for testing and debugging                                                                                                                                                                                        | ❌        | ❌    |
| `--llvm-ir`                | Switch to the LLVM IR mode. Only one input LLVM IR file is allowed. Cannot be used with the combined and standard JSON modes                                                                                                                                | ❌        | ❌    |
| `--llvm-verify-each`       | Set the verify-each option in LLVM. Only for testing and debugging                                                                                                                                                                                          | ❌        | ❌    |
| `--asm`                    | Output zkEVM assembly of the contracts                                                                                                                                                                                                                      | ❌        | ❌    |
| `--bin`                    | Output zkEVM bytecode of the contracts                                                                                                                                                                                                                      | ❌        | ❌    |
| `--overwrite`              | Overwrite existing files (used together with -o)                                                                                                                                                                                                            | ❌        | ❌    |
| `--standard-json`          | Switch to standard JSON input/output mode. Read from stdin, write the result to stdout. This is the default used by the hardhat plugin                                                                                                                      | ❌        | 🏗     |
| `--version`                | Print the version and exit                                                                                                                                                                                                                                  | ❌        | ❌    |
| `--yul`                    | Switch to the Yul mode. Only one input Yul file is allowed. Cannot be used with the combined and standard JSON modes                                                                                                                                        | ❌        | ❌    |

| Options                                       | Description                                                                                                                                                                                                                      | Supported | State |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----- |
| `--allow-paths <allow-paths>`                 | Allow a given path for imports. A list of paths can be supplied by separating them with a comma. Passed to `solc` without changes                                                                                                | ❌        | ❌    |
| `--base-path <base-path>`                     | Set the given path as the root of the source tree instead of the root of the filesystem. Passed to `solc` without changes                                                                                                        | ❌        | ❌    |
| `--combined-json <combined-json>`             | Output a single JSON document containing the specified information. Available arguments: `abi`, `hashes`, `metadata`, `devdoc`, `userdoc`, `storage-layout`, `ast`, `asm`, `bin`, `bin-runtime`                                  | ✅        | ✅    |
| `--debug-output-dir <debug-output-directory>` | Dump all IRs to files in the specified directory. Only for testing and debugging                                                                                                                                                 | ❌        | ❌    |
| `--include-path <include-paths>...`           | Make an additional source directory available to the default import callback. Can be used multiple times. Can only be used if the base path has a non-empty value. Passed to `solc` without changes                              | ❌        | ❌    |
| `-l, --libraries <libraries>...`              | Specify addresses of deployable libraries. Syntax: `<libraryName>=<address> [, or whitespace] ...`. Addresses are interpreted as hexadecimal strings prefixed with `0x`                                                          | ❌        |   ❌    |
| `--metadata-hash <metadata-hash>`             | Set the metadata hash mode. The only supported value is `none` that disables appending the metadata hash. Is enabled by default                                                                                                  | ❌        |   ❌    |
| `-O, --optimization <optimization>`           | Set the optimization parameter -O\[0 \| 1 \| 2 \| 3 \| s \| z\]. Use `3` for best performance and `z` for minimal size                                                                                                           | ❌        |      ❌ |
| `-o, --output-dir <output-directory>`         | Create one file per component and contract/file at the specified directory, if given                                                                                                                                             | ❌        |      ❌ |
| `--solc <solc>`                               | Specify the path to the `solc` executable. By default, the one in `${PATH}` is used. Yul mode: `solc` is used for source code validation, as `zksolc` itself assumes that the input Yul is valid. LLVM IR mode: `solc` is unused | ✅        |  🏗     |

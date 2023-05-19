# zksync-web3-rs

## Table of Contents

- [Getting Started with zkSync Web3 SDK](#getting-started-with-zksync-web3-sdk)
    - [Prerequisites](#prerequisites)
    - [Clone the Repository](#clone-the-repository)
    - [Running the Payment Transaction Example](#running-the-payment-transaction-example)
    - [Conclusion](#conclusion)
- [CLI](#cli)
    - [Installation](#installation)
    - [Usage](#usage)
        - [`zksync-web3-cli deploy`](#zksync-web3-cli-deploy)
        - [`zksync-web3-cli call`](#zksync-web3-cli-call)
        - [`zksync-web3-cli get-contract`](#zksync-web3-cli-get-contract)
        - [`zksync-web3-cli get-transaction`](#zksync-web3-cli-get-transaction)
        - [`zksync-web3-cli balance`](#zksync-web3-cli-balance)
        - [`zksync-web3-cli pay`](#zksync-web3-cli-pay)
        - [`zksync-web3-cli compile`](#zksync-web3-cli-compile)


## Getting Started with zkSync Web3 SDK

The `zksync-web3-rs` SDK is meant for developers who want to develop on zkSync Era's testnet using Rust code. This guide will walk you through the process of getting started with the SDK and running a payment transaction example using EIP1559 transactions on zkSync Era.

### Prerequisites

Before you begin, make sure you have the following prerequisites:

- Rust: Ensure that Rust is installed on your system. You can install Rust by following the instructions at [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

- Git: Install Git on your system if you haven't already. You can find installation instructions at [https://git-scm.com/book/en/v2/Getting-Started-Installing-Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

### Clone the Repository

To get started, clone the `zksync-web3-rs` repository from GitHub. Open a terminal or command prompt and execute the following commands:

```bash
git clone https://github.com/lambdaclass/zksync-web3-rs.git
cd zksync-web3-rs
```

### Step by step explanation [WIP]

The example payment transaction code can be found in the `main.rs` file located in the `examples/simple_payment` directory of the repository.

### Running the Payment Transaction Example

To run the payment transaction example using EIP1559 transactions on zkSync Era, run the following command:

```bash
make simple_payment HOST=<host> PORT=<port> AMOUNT=<amount_to_transfer> SENDER_ADDRESS=<sender> RECEIVER_ADDRESS=<receiver> PRIVATE_KEY=<pk> NETWORK=<net>
```

- `HOST`: The IP address or hostname of the L1 node where zkSync is running.
- `PORT`: The port number used to connect to the L1 node (usually `8545`).
- `AMOUNT`: The amount to transfer, specified in wei. For example, if you want to transfer 1 ETH, specify `1000000000000000000` (which is 10^18 wei).
- `SENDER_ADDRESS`: The address of the sender's Ethereum account, represented in hexadecimal format with the `0x` prefix. For example, `0x123abc...`.
- `RECEIVER_ADDRESS`: The address of the receiver's Ethereum account, represented in hexadecimal format with the `0x` prefix. For example, `0x456def...`.
- `PRIVATE_KEY`: The private key of an Ethereum account with sufficient funds to perform the transaction, represented in hexadecimal format with the `0x` prefix.
- `NETWORK`: The network you want to connect to. There are two options: `era` which will connect to the L2 node and `eth` which will connect to the L1 node.

**Note:** Ensure that you have properly configured the environment variables or provided the required values as command-line arguments.

This command executes the `simple_payment` binary using the provided Makefile.

### Conclusion

Congratulations! You have successfully completed the "Getting Started" guide for the `zksync-web3-rs` SDK. You have learned how to send a simple payment transaction example using EIP1559 transactions on zkSync Era.

By exploring the example code and the repository's documentation, you can further enhance your understanding of interacting with zkSync Era's testnet using the `zksync-web3-rs` SDK.

Feel free to experiment with different configurations and explore other functionalities provided by the SDK.

If you have any questions or need further assistance, don't hesitate to reach out to the repository's community or maintainers.

Happy coding!


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

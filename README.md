# zksync-web3-rs

## Table of Contents

- [Getting Started with zkSync Web3 SDK](#getting-started-with-zksync-web3-sdk)
  - [Prerequisites](#prerequisites)
  - [Adding dependencies](#adding-dependencies)
  - [First steps](#first-steps)
    - [Importing dependencies](#importing-dependencies)
    - [Creating a Wallet](#creating-a-wallet)
    - [Connecting to the zkSync Network](#connecting-to-the-zksync-network)
    - [Creating a Payment Transaction](#creating-a-payment-transaction)
    - [Sending the Transaction](#sending-the-transaction)
    - [Checking zkSync account balance](#checking-zksync-account-balance)
  - [Simple Transfer Example](#simple-transfer-example)
    - [Clone the Repository](#clone-the-repository)
    - [Run a zkSync localnet](#run-a-zksync-localnet)
    - [Run the Simple Transfer Example](#run-the-simple-transfer-example)
  - [Conclusion](#conclusion)
- [CLI](#cli)
  - [Installation](#installation)
  - [Usage](#usage)
    - [`zksync-web3-rs deploy`](#zksync-web3-rs-deploy)
    - [`zksync-web3-rs call`](#zksync-web3-rs-call)
    - [`zksync-web3-rs get-contract`](#zksync-web3-rs-get-contract)
    - [`zksync-web3-rs get-transaction`](#zksync-web3-rs-get-transaction)
    - [`zksync-web3-rs balance`](#zksync-web3-rs-balance)
    - [`zksync-web3-rs pay`](#zksync-web3-rs-pay)
    - [`zksync-web3-rs compile`](#zksync-web3-rs-compile)
      - [Status (for full compatibility)](#status-for-full-compatibility)


## Getting Started with zkSync Web3 SDK

While most of the existing SDKs should work out of the box, deploying smart contracts or using unique zkSync features, like account abstraction, requires providing additional fields to those that Ethereum transactions have by default.

To provide easy access to all of the features of zkSync Era, the `zksync-web3-rs` Rust SDK was created, which is made in a way that has an interface very similar to those of [ethers](https://docs.ethers.io/v5/). In fact, ethers is a peer dependency of our library and most of the objects exported by `zksync-web3-rs` (e.g. `Provider` etc.) inherit from the corresponding `ethers` objects and override only the fields that need to be changed.

The library is made in such a way that after replacing `ethers` with `zksync-web3-rs` most client apps will work out of box.

### Prerequisites

Before you begin, make sure you have the following prerequisites:

- Rust: Ensure that Rust is installed on your system. You can install Rust by following the instructions at [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install).

- Git: Install Git on your system if you haven't already. You can find installation instructions at [https://git-scm.com/book/en/v2/Getting-Started-Installing-Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

- zkSync CLI (only if you want to run a localnet): Install the zkSync CLI on your system
  > This particular CLI command uses Docker under the hood, you should also have Docker installed on your system. You can find installation instructions at [https://docs.docker.com/get-docker/](https://docs.docker.com/get-docker/).

  ```bash
  git clone https://github.com/lambdaclass/zksync-cli.git
  cd zksync-cli
  npm i -g && npm run build
  zksync-cli localnet up
  ```

### Adding dependencies

Add the following dependencies to your `Cargo.toml` file:

```bash
zksync-web3-rs = { git = "https://www.github.com/lambdaclass/zksync-web3-rs" }
```

> Maybe consider adding tokio as dependency since we are using a lot of async/await functions. If this example is meant to be done in the main function the #[tokio::main] annotation is needed.

### First steps

In the following steps, we will show you how to create a payment transaction using the `zksync-web3-rs` library.

#### Importing dependencies

Import the `zksync-web3-rs` library into your project by adding the following line to the top of your `main.rs` file:

```rust
use zksync-web3-rs as zksync;
```

#### Creating a Wallet

To create a wallet, you need to provide the private key of the Ethereum account that will be used to sign the transaction. You can create a wallet using the following code:

> We set the chain id to 270 because we are using the zkSync Era node. If you want to use the mainnet, you should set the chain id to 9.
> https://era.zksync.io/docs/api/hardhat/testing.html#connect-wallet-to-local-nodes

```rust
use zksync::{Signer, k256::ecdsa::SigningKey};

let private_key: Wallet<SigningKey> = "0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110".parse().unwrap();
let zksync_era_chain_id: u64 = 270;

let wallet = zksync::Wallet::with_chain_id(private_key, zksync_era_chain_id);
```

#### Connecting to the zkSync Network

To connect to the zkSync network, you need to provide the URL of the zkSync node. The localnet runs both an *Ethereum* node (L1) on port `8545` and an *Era* node (L2) on port `3050`. You can connect to the zkSync Era network using the following code:

```rust
let provider = zksync::Provider::try_from("http://65.21.140.36:3050").unwrap();
```

#### Creating a Payment Transaction

To create a payment transaction, you need to provide the sender's address, the receiver's address, and the amount to transfer. You can create a payment transaction using the following code:

```rust
use zksync::zks_provider::ZKSProvider;

let sender_address: zksync::Address = "0x36615Cf349d7F6344891B1e7CA7C72883F5dc049".parse().unwrap();
let receiver_address: zksync::Address = "0xa61464658AfeAf65CccaaFD3a512b69A83B77618".parse().unwrap();
let amount_to_transfer = zksync::U256::from(1);

let mut payment_request = zksync::Eip1559TransactionRequest::new()
    .from(sender_address)
    .to(receiver_address)
    .value(amount_to_transfer);

let fee = provider
    .clone()
    .estimate_fee(payment_request.clone())
    .await
    .unwrap();

payment_request = payment_request.max_priority_fee_per_gas(fee.max_priority_fee_per_gas);
payment_request = payment_request.max_fee_per_gas(fee.max_fee_per_gas);

let transaction: zksync::TypedTransaction = payment_request.into();
```

#### Sending the Transaction

To send the transaction, you need to provide the wallet and the transaction. You can send the transaction using the following code:

> In case you are wondering, the transaction is signed in the `send_transaction` method.

```rust
use zksync::MiddlewareBuilder;

let signer_middleware = provider.clone().with_signer(wallet);

let payment_response: zksync::TransactionReceipt =
    zksync::SignerMiddleware::send_transaction(&signer_middleware, transaction, None)
        .await
        .unwrap()
        .await
        .unwrap()
        .unwrap();
```

#### Checking zkSync account balance

```rust
let sender_balance = provider
    .get_balance(sender_address, None)
    .await
    .unwrap();
```

### Simple Transfer Example

There's an executable example involving the previous steps in the `examples` folder. To run the example, follow the steps below:

#### Clone the Repository

To get started, clone the `zksync-web3-rs` repository from GitHub. Open a terminal or command prompt and execute the following commands:

```bash
git clone https://github.com/lambdaclass/zksync-web3-rs.git
cd zksync-web3-rs
```

#### Run a zkSync localnet

To run the zkSync localnet, execute the following command:

```bash
zksync-cli localnet up
```

#### Run the Simple Transfer Example

To run the payment transaction example using EIP1559 transactions on zkSync Era, run the following command:

```bash
make simple_payment HOST=<host> PORT=<port> AMOUNT=<amount_to_transfer> SENDER_ADDRESS=<sender> RECEIVER_ADDRESS=<receiver> PRIVATE_KEY=<pk> NETWORK=<net>
```

- `HOST`: The IP address or hostname of the node.
- `PORT`: The port number of the node.
- `AMOUNT`: The amount to transfer.
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

Running `zksync-web3-rs` outputs the following:

```
Usage: zksync-web3-rs [OPTIONS] <COMMAND>

Commands:
  deploy
  call
  get-contract
  get-transaction
  help             Print this message or the help of the given subcommand(s)

Options:
      --host <HOST>  [default: 65.21.140.36]
  -p, --port <PORT>  [default: 8545]
  -h, --help         Print help
  -V, --version      Print version
```

#### `zksync-web3-rs deploy`

Deploys the contract located in `CONTRACT_PATH/src` signing the transaction with `PRIVATE_KEY`.

```
zksync-web3-rs deploy --contract <CONTRACT_PATH> --private-key <PRIVATE_KEY>
```

#### `zksync-web3-rs call`

Calls `FUNCTION_SIGNATURE` of `CONTRACT_ADDRESS` with args `FUNCTION_ARGS`. If you want o call a `public view` contract function then you don't need to provide your `PRIVATE_KEY`. You must provide the latter only if you want to call a contract function that performs a state change.

```
zksync-web3-rs call --contract <CONTRACT_ADDRESS> --function <FUNCTION_SIGNATURE> --args <FUNCTION_ARGS> --private-key <PRIVATE_KEY>
```

#### `zksync-web3-rs get-contract`

Gets `CONTRACT_ADDRESS`'s bytecode.

```
zksync-web3-rs get-contract --contract <CONTRACT_ADDRESS>
```

#### `zksync-web3-rs get-transaction`

Get the transaction corresponding to `TRANSACTION_HASH`.

```
zksync-web3-rs get-transaction --transaction <TRANSACTION_HASH>
```

#### `zksync-web3-rs balance`

Gets the balance of the `ACCOUNT_ADDRESS`.

```
zksync-web3-rs balance --account <ACCOUNT_ADDRESS>
```

#### `zksync-web3-rs pay`

Pays `AMOUNT` from `SENDER_ADDRESS` to `RECEIVER_ADDRESS` signing the transaction with `SENDER_PRIVATE_KEY`.

```
zksync-web3-rs pay --amount <AMOUNT_TO_TRANSFER> --from <SENDER_ADDRESS> --to <RECEIVER_ADDRESS> --private-key <SENDER_PRIVATE_KEY>
```

#### `zksync-web3-rs compile`

> This command is a wrapper for the zksolc compiler.

Compiles the contract located in `PATH_TO_CONTRACT` using the zksolc compiler.

```
zksync-web3-rs compile --solc <PATH_TO_SOLC> --standard-json -- <PATH_TO_CONTRACT>
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

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

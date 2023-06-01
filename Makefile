cli:
	cargo install --path .

format:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Examples

simple_payment:
	cargo run --release --example simple_payment -- --host ${HOST} --port ${PORT} --from ${SENDER_ADRESS} --to ${RECEIVER_ADDRESS} --amount ${AMOUNT} --private-key ${PRIVATE_KEY} --network ${NETWORK}

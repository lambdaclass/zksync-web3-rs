cli:
	cargo install --path .

format:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

coverage:
	cargo llvm-cov --lcov --output-path lcov.info -- --test-threads=1

test:
	cargo test -- --test-threads=1

# Examples

simple_payment:
	cargo run --release --example simple_payment -- --host ${HOST} --port ${PORT} --from ${SENDER_ADRESS} --to ${RECEIVER_ADDRESS} --amount ${AMOUNT} --private-key ${PRIVATE_KEY} --network ${NETWORK}

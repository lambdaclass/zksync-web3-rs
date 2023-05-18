cli:
	cargo install --path .

format:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

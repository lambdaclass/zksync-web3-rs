format:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

coverage:
	cargo llvm-cov --lcov --output-path lcov.info -- --test-threads=1

test:
	cargo test -- --test-threads=1

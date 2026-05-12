.PHONY: help check test fmt lint doc ci

help:
	@echo "Available targets:"
	@echo "  check     Check workspace compiles"
	@echo "  test      Run all tests"
	@echo "  fmt       Format code"
	@echo "  lint      Run clippy with warnings as errors"
	@echo "  doc       Build and open docs in browser"
	@echo "  ci        Run all CI checks locally (fmt, clippy, test, doc)"

check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace -- -D warnings

doc:
	cargo doc --no-deps -p wavekat-sip --all-features --open

ci:
	cargo fmt --all -- --check
	cargo clippy --workspace -- -D warnings
	cargo test --workspace
	cargo doc --no-deps -p wavekat-sip --all-features

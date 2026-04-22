# Makefile for Rust project using Cargo

.PHONY: all build check check-no-std run test bench clippy clippy-fix fmt doc update

all: fmt clippy-fix check-no-std

# Build the project with all features enabled in release mode
build:
	cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
	cargo check --workspace --all-features

# Verify no_std compilation (all crates use #![cfg_attr(not(feature = "std"), no_std)])
# CI uses thumbv7m-none-eabi for strict bare-metal verification
check-no-std:
	cargo check -p kobe-primitives --no-default-features
	cargo check -p kobe-primitives --no-default-features --features alloc
	cargo check -p kobe-primitives --no-default-features --features "alloc,bip32,slip10,camouflage"
	cargo check -p kobe-aptos --no-default-features --features alloc
	cargo check -p kobe-btc --no-default-features --features alloc
	cargo check -p kobe-evm --no-default-features --features alloc
	cargo check -p kobe-svm --no-default-features --features alloc
	cargo check -p kobe-cosmos --no-default-features --features alloc
	cargo check -p kobe-tron --no-default-features --features alloc
	cargo check -p kobe-spark --no-default-features --features alloc
	cargo check -p kobe-fil --no-default-features --features alloc
	cargo check -p kobe-ton --no-default-features --features alloc
	cargo check -p kobe-sui --no-default-features --features alloc
	cargo check -p kobe-xrpl --no-default-features --features alloc
	cargo check -p kobe --no-default-features --features alloc
	cargo check -p kobe --no-default-features --features "alloc,all-chains"

# Update dependencies to their latest compatible versions
update:
	cargo update

# Run the project with all features enabled in release mode
run:
	cargo run --release --all-features

# Run all tests with all features enabled
test:
	cargo test --workspace --all-features

# Run benchmarks with all features enabled
bench:
	cargo bench --all-features

# Run Clippy linter with nightly toolchain (check only, for CI)
# Uses workspace lints from Cargo.toml
clippy:
	cargo +nightly clippy --workspace \
		--all-targets \
		--all-features \
		-- -D warnings

# Run Clippy linter with auto-fix (for development)
clippy-fix:
	cargo +nightly clippy --workspace \
		--fix \
		--all-targets \
		--all-features \
		--allow-dirty \
		--allow-staged \
		-- -D warnings

# Format the code using rustfmt with nightly toolchain
fmt:
	cargo +nightly fmt

# Generate documentation for all crates and open it in the browser
doc:
	cargo +nightly doc --all-features --no-deps --open

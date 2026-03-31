# Makefile for Rust project using Cargo

NOSTD_TARGET := thumbv7m-none-eabi

.PHONY: all build check check-no-std run test bench clippy clippy-fix fmt doc update

all: fmt clippy-fix

# Build the project with all features enabled in release mode
build:
	cargo build --workspace --release --all-features

# Check the project for compilation errors without producing binaries
check:
	cargo check --workspace --all-features

# Verify no_std compilation against a bare-metal target (no std available)
# Requires: rustup target add $(NOSTD_TARGET)
check-no-std:
	cargo check -p kobe-core --target $(NOSTD_TARGET) --no-default-features
	cargo check -p kobe-core --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-core --target $(NOSTD_TARGET) --no-default-features --features "alloc,bip32,slip10,camouflage"
	cargo check -p kobe-btc --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-evm --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-svm --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-cosmos --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-tron --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-spark --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-fil --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-ton --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe-sui --target $(NOSTD_TARGET) --no-default-features --features alloc
	cargo check -p kobe --target $(NOSTD_TARGET) --no-default-features --features alloc

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

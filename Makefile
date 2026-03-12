# Makefile for Kobe multi-chain wallet

.PHONY: all
all: pre-commit

.PHONY: build
build:
	cargo build --release --all-features

.PHONY: update
update:
	cargo update

.PHONY: run
run:
	cargo run --release --all-features

.PHONY: test
test:
	cargo test --all-features

.PHONY: bench
bench:
	cargo bench --all-features

.PHONY: clippy
clippy:
	cargo +nightly clippy --fix \
		--all-targets \
		--all-features \
		--allow-dirty \
		--allow-staged \
		-- -D warnings

.PHONY: fmt
fmt:
	cargo +nightly fmt

.PHONY: doc
doc:
	cargo +nightly doc --all-features --no-deps --open

.PHONY: cliff
cliff:
	git-cliff
	git cliff --output CHANGELOG.md

.PHONY: udeps
udeps:
	cargo +nightly udeps --all-features

.PHONY: udeps-check
udeps-check:
	cargo update
	cargo +nightly udeps --all-features

.PHONY: pre-commit
pre-commit:
	$(MAKE) build
	$(MAKE) test
	$(MAKE) clippy
	$(MAKE) fmt

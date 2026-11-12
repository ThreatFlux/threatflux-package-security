.DEFAULT_GOAL := help

MSRV := 1.95.0
STABLE := 1.100.0
MARKDOWN_TARGET_DIR := target/markdown-doctests

.PHONY: help fmt fmt-check check lint test test-doc markdown msrv-check docs examples
.PHONY: coverage audit deny package publish-dry-run ci clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format Rust sources
	cargo fmt --all

fmt-check: ## Check Rust formatting
	cargo fmt --all -- --check

check: ## Check all targets and features
	cargo check --all-targets --all-features --locked

lint: ## Run strict Clippy checks
	cargo clippy --all-targets --all-features --locked -- -D warnings

test: ## Run the complete test suite
	cargo test --all-targets --all-features --locked

test-doc: ## Run crate documentation tests
	cargo test --doc --all-features --locked

markdown: ## Compile Rust blocks in README and guides
	@mkdir -p "$(MARKDOWN_TARGET_DIR)"
	CARGO_TARGET_DIR="$(MARKDOWN_TARGET_DIR)" cargo +$(STABLE) metadata --all-features --locked --format-version=1 > "$(MARKDOWN_TARGET_DIR)/metadata.json"
	CARGO_TARGET_DIR="$(MARKDOWN_TARGET_DIR)" cargo +$(STABLE) build --all-features --examples --locked --message-format=json > "$(MARKDOWN_TARGET_DIR)/artifacts.json" || { cat "$(MARKDOWN_TARGET_DIR)/artifacts.json" >&2; exit 1; }
	@set -eu; \
	for document in README.md $$(find docs -type f -name '*.md' -print 2>/dev/null | sort); do \
		python3 scripts/check_markdown.py --package threatflux-package-security --metadata "$(MARKDOWN_TARGET_DIR)/metadata.json" \
			--artifacts "$(MARKDOWN_TARGET_DIR)/artifacts.json" --document "$$document" --extern tokio > "$(MARKDOWN_TARGET_DIR)/arguments.bin"; \
		test -s "$(MARKDOWN_TARGET_DIR)/arguments.bin"; \
		xargs -0 rustup run "$(STABLE)" rustdoc < "$(MARKDOWN_TARGET_DIR)/arguments.bin"; \
	done

msrv-check: ## Check and test with the minimum Rust version
	cargo +$(MSRV) check --all-targets --all-features --locked
	cargo +$(MSRV) test --all-targets --all-features --locked

docs: ## Build documentation with warnings denied
	RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked

examples: ## Build all examples
	cargo build --examples --all-features --locked

coverage: ## Generate an LCOV coverage report with cargo-llvm-cov
	cargo llvm-cov --all-features --workspace --locked --lcov --output-path lcov.info

audit: ## Check RustSec advisories
	cargo audit --deny warnings

deny: ## Check dependency and license policy
	cargo deny check

package: ## Build and verify the crates.io package
	cargo package --allow-dirty --locked

publish-dry-run: ## Validate crates.io publication without uploading
	cargo publish --dry-run --allow-dirty --locked

ci: fmt-check check lint test test-doc markdown msrv-check docs examples audit deny package ## Run local release gates

clean: ## Remove Cargo build output
	cargo clean

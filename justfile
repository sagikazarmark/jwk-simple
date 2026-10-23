# The feature sets CI builds and tests. `cloudflare` and `web-crypto` are
# wasm32-only, `moka` and the TLS backends are native-only.
native := "http,reqwest,tower,default-tls,jwt-simple,jwt-simple/pure-rust,moka"
wasm := "cloudflare,http,reqwest,tower,jwt-simple,jwt-simple/pure-rust,web-crypto"
wasm_target := "wasm32-unknown-unknown"

# What docs.rs builds, on both targets: `[package.metadata.docs.rs]` in Cargo.toml,
# which must stay in sync with this. Nightly, because `--cfg docsrs` enables
# `#![feature(doc_cfg)]`; devenv provides it as `CARGO_NIGHTLY`.
docsrs := "http,reqwest,tower,moka,jwt-simple,jwt-simple/pure-rust,web-crypto,cloudflare"
cargo_nightly := env("CARGO_NIGHTLY", "cargo +nightly")

# List the recipes.
[private]
default:
    @just --list --unsorted

# Run all CI jobs.
ci: audit build lint test examples

# Audit dependencies for advisories.
audit:
    cargo audit

# Build for every target.
build: build-native build-wasm

# Build for the native target.
build-native:
    cargo build --features {{native}} --locked

# Build for wasm32.
build-wasm:
    cargo build --target {{wasm_target}} --features {{wasm}} --locked

# Run the tests on every target.
test: test-native test-wasm

# Run the tests on the native target.
test-native:
    cargo test --features {{native}} --locked

# Run the tests on wasm32, the browser ones in headless Firefox.
test-wasm:
    cargo test --target {{wasm_target}} --features {{wasm}} --locked

# Format, lint and document.
lint: lint-native lint-wasm

# Check formatting, run clippy and rustdoc for the native target.
lint-native: fmt clippy-native doc docsrs-native

# Run clippy and the docs.rs build for wasm32.
lint-wasm: clippy-wasm docsrs-wasm

# Check formatting.
fmt:
    cargo fmt --all --check

# Run clippy for the native target.
clippy-native:
    cargo clippy --features {{native}} --locked -- --deny warnings

# Run clippy for wasm32.
clippy-wasm:
    cargo clippy --target {{wasm_target}} --features {{wasm}} --locked -- --deny warnings

# Run rustdoc.
[env("RUSTDOCFLAGS", "--deny warnings")]
doc:
    cargo doc --no-deps --features {{native}} --locked

# Reproduce the docs.rs build on every target.
docsrs: docsrs-native docsrs-wasm

# Reproduce the docs.rs build for the native target.
[env("RUSTDOCFLAGS", "--cfg docsrs --deny warnings")]
docsrs-native:
    {{cargo_nightly}} doc --no-deps --features {{docsrs}} --locked

# Reproduce the docs.rs build for wasm32.
[env("RUSTDOCFLAGS", "--cfg docsrs --deny warnings")]
docsrs-wasm:
    {{cargo_nightly}} doc --no-deps --target {{wasm_target}} --features {{docsrs}} --locked

# Check the examples on every target, and run the native ones.
examples: examples-native examples-wasm

# Check and run the examples on the native target (`http_fetch` hits Google's JWKS).
examples-native:
    cargo check --examples --features {{native}} --locked
    cargo run --example basic_usage --features {{native}} --locked
    cargo run --example jwt_verify --features {{native}} --locked
    cargo run --example http_fetch --features {{native}} --locked

# Check the examples on wasm32.
examples-wasm:
    cargo check --target {{wasm_target}} --examples --features {{wasm}} --locked

# The full feature sets CI builds and tests. `cloudflare` and `web-crypto` are
# wasm32-only, `moka` and the TLS backends are native-only.
native := "http,reqwest,tower,default-tls,jwt-simple,jwt-simple/pure-rust,moka"
wasm := "cloudflare,http,reqwest,tower,jwt-simple,jwt-simple/pure-rust,web-crypto"
wasm_target := "wasm32-unknown-unknown"

# The feature matrix (`cargo hack`) also runs every feature on its own and, for
# `check`, every combination: that is what catches a missing `cfg` gate. These
# stay out of it: `default` (empty, so it would only double the matrix), the
# features that `compile_error!` on the other target, and the TLS backends,
# which only forward to reqwest (`default-tls` is in the full native set;
# `native-tls` needs OpenSSL, which devenv does not ship).
native_skip := "default,cloudflare,web-crypto,default-tls,rustls,native-tls"
wasm_skip := "default,moka,default-tls,rustls,native-tls"

# `jwt-simple` needs a crypto backend. The `?` turns `pure-rust` on only when
# the feature is, so the matrix still has runs without `jwt-simple`. cargo-hack
# warns that it is not a feature of this package; that is expected.
hack_features := "jwt-simple?/pure-rust"

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
ci: audit fmt build check clippy test doc examples

# Audit dependencies for advisories.
audit:
    cargo audit

# Check formatting.
fmt:
    cargo fmt --all --check

# Build for every target.
build: build-native build-wasm

# Build for the native target.
build-native:
    cargo build --features {{native}} --locked

# Build for wasm32.
build-wasm:
    cargo build --target {{wasm_target}} --features {{wasm}} --locked

# Check every feature combination on every target.
check: check-native check-wasm

# Check every feature combination, with tests, benches and examples, for the native target.
check-native:
    cargo hack check --feature-powerset --exclude-features {{native_skip}} --features {{hack_features}} --all-targets --locked

# Check every feature combination, with tests and examples, for wasm32.
check-wasm:
    cargo hack check --target {{wasm_target}} --feature-powerset --exclude-features {{wasm_skip}} --features {{hack_features}} --lib --tests --examples --locked

# Run clippy on every target.
clippy: clippy-native clippy-wasm

# Run clippy for the native target: each feature on its own, then the full set.
clippy-native:
    cargo hack clippy --each-feature --exclude-features {{native_skip}} --features {{hack_features}} --all-targets --locked -- --deny warnings
    cargo clippy --features {{native}} --all-targets --locked -- --deny warnings

# Run clippy for wasm32: each feature on its own, then the full set.
clippy-wasm:
    cargo hack clippy --target {{wasm_target}} --each-feature --exclude-features {{wasm_skip}} --features {{hack_features}} --lib --tests --examples --locked -- --deny warnings
    cargo clippy --target {{wasm_target}} --features {{wasm}} --lib --tests --examples --locked -- --deny warnings

# Run the tests on every target.
test: test-native test-wasm

# Run the tests on the native target: each feature on its own, then the full set.
test-native:
    cargo hack test --each-feature --exclude-features {{native_skip}} --features {{hack_features}} --locked
    cargo test --features {{native}} --locked

# Run the tests on wasm32, the browser ones in headless Firefox: each feature on its own, then the full set.
test-wasm:
    cargo hack test --target {{wasm_target}} --each-feature --exclude-features {{wasm_skip}} --features {{hack_features}} --locked
    cargo test --target {{wasm_target}} --features {{wasm}} --locked

# Run rustdoc and reproduce the docs.rs build on every target.
doc: doc-native doc-wasm

# Run rustdoc for the native target (each feature on its own, then the full set), and the docs.rs build.
doc-native: rustdoc docsrs-native

# Reproduce the docs.rs build for wasm32.
doc-wasm: docsrs-wasm

# Run rustdoc for the native target: each feature on its own, then the full set.
[env("RUSTDOCFLAGS", "--deny warnings")]
rustdoc:
    cargo hack doc --no-deps --each-feature --exclude-features {{native_skip}} --features {{hack_features}} --locked
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

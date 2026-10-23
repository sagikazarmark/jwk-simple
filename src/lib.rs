//! # jwk-simple
//!
//! A Rust library for working with JSON Web Keys (JWK) and JWK Sets (JWKS) as
//! defined in RFC 7517, with full support for WASM environments and optional
//! jwt-simple integration.
//!
//! ## Features
//!
//! - **RFC coverage (JOSE/JWK)**: Supports RFC 7517 (JWK), RFC 7518 (algorithms),
//!   RFC 8037 (OKP), RFC 9864 (Ed25519/Ed448 JOSE algorithms), and RFC 7638
//!   (thumbprints)
//! - **Multiple key types**: RSA, EC (P-256, P-384, P-521, secp256k1),
//!   Symmetric (HMAC), and OKP (Ed25519, Ed448, X25519, X448)
//! - **WASM compatible**: Core functionality works in WebAssembly environments
//! - **Security-first**: Zeroize support for sensitive data, constant-time base64 encoding
//! - **jwt-simple integration**: Optional feature for converting JWKs to jwt-simple key types
//! - **Remote fetching**: Load JWKS from HTTP endpoints through a pluggable
//!   transport (reqwest, any `tower::Service`, or your own) with caching support
//! - **Runs on Cloudflare Workers**: `Send` futures on `wasm32`, KV caching, and
//!   `tower-worker-fetch` as the HTTP transport
//! - **Strict selection API**: `KeySet::selector(...).select(...)` with typed errors
//!
//! ## Quick Start
//!
//! Parse a JWKS and strictly select a verification key:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
//!
//! let json = r#"{
//!     "keys": [{
//!         "kty": "RSA",
//!         "kid": "my-key-id",
//!         "use": "sig",
//!         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
//!         "e": "AQAB"
//!     }]
//! }"#;
//!
//! let jwks = serde_json::from_str::<KeySet>(json)?;
//! let key = jwks
//!     .selector(&[Algorithm::Rs256])
//!     .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-key-id"))?;
//! assert!(key.is_public_key_only());
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! Feature definitions live in `Cargo.toml` (`[features]`), while this section
//! documents expected usage and platform constraints.
//!
//! | Feature | Platform | Description |
//! |---------|----------|-------------|
//! | `jwt-simple` | all targets | Integration with the jwt-simple crate (requires a `jwt-simple` backend feature such as `jwt-simple/pure-rust`) |
//! | `http` | all targets | Remote JWKS fetching through the `jwks::HttpTransport` trait: `jwks::HttpKeyStore` and the transport types. Bring your own transport, or enable one below |
//! | `reqwest` | all targets | The default transport, `jwks::ReqwestTransport` (implies `http`). On native targets it needs a TLS backend: `default-tls`, `rustls` or `native-tls` |
//! | `default-tls`, `rustls`, `native-tls` | non-`wasm32` | TLS backends for `reqwest` (no-ops without it, and on `wasm32` where the JS host does TLS) |
//! | `tower` | all targets | `jwks::TowerTransport`, an `HttpTransport` over any `tower::Service` speaking `http` types (implies `http`): `tower-reqwest` natively, `tower-worker-fetch` on Cloudflare Workers |
//! | `web-crypto` | `wasm32` only | WebCrypto integration for browser/WASM environments |
//! | `cloudflare` | `wasm32` only | Cloudflare Workers support: `jwks::cloudflare::KvKeyCache` over Workers KV |
//! | `moka` | non-`wasm32` only | In-memory `KeyCache` implementation using Moka |
//!
//! Invalid platform/feature combinations fail at compile time with clear
//! `compile_error!` messages.
//!
//! ## Fetching a remote JWKS
//!
//! With the `reqwest` feature (and a TLS feature on native targets):
//!
#![cfg_attr(feature = "reqwest", doc = "```no_run")]
#![cfg_attr(not(feature = "reqwest"), doc = "```ignore")]
//! use jwk_simple::jwks::{HttpKeyStore, KeyStore};
//!
//! # async fn example() -> jwk_simple::Result<()> {
//! let store = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;
//! let key = store.get_key("my-key-id").await?;
//! # Ok(())
//! # }
//! ```
//!
//! HTTP goes through the `jwks::HttpTransport` trait, so the store does not
//! depend on reqwest: `HttpKeyStore::new_with_transport` takes a
//! `ReqwestTransport` over your own client, a `jwks::TowerTransport` over a
//! `tower::Service` (feature `tower`), or your own implementation. Wrap the
//! store in [`jwks::CachedKeyStore`] for production use.
//!
//! ## `Send` on every target
//!
//! [`jwks::KeyStore`], [`jwks::KeyCache`] and `jwks::HttpTransport` are
//! `Send + Sync` with `Send` futures on `wasm32` too, so a store can be shared
//! state in `Send`-requiring frameworks (axum, tower) on Cloudflare Workers
//! without `#[worker::send]`. JS futures are wrapped on the single-threaded
//! assumption (see [`jwks::assume_send`]); threaded wasm (`atomics`) is
//! rejected at compile time. The exception is the `web-crypto` integration:
//! `web_sys::CryptoKey` and the SubtleCrypto futures are not `Send` and cannot
//! be made so, so a handler that verifies with WebCrypto still needs
//! `#[worker::send]`. Verifying with `jwt-simple` (feature `pure-rust`) on
//! `wasm32` involves no JS values and is `Send` end to end.
//!
//! ## Converting to jwt-simple keys
//!
//! With the `jwt-simple` feature enabled, you can convert JWKs to jwt-simple key types.
//! Make sure your crate also enables a concrete `jwt-simple` backend feature
//! (for example `jwt-simple/pure-rust`).
//!
#![cfg_attr(feature = "jwt-simple", doc = "```no_run")]
#![cfg_attr(not(feature = "jwt-simple"), doc = "```ignore")]
//! use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
//! use jwt_simple::prelude::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let json = "{}";
//! # let token = "";
//! let keyset: KeySet = serde_json::from_str(json)?;
//! let jwk = keyset
//!     .selector(&[Algorithm::Rs256])
//!     .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-key-id"))?
//!     .clone();
//!
//! // Convert to jwt-simple key
//! // Conversion failures use `JwtSimpleKeyConversionError`.
//! let key: RS256PublicKey = jwk.try_into()?;
//!
//! // Use for JWT verification
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Using with WebCrypto (Browser/WASM)
//!
//! With the `web-crypto` feature enabled, you can use JWKs with the browser's
//! native SubtleCrypto API:
//!
#![cfg_attr(
    all(feature = "web-crypto", any(target_arch = "wasm32", docsrs)),
    doc = "```no_run"
)]
#![cfg_attr(
    not(all(feature = "web-crypto", any(target_arch = "wasm32", docsrs))),
    doc = "```ignore"
)]
//! use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
//! use std::convert::TryInto;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let json = r#"{"keys":[{"kty":"RSA","kid":"my-key-id","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;
//! // Parse a JWKS
//! let keyset: KeySet = serde_json::from_str(json)?;
//! let key = keyset
//!     .selector(&[Algorithm::Rs256])
//!     .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-key-id"))?;
//!
//! // Check if the key is WebCrypto compatible
//! if key.is_web_crypto_compatible() {
//!     // Import as a CryptoKey for verification.
//!     // Use the _for_alg variant because many JWKS keys (especially from OIDC
//!     // providers) omit the `alg` field, and WebCrypto requires the algorithm
//!     // to be known at import time for RSA and HMAC keys.
//!     let alg = Algorithm::Rs256; // typically from the JWT header
//!     let crypto_key = key.import_as_verify_key_for_alg(&alg).await?;
//!
//!     // Or get the JsonWebKey directly
//!     let jwk: web_sys::JsonWebKey = key.try_into()?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! If the key's `alg` field is present, you can use the simpler
//! `Key::import_as_verify_key` instead. EC keys always work without an explicit
//! algorithm since the curve determines the WebCrypto parameters.
//!
//! **Note:** WebCrypto does not support OKP keys (Ed25519, Ed448, X25519, X448)
//! or the secp256k1 curve. Use `Key::is_web_crypto_compatible()` to check
//! compatibility before attempting to use a key with WebCrypto.
//!
//! ## Security
//!
//! This crate prioritizes security:
//!
//! - Private key parameters are zeroed from memory on drop via `zeroize`
//! - Base64 encoding uses constant-time operations via `base64ct`
//! - Debug output redacts sensitive key material
//! - All fallible operations return `Result` types. The crate avoids panics,
//!   though standard trait implementations like `Index` follow normal Rust
//!   semantics and may panic on invalid input (e.g., out-of-bounds indexing)
//! - Validation entry points are layered:
//!
//!   | API | Structural key params | `use`/`key_ops` consistency | Cert metadata (`x5u`/`x5c`/`x5t`) | Alg suitability/strength | Op/alg compatibility | Private material capability | Selection policy |
//!   |-----|------------------------|-----------------------------|-----------------------------------|--------------------------|----------------------|-----------------------------|------------------|
//!   | [`Key::validate`] | yes | yes | yes | no | no | no | no |
//!   | [`Key::validate_for_use`] | yes | yes | yes | yes | yes | yes | no |
//!   | [`KeySet::selector(...).select(...)`](crate::jwks::KeySelector::select) | yes, per candidate | yes, per candidate | yes, per candidate | yes, per candidate | yes, up front | yes, per candidate | yes |
//!
//!   PKIX trust validation for `x5c` chains is application-defined and out of
//!   scope for this crate.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::all)]

// ---------------------------------------------------------------------------
// Feature/target compatibility guards
// ---------------------------------------------------------------------------
//
// docs.rs builds with all features enabled on a native target to render API docs.
// We skip hard errors there so docs can still be generated for feature-gated APIs.
#[cfg(all(feature = "web-crypto", not(target_arch = "wasm32"), not(docsrs)))]
compile_error!("feature `web-crypto` is only supported on `wasm32` targets");

#[cfg(all(feature = "cloudflare", not(target_arch = "wasm32"), not(docsrs)))]
compile_error!("feature `cloudflare` is only supported on `wasm32` targets");

#[cfg(all(feature = "moka", target_arch = "wasm32", not(docsrs)))]
compile_error!("feature `moka` is not supported on `wasm32` targets");

// `KeyStore` and `KeyCache` futures are `Send` on every target. On wasm32 that
// rests on the target being single-threaded (JS futures are wrapped, see
// `jwks::assume_send`); threaded wasm would make that unsound.
#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
compile_error!(
    "jwk-simple assumes single-threaded wasm (no `atomics`): it marks JS futures `Send`"
);

pub mod encoding;
pub mod error;
mod integrations;
pub mod jwk;
pub mod jwks;

// Re-exports for convenience
#[cfg(feature = "jwt-simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-simple")))]
pub use error::JwtSimpleKeyConversionError;
pub use error::{Error, IncompatibleKeyError, InvalidKeyError, ParseError, Result};
pub use jwk::{
    Algorithm, EcCurve, EcParams, Key, KeyOperation, KeyParams, KeyType, KeyUse, OkpCurve,
    OkpParams, RsaOtherPrime, RsaParams, RsaParamsBuilder, SymmetricParams,
};
pub use jwks::{KeyFilter, KeyMatcher, KeySelector, KeySet, SelectionError};

#[cfg(all(feature = "web-crypto", any(target_arch = "wasm32", docsrs)))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "web-crypto", target_arch = "wasm32"))))]
pub use integrations::web_crypto;

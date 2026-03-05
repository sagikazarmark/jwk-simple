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
//! - **Remote fetching**: Load JWKS from HTTP endpoints with caching support
//! - **Strict selection API**: `KeySet::selector(...).select(...)` with typed errors
//!
//! ## Quick Start
//!
//! Parse a JWKS and find a key:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use jwk_simple::KeySet;
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
//! let key = jwks.get_by_kid("my-key-id").expect("key not found");
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
//! | `jwt-simple` | all targets | Integration with the jwt-simple crate |
//! | `http` | all targets | Async HTTP fetching with `HttpKeyStore` |
//! | `web-crypto` | `wasm32` only | WebCrypto integration for browser/WASM environments |
//! | `cloudflare` | `wasm32` only | Cloudflare Workers support (Fetch API + KV cache) |
//! | `moka` | non-`wasm32` only | In-memory `KeyCache` implementation using Moka |
//!
//! Invalid platform/feature combinations fail at compile time with clear
//! `compile_error!` messages.
//!
//! ## Converting to jwt-simple keys
//!
//! With the `jwt-simple` feature enabled, you can convert JWKs to jwt-simple key types:
//!
//! ```ignore
//! use jwk_simple::KeySet;
//! use jwt_simple::prelude::*;
//!
//! let keyset: KeySet = serde_json::from_str(json)?;
//! let jwk = keyset.get_by_kid("my-key-id")?;
//!
//! // Convert to jwt-simple key
//! let key: RS256PublicKey = jwk.try_into()?;
//!
//! // Use for JWT verification
//! let claims: NoCustomClaims = key.verify_token(&token, None)?;
//! ```
//!
//! ## Using with WebCrypto (Browser/WASM)
//!
//! With the `web-crypto` feature enabled, you can use JWKs with the browser's
//! native SubtleCrypto API:
//!
//! ```ignore
//! use jwk_simple::{Algorithm, KeySet};
//! use std::convert::TryInto;
//!
//! // Parse a JWKS
//! let keyset: KeySet = serde_json::from_str(json)?;
//! let key = keyset.get_by_kid("my-key-id").unwrap();
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
//! ```
//!
//! If the key's `alg` field is present, you can use the simpler
//! [`Key::import_as_verify_key`] instead. EC keys always work without an explicit
//! algorithm since the curve determines the WebCrypto parameters.
//!
//! **Note:** WebCrypto does not support OKP keys (Ed25519, Ed448, X25519, X448)
//! or the secp256k1 curve. Use [`Key::is_web_crypto_compatible()`] to check
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
//! - `Key::validate_structure` performs structural and consistency checks
//!   only. PKIX trust validation for `x5c` chains is application-defined and
//!   out of scope for this crate.

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

pub mod encoding;
pub mod error;
mod integrations;
pub mod jwk;
pub mod jwks;

// Re-exports for convenience
pub use error::{Error, Result, ValidationError};
pub use jwk::{
    Algorithm, EcCurve, EcParams, Key, KeyOperation, KeyParams, KeyType, KeyUse, OkpCurve,
    OkpParams, RsaOtherPrime, RsaParams, RsaParamsBuilder, SymmetricParams,
};
pub use jwks::{KeyFilter, KeyMatcher, KeySelector, KeySet, SelectionError};

#[cfg(all(feature = "web-crypto", any(target_arch = "wasm32", docsrs)))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "web-crypto", target_arch = "wasm32"))))]
pub use integrations::web_crypto;

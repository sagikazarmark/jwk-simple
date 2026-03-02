//! # jwk-simple
//!
//! A Rust library for working with JSON Web Keys (JWK) and JWK Sets (JWKS) as
//! defined in RFC 7517, with full support for WASM environments and optional
//! jwt-simple integration.
//!
//! ## Features
//!
//! - **Full RFC compliance**: Supports RFC 7517 (JWK), RFC 7518 (algorithms),
//!   RFC 8037 (OKP), RFC 9864 (Ed25519/Ed448 JOSE algorithms), and RFC 7638
//!   (thumbprints)
//! - **Multiple key types**: RSA, EC (P-256, P-384, P-521, secp256k1),
//!   Symmetric (HMAC), and OKP (Ed25519, Ed448, X25519, X448)
//! - **WASM compatible**: Core functionality works in WebAssembly environments
//! - **Security-first**: Zeroize support for sensitive data, constant-time base64 encoding
//! - **jwt-simple integration**: Optional feature for converting JWKs to jwt-simple key types
//! - **Remote fetching**: Load JWKS from HTTP endpoints with caching support
//!
//! ## Quick Start
//!
//! Parse a JWKS and find a key:
//!
//! ```
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
//! let jwks = serde_json::from_str::<KeySet>(json).unwrap();
//! let key = jwks.find_by_kid("my-key-id").expect("key not found");
//! assert!(key.is_public_key_only());
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `jwt-simple` | Integration with the jwt-simple crate |
//! | `web-crypto` | WebCrypto integration for browser/WASM environments |
//! | `http` | Async HTTP fetching with `RemoteKeyStore` |
//! | `cache-inmemory` | In-memory `KeyCache` implementation using Tokio |
//! | `cloudflare` | Cloudflare Workers support (Fetch API + KV cache) |
//!
//! ## Converting to jwt-simple keys
//!
//! With the `jwt-simple` feature enabled, you can convert JWKs to jwt-simple key types:
//!
//! ```ignore
//! use jwk_simple::KeySet;
//! use jwt_simple::prelude::*;
//!
//! let keyset = serde_json::from_str::<KeySet>(json)?;
//! let jwk = keyset.find_by_kid("my-key-id").unwrap();
//!
//! // Convert to jwt-simple key
//! let key: RS256PublicKey = jwk.try_into()?;
//!
//! // Use for JWT verification
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! ```
//!
//! ## Using with WebCrypto (Browser/WASM)
//!
//! With the `web-crypto` feature enabled, you can use JWKs with the browser's
//! native SubtleCrypto API:
//!
//! ```ignore
//! use jwk_simple::{Algorithm, KeySet, integrations::web_crypto};
//!
//! // Parse a JWKS
//! let keyset: KeySet = serde_json::from_str(json)?;
//! let key = keyset.find_by_kid("my-key-id").unwrap();
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
//!     let jwk = key.to_web_crypto_jwk()?;
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
//! - All fallible operations return `Result` types — the crate avoids panics,
//!   though standard trait implementations like `Index` follow normal Rust
//!   semantics and may panic on invalid input (e.g., out-of-bounds indexing)

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::all)]

pub mod encoding;
pub mod error;
pub mod jwk;
pub mod jwks;

pub mod integrations;

// Re-exports for convenience
pub use error::{Error, Result};
pub use jwk::{
    Algorithm, EcCurve, EcParams, Key, KeyOperation, KeyParams, KeyType, KeyUse, OkpCurve,
    OkpParams, RsaOtherPrime, RsaParams, RsaParamsBuilder, SymmetricParams,
};
pub use jwks::{CachedKeyStore, KeyCache, KeySet, KeySetParseDiagnostics, KeyStore};

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub use jwks::{DEFAULT_TIMEOUT, RemoteKeyStore};

#[cfg(feature = "cache-inmemory")]
#[cfg_attr(docsrs, doc(cfg(feature = "cache-inmemory")))]
pub use jwks::{DEFAULT_CACHE_TTL, InMemoryCachedKeyStore, InMemoryKeyCache};

#[cfg(feature = "web-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
pub use integrations::web_crypto;

//! Integrations with external cryptographic libraries.
//!
//! This module provides conversions between JWK types and various
//! cryptographic library types, enabling seamless use of keys loaded from
//! a JWKS with different verification and signing implementations.
//!
//! # Available Integrations
//!
//! ## jwt-simple (feature: `jwt-simple`)
//!
//! Provides `TryFrom` implementations for converting JWK keys to jwt-simple
//! key types, enabling JWT verification with keys loaded from a JWKS.
//!
//! ## WebCrypto (feature: `web-crypto`)
//!
//! Provides conversions to `web_sys::JsonWebKey` and helpers for importing
//! keys as `CryptoKey` for use with the browser's native SubtleCrypto API.
//! This is useful for WASM applications that want to use browser-native
//! cryptographic operations.
//!
//! # Supported Conversions
//!
//! | JWK Type | jwt-simple Type | Requirements |
//! |----------|-----------------|--------------|
//! | RSA | RS256PublicKey/RS256KeyPair | kty="RSA" |
//! | RSA | RS384PublicKey/RS384KeyPair | kty="RSA" |
//! | RSA | RS512PublicKey/RS512KeyPair | kty="RSA" |
//! | RSA | PS256PublicKey/PS256KeyPair | kty="RSA" |
//! | RSA | PS384PublicKey/PS384KeyPair | kty="RSA" |
//! | RSA | PS512PublicKey/PS512KeyPair | kty="RSA" |
//! | EC P-256 | ES256PublicKey/ES256KeyPair | kty="EC", crv="P-256" |
//! | EC P-384 | ES384PublicKey/ES384KeyPair | kty="EC", crv="P-384" |
//! | EC secp256k1 | ES256kPublicKey/ES256kKeyPair | kty="EC", crv="secp256k1" |
//! | OKP Ed25519 | Ed25519PublicKey/Ed25519KeyPair | kty="OKP", crv="Ed25519" |
//! | oct | HS256Key/HS384Key/HS512Key | kty="oct" |
//!
//! # Examples
//!
//! ```ignore
//! use jwk_simple::KeySet;
//! use jwt_simple::prelude::*;
//!
//! // Load JWKS and find a key
//! let jwks = serde_json::from_str::<KeySet>(json)?;
//! let jwk = jwks.get_by_kid("my-key").unwrap();
//!
//! // Convert to jwt-simple key using TryFrom
//! let key: RS256PublicKey = jwk.try_into()?;
//!
//! // Verify a JWT
//! let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
//! ```

// This module provides TryFrom implementations for Key conversions.
#[cfg(feature = "jwt-simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-simple")))]
mod jwt_simple;

#[cfg(all(feature = "web-crypto", any(target_arch = "wasm32", docsrs)))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "web-crypto", target_arch = "wasm32"))))]
pub mod web_crypto;

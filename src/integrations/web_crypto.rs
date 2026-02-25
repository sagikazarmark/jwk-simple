//! WebCrypto integration for browser/WASM environments.
//!
//! This module provides conversions from jwk-simple [`Key`] types to
//! [`web_sys::JsonWebKey`] for use with the browser's SubtleCrypto API,
//! as well as helper functions for importing keys as [`web_sys::CryptoKey`].
//!
//! # Supported Key Types
//!
//! | Key Type | Curve/Algorithm | WebCrypto Support |
//! |----------|-----------------|-------------------|
//! | RSA | RS256/RS384/RS512 | Yes (RSASSA-PKCS1-v1_5) |
//! | RSA | PS256/PS384/PS512 | Yes (RSA-PSS) |
//! | EC | P-256 | Yes (ECDSA) |
//! | EC | P-384 | Yes (ECDSA) |
//! | EC | P-521 | Yes (ECDSA) |
//! | EC | secp256k1 | **No** |
//! | OKP | Ed25519/Ed448 | **No** |
//! | OKP | X25519/X448 | **No** |
//! | Symmetric | HMAC | Yes |
//! | Symmetric | AES | Yes |
//!
//! # Examples
//!
//! ## Converting a Key to JsonWebKey
//!
//! ```ignore
//! use jwk_simple::{Key, integrations::web_crypto};
//!
//! let key: Key = serde_json::from_str(jwk_json)?;
//! let web_jwk: web_sys::JsonWebKey = web_crypto::to_json_web_key(&key)?;
//! ```
//!
//! ## Importing a Key for Signature Verification
//!
//! ```ignore
//! use jwk_simple::{Key, integrations::web_crypto};
//!
//! let key: Key = serde_json::from_str(jwk_json)?;
//! let crypto_key = web_crypto::import_verify_key(&key).await?;
//!
//! // Use with SubtleCrypto.verify()
//! let subtle = web_crypto::get_subtle_crypto()?;
//! // ... perform verification
//! ```
//!
//! # Limitations
//!
//! WebCrypto does not support:
//! - **OKP keys** (Ed25519, Ed448, X25519, X448) - These use Edwards/Montgomery curves
//!   which are not part of the WebCrypto specification.
//! - **secp256k1 curve** - While popular in cryptocurrency applications, this curve
//!   is not supported by WebCrypto.
//!
//! Attempting to convert these key types will return an
//! [`Error::UnsupportedForWebCrypto`](crate::Error::UnsupportedForWebCrypto) error.

use js_sys::{Array, Object, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::error::{Error, Result};
use crate::jwk::{Algorithm, EcCurve, Key, KeyParams};

// ============================================================================
// SubtleCrypto Access
// ============================================================================

/// Gets the SubtleCrypto interface from the current environment.
///
/// This function works in both browser (Window) and Web Worker contexts.
///
/// # Errors
///
/// Returns an error if the crypto API is not available in the current context.
///
/// # Examples
///
/// ```ignore
/// let subtle = web_crypto::get_subtle_crypto()?;
/// ```
pub fn get_subtle_crypto() -> Result<SubtleCrypto> {
    // Try window first (browser context)
    if let Some(window) = web_sys::window() {
        if let Ok(crypto) = window.crypto() {
            return Ok(crypto.subtle());
        }
    }

    // Try WorkerGlobalScope (Web Worker context)
    let global = js_sys::global();
    if let Ok(worker_scope) = global.dyn_into::<web_sys::WorkerGlobalScope>() {
        if let Ok(crypto) = worker_scope.crypto() {
            return Ok(crypto.subtle());
        }
    }

    Err(Error::WebCrypto(
        "crypto API not available in this context".to_string(),
    ))
}

// ============================================================================
// Key to JsonWebKey Conversion
// ============================================================================

/// Converts a jwk-simple [`Key`] to a [`web_sys::JsonWebKey`].
///
/// This function creates a `JsonWebKey` object that can be used with
/// the WebCrypto `SubtleCrypto.importKey()` method.
///
/// # Supported Key Types
///
/// - **RSA**: All RSA keys are supported
/// - **EC**: P-256, P-384, P-521 curves are supported; secp256k1 is NOT supported
/// - **Symmetric**: All symmetric keys are supported
/// - **OKP**: NOT supported (Ed25519, Ed448, X25519, X448)
///
/// # Errors
///
/// Returns [`Error::UnsupportedForWebCrypto`] if the key type or curve is not
/// supported by WebCrypto.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{Key, integrations::web_crypto};
///
/// let key: Key = serde_json::from_str(r#"{"kty":"RSA","n":"...","e":"AQAB"}"#)?;
/// let jwk = web_crypto::to_json_web_key(&key)?;
/// assert_eq!(jwk.kty(), "RSA");
/// ```
pub fn to_json_web_key(key: &Key) -> Result<web_sys::JsonWebKey> {
    // Validate that the key type is supported
    validate_webcrypto_support(key)?;

    let jwk = web_sys::JsonWebKey::new(&key.kty.as_str());

    // Set common optional fields
    if let Some(kid) = &key.kid {
        jwk.set_kid(kid);
    }

    if let Some(alg) = &key.alg {
        jwk.set_alg(alg.as_str());
    }

    if let Some(key_use) = &key.key_use {
        jwk.set_use_(key_use.as_str());
    }

    if let Some(key_ops) = &key.key_ops {
        let ops = Array::new();
        for op in key_ops {
            ops.push(&JsValue::from_str(op.as_str()));
        }
        jwk.set_key_ops(&ops);
    }

    // Set type-specific parameters
    match &key.params {
        KeyParams::Rsa(params) => {
            // Public key components (always present)
            jwk.set_n(&params.n.to_base64url());
            jwk.set_e(&params.e.to_base64url());

            // Private key components (optional)
            if let Some(d) = &params.d {
                jwk.set_d(&d.to_base64url());
            }
            if let Some(p) = &params.p {
                jwk.set_p(&p.to_base64url());
            }
            if let Some(q) = &params.q {
                jwk.set_q(&q.to_base64url());
            }
            if let Some(dp) = &params.dp {
                jwk.set_dp(&dp.to_base64url());
            }
            if let Some(dq) = &params.dq {
                jwk.set_dq(&dq.to_base64url());
            }
            if let Some(qi) = &params.qi {
                jwk.set_qi(&qi.to_base64url());
            }
            // Note: 'oth' (other primes) is not supported by web_sys::JsonWebKey
        }
        KeyParams::Ec(params) => {
            jwk.set_crv(params.crv.name());
            jwk.set_x(&params.x.to_base64url());
            jwk.set_y(&params.y.to_base64url());

            if let Some(d) = &params.d {
                jwk.set_d(&d.to_base64url());
            }
        }
        KeyParams::Symmetric(params) => {
            jwk.set_k(&params.k.to_base64url());
        }
        KeyParams::Okp(_) => {
            // This should never be reached due to validate_webcrypto_support
            return Err(Error::UnsupportedForWebCrypto {
                reason: "OKP keys (Ed25519, Ed448, X25519, X448) are not supported by WebCrypto",
            });
        }
    }

    Ok(jwk)
}

/// Validates that a key is supported by WebCrypto.
fn validate_webcrypto_support(key: &Key) -> Result<()> {
    match &key.params {
        KeyParams::Okp(_) => Err(Error::UnsupportedForWebCrypto {
            reason: "OKP keys (Ed25519, Ed448, X25519, X448) are not supported by WebCrypto",
        }),
        KeyParams::Ec(params) => {
            if params.crv == EcCurve::Secp256k1 {
                Err(Error::UnsupportedForWebCrypto {
                    reason: "secp256k1 curve is not supported by WebCrypto",
                })
            } else {
                Ok(())
            }
        }
        KeyParams::Rsa(_) | KeyParams::Symmetric(_) => Ok(()),
    }
}

// ============================================================================
// Algorithm Object Builders
// ============================================================================

/// Builds a WebCrypto algorithm object for the given key.
///
/// The algorithm object is used with `SubtleCrypto.importKey()`.
fn build_algorithm_object(key: &Key, usage: KeyUsage) -> Result<Object> {
    match &key.params {
        KeyParams::Rsa(_) => build_rsa_algorithm(key, usage),
        KeyParams::Ec(params) => build_ec_algorithm(params.crv, usage),
        KeyParams::Symmetric(_) => build_symmetric_algorithm(key, usage),
        KeyParams::Okp(_) => Err(Error::UnsupportedForWebCrypto {
            reason: "OKP keys are not supported by WebCrypto",
        }),
    }
}

/// Key usage category for determining the appropriate algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyUsage {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
}

/// Builds an RSA algorithm object.
fn build_rsa_algorithm(key: &Key, usage: KeyUsage) -> Result<Object> {
    let obj = Object::new();

    // Determine algorithm name based on key's algorithm or usage
    let (alg_name, hash) = match &key.alg {
        Some(Algorithm::Rs256) => ("RSASSA-PKCS1-v1_5", "SHA-256"),
        Some(Algorithm::Rs384) => ("RSASSA-PKCS1-v1_5", "SHA-384"),
        Some(Algorithm::Rs512) => ("RSASSA-PKCS1-v1_5", "SHA-512"),
        Some(Algorithm::Ps256) => ("RSA-PSS", "SHA-256"),
        Some(Algorithm::Ps384) => ("RSA-PSS", "SHA-384"),
        Some(Algorithm::Ps512) => ("RSA-PSS", "SHA-512"),
        Some(Algorithm::RsaOaep) => ("RSA-OAEP", "SHA-1"),
        Some(Algorithm::RsaOaep256) => ("RSA-OAEP", "SHA-256"),
        _ => {
            // Default based on usage
            match usage {
                KeyUsage::Sign | KeyUsage::Verify => ("RSASSA-PKCS1-v1_5", "SHA-256"),
                KeyUsage::Encrypt | KeyUsage::Decrypt => ("RSA-OAEP", "SHA-256"),
                KeyUsage::WrapKey | KeyUsage::UnwrapKey => ("RSA-OAEP", "SHA-256"),
            }
        }
    };

    Reflect::set(&obj, &"name".into(), &alg_name.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

    // Set hash algorithm
    let hash_obj = Object::new();
    Reflect::set(&hash_obj, &"name".into(), &hash.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set hash name: {:?}", e)))?;
    Reflect::set(&obj, &"hash".into(), &hash_obj.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set hash: {:?}", e)))?;

    Ok(obj)
}

/// Builds an EC algorithm object.
fn build_ec_algorithm(curve: EcCurve, usage: KeyUsage) -> Result<Object> {
    let obj = Object::new();

    let alg_name = match usage {
        KeyUsage::Sign | KeyUsage::Verify => "ECDSA",
        KeyUsage::Encrypt | KeyUsage::Decrypt | KeyUsage::WrapKey | KeyUsage::UnwrapKey => "ECDH",
    };

    Reflect::set(&obj, &"name".into(), &alg_name.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

    let named_curve = match curve {
        EcCurve::P256 => "P-256",
        EcCurve::P384 => "P-384",
        EcCurve::P521 => "P-521",
        EcCurve::Secp256k1 => {
            return Err(Error::UnsupportedForWebCrypto {
                reason: "secp256k1 curve is not supported by WebCrypto",
            })
        }
    };

    Reflect::set(&obj, &"namedCurve".into(), &named_curve.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set namedCurve: {:?}", e)))?;

    Ok(obj)
}

/// Builds a symmetric key algorithm object.
fn build_symmetric_algorithm(key: &Key, usage: KeyUsage) -> Result<Object> {
    let obj = Object::new();

    let (alg_name, extra) = match &key.alg {
        Some(Algorithm::Hs256) => ("HMAC", Some(("hash", "SHA-256"))),
        Some(Algorithm::Hs384) => ("HMAC", Some(("hash", "SHA-384"))),
        Some(Algorithm::Hs512) => ("HMAC", Some(("hash", "SHA-512"))),
        Some(Algorithm::A128kw) => ("AES-KW", Some(("length", "128"))),
        Some(Algorithm::A192kw) => ("AES-KW", Some(("length", "192"))),
        Some(Algorithm::A256kw) => ("AES-KW", Some(("length", "256"))),
        Some(Algorithm::A128gcm) => ("AES-GCM", Some(("length", "128"))),
        Some(Algorithm::A192gcm) => ("AES-GCM", Some(("length", "192"))),
        Some(Algorithm::A256gcm) => ("AES-GCM", Some(("length", "256"))),
        Some(Algorithm::A128cbcHs256)
        | Some(Algorithm::A192cbcHs384)
        | Some(Algorithm::A256cbcHs512) => ("AES-CBC", None),
        _ => {
            // Default based on usage
            match usage {
                KeyUsage::Sign | KeyUsage::Verify => ("HMAC", Some(("hash", "SHA-256"))),
                KeyUsage::Encrypt | KeyUsage::Decrypt => ("AES-GCM", None),
                KeyUsage::WrapKey | KeyUsage::UnwrapKey => ("AES-KW", None),
            }
        }
    };

    Reflect::set(&obj, &"name".into(), &alg_name.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

    if let Some((prop, val)) = extra {
        if prop == "hash" {
            let hash_obj = Object::new();
            Reflect::set(&hash_obj, &"name".into(), &val.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash name: {:?}", e)))?;
            Reflect::set(&obj, &"hash".into(), &hash_obj.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash: {:?}", e)))?;
        } else if prop == "length" {
            let length: u32 = val.parse().unwrap_or(256);
            Reflect::set(&obj, &"length".into(), &length.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set length: {:?}", e)))?;
        }
    }

    Ok(obj)
}

// ============================================================================
// Key Import Functions
// ============================================================================

/// Imports a JWK as a [`CryptoKey`] for signature verification.
///
/// This is the most common use case: importing a public key from a JWKS
/// to verify JWT signatures.
///
/// # Supported Key Types
///
/// - RSA public keys (RS256, RS384, RS512, PS256, PS384, PS512)
/// - EC public keys (P-256, P-384, P-521)
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeySet, integrations::web_crypto};
///
/// let jwks: KeySet = serde_json::from_str(jwks_json)?;
/// let key = jwks.find_by_kid("my-key-id").unwrap();
/// let crypto_key = web_crypto::import_verify_key(key).await?;
/// ```
pub async fn import_verify_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["verify"], KeyUsage::Verify).await
}

/// Imports a JWK as a [`CryptoKey`] for signing.
///
/// This requires a private key (RSA or EC with the `d` parameter).
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails (e.g., missing private key)
///
/// # Examples
///
/// ```ignore
/// let crypto_key = web_crypto::import_sign_key(&private_key).await?;
/// ```
pub async fn import_sign_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["sign"], KeyUsage::Sign).await
}

/// Imports a JWK as a [`CryptoKey`] for encryption.
///
/// # Supported Key Types
///
/// - RSA public keys (RSA-OAEP)
/// - Symmetric keys (AES-GCM, AES-CBC)
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
pub async fn import_encrypt_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["encrypt"], KeyUsage::Encrypt).await
}

/// Imports a JWK as a [`CryptoKey`] for decryption.
///
/// This requires a private key (RSA) or symmetric key.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
pub async fn import_decrypt_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["decrypt"], KeyUsage::Decrypt).await
}

/// Imports a JWK as a [`CryptoKey`] for key wrapping.
///
/// # Supported Key Types
///
/// - RSA public keys (RSA-OAEP)
/// - Symmetric keys (AES-KW)
pub async fn import_wrap_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["wrapKey"], KeyUsage::WrapKey).await
}

/// Imports a JWK as a [`CryptoKey`] for key unwrapping.
///
/// # Supported Key Types
///
/// - RSA private keys (RSA-OAEP)
/// - Symmetric keys (AES-KW)
pub async fn import_unwrap_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["unwrapKey"], KeyUsage::UnwrapKey).await
}

/// Imports a JWK as a [`CryptoKey`] with custom key usages.
///
/// This is the low-level function that allows specifying arbitrary key usages.
///
/// # Arguments
///
/// * `key` - The JWK to import
/// * `usages` - Array of key usage strings (e.g., `["sign", "verify"]`)
/// * `usage` - The primary usage for determining the algorithm
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
pub async fn import_key_with_usages(
    key: &Key,
    usages: &[&str],
    usage: KeyUsage,
) -> Result<CryptoKey> {
    let jwk = to_json_web_key(key)?;
    let algorithm = build_algorithm_object(key, usage)?;

    let key_usages = Array::new();
    for u in usages {
        key_usages.push(&JsValue::from_str(u));
    }

    let subtle = get_subtle_crypto()?;

    // Import the key
    let promise = subtle
        .import_key_with_object("jwk", &jwk.into(), &algorithm, false, &key_usages)
        .map_err(|e| Error::WebCrypto(format!("import_key failed: {:?}", e)))?;

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| Error::WebCrypto(format!("import_key promise rejected: {:?}", e)))?;

    Ok(result.unchecked_into())
}

// ============================================================================
// Convenience Methods on Key
// ============================================================================

impl Key {
    /// Converts this key to a [`web_sys::JsonWebKey`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedForWebCrypto`] if the key type or curve
    /// is not supported by WebCrypto.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let jwk = key.to_web_crypto_jwk()?;
    /// ```
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub fn to_web_crypto_jwk(&self) -> Result<web_sys::JsonWebKey> {
        to_json_web_key(self)
    }

    /// Returns `true` if this key can be used with WebCrypto.
    ///
    /// OKP keys and secp256k1 EC keys are not supported by WebCrypto.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if key.is_web_crypto_compatible() {
    ///     let crypto_key = key.import_as_verify_key().await?;
    /// }
    /// ```
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub fn is_web_crypto_compatible(&self) -> bool {
        validate_webcrypto_support(self).is_ok()
    }

    /// Imports this key as a [`CryptoKey`] for signature verification.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_verify_key(&self) -> Result<CryptoKey> {
        import_verify_key(self).await
    }

    /// Imports this key as a [`CryptoKey`] for signing.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_sign_key(&self) -> Result<CryptoKey> {
        import_sign_key(self).await
    }

    /// Imports this key as a [`CryptoKey`] for encryption.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_encrypt_key(&self) -> Result<CryptoKey> {
        import_encrypt_key(self).await
    }

    /// Imports this key as a [`CryptoKey`] for decryption.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_decrypt_key(&self) -> Result<CryptoKey> {
        import_decrypt_key(self).await
    }
}

// ============================================================================
// Tests
// ============================================================================

// Validation tests that can run on any target (no web_sys dependencies).
#[cfg(test)]
mod validation_tests {
    use super::*;

    const RFC_RSA_PUBLIC_KEY: &str = r#"{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    }"#;

    const RFC_EC_P256_PUBLIC_KEY: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }"#;

    const EC_SECP256K1_KEY: &str = r#"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "WbbXwISW8TLWM3IDLGm1cX_3IrYgWl_bzcLe0tSCDj4",
        "y": "KGk8DRQHPeV4S3Oq2jVJLNSV_3ngGgbfHTKsS5aw30c"
    }"#;

    const OKP_ED25519_KEY: &str = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }"#;

    const SYMMETRIC_KEY: &str = r#"{
        "kty": "oct",
        "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q",
        "alg": "HS256"
    }"#;

    #[test]
    fn test_validate_rsa_supported() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_validate_ec_p256_supported() {
        let key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_validate_symmetric_supported() {
        let key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_validate_okp_unsupported() {
        let key: Key = serde_json::from_str(OKP_ED25519_KEY).unwrap();
        let result = validate_webcrypto_support(&key);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));
    }

    #[test]
    fn test_validate_secp256k1_unsupported() {
        let key: Key = serde_json::from_str(EC_SECP256K1_KEY).unwrap();
        let result = validate_webcrypto_support(&key);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));
    }

    #[test]
    fn test_is_web_crypto_compatible_rsa() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(key.is_web_crypto_compatible());
    }

    #[test]
    fn test_is_web_crypto_compatible_okp() {
        let key: Key = serde_json::from_str(OKP_ED25519_KEY).unwrap();
        assert!(!key.is_web_crypto_compatible());
    }

    #[test]
    fn test_is_web_crypto_compatible_secp256k1() {
        let key: Key = serde_json::from_str(EC_SECP256K1_KEY).unwrap();
        assert!(!key.is_web_crypto_compatible());
    }
}

// Tests that use web_sys types - only compiled for wasm32 targets.
// For WASM integration tests, see tests/web_crypto.rs which uses wasm_bindgen_test.
#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;

    // Test RSA public key from RFC 7517 Appendix A.1
    const RFC_RSA_PUBLIC_KEY: &str = r#"{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    }"#;

    // Test EC P-256 public key from RFC 7517 Appendix A.1
    const RFC_EC_P256_PUBLIC_KEY: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }"#;

    // Test EC secp256k1 key (unsupported)
    const EC_SECP256K1_KEY: &str = r#"{
        "kty": "EC",
        "crv": "secp256k1",
        "x": "WbbXwISW8TLWM3IDLGm1cX_3IrYgWl_bzcLe0tSCDj4",
        "y": "KGk8DRQHPeV4S3Oq2jVJLNSV_3ngGgbfHTKsS5aw30c"
    }"#;

    // Test OKP Ed25519 key (unsupported)
    const OKP_ED25519_KEY: &str = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }"#;

    // Test symmetric key
    const SYMMETRIC_KEY: &str = r#"{
        "kty": "oct",
        "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q",
        "alg": "HS256"
    }"#;

    #[test]
    fn test_rsa_key_to_json_web_key() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let jwk = to_json_web_key(&key).unwrap();
        assert_eq!(jwk.kty(), "RSA");
        assert!(jwk.n().is_some());
        assert!(jwk.e().is_some());
        assert!(jwk.d().is_none()); // Public key only
    }

    #[test]
    fn test_ec_p256_key_to_json_web_key() {
        let key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        let jwk = to_json_web_key(&key).unwrap();
        assert_eq!(jwk.kty(), "EC");
        assert_eq!(jwk.crv(), Some("P-256".to_string()));
        assert!(jwk.x().is_some());
        assert!(jwk.y().is_some());
    }

    #[test]
    fn test_symmetric_key_to_json_web_key() {
        let key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        let jwk = to_json_web_key(&key).unwrap();
        assert_eq!(jwk.kty(), "oct");
        assert!(jwk.k().is_some());
    }

    #[test]
    fn test_okp_key_unsupported() {
        let key: Key = serde_json::from_str(OKP_ED25519_KEY).unwrap();
        let result = to_json_web_key(&key);
        assert!(matches!(
            result,
            Err(Error::UnsupportedForWebCrypto { .. })
        ));
    }

    #[test]
    fn test_secp256k1_key_unsupported() {
        let key: Key = serde_json::from_str(EC_SECP256K1_KEY).unwrap();
        let result = to_json_web_key(&key);
        assert!(matches!(
            result,
            Err(Error::UnsupportedForWebCrypto { .. })
        ));
    }

    #[test]
    fn test_is_web_crypto_compatible() {
        let rsa_key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(rsa_key.is_web_crypto_compatible());

        let ec_key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        assert!(ec_key.is_web_crypto_compatible());

        let okp_key: Key = serde_json::from_str(OKP_ED25519_KEY).unwrap();
        assert!(!okp_key.is_web_crypto_compatible());

        let secp256k1_key: Key = serde_json::from_str(EC_SECP256K1_KEY).unwrap();
        assert!(!secp256k1_key.is_web_crypto_compatible());
    }

    #[test]
    fn test_validate_webcrypto_support_rsa() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_validate_webcrypto_support_ec_p256() {
        let key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_validate_webcrypto_support_symmetric() {
        let key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        assert!(validate_webcrypto_support(&key).is_ok());
    }

    #[test]
    fn test_build_rsa_algorithm() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let alg = build_algorithm_object(&key, KeyUsage::Verify).unwrap();

        let name = Reflect::get(&alg, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "RSASSA-PKCS1-v1_5");
    }

    #[test]
    fn test_build_ec_algorithm() {
        let key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        let alg = build_algorithm_object(&key, KeyUsage::Verify).unwrap();

        let name = Reflect::get(&alg, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "ECDSA");

        let curve = Reflect::get(&alg, &"namedCurve".into()).unwrap();
        assert_eq!(curve.as_string().unwrap(), "P-256");
    }

    #[test]
    fn test_build_hmac_algorithm() {
        let key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        let alg = build_algorithm_object(&key, KeyUsage::Sign).unwrap();

        let name = Reflect::get(&alg, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "HMAC");
    }
}

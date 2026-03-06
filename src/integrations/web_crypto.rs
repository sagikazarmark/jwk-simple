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
//! | Symmetric | AES-GCM, AES-KW | Yes |
//!
//! # Examples
//!
//! ## Converting a Key to JsonWebKey
//!
//! ```ignore
//! use jwk_simple::Key;
//! use std::convert::TryInto;
//!
//! let key: Key = serde_json::from_str(jwk_json)?;
//! let web_jwk: web_sys::JsonWebKey = (&key).try_into()?;
//! ```
//!
//! ## Importing a Key for Signature Verification
//!
//! ```ignore
//! use jwk_simple::{Key, web_crypto};
//! use jwk_simple::Algorithm;
//!
//! let key: Key = serde_json::from_str(jwk_json)?;
//! let crypto_key = web_crypto::import_verify_key_for_alg(&key, &Algorithm::Rs256).await?;
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
//! [`Error::UnsupportedForWebCrypto`] error.

use js_sys::{Array, Object, Reflect};
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

use crate::error::{Error, Result};
use crate::jwk::{Algorithm, EcCurve, Key, KeyOperation, KeyParams};
use crate::jwks::{KeyMatcher, KeySet};

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

/// Conversion from [`Key`] to [`web_sys::JsonWebKey`] for WebCrypto usage.
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
/// use jwk_simple::Key;
/// use std::convert::TryInto;
///
/// let key: Key = serde_json::from_str(r#"{"kty":"RSA","n":"...","e":"AQAB"}"#)?;
/// let jwk: web_sys::JsonWebKey = (&key).try_into()?;
/// assert_eq!(jwk.get_kty(), "RSA");
/// ```
impl TryFrom<&Key> for web_sys::JsonWebKey {
    type Error = Error;

    fn try_from(key: &Key) -> Result<Self> {
        // Keep conversion-level validation focused on key material shape.
        // Full JWK metadata validation (including `use`/`key_ops`/x509 checks)
        // is context-dependent and should be performed by callers that need it.
        // This also avoids enforcing `key.alg` in explicit-alg import flows.
        key.params.validate()?;

        // Validate that the key type is supported
        validate_webcrypto_support(key)?;

        let jwk = web_sys::JsonWebKey::new(&key.kty().as_str());

        // Set common optional fields
        // Note: `kid` is not part of the WebCrypto JsonWebKey dictionary,
        // so it is not set here.

        if let Some(alg) = &key.alg {
            jwk.set_alg(alg.as_str());
        }

        if let Some(key_use) = &key.key_use {
            jwk.set_use(key_use.as_str());
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
    build_algorithm_object_with_alg(key, usage, None)
}

fn build_algorithm_object_for_alg(key: &Key, alg: &Algorithm, usage: KeyUsage) -> Result<Object> {
    build_algorithm_object_with_alg(key, usage, Some(alg))
}

fn build_algorithm_object_with_alg(
    key: &Key,
    usage: KeyUsage,
    alg_override: Option<&Algorithm>,
) -> Result<Object> {
    match &key.params {
        KeyParams::Rsa(_) => build_rsa_algorithm(key, usage, alg_override),
        KeyParams::Ec(params) => {
            // When an explicit algorithm is provided, validate that it is
            // compatible with the key's curve before building the import
            // algorithm object. This catches mismatches like ES384 with a
            // P-256 key early, instead of letting them surface as opaque
            // WebCrypto errors during verify/sign.
            if let Some(alg) = alg_override {
                let expected_curve = match alg {
                    Algorithm::Es256 => Some(EcCurve::P256),
                    Algorithm::Es384 => Some(EcCurve::P384),
                    Algorithm::Es512 => Some(EcCurve::P521),
                    _ => None,
                };
                match expected_curve {
                    Some(curve) if curve != params.crv => {
                        return Err(Error::WebCrypto(format!(
                            "algorithm {} requires curve {}, but the key uses {}",
                            alg.as_str(),
                            curve.name(),
                            params.crv.name(),
                        )));
                    }
                    None => {
                        return Err(Error::WebCrypto(format!(
                            "algorithm {} is not supported for EC key import in WebCrypto",
                            alg.as_str(),
                        )));
                    }
                    _ => {} // curve matches, proceed
                }
            }
            build_ec_algorithm(params.crv, usage)
        }
        KeyParams::Symmetric(_) => build_symmetric_algorithm(key, usage, alg_override),
        KeyParams::Okp(_) => Err(Error::UnsupportedForWebCrypto {
            reason: "OKP keys are not supported by WebCrypto",
        }),
    }
}

fn validate_usage_algorithm_compatibility(usage: KeyUsage, alg: &Algorithm) -> Result<()> {
    let allowed = match usage {
        KeyUsage::Verify => matches!(
            alg,
            Algorithm::Rs256
                | Algorithm::Rs384
                | Algorithm::Rs512
                | Algorithm::Ps256
                | Algorithm::Ps384
                | Algorithm::Ps512
                | Algorithm::Es256
                | Algorithm::Es384
                | Algorithm::Es512
                | Algorithm::Hs256
                | Algorithm::Hs384
                | Algorithm::Hs512
        ),
        KeyUsage::Sign => matches!(
            alg,
            Algorithm::Rs256
                | Algorithm::Rs384
                | Algorithm::Rs512
                | Algorithm::Ps256
                | Algorithm::Ps384
                | Algorithm::Ps512
                | Algorithm::Es256
                | Algorithm::Es384
                | Algorithm::Es512
                | Algorithm::Hs256
                | Algorithm::Hs384
                | Algorithm::Hs512
        ),
        KeyUsage::Encrypt => matches!(
            alg,
            Algorithm::RsaOaep
                | Algorithm::RsaOaep256
                | Algorithm::RsaOaep384
                | Algorithm::RsaOaep512
                | Algorithm::A128gcm
                | Algorithm::A192gcm
                | Algorithm::A256gcm
        ),
        KeyUsage::Decrypt => matches!(
            alg,
            Algorithm::RsaOaep
                | Algorithm::RsaOaep256
                | Algorithm::RsaOaep384
                | Algorithm::RsaOaep512
                | Algorithm::A128gcm
                | Algorithm::A192gcm
                | Algorithm::A256gcm
        ),
        KeyUsage::WrapKey => matches!(
            alg,
            Algorithm::RsaOaep
                | Algorithm::RsaOaep256
                | Algorithm::RsaOaep384
                | Algorithm::RsaOaep512
                | Algorithm::A128kw
                | Algorithm::A192kw
                | Algorithm::A256kw
        ),
        KeyUsage::UnwrapKey => matches!(
            alg,
            Algorithm::RsaOaep
                | Algorithm::RsaOaep256
                | Algorithm::RsaOaep384
                | Algorithm::RsaOaep512
                | Algorithm::A128kw
                | Algorithm::A192kw
                | Algorithm::A256kw
        ),
    };

    if allowed {
        Ok(())
    } else {
        Err(Error::UnsupportedForWebCrypto {
            reason: "algorithm is not compatible with requested key usage",
        })
    }
}

fn validate_key_for_webcrypto_usage_with_alg(
    key: &Key,
    usage: KeyUsage,
    alg: &Algorithm,
) -> Result<()> {
    validate_usage_algorithm_compatibility(usage, alg)?;
    key.validate_for_use(alg, [key_operation_for_usage(usage)])
}

fn validate_key_for_webcrypto_usage(key: &Key, usage: KeyUsage) -> Result<()> {
    let requested_op = key_operation_for_usage(usage);

    if let Some(alg) = key.alg.as_ref() {
        validate_usage_algorithm_compatibility(usage, alg)?;
        key.validate_for_use(alg, [requested_op])?;
        return Ok(());
    }

    // No algorithm on key: structural validation + operation intent only.
    // `validate()` already enforced `use`/`key_ops` consistency and uniqueness,
    // so we call the intent-only helper directly.
    key.validate()?;
    key.validate_operation_intent_for_all(std::slice::from_ref(&requested_op))?;

    Ok(())
}

fn key_operation_for_usage(usage: KeyUsage) -> KeyOperation {
    match usage {
        KeyUsage::Sign => KeyOperation::Sign,
        KeyUsage::Verify => KeyOperation::Verify,
        KeyUsage::Encrypt => KeyOperation::Encrypt,
        KeyUsage::Decrypt => KeyOperation::Decrypt,
        KeyUsage::WrapKey => KeyOperation::WrapKey,
        KeyUsage::UnwrapKey => KeyOperation::UnwrapKey,
    }
}

/// Key usage category for determining the appropriate algorithm.
///
/// This is used by the low-level [`import_key_with_usages`] and
/// [`import_key_with_usages_for_alg`] functions to select the correct
/// WebCrypto algorithm parameters at import time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyUsage {
    /// The key will be used for signing.
    Sign,
    /// The key will be used for signature verification.
    Verify,
    /// The key will be used for encryption.
    Encrypt,
    /// The key will be used for decryption.
    Decrypt,
    /// The key will be used for wrapping other keys.
    WrapKey,
    /// The key will be used for unwrapping other keys.
    UnwrapKey,
}

/// Builds an RSA algorithm object.
///
/// The algorithm is determined from (in order of priority):
/// 1. The `alg_override` parameter (if provided)
/// 2. The key's `alg` field (if present)
///
/// If neither is available, an error is returned because WebCrypto requires
/// the hash algorithm to be specified at import time and a wrong default
/// (e.g., SHA-256 for a key intended for RS384) would cause silent
/// verification failures.
fn build_rsa_algorithm(
    key: &Key,
    _usage: KeyUsage,
    alg_override: Option<&Algorithm>,
) -> Result<Object> {
    let obj = Object::new();

    // Use the override first, then fall back to the key's own algorithm
    let effective_alg = alg_override.or(key.alg.as_ref());

    // Determine algorithm name and hash based on the effective algorithm
    let (alg_name, hash) = match effective_alg {
        Some(Algorithm::Rs256) => ("RSASSA-PKCS1-v1_5", "SHA-256"),
        Some(Algorithm::Rs384) => ("RSASSA-PKCS1-v1_5", "SHA-384"),
        Some(Algorithm::Rs512) => ("RSASSA-PKCS1-v1_5", "SHA-512"),
        Some(Algorithm::Ps256) => ("RSA-PSS", "SHA-256"),
        Some(Algorithm::Ps384) => ("RSA-PSS", "SHA-384"),
        Some(Algorithm::Ps512) => ("RSA-PSS", "SHA-512"),
        Some(Algorithm::RsaOaep) => ("RSA-OAEP", "SHA-1"),
        Some(Algorithm::RsaOaep256) => ("RSA-OAEP", "SHA-256"),
        Some(Algorithm::RsaOaep384) => ("RSA-OAEP", "SHA-384"),
        Some(Algorithm::RsaOaep512) => ("RSA-OAEP", "SHA-512"),
        _ => {
            return Err(Error::WebCrypto(
                "RSA key import requires an algorithm to determine the hash function; \
                 set the `alg` field on the key or use an import function that accepts \
                 an explicit algorithm (e.g., `import_verify_key_for_alg`)"
                    .to_string(),
            ));
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
        KeyUsage::Encrypt | KeyUsage::Decrypt | KeyUsage::WrapKey | KeyUsage::UnwrapKey => {
            return Err(Error::UnsupportedForWebCrypto {
                reason: "EC key derivation (ECDH) and direct encrypt/decrypt/wrap/unwrap \
                         are not yet supported by this library; \
                         only ECDSA sign/verify is currently implemented for EC keys",
            });
        }
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
            });
        }
    };

    Reflect::set(&obj, &"namedCurve".into(), &named_curve.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set namedCurve: {:?}", e)))?;

    Ok(obj)
}

/// Builds a symmetric key algorithm object.
///
/// The algorithm is determined from (in order of priority):
/// 1. The `alg_override` parameter (if provided)
/// 2. The key's `alg` field (if present)
///
/// If neither is available, an error is returned because WebCrypto requires
/// the hash algorithm to be specified at import time for HMAC keys, and a
/// wrong default would cause silent verification failures.
fn build_symmetric_algorithm(
    key: &Key,
    _usage: KeyUsage,
    alg_override: Option<&Algorithm>,
) -> Result<Object> {
    let obj = Object::new();

    // Use the override first, then fall back to the key's own algorithm
    let effective_alg = alg_override.or(key.alg.as_ref());

    let (alg_name, extra) = match effective_alg {
        Some(Algorithm::Hs256) => ("HMAC", Some(("hash", "SHA-256"))),
        Some(Algorithm::Hs384) => ("HMAC", Some(("hash", "SHA-384"))),
        Some(Algorithm::Hs512) => ("HMAC", Some(("hash", "SHA-512"))),
        // AES-KW and AES-GCM importKey takes no algorithm parameters beyond the name.
        // The key size is determined from the imported key material itself.
        // See W3C WebCrypto spec sections 30.3.4 (AES-KW) and 29.4.4 (AES-GCM).
        Some(Algorithm::A128kw) | Some(Algorithm::A192kw) | Some(Algorithm::A256kw) => {
            ("AES-KW", None)
        }
        Some(Algorithm::A128gcm) | Some(Algorithm::A192gcm) | Some(Algorithm::A256gcm) => {
            ("AES-GCM", None)
        }
        Some(Algorithm::A128cbcHs256)
        | Some(Algorithm::A192cbcHs384)
        | Some(Algorithm::A256cbcHs512) => {
            return Err(Error::UnsupportedForWebCrypto {
                reason: "AES-CBC-HS algorithms (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512) \
                         are composite authenticated encryption algorithms requiring split-key \
                         handling (AES-CBC + HMAC) which WebCrypto does not natively support",
            });
        }
        _ => {
            return Err(Error::WebCrypto(
                "symmetric key import requires an algorithm to determine the operation; \
                 set the `alg` field on the key or use an import function that accepts \
                 an explicit algorithm (e.g., `import_verify_key_for_alg`)"
                    .to_string(),
            ));
        }
    };

    Reflect::set(&obj, &"name".into(), &alg_name.into())
        .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

    if let Some((prop, val)) = extra {
        debug_assert_eq!(prop, "hash", "only HMAC uses extra parameters");
        let hash_obj = Object::new();
        Reflect::set(&hash_obj, &"name".into(), &val.into())
            .map_err(|e| Error::WebCrypto(format!("failed to set hash name: {:?}", e)))?;
        Reflect::set(&obj, &"hash".into(), &hash_obj.into())
            .map_err(|e| Error::WebCrypto(format!("failed to set hash: {:?}", e)))?;
    }

    Ok(obj)
}

/// Builds a WebCrypto algorithm object for use with `SubtleCrypto.verify()`.
///
/// This is different from the import algorithm: `verify()` requires algorithm-specific
/// parameters like `saltLength` (RSA-PSS) or `hash` (ECDSA), while not needing
/// parameters like `namedCurve` that are only needed during import.
///
/// # Supported Algorithms
///
/// | Algorithm | Verify Object |
/// |-----------|---------------|
/// | RS256/384/512 | `{ name: "RSASSA-PKCS1-v1_5" }` |
/// | PS256/384/512 | `{ name: "RSA-PSS", saltLength }` |
/// | ES256/384/512 | `{ name: "ECDSA", hash }` |
/// | HS256/384/512 | `{ name: "HMAC" }` |
///
/// # Errors
///
/// Returns [`Error::UnsupportedForWebCrypto`] if the algorithm is not supported
/// by WebCrypto (e.g., EdDSA, Ed25519, Ed448, ES256K).
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{Algorithm, web_crypto};
///
/// let alg = Algorithm::Rs256;
/// let verify_algo = web_crypto::build_verify_algorithm(&alg)?;
///
/// // Use with SubtleCrypto.verify()
/// let subtle = web_crypto::get_subtle_crypto()?;
/// let result = subtle.verify_with_object_and_buffer_source_and_buffer_source(
///     &verify_algo, &crypto_key, &signature, &data,
/// )?;
/// ```
pub fn build_verify_algorithm(alg: &Algorithm) -> Result<Object> {
    let obj = Object::new();

    match alg {
        // RSASSA-PKCS1-v1_5: only needs the algorithm name
        Algorithm::Rs256 | Algorithm::Rs384 | Algorithm::Rs512 => {
            Reflect::set(&obj, &"name".into(), &"RSASSA-PKCS1-v1_5".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
        }

        // RSA-PSS: needs algorithm name and salt length (= hash output size in bytes)
        Algorithm::Ps256 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &32.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }
        Algorithm::Ps384 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &48.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }
        Algorithm::Ps512 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &64.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }

        // ECDSA: needs algorithm name and hash
        Algorithm::Es256 | Algorithm::Es384 | Algorithm::Es512 => {
            Reflect::set(&obj, &"name".into(), &"ECDSA".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

            let hash = match alg {
                Algorithm::Es256 => "SHA-256",
                Algorithm::Es384 => "SHA-384",
                Algorithm::Es512 => "SHA-512",
                _ => unreachable!(),
            };

            let hash_obj = Object::new();
            Reflect::set(&hash_obj, &"name".into(), &hash.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash name: {:?}", e)))?;
            Reflect::set(&obj, &"hash".into(), &hash_obj.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash: {:?}", e)))?;
        }

        // HMAC: only needs the algorithm name
        Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
            Reflect::set(&obj, &"name".into(), &"HMAC".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
        }

        _ => {
            return Err(Error::UnsupportedForWebCrypto {
                reason: "algorithm not supported for WebCrypto verify",
            });
        }
    }

    Ok(obj)
}

// ============================================================================
// Key Import Functions
// ============================================================================

/// Imports a JWK as a [`CryptoKey`] for signature verification.
///
/// This requires the key's `alg` field to be set for RSA and HMAC keys, because
/// WebCrypto locks the hash algorithm at import time. EC keys do not require `alg`
/// since the curve already determines the algorithm parameters.
///
/// **For keys without an `alg` field** (common in JWKS from OIDC providers), use
/// [`import_verify_key_for_alg`] instead, passing the algorithm from the JWT header.
///
/// # Supported Key Types
///
/// - RSA public keys (RS256, RS384, RS512, PS256, PS384, PS512) - requires `alg`
/// - EC public keys (P-256, P-384, P-521)
/// - HMAC symmetric keys (HS256, HS384, HS512) - requires `alg`
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails or the key is missing
///   a required `alg` field (RSA/HMAC only)
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{web_crypto, KeySet};
///
/// let jwks: KeySet = serde_json::from_str(jwks_json)?;
/// let key = jwks.get_by_kid("my-key-id").unwrap();
///
/// // Works when the key has an `alg` field set
/// let crypto_key = web_crypto::import_verify_key(key).await?;
/// ```
pub async fn import_verify_key(key: &Key) -> Result<CryptoKey> {
    import_key_with_usages(key, &["verify"], KeyUsage::Verify).await
}

/// Imports a JWK as a [`CryptoKey`] for signing.
///
/// This requires a private key (RSA or EC with the `d` parameter) and, for RSA
/// and HMAC keys, the key's `alg` field must be set because WebCrypto locks the
/// hash algorithm at import time.
///
/// **For keys without an `alg` field**, use [`import_sign_key_for_alg`] instead.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails (e.g., missing private key
///   or missing `alg` field for RSA/HMAC)
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
/// This requires the key's `alg` field to be set for RSA and symmetric keys,
/// because WebCrypto requires the import algorithm to be specified.
/// For keys without an `alg` field, use [`import_key_with_usages_for_alg`]
/// with [`KeyUsage::Encrypt`] and an explicit algorithm.
///
/// # Supported Key Types
///
/// - RSA public keys (RSA-OAEP)
/// - Symmetric keys (AES-GCM)
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails (including missing `alg`)
pub async fn import_encrypt_key(key: &Key) -> Result<CryptoKey> {
    if matches!(&key.params, KeyParams::Ec(_)) {
        return Err(Error::UnsupportedForWebCrypto {
            reason: "EC keys do not support direct encryption; \
                     use ECDH key agreement (deriveKey/deriveBits) instead",
        });
    }
    import_key_with_usages(key, &["encrypt"], KeyUsage::Encrypt).await
}

/// Imports a JWK as a [`CryptoKey`] for decryption.
///
/// This requires a private key (RSA) or symmetric key.
/// This also requires the key's `alg` field to be set for RSA and symmetric keys,
/// because WebCrypto requires the import algorithm to be specified.
/// For keys without an `alg` field, use [`import_key_with_usages_for_alg`]
/// with [`KeyUsage::Decrypt`] and an explicit algorithm.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails (including missing `alg`)
pub async fn import_decrypt_key(key: &Key) -> Result<CryptoKey> {
    if matches!(&key.params, KeyParams::Ec(_)) {
        return Err(Error::UnsupportedForWebCrypto {
            reason: "EC keys do not support direct decryption; \
                     use ECDH key agreement (deriveKey/deriveBits) instead",
        });
    }
    import_key_with_usages(key, &["decrypt"], KeyUsage::Decrypt).await
}

/// Imports a JWK as a [`CryptoKey`] for key wrapping.
///
/// This requires the key's `alg` field to be set for RSA and symmetric keys,
/// because WebCrypto requires the import algorithm to be specified.
/// For keys without an `alg` field, use [`import_key_with_usages_for_alg`]
/// with [`KeyUsage::WrapKey`] and an explicit algorithm.
///
/// # Supported Key Types
///
/// - RSA public keys (RSA-OAEP)
/// - Symmetric keys (AES-KW)
pub async fn import_wrap_key(key: &Key) -> Result<CryptoKey> {
    if matches!(&key.params, KeyParams::Ec(_)) {
        return Err(Error::UnsupportedForWebCrypto {
            reason: "EC keys do not support direct key wrapping; \
                     use ECDH key agreement (deriveKey/deriveBits) instead",
        });
    }
    import_key_with_usages(key, &["wrapKey"], KeyUsage::WrapKey).await
}

/// Imports a JWK as a [`CryptoKey`] for key unwrapping.
///
/// This requires the key's `alg` field to be set for RSA and symmetric keys,
/// because WebCrypto requires the import algorithm to be specified.
/// For keys without an `alg` field, use [`import_key_with_usages_for_alg`]
/// with [`KeyUsage::UnwrapKey`] and an explicit algorithm.
///
/// # Supported Key Types
///
/// - RSA private keys (RSA-OAEP)
/// - Symmetric keys (AES-KW)
pub async fn import_unwrap_key(key: &Key) -> Result<CryptoKey> {
    if matches!(&key.params, KeyParams::Ec(_)) {
        return Err(Error::UnsupportedForWebCrypto {
            reason: "EC keys do not support direct key unwrapping; \
                     use ECDH key agreement (deriveKey/deriveBits) instead",
        });
    }
    import_key_with_usages(key, &["unwrapKey"], KeyUsage::UnwrapKey).await
}

/// Imports a JWK as a [`CryptoKey`] for signature verification with an explicit algorithm.
///
/// This is useful when the key's `alg` field is absent (common in JWKS from OIDC providers).
/// WebCrypto locks the hash algorithm at import time, so the algorithm must be known
/// before importing the key. Using this function avoids a potential mismatch between
/// the import algorithm and the verification algorithm.
///
/// # Supported Algorithms
///
/// - RSA: RS256, RS384, RS512, PS256, PS384, PS512
/// - EC: ES256, ES384, ES512
/// - HMAC: HS256, HS384, HS512
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{Algorithm, web_crypto, KeySet};
///
/// let jwks: KeySet = serde_json::from_str(jwks_json)?;
/// let key = jwks.get_by_kid("my-key-id").unwrap();
/// // Use the algorithm from the JWT header, not the key
/// let crypto_key = web_crypto::import_verify_key_for_alg(key, &Algorithm::Rs384).await?;
/// ```
pub async fn import_verify_key_for_alg(key: &Key, alg: &Algorithm) -> Result<CryptoKey> {
    import_key_with_usages_for_alg(key, &["verify"], KeyUsage::Verify, alg).await
}

/// Imports a JWK as a [`CryptoKey`] for signing with an explicit algorithm.
///
/// This is useful when the key's `alg` field is absent. See
/// [`import_verify_key_for_alg`] for more details on why this matters.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
pub async fn import_sign_key_for_alg(key: &Key, alg: &Algorithm) -> Result<CryptoKey> {
    import_key_with_usages_for_alg(key, &["sign"], KeyUsage::Sign, alg).await
}

/// Imports a JWK as a [`CryptoKey`] with custom key usages.
///
/// This is the low-level function that allows specifying arbitrary key usages.
///
/// The key must have an `alg` field set so that the correct WebCrypto algorithm
/// parameters can be determined. For RSA and HMAC keys without an `alg` field,
/// use [`import_key_with_usages_for_alg`] instead.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails or the key is missing
///   a required `alg` field
pub async fn import_key_with_usages(
    key: &Key,
    usages: &[&str],
    usage: KeyUsage,
) -> Result<CryptoKey> {
    validate_key_for_webcrypto_usage(key, usage)?;

    let jwk = web_sys::JsonWebKey::try_from(key)?;
    let algorithm = build_algorithm_object(key, usage)?;

    import_crypto_key(jwk, &algorithm, usages).await
}

/// Imports a JWK as a [`CryptoKey`] with custom key usages and an explicit algorithm.
///
/// This is the low-level function that allows specifying arbitrary key usages
/// and an explicit algorithm. The `alg` parameter overrides the key's own `alg`
/// field, ensuring the correct WebCrypto algorithm parameters are used at import time.
///
/// # Errors
///
/// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
/// - [`Error::WebCrypto`] if the import operation fails
pub async fn import_key_with_usages_for_alg(
    key: &Key,
    usages: &[&str],
    usage: KeyUsage,
    alg: &Algorithm,
) -> Result<CryptoKey> {
    validate_key_for_webcrypto_usage_with_alg(key, usage, alg)?;
    let jwk = web_sys::JsonWebKey::try_from(key)?;

    // Override the JWK's `alg` field to match the explicit algorithm.
    // WebCrypto validates that the JWK `alg` (if present) is consistent with
    // the algorithm parameter passed to importKey(). Without this override,
    // importing a key whose `alg` differs from the explicit algorithm would
    // fail with a DataError.
    jwk.set_alg(alg.as_str());

    let algorithm = build_algorithm_object_for_alg(key, alg, usage)?;

    import_crypto_key(jwk, &algorithm, usages).await
}

/// Internal helper that performs the actual SubtleCrypto.importKey() call.
async fn import_crypto_key(
    jwk: web_sys::JsonWebKey,
    algorithm: &Object,
    usages: &[&str],
) -> Result<CryptoKey> {
    let key_usages = Array::new();
    for u in usages {
        key_usages.push(&JsValue::from_str(u));
    }

    let subtle = get_subtle_crypto()?;

    // Import the key
    let promise = subtle
        .import_key_with_object("jwk", &jwk.into(), algorithm, false, &key_usages)
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
    /// Returns `true` if this key can be used with WebCrypto.
    ///
    /// OKP keys and secp256k1 EC keys are not supported by WebCrypto.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if key.is_web_crypto_compatible() {
    ///     let crypto_key = key.import_as_verify_key_for_alg(&alg).await?;
    /// }
    /// ```
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub fn is_web_crypto_compatible(&self) -> bool {
        validate_webcrypto_support(self).is_ok()
    }

    /// Imports this key as a [`CryptoKey`] for signature verification.
    ///
    /// RSA and HMAC keys must have their `alg` field set. For keys without `alg`
    /// (common in JWKS from OIDC providers), use
    /// [`import_as_verify_key_for_alg`](Key::import_as_verify_key_for_alg) instead.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails or the key is missing
    ///   a required `alg` field (RSA/HMAC only)
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_verify_key(&self) -> Result<CryptoKey> {
        import_verify_key(self).await
    }

    /// Imports this key as a [`CryptoKey`] for signing.
    ///
    /// RSA and HMAC keys must have their `alg` field set. For keys without `alg`,
    /// use [`import_as_sign_key_for_alg`](Key::import_as_sign_key_for_alg) instead.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails or the key is missing
    ///   a required `alg` field (RSA/HMAC only)
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
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_decrypt_key(&self) -> Result<CryptoKey> {
        import_decrypt_key(self).await
    }

    /// Imports this key as a [`CryptoKey`] for signature verification with an explicit algorithm.
    ///
    /// This is useful when the key's `alg` field is absent (common in JWKS from
    /// OIDC providers). WebCrypto locks the hash algorithm at import time, so the
    /// algorithm must be known before importing. The `alg` parameter overrides the
    /// key's own `alg` field.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_verify_key_for_alg(&self, alg: &Algorithm) -> Result<CryptoKey> {
        import_verify_key_for_alg(self, alg).await
    }

    /// Imports this key as a [`CryptoKey`] for signing with an explicit algorithm.
    ///
    /// This is useful when the key's `alg` field is absent. See
    /// [`Key::import_as_verify_key_for_alg`] for more details.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedForWebCrypto`] if the key type is not supported
    /// - [`Error::WebCrypto`] if the import operation fails
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    pub async fn import_as_sign_key_for_alg(&self, alg: &Algorithm) -> Result<CryptoKey> {
        import_sign_key_for_alg(self, alg).await
    }
}

// ============================================================================
// Tests
// ============================================================================

// Validation tests that can run on any target (no web_sys dependencies).
#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::jwks::KeySet;

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

    #[test]
    fn test_usage_algorithm_compatibility_rejects_mismatch() {
        let result = validate_usage_algorithm_compatibility(KeyUsage::Encrypt, &Algorithm::Rs256);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));

        let result =
            validate_usage_algorithm_compatibility(KeyUsage::Verify, &Algorithm::RsaOaep256);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));
    }

    #[test]
    fn test_usage_algorithm_compatibility_accepts_valid_pairs() {
        assert!(
            validate_usage_algorithm_compatibility(KeyUsage::Verify, &Algorithm::Rs256).is_ok()
        );
        assert!(
            validate_usage_algorithm_compatibility(KeyUsage::Encrypt, &Algorithm::RsaOaep256)
                .is_ok()
        );
        assert!(
            validate_usage_algorithm_compatibility(KeyUsage::WrapKey, &Algorithm::A128kw).is_ok()
        );
    }

    #[test]
    fn test_import_usage_validation_enforces_metadata_when_alg_present() {
        let mut key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        key.key_ops = Some(vec![
            crate::jwk::KeyOperation::Sign,
            crate::jwk::KeyOperation::Sign,
        ]);

        let result = validate_key_for_webcrypto_usage(&key, KeyUsage::Sign);
        assert!(result.is_err(), "duplicate key_ops must be rejected");
    }

    #[test]
    fn test_validate_key_for_webcrypto_usage_rejects_incompatible_use() {
        let json = r#"{
            "kty": "RSA",
            "use": "enc",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let key: Key = serde_json::from_str(json).unwrap();
        let result = validate_key_for_webcrypto_usage(&key, KeyUsage::Verify);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_key_for_webcrypto_usage_allows_missing_optional_metadata() {
        let json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let key: Key = serde_json::from_str(json).unwrap();
        let result = validate_key_for_webcrypto_usage(&key, KeyUsage::Verify);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_for_webcrypto_usage_rejects_incompatible_use_without_alg() {
        let json = r#"{
            "kty": "RSA",
            "use": "enc",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let key: Key = serde_json::from_str(json).unwrap();
        let result = validate_key_for_webcrypto_usage(&key, KeyUsage::Verify);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_verify_key_strict_for_web_crypto_flow() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-verify", "use": "sig", "alg": "RS256", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .selector(&[Algorithm::Rs256])
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("rsa-verify"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("rsa-verify"));
    }

    #[test]
    fn test_select_signing_key_strict_for_web_crypto_flow() {
        let json = r#"{"keys": [
            {"kty": "EC", "kid": "ec-sign", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .selector(&[])
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("ec-sign"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("ec-sign"));
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
        let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();
        assert_eq!(jwk.get_kty(), "RSA");
        assert!(jwk.get_n().is_some());
        assert!(jwk.get_e().is_some());
        assert!(jwk.get_d().is_none()); // Public key only
    }

    #[test]
    fn test_ec_p256_key_to_json_web_key() {
        let key: Key = serde_json::from_str(RFC_EC_P256_PUBLIC_KEY).unwrap();
        let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();
        assert_eq!(jwk.get_kty(), "EC");
        assert_eq!(jwk.get_crv(), Some("P-256".to_string()));
        assert!(jwk.get_x().is_some());
        assert!(jwk.get_y().is_some());
    }

    #[test]
    fn test_symmetric_key_to_json_web_key() {
        let key: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();
        assert_eq!(jwk.get_kty(), "oct");
        assert!(jwk.get_k().is_some());
    }

    #[test]
    fn test_okp_key_unsupported() {
        let key: Key = serde_json::from_str(OKP_ED25519_KEY).unwrap();
        let result = web_sys::JsonWebKey::try_from(&key);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));
    }

    #[test]
    fn test_secp256k1_key_unsupported() {
        let key: Key = serde_json::from_str(EC_SECP256K1_KEY).unwrap();
        let result = web_sys::JsonWebKey::try_from(&key);
        assert!(matches!(result, Err(Error::UnsupportedForWebCrypto { .. })));
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
    fn test_build_rsa_algorithm_with_explicit_alg() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let alg =
            build_algorithm_object_for_alg(&key, &Algorithm::Rs256, KeyUsage::Verify).unwrap();

        let name = Reflect::get(&alg, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "RSASSA-PKCS1-v1_5");
    }

    #[test]
    fn test_build_rsa_algorithm_without_alg_errors() {
        let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let result = build_algorithm_object(&key, KeyUsage::Verify);
        assert!(result.is_err(), "RSA key without alg should error");
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

    #[test]
    fn test_build_verify_algorithm_rs256() {
        let alg = Algorithm::Rs256;
        let obj = build_verify_algorithm(&alg).unwrap();

        let name = Reflect::get(&obj, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "RSASSA-PKCS1-v1_5");

        // RSASSA-PKCS1-v1_5 verify does NOT need hash
        let hash = Reflect::get(&obj, &"hash".into()).unwrap();
        assert!(hash.is_undefined());
    }

    #[test]
    fn test_build_verify_algorithm_ps256() {
        let alg = Algorithm::Ps256;
        let obj = build_verify_algorithm(&alg).unwrap();

        let name = Reflect::get(&obj, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "RSA-PSS");

        let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
        assert_eq!(salt_length.as_f64().unwrap() as u32, 32);
    }

    #[test]
    fn test_build_verify_algorithm_ps384() {
        let alg = Algorithm::Ps384;
        let obj = build_verify_algorithm(&alg).unwrap();

        let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
        assert_eq!(salt_length.as_f64().unwrap() as u32, 48);
    }

    #[test]
    fn test_build_verify_algorithm_ps512() {
        let alg = Algorithm::Ps512;
        let obj = build_verify_algorithm(&alg).unwrap();

        let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
        assert_eq!(salt_length.as_f64().unwrap() as u32, 64);
    }

    #[test]
    fn test_build_verify_algorithm_es256() {
        let alg = Algorithm::Es256;
        let obj = build_verify_algorithm(&alg).unwrap();

        let name = Reflect::get(&obj, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "ECDSA");

        let hash = Reflect::get(&obj, &"hash".into()).unwrap();
        let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
        assert_eq!(hash_name.as_string().unwrap(), "SHA-256");
    }

    #[test]
    fn test_build_verify_algorithm_es384() {
        let alg = Algorithm::Es384;
        let obj = build_verify_algorithm(&alg).unwrap();

        let hash = Reflect::get(&obj, &"hash".into()).unwrap();
        let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
        assert_eq!(hash_name.as_string().unwrap(), "SHA-384");
    }

    #[test]
    fn test_build_verify_algorithm_es512() {
        let alg = Algorithm::Es512;
        let obj = build_verify_algorithm(&alg).unwrap();

        let hash = Reflect::get(&obj, &"hash".into()).unwrap();
        let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
        assert_eq!(hash_name.as_string().unwrap(), "SHA-512");
    }

    #[test]
    fn test_build_verify_algorithm_hs256() {
        let alg = Algorithm::Hs256;
        let obj = build_verify_algorithm(&alg).unwrap();

        let name = Reflect::get(&obj, &"name".into()).unwrap();
        assert_eq!(name.as_string().unwrap(), "HMAC");
    }

    #[test]
    fn test_build_verify_algorithm_unsupported() {
        let alg = Algorithm::EdDsa;
        let result = build_verify_algorithm(&alg);
        assert!(result.is_err());

        let alg = Algorithm::Ed25519;
        let result = build_verify_algorithm(&alg);
        assert!(result.is_err());

        let alg = Algorithm::Ed448;
        let result = build_verify_algorithm(&alg);
        assert!(result.is_err());
    }
}

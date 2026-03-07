//! jwt-simple key conversion implementations.
//!
//! # Security Note — RSA Timing Side-Channel (RUSTSEC-2023-0071)
//!
//! The underlying [`rsa`] crate (used by `jwt-simple`) does not perform
//! RSA private-key operations in constant time. This means RSA **signing**
//! conversions produced by this module may be vulnerable to timing
//! side-channel attacks that could leak private key material.
//!
//! This library is primarily designed for key parsing, selection, and
//! **verification**, where the timing issue is not relevant (verification
//! uses the public exponent). If you use these conversions for RSA signing
//! in a threat model where timing attacks are a concern, evaluate whether
//! the risk is acceptable for your deployment.
//!
//! See [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)
//! for details. No upstream fix is currently available.

use jwt_simple::prelude::*;
use pkcs1::der::Encode;
use pkcs1::{RsaPrivateKey as Pkcs1RsaPrivateKey, RsaPublicKey as Pkcs1RsaPublicKey, UintRef};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::jwk::{Algorithm, EcCurve, Key, KeyOperation, KeyParams, OkpCurve, RsaParams};

// ============================================================================
// RSA Key Conversions
// ============================================================================

/// Builds a DER-encoded RSA public key from JWK parameters.
///
/// The DER format used is PKCS#1 RSAPublicKey:
/// ```text
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
fn build_rsa_public_key_der(params: &RsaParams) -> Result<Vec<u8>> {
    let modulus = uint_ref(params.n.as_bytes(), "n")?;
    let public_exponent = uint_ref(params.e.as_bytes(), "e")?;

    Pkcs1RsaPublicKey {
        modulus,
        public_exponent,
    }
    .to_der()
    .map_err(|e| Error::Other(format!("failed to encode PKCS#1 RSA public key: {e}")))
}

/// Builds a DER-encoded RSA private key from JWK parameters.
///
/// The DER format used is PKCS#1 RSAPrivateKey:
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- dp (d mod p-1)
///     exponent2         INTEGER,  -- dq (d mod q-1)
///     coefficient       INTEGER,  -- qi (q^-1 mod p)
/// }
/// ```
fn build_rsa_private_key_der(params: &RsaParams) -> Result<Zeroizing<Vec<u8>>> {
    // Multi-prime RSA keys (with `oth` parameter) require PKCS#1 version 1
    // encoding with otherPrimeInfos, which is not implemented. Reject them
    // explicitly rather than producing a structurally incorrect two-prime DER.
    if params.oth.is_some() {
        return Err(Error::Other(
            "multi-prime RSA keys are not supported for jwt-simple conversion".into(),
        ));
    }

    let d = params.d.as_ref().ok_or(Error::MissingPrivateKey)?;
    let p = params
        .p
        .as_ref()
        .ok_or(Error::MissingField { field: "p" })?;
    let q = params
        .q
        .as_ref()
        .ok_or(Error::MissingField { field: "q" })?;
    let dp = params
        .dp
        .as_ref()
        .ok_or(Error::MissingField { field: "dp" })?;
    let dq = params
        .dq
        .as_ref()
        .ok_or(Error::MissingField { field: "dq" })?;
    let qi = params
        .qi
        .as_ref()
        .ok_or(Error::MissingField { field: "qi" })?;

    let private_key = Pkcs1RsaPrivateKey {
        modulus: uint_ref(params.n.as_bytes(), "n")?,
        public_exponent: uint_ref(params.e.as_bytes(), "e")?,
        private_exponent: uint_ref(d.as_bytes(), "d")?,
        prime1: uint_ref(p.as_bytes(), "p")?,
        prime2: uint_ref(q.as_bytes(), "q")?,
        exponent1: uint_ref(dp.as_bytes(), "dp")?,
        exponent2: uint_ref(dq.as_bytes(), "dq")?,
        coefficient: uint_ref(qi.as_bytes(), "qi")?,
        other_prime_infos: None,
    };

    private_key
        .to_der()
        .map(Zeroizing::new)
        .map_err(|e| Error::Other(format!("failed to encode PKCS#1 RSA private key: {e}")))
}

fn uint_ref<'a>(bytes: &'a [u8], field: &'static str) -> Result<UintRef<'a>> {
    UintRef::new(bytes).map_err(|e| {
        Error::Other(format!(
            "invalid RSA integer '{field}' for PKCS#1 encoding: {e}"
        ))
    })
}

fn build_ed25519_jwt_simple_keypair_bytes(jwk: &Key) -> Result<Zeroizing<Vec<u8>>> {
    let params = match jwk.params() {
        KeyParams::Okp(p) => p,
        _ => {
            return Err(Error::KeyTypeMismatch {
                expected: "OKP",
                actual: jwk.kty().as_str().to_string(),
            });
        }
    };

    if params.crv != OkpCurve::Ed25519 {
        return Err(Error::CurveMismatch {
            expected: "Ed25519",
            actual: params.crv.name().to_string(),
        });
    }

    let d = params.d.as_ref().ok_or(Error::MissingPrivateKey)?;
    let d_bytes = d.as_bytes();

    match d_bytes.len() {
        32 => {
            let mut bytes = Zeroizing::new(Vec::with_capacity(64));
            bytes.extend_from_slice(d_bytes);
            bytes.extend_from_slice(params.x.as_bytes());
            Ok(bytes)
        }
        64 => Ok(Zeroizing::new(d_bytes.to_vec())),
        len => Err(Error::Other(format!(
            "invalid Ed25519 private key length for jwt-simple conversion: expected 32 or 64 bytes, got {len}"
        ))),
    }
}

// Macro to implement RSA public key conversions
macro_rules! impl_rsa_public_key_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match jwk.params() {
                    KeyParams::Rsa(p) => p,
                    _ => {
                        return Err(Error::KeyTypeMismatch {
                            expected: "RSA",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                jwk.validate_for_use(&$alg, [KeyOperation::Verify])?;

                let der = build_rsa_public_key_der(params)?;
                <$key_type>::from_der(&der).map_err(|e| Error::Other(e.to_string()))
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

// Macro to implement RSA key pair conversions
macro_rules! impl_rsa_key_pair_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match jwk.params() {
                    KeyParams::Rsa(p) => p,
                    _ => {
                        return Err(Error::KeyTypeMismatch {
                            expected: "RSA",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                if !params.has_private_key() {
                    return Err(Error::MissingPrivateKey);
                }

                jwk.validate_for_use(&$alg, [KeyOperation::Sign])?;

                let der = build_rsa_private_key_der(params)?;
                <$key_type>::from_der(&der).map_err(|e| Error::Other(e.to_string()))
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

// Implement conversions for all RSA types
impl_rsa_public_key_conversion!(RS256PublicKey, Algorithm::Rs256);
impl_rsa_public_key_conversion!(RS384PublicKey, Algorithm::Rs384);
impl_rsa_public_key_conversion!(RS512PublicKey, Algorithm::Rs512);
impl_rsa_public_key_conversion!(PS256PublicKey, Algorithm::Ps256);
impl_rsa_public_key_conversion!(PS384PublicKey, Algorithm::Ps384);
impl_rsa_public_key_conversion!(PS512PublicKey, Algorithm::Ps512);

impl_rsa_key_pair_conversion!(RS256KeyPair, Algorithm::Rs256);
impl_rsa_key_pair_conversion!(RS384KeyPair, Algorithm::Rs384);
impl_rsa_key_pair_conversion!(RS512KeyPair, Algorithm::Rs512);
impl_rsa_key_pair_conversion!(PS256KeyPair, Algorithm::Ps256);
impl_rsa_key_pair_conversion!(PS384KeyPair, Algorithm::Ps384);
impl_rsa_key_pair_conversion!(PS512KeyPair, Algorithm::Ps512);

// ============================================================================
// EC Key Conversions
// ============================================================================

// Macro to implement EC public key conversions
macro_rules! impl_ec_public_key_conversion {
    ($key_type:ty, $curve:expr, $curve_name:expr, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match jwk.params() {
                    KeyParams::Ec(p) => p,
                    _ => {
                        return Err(Error::KeyTypeMismatch {
                            expected: "EC",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                if params.crv != $curve {
                    return Err(Error::CurveMismatch {
                        expected: $curve_name,
                        actual: params.crv.name().to_string(),
                    });
                }

                jwk.validate_for_use(&$alg, [KeyOperation::Verify])?;

                let bytes = params.to_uncompressed_point();
                <$key_type>::from_bytes(&bytes).map_err(|e| Error::Other(e.to_string()))
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

// Macro to implement EC key pair conversions
macro_rules! impl_ec_key_pair_conversion {
    ($key_type:ty, $curve:expr, $curve_name:expr, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match jwk.params() {
                    KeyParams::Ec(p) => p,
                    _ => {
                        return Err(Error::KeyTypeMismatch {
                            expected: "EC",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                if params.crv != $curve {
                    return Err(Error::CurveMismatch {
                        expected: $curve_name,
                        actual: params.crv.name().to_string(),
                    });
                }

                jwk.validate_for_use(&$alg, [KeyOperation::Sign])?;

                let d = params.d.as_ref().ok_or(Error::MissingPrivateKey)?;

                <$key_type>::from_bytes(d.as_bytes()).map_err(|e| Error::Other(e.to_string()))
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

// Implement EC conversions
impl_ec_public_key_conversion!(ES256PublicKey, EcCurve::P256, "P-256", Algorithm::Es256);
impl_ec_public_key_conversion!(ES384PublicKey, EcCurve::P384, "P-384", Algorithm::Es384);
// Note: ES512 uses P-521, but jwt-simple may not support it
impl_ec_public_key_conversion!(
    ES256kPublicKey,
    EcCurve::Secp256k1,
    "secp256k1",
    Algorithm::Es256k
);

impl_ec_key_pair_conversion!(ES256KeyPair, EcCurve::P256, "P-256", Algorithm::Es256);
impl_ec_key_pair_conversion!(ES384KeyPair, EcCurve::P384, "P-384", Algorithm::Es384);
impl_ec_key_pair_conversion!(
    ES256kKeyPair,
    EcCurve::Secp256k1,
    "secp256k1",
    Algorithm::Es256k
);

// ============================================================================
// EdDSA Key Conversions
// ============================================================================

impl TryFrom<&Key> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = match jwk.params() {
            KeyParams::Okp(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "OKP",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        if params.crv != OkpCurve::Ed25519 {
            return Err(Error::CurveMismatch {
                expected: "Ed25519",
                actual: params.crv.name().to_string(),
            });
        }

        jwk.validate_for_use(&Algorithm::Ed25519, [KeyOperation::Verify])?;

        Ed25519PublicKey::from_bytes(params.x.as_bytes()).map_err(|e| Error::Other(e.to_string()))
    }
}

impl TryFrom<Key> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        Ed25519PublicKey::try_from(&jwk)
    }
}

impl TryFrom<&Key> for Ed25519KeyPair {
    type Error = Error;

    fn try_from(jwk: &Key) -> Result<Self> {
        jwk.validate_for_use(&Algorithm::Ed25519, [KeyOperation::Sign])?;

        let keypair_bytes = build_ed25519_jwt_simple_keypair_bytes(jwk)?;
        Ed25519KeyPair::from_bytes(&keypair_bytes).map_err(|e| Error::Other(e.to_string()))
    }
}

impl TryFrom<Key> for Ed25519KeyPair {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        Ed25519KeyPair::try_from(&jwk)
    }
}

// ============================================================================
// Symmetric Key Conversions
// ============================================================================

impl TryFrom<&Key> for HS256Key {
    type Error = Error;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = match jwk.params() {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_use(
            &Algorithm::Hs256,
            [KeyOperation::Sign, KeyOperation::Verify],
        )?;

        Ok(HS256Key::from_bytes(params.k.as_bytes()))
    }
}

impl TryFrom<Key> for HS256Key {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        HS256Key::try_from(&jwk)
    }
}

impl TryFrom<&Key> for HS384Key {
    type Error = Error;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = match jwk.params() {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_use(
            &Algorithm::Hs384,
            [KeyOperation::Sign, KeyOperation::Verify],
        )?;

        Ok(HS384Key::from_bytes(params.k.as_bytes()))
    }
}

impl TryFrom<Key> for HS384Key {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        HS384Key::try_from(&jwk)
    }
}

impl TryFrom<&Key> for HS512Key {
    type Error = Error;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = match jwk.params() {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_use(
            &Algorithm::Hs512,
            [KeyOperation::Sign, KeyOperation::Verify],
        )?;

        Ok(HS512Key::from_bytes(params.k.as_bytes()))
    }
}

impl TryFrom<Key> for HS512Key {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        HS512Key::try_from(&jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyMatcher;
    use crate::SelectionError;
    use crate::jwks::KeySet;

    // Test RSA public key from RFC 7517 Appendix A.1
    const RFC_RSA_PUBLIC_KEY: &str = r#"{
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    }"#;

    // Test EC P-256 public key from RFC 7517 Appendix A.1
    const RFC_EC_PUBLIC_KEY: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }"#;

    // Test EC P-256 private key from RFC 7517 Appendix A.2
    const RFC_EC_P256_PRIVATE_KEY: &str = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
    }"#;

    // Test symmetric key
    const SYMMETRIC_KEY: &str = r#"{
        "kty": "oct",
        "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
    }"#;

    #[test]
    fn test_rsa_public_key_conversion() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let key: RS256PublicKey = (&jwk).try_into().unwrap();
        // Just verify it doesn't panic - the key was successfully converted
        assert!(!key.to_der().expect("to_der failed").is_empty());
    }

    #[test]
    fn test_ec_public_key_conversion() {
        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        let key: ES256PublicKey = (&jwk).try_into().unwrap();
        assert!(!key.to_bytes().is_empty());
    }

    #[test]
    fn test_rsa_conversion_rejects_mismatched_token() {
        let public_jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let ec_private_jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();

        let public_key: RS256PublicKey = (&public_jwk).try_into().unwrap();
        let ec_key_pair: ES256KeyPair = (&ec_private_jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("rsa-conversion-test");
        let token = ec_key_pair.sign(claims).unwrap();

        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&token, None)
                .is_err()
        );

        let mut tampered = token.clone();
        tampered.push('x');
        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&tampered, None)
                .is_err()
        );
    }

    #[test]
    fn test_ec_conversion_verifies_real_token() {
        let private_jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();
        let public_jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();

        let key_pair: ES256KeyPair = (&private_jwk).try_into().unwrap();
        let public_key: ES256PublicKey = (&public_jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("ec-conversion-test");
        let token = key_pair.sign(claims).unwrap();

        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );

        let mut tampered = token.clone();
        tampered.push('x');
        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&tampered, None)
                .is_err()
        );
    }

    #[test]
    fn test_symmetric_key_conversion() {
        let jwk: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();

        let hs256_key: HS256Key = (&jwk).try_into().unwrap();
        let hs384_key: HS384Key = (&jwk).try_into().unwrap();
        let hs512_key: HS512Key = (&jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("conversion-test");

        let token_256 = hs256_key.authenticate(claims.clone()).unwrap();
        assert!(
            hs256_key
                .verify_token::<NoCustomClaims>(&token_256, None)
                .is_ok()
        );

        let token_384 = hs384_key.authenticate(claims.clone()).unwrap();
        assert!(
            hs384_key
                .verify_token::<NoCustomClaims>(&token_384, None)
                .is_ok()
        );

        let token_512 = hs512_key.authenticate(claims).unwrap();
        assert!(
            hs512_key
                .verify_token::<NoCustomClaims>(&token_512, None)
                .is_ok()
        );

        assert!(
            hs256_key
                .verify_token::<NoCustomClaims>(&token_384, None)
                .is_err(),
            "HS384 token should not verify with HS256 key"
        );

        let mut tampered = token_256.clone();
        tampered.push('x');
        assert!(
            hs256_key
                .verify_token::<NoCustomClaims>(&tampered, None)
                .is_err(),
            "Tampered token must fail verification"
        );
    }

    #[test]
    fn test_key_type_mismatch() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let result: Result<ES256PublicKey> = (&jwk).try_into();
        assert!(matches!(result, Err(Error::KeyTypeMismatch { .. })));
    }

    #[test]
    fn test_curve_mismatch() {
        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        let result: Result<ES384PublicKey> = (&jwk).try_into();
        assert!(matches!(result, Err(Error::CurveMismatch { .. })));
    }

    #[test]
    fn test_missing_private_key() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let result: Result<RS256KeyPair> = (&jwk).try_into();
        assert!(matches!(result, Err(Error::MissingPrivateKey)));
    }

    #[test]
    fn test_rsa_public_key_empty_params_no_panic() {
        // A JWK with empty base64url strings should produce an error, not a panic
        let json = r#"{"kty":"RSA","n":"","e":"AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256PublicKey> = (&key).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_tryfrom_conversions() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(RS256PublicKey::try_from(&jwk).is_ok());
        assert!(RS384PublicKey::try_from(&jwk).is_ok());
        assert!(RS512PublicKey::try_from(&jwk).is_ok());
        assert!(PS256PublicKey::try_from(&jwk).is_ok());

        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        assert!(ES256PublicKey::try_from(&jwk).is_ok());

        let jwk: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        assert!(HS256Key::try_from(&jwk).is_ok());
    }

    #[test]
    fn test_hs256_conversion_rejects_weak_key_without_alg_field() {
        let weak_hs_key_json = r#"{
            "kty": "oct",
            "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }"#;

        let jwk: Key = serde_json::from_str(weak_hs_key_json).unwrap();
        let result: Result<HS256Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_rs256_conversion_rejects_weak_rsa_without_alg_field() {
        let weak_rsa_json = r#"{
            "kty": "RSA",
            "n": "sXchhHu5Mdu8J-4n8x66I8f32xNkoTfEhQ",
            "e": "AQAB"
        }"#;

        let jwk: Key = serde_json::from_str(weak_rsa_json).unwrap();
        let result: Result<RS256PublicKey> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_rs256_public_conversion_rejects_encryption_use() {
        let json = r#"{
            "kty": "RSA",
            "use": "enc",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256PublicKey> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_select_verify_key_strict_for_jwt_simple_flow() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-verify", "use": "sig", "alg": "RS256", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB"},
            {"kty": "EC", "kid": "ec-verify", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .selector(&[Algorithm::Rs256])
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("rsa-verify"))
            .unwrap();

        assert_eq!(key.kid(), Some("rsa-verify"));

        let err = jwks
            .selector(&[Algorithm::Rs256])
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Es256).with_kid("rsa-verify"))
            .unwrap_err();
        assert!(matches!(err, SelectionError::AlgorithmNotAllowed));
    }

    #[test]
    fn test_select_signing_key_strict_for_jwt_simple_flow() {
        let json = r#"{"keys": [
            {"kty": "EC", "kid": "ec-sign", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .selector(&[])
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("ec-sign"))
            .unwrap();

        assert_eq!(key.kid(), Some("ec-sign"));
    }

    #[test]
    fn test_rs256_public_conversion_rejects_verify_missing_in_key_ops() {
        let json = r#"{
            "kty": "RSA",
            "key_ops": ["encrypt"],
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256PublicKey> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_rs256_key_pair_conversion_rejects_encryption_use() {
        let json = r#"{
            "kty": "RSA",
            "use": "enc",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rd5Qw9Y8Q8fN4EuM4fM9x2s8"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256KeyPair> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                crate::error::IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_ed25519_key_pair_conversion_rejects_verify_only_key_ops() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "key_ops": ["verify"]
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<Ed25519KeyPair> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_key_pair_conversion_accepts_seed_form_private_key() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let key_pair: Ed25519KeyPair = (&jwk).try_into().unwrap();
        let public_key = key_pair.public_key();
        let expected_x = match jwk.params() {
            KeyParams::Okp(params) => params.x.as_bytes(),
            _ => unreachable!("test fixture must be an OKP key"),
        };

        assert_eq!(public_key.to_bytes(), expected_x);
    }

    #[test]
    fn test_hs256_conversion_rejects_sign_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["sign"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS256Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs256_conversion_rejects_verify_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["verify"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS256Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs256_conversion_accepts_sign_and_verify_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["sign", "verify"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS256Key> = (&jwk).try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_hs256_conversion_rejects_encryption_use() {
        let json = r#"{
            "kty": "oct",
            "use": "enc",
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS256Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs384_conversion_rejects_sign_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["sign"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS384Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs512_conversion_rejects_verify_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["verify"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS512Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs384_conversion_rejects_verify_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["verify"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS384Key> = (&jwk).try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_hs512_conversion_rejects_sign_only_key_ops() {
        let json = r#"{
            "kty": "oct",
            "key_ops": ["sign"],
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<HS512Key> = (&jwk).try_into();
        assert!(result.is_err());
    }
}

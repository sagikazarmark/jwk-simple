//! jwt-simple key conversion implementations.

use jwt_simple::prelude::*;

use crate::error::{Error, Result};
use crate::jwk::{Algorithm, EcCurve, Key, KeyOperation, KeyParams, OkpCurve, RsaParams};
use crate::jwks::{KeyMatcher, KeySet, SelectionError};

impl KeySet {
    /// Selects a verification key from this set for jwt-simple workflows.
    ///
    /// This helper uses strict selection (`selector(...).select(...)`) to enforce
    /// algorithm allowlist and key suitability before conversion to jwt-simple key types.
    pub fn select_jwt_simple_verify_key<'a>(
        &'a self,
        alg: &Algorithm,
        kid: Option<&str>,
        allowed_verify_algs: &[Algorithm],
    ) -> std::result::Result<&'a Key, SelectionError> {
        self.selector(allowed_verify_algs)
            .select(KeyMatcher::new(KeyOperation::Verify, alg.clone()).with_optional_kid(kid))
    }

    /// Selects a signing key from this set for jwt-simple workflows.
    ///
    /// This helper uses strict selection (`selector(...).select(...)`) with
    /// `KeyOperation::Sign` semantics.
    pub fn select_jwt_simple_signing_key<'a>(
        &'a self,
        alg: &Algorithm,
        kid: Option<&str>,
    ) -> std::result::Result<&'a Key, SelectionError> {
        self.selector(&[])
            .select(KeyMatcher::new(KeyOperation::Sign, alg.clone()).with_optional_kid(kid))
    }
}

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
fn build_rsa_public_key_der(params: &RsaParams) -> Vec<u8> {
    let n = params.n.as_bytes();
    let e = params.e.as_bytes();

    // Build DER-encoded integers (with leading zero if high bit is set)
    let n_der = encode_der_integer(n);
    let e_der = encode_der_integer(e);

    // Build SEQUENCE
    let content_len = n_der.len() + e_der.len();
    let mut der = Vec::with_capacity(4 + content_len);

    // SEQUENCE tag and length
    der.push(0x30);
    encode_der_length(&mut der, content_len);

    // Content
    der.extend_from_slice(&n_der);
    der.extend_from_slice(&e_der);

    der
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
fn build_rsa_private_key_der(params: &RsaParams) -> Result<Vec<u8>> {
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

    // Build DER-encoded integers
    let version_der = encode_der_integer(&[0]); // version 0
    let n_der = encode_der_integer(params.n.as_bytes());
    let e_der = encode_der_integer(params.e.as_bytes());
    let d_der = encode_der_integer(d.as_bytes());
    let p_der = encode_der_integer(p.as_bytes());
    let q_der = encode_der_integer(q.as_bytes());
    let dp_der = encode_der_integer(dp.as_bytes());
    let dq_der = encode_der_integer(dq.as_bytes());
    let qi_der = encode_der_integer(qi.as_bytes());

    let content_len = version_der.len()
        + n_der.len()
        + e_der.len()
        + d_der.len()
        + p_der.len()
        + q_der.len()
        + dp_der.len()
        + dq_der.len()
        + qi_der.len();

    let mut der = Vec::with_capacity(4 + content_len);

    // SEQUENCE tag and length
    der.push(0x30);
    encode_der_length(&mut der, content_len);

    // Content
    der.extend_from_slice(&version_der);
    der.extend_from_slice(&n_der);
    der.extend_from_slice(&e_der);
    der.extend_from_slice(&d_der);
    der.extend_from_slice(&p_der);
    der.extend_from_slice(&q_der);
    der.extend_from_slice(&dp_der);
    der.extend_from_slice(&dq_der);
    der.extend_from_slice(&qi_der);

    Ok(der)
}

/// Encodes a byte slice as a DER INTEGER.
fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        // Encode zero: INTEGER tag, length 1, value 0x00
        return vec![0x02, 0x01, 0x00];
    }

    // Skip leading zeros (but keep at least one byte)
    let bytes = {
        let mut start = 0;
        while start < bytes.len() - 1 && bytes[start] == 0 {
            start += 1;
        }
        &bytes[start..]
    };

    // Add leading zero if high bit is set (to keep positive)
    let needs_padding = !bytes.is_empty() && (bytes[0] & 0x80) != 0;

    let len = bytes.len() + if needs_padding { 1 } else { 0 };
    let mut der = Vec::with_capacity(2 + len + 2); // tag + length + content

    // INTEGER tag
    der.push(0x02);
    encode_der_length(&mut der, len);

    // Content
    if needs_padding {
        der.push(0x00);
    }
    der.extend_from_slice(bytes);

    der
}

/// Encodes a length in DER format.
fn encode_der_length(der: &mut Vec<u8>, len: usize) {
    if len < 128 {
        der.push(len as u8);
    } else if len < 256 {
        der.push(0x81);
        der.push(len as u8);
    } else if len < 65536 {
        der.push(0x82);
        der.push((len >> 8) as u8);
        der.push(len as u8);
    } else {
        der.push(0x83);
        der.push((len >> 16) as u8);
        der.push((len >> 8) as u8);
        der.push(len as u8);
    }
}

// Macro to implement RSA public key conversions
macro_rules! impl_rsa_public_key_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = Error;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match &jwk.params {
                    KeyParams::Rsa(p) => p,
                    _ => {
                        return Err(Error::KeyTypeMismatch {
                            expected: "RSA",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                jwk.validate_for_operation(&$alg, KeyOperation::Verify)?;

                let der = build_rsa_public_key_der(params);
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
                let params = match &jwk.params {
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

                jwk.validate_for_operation(&$alg, KeyOperation::Sign)?;

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
                let params = match &jwk.params {
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

                jwk.validate_for_operation(&$alg, KeyOperation::Verify)?;

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
                let params = match &jwk.params {
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

                jwk.validate_for_operation(&$alg, KeyOperation::Sign)?;

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
        let params = match &jwk.params {
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

        jwk.validate_for_operation(&Algorithm::Ed25519, KeyOperation::Verify)?;

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
        let params = match &jwk.params {
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

        jwk.validate_for_operation(&Algorithm::Ed25519, KeyOperation::Sign)?;

        let d = params.d.as_ref().ok_or(Error::MissingPrivateKey)?;

        // Ed25519 private key is the seed (32 bytes)
        Ed25519KeyPair::from_bytes(d.as_bytes()).map_err(|e| Error::Other(e.to_string()))
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
        let params = match &jwk.params {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_operations(
            &Algorithm::Hs256,
            &[KeyOperation::Sign, KeyOperation::Verify],
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
        let params = match &jwk.params {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_operations(
            &Algorithm::Hs384,
            &[KeyOperation::Sign, KeyOperation::Verify],
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
        let params = match &jwk.params {
            KeyParams::Symmetric(p) => p,
            _ => {
                return Err(Error::KeyTypeMismatch {
                    expected: "oct",
                    actual: jwk.kty().as_str().to_string(),
                });
            }
        };

        jwk.validate_for_operations(
            &Algorithm::Hs512,
            &[KeyOperation::Sign, KeyOperation::Verify],
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
        assert!(key.to_der().expect("to_der failed").len() > 0);
    }

    #[test]
    fn test_ec_public_key_conversion() {
        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        let key: ES256PublicKey = (&jwk).try_into().unwrap();
        assert!(key.to_bytes().len() > 0);
    }

    #[test]
    fn test_rsa_conversion_rejects_mismatched_token() {
        let public_jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let ec_private_jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();

        let public_key: RS256PublicKey = (&public_jwk).try_into().unwrap();
        let ec_key_pair: ES256KeyPair = (&ec_private_jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("rsa-conversion-test");
        let token = ec_key_pair.sign(claims).unwrap();

        assert!(public_key
            .verify_token::<NoCustomClaims>(&token, None)
            .is_err());

        let mut tampered = token.clone();
        tampered.push('x');
        assert!(public_key
            .verify_token::<NoCustomClaims>(&tampered, None)
            .is_err());
    }

    #[test]
    fn test_ec_conversion_verifies_real_token() {
        let private_jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();
        let public_jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();

        let key_pair: ES256KeyPair = (&private_jwk).try_into().unwrap();
        let public_key: ES256PublicKey = (&public_jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("ec-conversion-test");
        let token = key_pair.sign(claims).unwrap();

        assert!(public_key
            .verify_token::<NoCustomClaims>(&token, None)
            .is_ok());

        let mut tampered = token.clone();
        tampered.push('x');
        assert!(public_key
            .verify_token::<NoCustomClaims>(&tampered, None)
            .is_err());
    }

    #[test]
    fn test_symmetric_key_conversion() {
        let jwk: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();

        let hs256_key: HS256Key = (&jwk).try_into().unwrap();
        let hs384_key: HS384Key = (&jwk).try_into().unwrap();
        let hs512_key: HS512Key = (&jwk).try_into().unwrap();

        let claims = Claims::create(Duration::from_hours(1)).with_subject("conversion-test");

        let token_256 = hs256_key.authenticate(claims.clone()).unwrap();
        assert!(hs256_key
            .verify_token::<NoCustomClaims>(&token_256, None)
            .is_ok());

        let token_384 = hs384_key.authenticate(claims.clone()).unwrap();
        assert!(hs384_key
            .verify_token::<NoCustomClaims>(&token_384, None)
            .is_ok());

        let token_512 = hs512_key.authenticate(claims).unwrap();
        assert!(hs512_key
            .verify_token::<NoCustomClaims>(&token_512, None)
            .is_ok());

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
    fn test_encode_der_integer_empty_bytes() {
        // Encoding an empty byte slice should produce DER INTEGER 0, not panic
        let result = encode_der_integer(&[]);
        assert_eq!(result, vec![0x02, 0x01, 0x00]);
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
    fn test_select_jwt_simple_verify_key_strict() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-verify", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "ec-verify", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .select_jwt_simple_verify_key(
                &Algorithm::Rs256,
                Some("rsa-verify"),
                &[Algorithm::Rs256],
            )
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("rsa-verify"));
    }

    #[test]
    fn test_select_jwt_simple_signing_key_strict() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-sign", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB", "d": "AQAB", "p": "AQAB", "q": "AQAB", "dp": "AQAB", "dq": "AQAB", "qi": "AQAB"}
        ]}"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let key = jwks
            .select_jwt_simple_signing_key(&Algorithm::Rs256, Some("rsa-sign"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("rsa-sign"));
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
            Err(Error::Validation(
                crate::error::ValidationError::InconsistentParameters(_)
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

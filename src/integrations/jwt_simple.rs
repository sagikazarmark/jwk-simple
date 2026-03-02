//! jwt-simple key conversion implementations.

use jwt_simple::prelude::*;

use crate::error::{Error, Result};
use crate::jwk::{EcCurve, Key, KeyParams, OkpCurve, RsaParams};

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
    ($key_type:ty) => {
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
    ($key_type:ty) => {
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
impl_rsa_public_key_conversion!(RS256PublicKey);
impl_rsa_public_key_conversion!(RS384PublicKey);
impl_rsa_public_key_conversion!(RS512PublicKey);
impl_rsa_public_key_conversion!(PS256PublicKey);
impl_rsa_public_key_conversion!(PS384PublicKey);
impl_rsa_public_key_conversion!(PS512PublicKey);

impl_rsa_key_pair_conversion!(RS256KeyPair);
impl_rsa_key_pair_conversion!(RS384KeyPair);
impl_rsa_key_pair_conversion!(RS512KeyPair);
impl_rsa_key_pair_conversion!(PS256KeyPair);
impl_rsa_key_pair_conversion!(PS384KeyPair);
impl_rsa_key_pair_conversion!(PS512KeyPair);

// ============================================================================
// EC Key Conversions
// ============================================================================

// Macro to implement EC public key conversions
macro_rules! impl_ec_public_key_conversion {
    ($key_type:ty, $curve:expr, $curve_name:expr) => {
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
    ($key_type:ty, $curve:expr, $curve_name:expr) => {
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
impl_ec_public_key_conversion!(ES256PublicKey, EcCurve::P256, "P-256");
impl_ec_public_key_conversion!(ES384PublicKey, EcCurve::P384, "P-384");
// Note: ES512 uses P-521, but jwt-simple may not support it
impl_ec_public_key_conversion!(ES256kPublicKey, EcCurve::Secp256k1, "secp256k1");

impl_ec_key_pair_conversion!(ES256KeyPair, EcCurve::P256, "P-256");
impl_ec_key_pair_conversion!(ES384KeyPair, EcCurve::P384, "P-384");
impl_ec_key_pair_conversion!(ES256kKeyPair, EcCurve::Secp256k1, "secp256k1");

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

        Ok(HS512Key::from_bytes(params.k.as_bytes()))
    }
}

impl TryFrom<Key> for HS512Key {
    type Error = Error;

    fn try_from(jwk: Key) -> Result<Self> {
        HS512Key::try_from(&jwk)
    }
}

// ============================================================================
// Convenience methods on Key
// ============================================================================

impl Key {
    /// Converts to an RS256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not an RSA key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs256_public_key(&self) -> Result<RS256PublicKey> {
        self.try_into()
    }

    /// Converts to an RS256 key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not an RSA private key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs256_key_pair(&self) -> Result<RS256KeyPair> {
        self.try_into()
    }

    /// Converts to an RS384 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs384_public_key(&self) -> Result<RS384PublicKey> {
        self.try_into()
    }

    /// Converts to an RS384 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs384_key_pair(&self) -> Result<RS384KeyPair> {
        self.try_into()
    }

    /// Converts to an RS512 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs512_public_key(&self) -> Result<RS512PublicKey> {
        self.try_into()
    }

    /// Converts to an RS512 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_rs512_key_pair(&self) -> Result<RS512KeyPair> {
        self.try_into()
    }

    /// Converts to a PS256 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps256_public_key(&self) -> Result<PS256PublicKey> {
        self.try_into()
    }

    /// Converts to a PS256 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps256_key_pair(&self) -> Result<PS256KeyPair> {
        self.try_into()
    }

    /// Converts to a PS384 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps384_public_key(&self) -> Result<PS384PublicKey> {
        self.try_into()
    }

    /// Converts to a PS384 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps384_key_pair(&self) -> Result<PS384KeyPair> {
        self.try_into()
    }

    /// Converts to a PS512 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps512_public_key(&self) -> Result<PS512PublicKey> {
        self.try_into()
    }

    /// Converts to a PS512 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ps512_key_pair(&self) -> Result<PS512KeyPair> {
        self.try_into()
    }

    /// Converts to an ES256 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es256_public_key(&self) -> Result<ES256PublicKey> {
        self.try_into()
    }

    /// Converts to an ES256 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es256_key_pair(&self) -> Result<ES256KeyPair> {
        self.try_into()
    }

    /// Converts to an ES384 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es384_public_key(&self) -> Result<ES384PublicKey> {
        self.try_into()
    }

    /// Converts to an ES384 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es384_key_pair(&self) -> Result<ES384KeyPair> {
        self.try_into()
    }

    /// Converts to an ES256k public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es256k_public_key(&self) -> Result<ES256kPublicKey> {
        self.try_into()
    }

    /// Converts to an ES256k key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_es256k_key_pair(&self) -> Result<ES256kKeyPair> {
        self.try_into()
    }

    /// Converts to an Ed25519 public key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ed25519_public_key(&self) -> Result<Ed25519PublicKey> {
        self.try_into()
    }

    /// Converts to an Ed25519 key pair.
    #[cfg(feature = "jwt-simple")]
    pub fn to_ed25519_key_pair(&self) -> Result<Ed25519KeyPair> {
        self.try_into()
    }

    /// Converts to an HS256 key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_hs256_key(&self) -> Result<HS256Key> {
        self.try_into()
    }

    /// Converts to an HS384 key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_hs384_key(&self) -> Result<HS384Key> {
        self.try_into()
    }

    /// Converts to an HS512 key.
    #[cfg(feature = "jwt-simple")]
    pub fn to_hs512_key(&self) -> Result<HS512Key> {
        self.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_symmetric_key_conversion() {
        let jwk: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        let _key: HS256Key = (&jwk).try_into().unwrap();
        let _key: HS384Key = (&jwk).try_into().unwrap();
        let _key: HS512Key = (&jwk).try_into().unwrap();
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
    fn test_convenience_methods() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        assert!(jwk.to_rs256_public_key().is_ok());
        assert!(jwk.to_rs384_public_key().is_ok());
        assert!(jwk.to_rs512_public_key().is_ok());
        assert!(jwk.to_ps256_public_key().is_ok());

        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        assert!(jwk.to_es256_public_key().is_ok());

        let jwk: Key = serde_json::from_str(SYMMETRIC_KEY).unwrap();
        assert!(jwk.to_hs256_key().is_ok());
    }
}

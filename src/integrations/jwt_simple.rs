//! jwt-simple key conversion implementations.
//!
//! Every conversion runs this crate's validation first ([`Key::validate_for_use`]:
//! structure, declared `alg`, `use`/`key_ops` intent, key strength), then hands
//! jwt-simple a *reduced* JWK — `kty`, `crv`, the key material and `kid`, nothing
//! else — through its `from_jwk` constructor. That constructor runs jwt-simple's
//! cryptographic checks (RSA key policy, EC points on the curve, private/public
//! consistency, canonical Ed25519 encoding), so neither layer re-implements the
//! other's rules.
//!
//! The metadata members (`alg`, `use`, `key_ops`) and the `x5*` certificate members
//! stay behind on purpose: this crate has already enforced its intent policy on
//! them, jwt-simple's rules for the same members differ in small ways, and an `x5c`
//! chain can push a document past jwt-simple's `MAX_JWK_LENGTH`.
//!
//! Symmetric (`HS*`) keys have no JWK import in jwt-simple and go through
//! `from_bytes`.
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

use base64ct::{Base64UrlUnpadded, Encoding};
use jwt_simple::algorithms::MAX_JWK_LENGTH;
use jwt_simple::prelude::*;
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(test)]
use crate::IncompatibleKeyError;
use crate::encoding::Base64UrlBytes;
use crate::error::{Error, JwtSimpleKeyConversionError};
use crate::jwk::{
    Algorithm, EcCurve, EcParams, Key, KeyOperation, KeyParams, OkpCurve, OkpParams, RsaParams,
};

type Result<T> = std::result::Result<T, JwtSimpleKeyConversionError>;

fn map_validation_error(err: Error) -> JwtSimpleKeyConversionError {
    match err {
        Error::InvalidKey(err) => JwtSimpleKeyConversionError::InvalidKey(err),
        Error::IncompatibleKey(err) => JwtSimpleKeyConversionError::IncompatibleKey(err),
        other => JwtSimpleKeyConversionError::Core(other),
    }
}

fn validate_for_jwt_simple(
    jwk: &Key,
    alg: &Algorithm,
    ops: impl IntoIterator<Item = KeyOperation>,
) -> Result<()> {
    jwk.validate_for_use(alg, ops).map_err(map_validation_error)
}

fn import_error(err: jwt_simple::Error) -> JwtSimpleKeyConversionError {
    JwtSimpleKeyConversionError::Import(err.to_string())
}

fn rsa_params(jwk: &Key) -> Result<&RsaParams> {
    match jwk.params() {
        KeyParams::Rsa(params) => Ok(params),
        _ => Err(JwtSimpleKeyConversionError::KeyTypeMismatch {
            expected: "RSA",
            actual: jwk.kty().as_str().to_string(),
        }),
    }
}

fn ec_params(jwk: &Key, curve: EcCurve) -> Result<&EcParams> {
    let params = match jwk.params() {
        KeyParams::Ec(params) => params,
        _ => {
            return Err(JwtSimpleKeyConversionError::KeyTypeMismatch {
                expected: "EC",
                actual: jwk.kty().as_str().to_string(),
            });
        }
    };
    if params.crv != curve {
        return Err(JwtSimpleKeyConversionError::CurveMismatch {
            expected: curve.as_str(),
            actual: params.crv.as_str().to_string(),
        });
    }
    Ok(params)
}

fn okp_params(jwk: &Key, curve: OkpCurve) -> Result<&OkpParams> {
    let params = match jwk.params() {
        KeyParams::Okp(params) => params,
        _ => {
            return Err(JwtSimpleKeyConversionError::KeyTypeMismatch {
                expected: "OKP",
                actual: jwk.kty().as_str().to_string(),
            });
        }
    };
    if params.crv != curve {
        return Err(JwtSimpleKeyConversionError::CurveMismatch {
            expected: curve.as_str(),
            actual: params.crv.as_str().to_string(),
        });
    }
    Ok(params)
}

// ============================================================================
// Reduced JWK
// ============================================================================

/// The members jwt-simple's `from_jwk` consumes: key type, curve, key material
/// and `kid`. Values borrow from the caller so secrets are not copied around.
#[derive(Default, Serialize)]
struct ReducedJwk<'a> {
    kty: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    q: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dq: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qi: Option<&'a str>,
}

impl ReducedJwk<'_> {
    /// Serializes into a buffer sized for jwt-simple's limit up front, so a
    /// document carrying private material is not left behind by reallocation.
    fn to_json(&self) -> Result<Zeroizing<String>> {
        let encoding_error = |e: &dyn std::fmt::Display| {
            JwtSimpleKeyConversionError::Encoding(format!(
                "failed to serialize JWK for jwt-simple: {e}"
            ))
        };
        let mut buf = Vec::with_capacity(MAX_JWK_LENGTH);
        serde_json::to_writer(&mut buf, self).map_err(|e| encoding_error(&e))?;
        // serde_json emits UTF-8; `from_utf8` takes the buffer over without copying.
        String::from_utf8(buf)
            .map(Zeroizing::new)
            .map_err(|e| encoding_error(&e))
    }
}

/// Base64url form of a secret member, wiped on drop.
fn secret_b64(bytes: &Base64UrlBytes) -> Zeroizing<String> {
    Zeroizing::new(bytes.to_base64url())
}

fn rsa_public_jwk(params: &RsaParams, kid: Option<&str>) -> Result<Zeroizing<String>> {
    let n = params.n.to_base64url();
    let e = params.e.to_base64url();
    ReducedJwk {
        kty: "RSA",
        kid,
        n: Some(&n),
        e: Some(&e),
        ..Default::default()
    }
    .to_json()
}

/// jwt-simple's import needs every CRT member. `RsaParams::validate` allows a
/// `d`-only private key, so the gap is reported here as
/// [`MissingComponent`](JwtSimpleKeyConversionError::MissingComponent).
fn rsa_private_jwk(params: &RsaParams, kid: Option<&str>) -> Result<Zeroizing<String>> {
    // jwt-simple rejects `oth` as a member of another key type; say why instead.
    if params.oth.is_some() {
        return Err(JwtSimpleKeyConversionError::Encoding(
            "multi-prime RSA keys are not supported for jwt-simple conversion".into(),
        ));
    }

    let d = params
        .d
        .as_ref()
        .ok_or(JwtSimpleKeyConversionError::MissingPrivateKey)?;
    let component = |value: &Option<Base64UrlBytes>, field: &'static str| {
        value
            .as_ref()
            .map(secret_b64)
            .ok_or(JwtSimpleKeyConversionError::MissingComponent { field })
    };
    let p = component(&params.p, "p")?;
    let q = component(&params.q, "q")?;
    let dp = component(&params.dp, "dp")?;
    let dq = component(&params.dq, "dq")?;
    let qi = component(&params.qi, "qi")?;
    let d = secret_b64(d);
    let n = params.n.to_base64url();
    let e = params.e.to_base64url();

    ReducedJwk {
        kty: "RSA",
        kid,
        n: Some(&n),
        e: Some(&e),
        d: Some(&d),
        p: Some(&p),
        q: Some(&q),
        dp: Some(&dp),
        dq: Some(&dq),
        qi: Some(&qi),
        ..Default::default()
    }
    .to_json()
}

fn ec_jwk(params: &EcParams, kid: Option<&str>, private: bool) -> Result<Zeroizing<String>> {
    let x = params.x.to_base64url();
    let y = params.y.to_base64url();
    let d = if private {
        let d = params
            .d
            .as_ref()
            .ok_or(JwtSimpleKeyConversionError::MissingPrivateKey)?;
        Some(secret_b64(d))
    } else {
        None
    };

    ReducedJwk {
        kty: "EC",
        crv: Some(params.crv.as_str()),
        kid,
        x: Some(&x),
        y: Some(&y),
        d: d.as_deref().map(String::as_str),
        ..Default::default()
    }
    .to_json()
}

fn okp_jwk(params: &OkpParams, kid: Option<&str>, private: bool) -> Result<Zeroizing<String>> {
    let x = params.x.to_base64url();
    let d = if private {
        Some(ed25519_seed_b64(params)?)
    } else {
        None
    };

    ReducedJwk {
        kty: "OKP",
        crv: Some(params.crv.as_str()),
        kid,
        x: Some(&x),
        d: d.as_deref().map(String::as_str),
        ..Default::default()
    }
    .to_json()
}

/// RFC 8037 defines `d` as the 32-byte seed, which is all jwt-simple's import
/// accepts. The 64-byte `seed || public-key` form used by some implementations
/// (libsodium) is accepted here for interoperability, after checking that its
/// embedded public key is the JWK's `x`, and reduced to the seed.
fn ed25519_seed_b64(params: &OkpParams) -> Result<Zeroizing<String>> {
    let d = params
        .d
        .as_ref()
        .ok_or(JwtSimpleKeyConversionError::MissingPrivateKey)?;
    let d_bytes = d.as_bytes();

    match d_bytes.len() {
        32 => Ok(secret_b64(d)),
        64 => {
            if d_bytes[32..] != *params.x.as_bytes() {
                return Err(JwtSimpleKeyConversionError::Import(
                    "Ed25519 extended private key: embedded public key does not match JWK x parameter".into(),
                ));
            }
            Ok(Zeroizing::new(Base64UrlUnpadded::encode_string(
                &d_bytes[..32],
            )))
        }
        len => Err(JwtSimpleKeyConversionError::Import(format!(
            "invalid Ed25519 private key length for jwt-simple conversion: expected 32 or 64 bytes, got {len}"
        ))),
    }
}

// ============================================================================
// RSA Key Conversions
// ============================================================================

macro_rules! impl_rsa_public_key_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = rsa_params(jwk)?;
                validate_for_jwt_simple(jwk, &$alg, [KeyOperation::Verify])?;
                let json = rsa_public_jwk(params, jwk.kid())?;
                <$key_type>::from_jwk(&json).map_err(import_error)
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

macro_rules! impl_rsa_key_pair_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = rsa_params(jwk)?;
                if !params.has_private_key() {
                    return Err(JwtSimpleKeyConversionError::MissingPrivateKey);
                }
                validate_for_jwt_simple(jwk, &$alg, [KeyOperation::Sign])?;
                let json = rsa_private_jwk(params, jwk.kid())?;
                <$key_type>::from_jwk(&json).map_err(import_error)
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

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

macro_rules! impl_ec_public_key_conversion {
    ($key_type:ty, $curve:expr, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = ec_params(jwk, $curve)?;
                validate_for_jwt_simple(jwk, &$alg, [KeyOperation::Verify])?;
                let json = ec_jwk(params, jwk.kid(), false)?;
                <$key_type>::from_jwk(&json).map_err(import_error)
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

macro_rules! impl_ec_key_pair_conversion {
    ($key_type:ty, $curve:expr, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: &Key) -> Result<Self> {
                let params = ec_params(jwk, $curve)?;
                validate_for_jwt_simple(jwk, &$alg, [KeyOperation::Sign])?;
                let json = ec_jwk(params, jwk.kid(), true)?;
                <$key_type>::from_jwk(&json).map_err(import_error)
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

impl_ec_public_key_conversion!(ES256PublicKey, EcCurve::P256, Algorithm::Es256);
impl_ec_public_key_conversion!(ES384PublicKey, EcCurve::P384, Algorithm::Es384);
// ES512 (P-521) has no jwt-simple key type.
impl_ec_public_key_conversion!(ES256kPublicKey, EcCurve::Secp256k1, Algorithm::Es256k);

impl_ec_key_pair_conversion!(ES256KeyPair, EcCurve::P256, Algorithm::Es256);
impl_ec_key_pair_conversion!(ES384KeyPair, EcCurve::P384, Algorithm::Es384);
impl_ec_key_pair_conversion!(ES256kKeyPair, EcCurve::Secp256k1, Algorithm::Es256k);

// ============================================================================
// EdDSA Key Conversions
// ============================================================================

impl TryFrom<&Key> for Ed25519PublicKey {
    type Error = JwtSimpleKeyConversionError;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = okp_params(jwk, OkpCurve::Ed25519)?;
        validate_for_jwt_simple(jwk, &Algorithm::Ed25519, [KeyOperation::Verify])?;
        let json = okp_jwk(params, jwk.kid(), false)?;
        Ed25519PublicKey::from_jwk(&json).map_err(import_error)
    }
}

impl TryFrom<Key> for Ed25519PublicKey {
    type Error = JwtSimpleKeyConversionError;

    fn try_from(jwk: Key) -> Result<Self> {
        Ed25519PublicKey::try_from(&jwk)
    }
}

impl TryFrom<&Key> for Ed25519KeyPair {
    type Error = JwtSimpleKeyConversionError;

    fn try_from(jwk: &Key) -> Result<Self> {
        let params = okp_params(jwk, OkpCurve::Ed25519)?;
        validate_for_jwt_simple(jwk, &Algorithm::Ed25519, [KeyOperation::Sign])?;
        let json = okp_jwk(params, jwk.kid(), true)?;
        Ed25519KeyPair::from_jwk(&json).map_err(import_error)
    }
}

impl TryFrom<Key> for Ed25519KeyPair {
    type Error = JwtSimpleKeyConversionError;

    fn try_from(jwk: Key) -> Result<Self> {
        Ed25519KeyPair::try_from(&jwk)
    }
}

// ============================================================================
// Symmetric Key Conversions
// ============================================================================

macro_rules! impl_symmetric_key_conversion {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            /// # Errors
            ///
            /// Returns [`JwtSimpleKeyConversionError::IncompatibleKey`] if `key_ops` is
            /// present but does not include both [`KeyOperation::Sign`] and
            /// [`KeyOperation::Verify`]. HMAC keys in `jwt-simple` are bidirectional;
            /// callers that need one-directional HMAC usage should remove `key_ops`
            /// before converting.
            fn try_from(jwk: &Key) -> Result<Self> {
                let params = match jwk.params() {
                    KeyParams::Symmetric(params) => params,
                    _ => {
                        return Err(JwtSimpleKeyConversionError::KeyTypeMismatch {
                            expected: "oct",
                            actual: jwk.kty().as_str().to_string(),
                        });
                    }
                };

                validate_for_jwt_simple(jwk, &$alg, [KeyOperation::Sign, KeyOperation::Verify])?;

                let key = <$key_type>::from_bytes(params.k.as_bytes());
                Ok(match jwk.kid() {
                    Some(kid) => key.with_key_id(kid),
                    None => key,
                })
            }
        }

        impl TryFrom<Key> for $key_type {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(jwk: Key) -> Result<Self> {
                <$key_type>::try_from(&jwk)
            }
        }
    };
}

impl_symmetric_key_conversion!(HS256Key, Algorithm::Hs256);
impl_symmetric_key_conversion!(HS384Key, Algorithm::Hs384);
impl_symmetric_key_conversion!(HS512Key, Algorithm::Hs512);

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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::KeyTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_curve_mismatch() {
        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        let result: Result<ES384PublicKey> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::CurveMismatch { .. })
        ));
    }

    #[test]
    fn test_missing_private_key() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let result: Result<RS256KeyPair> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::MissingPrivateKey)
        ));
    }

    #[test]
    fn test_rsa_public_key_empty_params_no_panic() {
        // A JWK with empty base64url strings should produce an error, not a panic
        let json = r#"{"kty":"RSA","n":"","e":"AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256PublicKey> = (&key).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::InvalidKey(_))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::InsufficientKeyStrength { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::InsufficientKeyStrength { .. }
            ))
        ));
    }

    #[test]
    fn test_rs256_conversion_rejects_declared_algorithm_mismatch() {
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let jwk = jwk.with_alg(Algorithm::Ps256);

        let result: Result<RS256PublicKey> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::AlgorithmMismatch { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_validation_error_preserves_source_chain() {
        let weak_hs_key_json = r#"{
            "kty": "oct",
            "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }"#;

        let jwk: Key = serde_json::from_str(weak_hs_key_json).unwrap();
        let err = HS256Key::try_from(&jwk).unwrap_err();

        let JwtSimpleKeyConversionError::IncompatibleKey(ref inner) = err else {
            panic!("expected IncompatibleKey, got {err}");
        };
        assert!(
            matches!(inner, IncompatibleKeyError::InsufficientKeyStrength { .. }),
            "expected InsufficientKeyStrength, got {inner}"
        );
    }

    // ------------------------------------------------------------------------
    // Behavior introduced by routing conversions through `from_jwk`
    // ------------------------------------------------------------------------

    /// Member names of a reduced JWK document, for asserting what reaches jwt-simple.
    fn member_names(json: &str) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let mut names: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    #[test]
    fn reduced_jwk_forwards_only_material_and_kid() {
        let json = r#"{
            "kty": "RSA",
            "kid": "rsa-1",
            "use": "sig",
            "alg": "RS256",
            "key_ops": ["verify"],
            "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let params = rsa_params(&jwk).unwrap();

        let reduced = rsa_public_jwk(params, jwk.kid()).unwrap();
        assert_eq!(member_names(&reduced), ["e", "kid", "kty", "n"]);

        let jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();
        let params = ec_params(&jwk, EcCurve::P256).unwrap();
        let reduced = ec_jwk(params, None, true).unwrap();
        assert_eq!(member_names(&reduced), ["crv", "d", "kty", "x", "y"]);
        let reduced = ec_jwk(params, None, false).unwrap();
        assert_eq!(member_names(&reduced), ["crv", "kty", "x", "y"]);
    }

    #[test]
    fn converted_keys_carry_the_jwk_kid() {
        let rsa: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY)
            .map(|k: Key| k.with_kid("rsa-kid"))
            .unwrap();
        let key: RS256PublicKey = (&rsa).try_into().unwrap();
        assert_eq!(key.key_id().as_deref(), Some("rsa-kid"));

        let ec: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY)
            .map(|k: Key| k.with_kid("ec-kid"))
            .unwrap();
        let key_pair: ES256KeyPair = (&ec).try_into().unwrap();
        assert_eq!(key_pair.key_id().as_deref(), Some("ec-kid"));
        // jwt-simple writes the key pair's id into the tokens it signs.
        let token = key_pair
            .sign(Claims::create(Duration::from_hours(1)))
            .unwrap();
        let metadata = Token::decode_metadata(&token).unwrap();
        assert_eq!(metadata.key_id(), Some("ec-kid"));

        let oct: Key = serde_json::from_str(SYMMETRIC_KEY)
            .map(|k: Key| k.with_kid("hs-kid"))
            .unwrap();
        let key: HS256Key = (&oct).try_into().unwrap();
        assert_eq!(key.key_id().as_deref(), Some("hs-kid"));

        // Without a kid, no id is attached.
        let rsa: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let key: RS256PublicKey = (&rsa).try_into().unwrap();
        assert_eq!(key.key_id(), &None);
    }

    #[test]
    fn ec_key_pair_conversion_rejects_public_point_not_derived_from_d() {
        // `d` from RFC 7517 A.2, `x`/`y` from a different P-256 key: structurally
        // valid, so this crate's validation passes, but jwt-simple's import derives
        // the public point from `d` and compares.
        let other = ES256KeyPair::generate().public_key().to_jwk();
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();
        let json = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": other["x"],
            "y": other["y"],
            "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        });
        let jwk: Key = serde_json::from_value(json).unwrap();
        assert!(
            jwk.validate().is_ok(),
            "structural validation is not the gate here"
        );

        let result: Result<ES256KeyPair> = (&jwk).try_into();
        assert!(
            matches!(result, Err(JwtSimpleKeyConversionError::Import(_))),
            "expected Import error, got {result:?}"
        );
    }

    #[test]
    fn ed25519_key_pair_conversion_reduces_extended_private_key_to_seed() {
        // RFC 8037 A.1 key in the 64-byte `seed || public-key` form.
        let seed =
            Base64UrlBytes::from_base64url("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
        let x =
            Base64UrlBytes::from_base64url("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        let mut extended = seed.as_bytes().to_vec();
        extended.extend_from_slice(x.as_bytes());
        let extended = Base64UrlBytes::from(extended);

        let json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x.to_base64url(),
            "d": extended.to_base64url()
        });
        let jwk: Key = serde_json::from_value(json).unwrap();
        let key_pair: Ed25519KeyPair = (&jwk).try_into().unwrap();
        assert_eq!(key_pair.public_key().to_bytes(), x.as_bytes());

        // Same form, but the embedded public key is not `x`.
        let mut wrong = seed.as_bytes().to_vec();
        wrong.extend_from_slice(&[0u8; 32]);
        let json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x.to_base64url(),
            "d": Base64UrlBytes::from(wrong).to_base64url()
        });
        let jwk: Key = serde_json::from_value(json).unwrap();
        let result: Result<Ed25519KeyPair> = (&jwk).try_into();
        assert!(
            matches!(result, Err(JwtSimpleKeyConversionError::Import(_))),
            "expected Import error, got {result:?}"
        );
    }

    #[test]
    fn ed25519_conversion_round_trips_through_jwt_simple_export() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "ed-1",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let key_pair: Ed25519KeyPair = (&jwk).try_into().unwrap();
        let public_key: Ed25519PublicKey = jwk.to_public().unwrap().try_into().unwrap();

        let token = key_pair
            .sign(Claims::create(Duration::from_hours(1)))
            .unwrap();
        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );

        // jwt-simple's own export parses back into this crate's model with the same
        // material and thumbprint, which is the publishing direction.
        let exported: Key = serde_json::from_str(&public_key.to_jwk()).unwrap();
        assert_eq!(exported.kid(), Some("ed-1"));
        assert_eq!(exported.thumbprint(), jwk.thumbprint());
        assert_eq!(exported.thumbprint(), key_pair.jwk_thumbprint());
    }

    #[test]
    fn rsa_key_pair_conversion_reports_missing_crt_component() {
        // `RsaParams::validate` accepts a `d`-only private key; jwt-simple needs the
        // CRT members, and the gap is reported before jwt-simple sees the document.
        let json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rd5Qw9Y8Q8fN4EuM4fM9x2s8"
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<RS256KeyPair> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::MissingComponent { field: "p" })
        ));
    }

    #[test]
    fn rsa_key_pair_conversion_round_trips_through_jwt_simple_export() {
        // A complete RSA private JWK, as jwt-simple itself exports one.
        let generated = RS256KeyPair::generate(2048)
            .unwrap()
            .with_key_id("rsa-pair");
        let jwk: Key = serde_json::from_str(&generated.to_jwk()).unwrap();
        assert!(jwk.has_private_key());

        let key_pair: RS256KeyPair = (&jwk).try_into().unwrap();
        assert_eq!(key_pair.key_id().as_deref(), Some("rsa-pair"));
        let public_key: RS256PublicKey = jwk.to_public().unwrap().try_into().unwrap();

        let token = key_pair
            .sign(Claims::create(Duration::from_hours(1)))
            .unwrap();
        assert!(
            public_key
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );
        assert_eq!(jwk.thumbprint(), generated.jwk_thumbprint());
    }
}

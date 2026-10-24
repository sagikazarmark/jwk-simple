//! jwt-simple key conversions, in both directions.
//!
//! # Into jwt-simple (`TryFrom<&Key>` for the jwt-simple key types)
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
//! # From jwt-simple (`TryFrom<&…>` for [`Key`])
//!
//! The publishing direction: a key generated or loaded with jwt-simple becomes a
//! [`Key`] that can go into a [`KeySet`](crate::KeySet) and be served as a JWKS.
//! Asymmetric signing keys are parsed from jwt-simple's own `to_jwk()` export, so
//! the result is exactly what jwt-simple would publish (`alg`, `use: sig`, `kid`
//! when one is set; Ed25519 as `alg: EdDSA`), and jwt-simple has already applied
//! its key policy when it constructed the key. HMAC keys are built from
//! `to_bytes()`; since jwt-simple accepts HMAC keys of any length, that conversion
//! applies this crate's strength policy (RFC 7518 §3.2) itself. jwt-simple's JWE
//! key types (X25519 and RSA-OAEP, behind its `jwe` feature) and ML-DSA keys are
//! not covered.
//!
//! Converting a key pair or an HMAC key exports private material. Use
//! `public_key()` first, or [`Key::to_public`] afterwards, to publish.
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
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::IncompatibleKeyError;
use crate::encoding::Base64UrlBytes;
use crate::error::{Error, JwtSimpleKeyConversionError};
use crate::jwk::{
    Algorithm, EcCurve, EcParams, Key, KeyOperation, KeyParams, KeyType, KeyUse, OkpCurve,
    OkpParams, RsaParams, SymmetricParams,
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

fn key_type_mismatch(jwk: &Key, expected: KeyType) -> JwtSimpleKeyConversionError {
    JwtSimpleKeyConversionError::KeyTypeMismatch {
        expected: expected.as_str(),
        actual: jwk.kty().as_str().to_string(),
    }
}

fn rsa_params(jwk: &Key) -> Result<&RsaParams> {
    match jwk.params() {
        KeyParams::Rsa(params) => Ok(params),
        _ => Err(key_type_mismatch(jwk, KeyType::Rsa)),
    }
}

fn ec_params(jwk: &Key, curve: EcCurve) -> Result<&EcParams> {
    let params = match jwk.params() {
        KeyParams::Ec(params) => params,
        _ => return Err(key_type_mismatch(jwk, KeyType::Ec)),
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
        _ => return Err(key_type_mismatch(jwk, KeyType::Okp)),
    };
    if params.crv != curve {
        return Err(JwtSimpleKeyConversionError::CurveMismatch {
            expected: curve.as_str(),
            actual: params.crv.as_str().to_string(),
        });
    }
    Ok(params)
}

fn symmetric_params(jwk: &Key) -> Result<&SymmetricParams> {
    match jwk.params() {
        KeyParams::Symmetric(params) => Ok(params),
        _ => Err(key_type_mismatch(jwk, KeyType::Symmetric)),
    }
}

/// A key pair conversion needs the private part; say so before anything else.
fn require_private_key(jwk: &Key) -> Result<()> {
    if jwk.has_private_key() {
        Ok(())
    } else {
        Err(JwtSimpleKeyConversionError::MissingPrivateKey)
    }
}

/// RFC 8037 registered `EdDSA`; RFC 9864 added `Ed25519` and deprecated `EdDSA`,
/// but deployed keys (and jwt-simple's own export) still carry it. jwt-simple
/// accepts either name on import, so a key is checked against the name it
/// declares. Without a declared `alg`, `Ed25519` is requested.
fn ed25519_requested_alg(jwk: &Key) -> Algorithm {
    match jwk.alg() {
        Some(Algorithm::EdDsa) => Algorithm::EdDsa,
        _ => Algorithm::Ed25519,
    }
}

// ============================================================================
// Reduced JWK
// ============================================================================

/// The members jwt-simple's `from_jwk` consumes: key type, curve, key material
/// and `kid`. Values are borrowed; the secret ones come from [`secret_b64`], so
/// their one base64 copy is wiped when the builder returns.
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
    /// Serializes the document jwt-simple will parse.
    ///
    /// The buffer is sized up front for jwt-simple's limit plus the worst-case
    /// JSON escaping of `kid` (six bytes per character, the same reservation
    /// jwt-simple's own export makes), so private material is never left behind
    /// by a reallocation. A document over [`MAX_JWK_LENGTH`] is reported here,
    /// by name, rather than as jwt-simple's generic import failure.
    fn to_json(&self) -> Result<Zeroizing<String>> {
        let encoding_error = |e: &dyn std::fmt::Display| {
            JwtSimpleKeyConversionError::Encoding(format!(
                "failed to serialize JWK for jwt-simple: {e}"
            ))
        };
        let kid_len = self.kid.map_or(0, str::len);
        let mut buf = Vec::with_capacity(MAX_JWK_LENGTH + 6 * kid_len);
        if let Err(e) = serde_json::to_writer(&mut buf, self) {
            buf.zeroize();
            return Err(encoding_error(&e));
        }
        // serde_json emits UTF-8; `from_utf8` takes the buffer over without copying.
        let json = match String::from_utf8(buf) {
            Ok(json) => Zeroizing::new(json),
            Err(e) => {
                let err = encoding_error(&e);
                e.into_bytes().zeroize();
                return Err(err);
            }
        };
        if json.len() > MAX_JWK_LENGTH {
            return Err(JwtSimpleKeyConversionError::Encoding(format!(
                "JWK document is {} bytes, over jwt-simple's MAX_JWK_LENGTH ({MAX_JWK_LENGTH}); shorten `kid`",
                json.len()
            )));
        }
        Ok(json)
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

            /// Converts an RSA JWK into a jwt-simple public key for this algorithm.
            ///
            /// The key carries the JWK's `kid`, if any.
            ///
            /// # Errors
            ///
            /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if
            ///   `kty` is not `RSA`.
            /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
            ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
            ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not this
            ///   one, `use`/`key_ops` that do not permit `verify`, or a modulus under
            ///   the algorithm's minimum.
            /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) if the document
            ///   would exceed jwt-simple's `MAX_JWK_LENGTH` (an oversized `kid`).
            /// - [`Import`](JwtSimpleKeyConversionError::Import) if jwt-simple rejects
            ///   the key: its RSA policy is 2048–4096 bits with `e = 65537`.
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

            /// Converts a private RSA JWK into a jwt-simple key pair for this algorithm.
            ///
            /// The key pair carries the JWK's `kid`, if any, and writes it into the
            /// tokens it signs.
            ///
            /// # Errors
            ///
            /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if
            ///   `kty` is not `RSA`.
            /// - [`MissingPrivateKey`](JwtSimpleKeyConversionError::MissingPrivateKey)
            ///   if the JWK has no `d`.
            /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
            ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
            ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not this
            ///   one, `use`/`key_ops` that do not permit `sign`, or a modulus under the
            ///   algorithm's minimum.
            /// - [`MissingComponent`](JwtSimpleKeyConversionError::MissingComponent) if
            ///   a CRT member (`p`, `q`, `dp`, `dq`, `qi`) is absent: jwt-simple needs all
            ///   of them, while [`RsaParams::validate`] allows a `d`-only private key.
            /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) for a multi-prime
            ///   key (`oth`), or if the document would exceed jwt-simple's
            ///   `MAX_JWK_LENGTH` (an oversized `kid`).
            /// - [`Import`](JwtSimpleKeyConversionError::Import) if jwt-simple rejects
            ///   the key: its RSA policy is 2048–4096 bits with `e = 65537`, and the
            ///   private members must be consistent with `n` and `e`.
            fn try_from(jwk: &Key) -> Result<Self> {
                let params = rsa_params(jwk)?;
                require_private_key(jwk)?;
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

            /// Converts an EC JWK on this curve into a jwt-simple public key.
            ///
            /// The key carries the JWK's `kid`, if any.
            ///
            /// # Errors
            ///
            /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if
            ///   `kty` is not `EC`; [`CurveMismatch`](JwtSimpleKeyConversionError::CurveMismatch)
            ///   if `crv` is another curve.
            /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
            ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
            ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not this
            ///   one, or `use`/`key_ops` that do not permit `verify`.
            /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) if the document
            ///   would exceed jwt-simple's `MAX_JWK_LENGTH` (an oversized `kid`).
            /// - [`Import`](JwtSimpleKeyConversionError::Import) if jwt-simple rejects
            ///   the key, notably a point that is not on the curve.
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

            /// Converts a private EC JWK on this curve into a jwt-simple key pair.
            ///
            /// The key pair carries the JWK's `kid`, if any, and writes it into the
            /// tokens it signs.
            ///
            /// # Errors
            ///
            /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if
            ///   `kty` is not `EC`; [`CurveMismatch`](JwtSimpleKeyConversionError::CurveMismatch)
            ///   if `crv` is another curve.
            /// - [`MissingPrivateKey`](JwtSimpleKeyConversionError::MissingPrivateKey)
            ///   if the JWK has no `d`.
            /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
            ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
            ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not this
            ///   one, or `use`/`key_ops` that do not permit `sign`.
            /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) if the document
            ///   would exceed jwt-simple's `MAX_JWK_LENGTH` (an oversized `kid`).
            /// - [`Import`](JwtSimpleKeyConversionError::Import) if jwt-simple rejects
            ///   the key: an invalid scalar, or `x`/`y` not derived from `d`.
            fn try_from(jwk: &Key) -> Result<Self> {
                let params = ec_params(jwk, $curve)?;
                require_private_key(jwk)?;
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

    /// Converts an Ed25519 OKP JWK into a jwt-simple public key.
    ///
    /// The key carries the JWK's `kid`, if any. A declared `alg` may be either
    /// registered name, `EdDSA` (RFC 8037) or `Ed25519` (RFC 9864).
    ///
    /// # Errors
    ///
    /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if `kty`
    ///   is not `OKP`; [`CurveMismatch`](JwtSimpleKeyConversionError::CurveMismatch)
    ///   if `crv` is not `Ed25519`.
    /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
    ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
    ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not an EdDSA
    ///   name, or `use`/`key_ops` that do not permit `verify`.
    /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) if the document would
    ///   exceed jwt-simple's `MAX_JWK_LENGTH` (an oversized `kid`).
    /// - [`Import`](JwtSimpleKeyConversionError::Import) if jwt-simple rejects the
    ///   key: a non-canonical encoding or a point of small order.
    fn try_from(jwk: &Key) -> Result<Self> {
        let params = okp_params(jwk, OkpCurve::Ed25519)?;
        validate_for_jwt_simple(jwk, &ed25519_requested_alg(jwk), [KeyOperation::Verify])?;
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

    /// Converts a private Ed25519 OKP JWK into a jwt-simple key pair.
    ///
    /// The key pair carries the JWK's `kid`, if any, and writes it into the tokens
    /// it signs. A declared `alg` may be either registered name, `EdDSA`
    /// (RFC 8037) or `Ed25519` (RFC 9864). `d` may be the 32-byte seed RFC 8037
    /// defines, or the 64-byte `seed || public-key` form some implementations use.
    ///
    /// # Errors
    ///
    /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if `kty`
    ///   is not `OKP`; [`CurveMismatch`](JwtSimpleKeyConversionError::CurveMismatch)
    ///   if `crv` is not `Ed25519`.
    /// - [`MissingPrivateKey`](JwtSimpleKeyConversionError::MissingPrivateKey) if
    ///   the JWK has no `d`.
    /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
    ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
    ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not an EdDSA
    ///   name, or `use`/`key_ops` that do not permit `sign`.
    /// - [`Encoding`](JwtSimpleKeyConversionError::Encoding) if the document would
    ///   exceed jwt-simple's `MAX_JWK_LENGTH` (an oversized `kid`).
    /// - [`Import`](JwtSimpleKeyConversionError::Import) if `d` has neither length,
    ///   if a 64-byte `d` embeds a public key other than `x`, or if jwt-simple
    ///   rejects the key: `x` not derived from the seed.
    fn try_from(jwk: &Key) -> Result<Self> {
        let params = okp_params(jwk, OkpCurve::Ed25519)?;
        require_private_key(jwk)?;
        validate_for_jwt_simple(jwk, &ed25519_requested_alg(jwk), [KeyOperation::Sign])?;
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

            /// Converts an `oct` JWK into a jwt-simple HMAC key for this algorithm.
            ///
            /// The key carries the JWK's `kid`, if any, and writes it into the tokens
            /// it authenticates. jwt-simple has no JWK import for symmetric keys, so
            /// the key is built from the bytes of `k`.
            ///
            /// # Errors
            ///
            /// - [`KeyTypeMismatch`](JwtSimpleKeyConversionError::KeyTypeMismatch) if
            ///   `kty` is not `oct`.
            /// - [`InvalidKey`](JwtSimpleKeyConversionError::InvalidKey) or
            ///   [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) from
            ///   [`Key::validate_for_use`]: structure, a declared `alg` that is not this
            ///   one, `k` shorter than the algorithm's hash output, or `key_ops` that
            ///   does not include both [`KeyOperation::Sign`] and
            ///   [`KeyOperation::Verify`]. HMAC keys in `jwt-simple` are bidirectional;
            ///   callers that need one-directional HMAC usage should remove `key_ops`
            ///   before converting.
            fn try_from(jwk: &Key) -> Result<Self> {
                let params = symmetric_params(jwk)?;
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

// ============================================================================
// Conversions from jwt-simple keys (the publishing direction)
// ============================================================================

/// Parses jwt-simple's `to_jwk()` output into a [`Key`] and validates it.
///
/// The document may hold private material, so it is wiped on drop.
fn key_from_jwt_simple_export(json: Zeroizing<String>) -> Result<Key> {
    let key: Key = serde_json::from_str(&json)
        .map_err(|e| JwtSimpleKeyConversionError::Core(Error::Json(e)))?;
    key.validate().map_err(map_validation_error)?;
    Ok(key)
}

macro_rules! impl_key_from_jwt_simple {
    ($($key_type:ty),* $(,)?) => {$(
        impl TryFrom<&$key_type> for Key {
            type Error = JwtSimpleKeyConversionError;

            /// Builds a [`Key`] from jwt-simple's own JWK export of this key.
            ///
            /// # Errors
            ///
            /// [`JwtSimpleKeyConversionError::Core`] or
            /// [`JwtSimpleKeyConversionError::InvalidKey`] if the export does not
            /// parse or validate as a JWK; neither happens for a key jwt-simple
            /// constructed.
            fn try_from(key: &$key_type) -> Result<Self> {
                key_from_jwt_simple_export(Zeroizing::new(key.to_jwk()))
            }
        }

        impl TryFrom<$key_type> for Key {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(key: $key_type) -> Result<Self> {
                Key::try_from(&key)
            }
        }
    )*};
}

impl_key_from_jwt_simple!(
    RS256PublicKey,
    RS384PublicKey,
    RS512PublicKey,
    PS256PublicKey,
    PS384PublicKey,
    PS512PublicKey,
    RS256KeyPair,
    RS384KeyPair,
    RS512KeyPair,
    PS256KeyPair,
    PS384KeyPair,
    PS512KeyPair,
    ES256PublicKey,
    ES384PublicKey,
    ES256kPublicKey,
    ES256KeyPair,
    ES384KeyPair,
    ES256kKeyPair,
    Ed25519PublicKey,
    Ed25519KeyPair,
);

macro_rules! impl_key_from_jwt_simple_hmac {
    ($key_type:ty, $alg:expr) => {
        impl TryFrom<&$key_type> for Key {
            type Error = JwtSimpleKeyConversionError;

            /// Builds an `oct` [`Key`] from the HMAC key's bytes, with `alg`,
            /// `use: sig` and the key's id as `kid`.
            ///
            /// jwt-simple accepts HMAC keys of any length, so unlike the asymmetric
            /// conversions this one applies this crate's strength policy itself: the
            /// result passes [`Key::validate_for_use`] for the algorithm it declares,
            /// which requires `k` to be at least the hash output size (RFC 7518 §3.2:
            /// 32 bytes for HS256, 48 for HS384, 64 for HS512).
            ///
            /// Note that jwt-simple's `HS384Key::generate()` and `HS512Key::generate()`
            /// produce 32-byte keys, which this rule rejects; build those from 48 or
            /// 64 random bytes with `from_bytes` instead.
            ///
            /// # Errors
            ///
            /// - [`Unrepresentable`](JwtSimpleKeyConversionError::Unrepresentable) if
            ///   the key has a salt attached: a JWK has no member for it, and a bare
            ///   `k` would produce a key that verifies none of the salted key's tokens.
            /// - [`IncompatibleKey`](JwtSimpleKeyConversionError::IncompatibleKey) with
            ///   [`InsufficientKeyStrength`](crate::IncompatibleKeyError::InsufficientKeyStrength)
            ///   if the key is shorter than the algorithm's hash output.
            fn try_from(key: &$key_type) -> Result<Self> {
                if !matches!(MACLike::salt(key), Salt::None) {
                    return Err(JwtSimpleKeyConversionError::Unrepresentable {
                        reason: "HMAC key has a salt attached",
                    });
                }

                let mut jwk = Key::new(KeyParams::Symmetric(SymmetricParams::new(
                    Base64UrlBytes::new(key.to_bytes()),
                )))
                .with_alg($alg)
                .with_use(KeyUse::Signature);
                if let Some(kid) = key.key_id() {
                    jwk = jwk.with_kid(kid.as_str());
                }
                validate_for_jwt_simple(&jwk, &$alg, [KeyOperation::Sign, KeyOperation::Verify])?;
                Ok(jwk)
            }
        }

        impl TryFrom<$key_type> for Key {
            type Error = JwtSimpleKeyConversionError;

            fn try_from(key: $key_type) -> Result<Self> {
                Key::try_from(&key)
            }
        }
    };
}

impl_key_from_jwt_simple_hmac!(HS256Key, Algorithm::Hs256);
impl_key_from_jwt_simple_hmac!(HS384Key, Algorithm::Hs384);
impl_key_from_jwt_simple_hmac!(HS512Key, Algorithm::Hs512);

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
        // Every key-pair conversion reports a public-only key the same way, before
        // intent validation gets a chance to call it an operation problem.
        let jwk: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
        let result: Result<RS256KeyPair> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::MissingPrivateKey)
        ));

        let jwk: Key = serde_json::from_str(RFC_EC_PUBLIC_KEY).unwrap();
        let result: Result<ES256KeyPair> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::MissingPrivateKey)
        ));

        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result: Result<Ed25519KeyPair> = (&jwk).try_into();
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

    // ------------------------------------------------------------------------
    // Ed25519 `alg` names (RFC 8037 `EdDSA`, RFC 9864 `Ed25519`)
    // ------------------------------------------------------------------------

    #[test]
    fn ed25519_conversion_accepts_either_registered_alg_name() {
        for alg in ["EdDSA", "Ed25519"] {
            let json = serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": alg,
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
            });
            let jwk: Key = serde_json::from_value(json).unwrap();
            let key_pair = Ed25519KeyPair::try_from(&jwk)
                .unwrap_or_else(|e| panic!("key pair with alg {alg}: {e}"));
            let public: Ed25519PublicKey = jwk
                .to_public()
                .unwrap()
                .try_into()
                .unwrap_or_else(|e| panic!("public key with alg {alg}: {e}"));

            let token = key_pair
                .sign(Claims::create(Duration::from_hours(1)))
                .unwrap();
            assert!(public.verify_token::<NoCustomClaims>(&token, None).is_ok());
        }

        // A declared algorithm that is not an EdDSA name is still a mismatch.
        let json = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "ES256",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        });
        let jwk: Key = serde_json::from_value(json).unwrap();
        let result: Result<Ed25519PublicKey> = (&jwk).try_into();
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::AlgorithmMismatch {
                    requested: Algorithm::Ed25519,
                    declared: Algorithm::Es256,
                }
            ))
        ));
    }

    // ------------------------------------------------------------------------
    // Document size (jwt-simple's `MAX_JWK_LENGTH`)
    // ------------------------------------------------------------------------

    #[test]
    fn oversized_kid_is_reported_before_jwt_simple_sees_the_document() {
        // A `kid` that pushes the reduced JWK over jwt-simple's 8 KiB limit. The
        // buffer is sized for it (no reallocation of a document holding `d`), and
        // the failure names the cause instead of surfacing as a generic import error.
        let jwk: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY)
            .map(|k: Key| k.with_kid("k".repeat(MAX_JWK_LENGTH)))
            .unwrap();

        let result: Result<ES256KeyPair> = (&jwk).try_into();
        match result {
            Err(JwtSimpleKeyConversionError::Encoding(msg)) => {
                assert!(msg.contains("MAX_JWK_LENGTH"), "unexpected message: {msg}");
                assert!(msg.contains("kid"), "unexpected message: {msg}");
            }
            other => panic!("expected Encoding error, got {other:?}"),
        }

        // The longest `kid` that still fits converts, with the `kid` intact.
        let probe: Key = serde_json::from_str(RFC_EC_P256_PRIVATE_KEY).unwrap();
        let params = ec_params(&probe, EcCurve::P256).unwrap();
        let headroom = MAX_JWK_LENGTH - ec_jwk(params, Some(""), true).unwrap().len();
        let kid = "k".repeat(headroom);
        let jwk = probe.with_kid(kid.clone());
        let key_pair: ES256KeyPair = (&jwk).try_into().unwrap();
        assert_eq!(key_pair.key_id().as_deref(), Some(kid.as_str()));
    }

    // ------------------------------------------------------------------------
    // From jwt-simple keys (publishing direction)
    // ------------------------------------------------------------------------

    /// What a published key must look like, and that it converts back and verifies.
    fn assert_published_public_key<P>(
        jwk: &Key,
        alg: Algorithm,
        kid: &str,
        thumbprint: &str,
        token: &str,
    ) where
        P: for<'a> TryFrom<&'a Key, Error = JwtSimpleKeyConversionError>,
        P: TokenVerifier,
    {
        assert!(
            jwk.is_public_key_only(),
            "{alg:?}: must not carry private material"
        );
        assert_eq!(jwk.alg(), Some(&alg));
        assert_eq!(jwk.key_use(), Some(&KeyUse::Signature));
        assert_eq!(jwk.kid(), Some(kid));
        assert_eq!(jwk.thumbprint(), thumbprint);
        assert!(jwk.validate().is_ok());

        let verifier =
            P::try_from(jwk).unwrap_or_else(|e| panic!("{alg:?} back to jwt-simple: {e}"));
        assert!(
            verifier.verifies(token),
            "{alg:?}: published key must verify the original pair's token"
        );
    }

    /// Test-local shim over the per-type `verify_token` methods, so the assertion
    /// helper can be generic over jwt-simple's public key types.
    trait TokenVerifier {
        fn verifies(&self, token: &str) -> bool;
    }

    macro_rules! impl_token_verifier {
        ($($key_type:ty),* $(,)?) => {$(
            impl TokenVerifier for $key_type {
                fn verifies(&self, token: &str) -> bool {
                    self.verify_token::<NoCustomClaims>(token, None).is_ok()
                }
            }
        )*};
    }

    impl_token_verifier!(
        RS256PublicKey,
        PS384PublicKey,
        ES256PublicKey,
        ES384PublicKey,
        ES256kPublicKey,
        Ed25519PublicKey,
    );

    #[test]
    fn key_from_jwt_simple_public_keys() {
        let claims = || Claims::create(Duration::from_hours(1));

        // One RSA key shared by an RS and a PS type.
        let rsa = RS256KeyPair::generate(2048).unwrap();
        let rs256 = rsa.clone().with_key_id("rs256");
        let rs_token = rs256.sign(claims()).unwrap();
        let rs_pub = rs256.public_key();
        assert_published_public_key::<RS256PublicKey>(
            &Key::try_from(&rs_pub).unwrap(),
            Algorithm::Rs256,
            "rs256",
            &rs_pub.jwk_thumbprint(),
            &rs_token,
        );
        let ps384 = PS384KeyPair::from_pem(&rsa.to_pem().unwrap())
            .unwrap()
            .with_key_id("ps384");
        let ps_token = ps384.sign(claims()).unwrap();
        let ps_pub = ps384.public_key();
        assert_published_public_key::<PS384PublicKey>(
            &Key::try_from(&ps_pub).unwrap(),
            Algorithm::Ps384,
            "ps384",
            &ps_pub.jwk_thumbprint(),
            &ps_token,
        );
        // Same material, different `alg`: thumbprints agree (RFC 7638 ignores `alg`).
        assert_eq!(rs_pub.jwk_thumbprint(), ps_pub.jwk_thumbprint());

        let es256 = ES256KeyPair::generate().with_key_id("es256");
        let token = es256.sign(claims()).unwrap();
        let public = es256.public_key();
        assert_published_public_key::<ES256PublicKey>(
            &Key::try_from(&public).unwrap(),
            Algorithm::Es256,
            "es256",
            &public.jwk_thumbprint(),
            &token,
        );

        let es384 = ES384KeyPair::generate().with_key_id("es384");
        let token = es384.sign(claims()).unwrap();
        let public = es384.public_key();
        assert_published_public_key::<ES384PublicKey>(
            &Key::try_from(&public).unwrap(),
            Algorithm::Es384,
            "es384",
            &public.jwk_thumbprint(),
            &token,
        );

        let es256k = ES256kKeyPair::generate().with_key_id("es256k");
        let token = es256k.sign(claims()).unwrap();
        let public = es256k.public_key();
        assert_published_public_key::<ES256kPublicKey>(
            &Key::try_from(&public).unwrap(),
            Algorithm::Es256k,
            "es256k",
            &public.jwk_thumbprint(),
            &token,
        );

        // jwt-simple publishes Ed25519 under the deployed name, `EdDSA`.
        let ed = Ed25519KeyPair::generate().with_key_id("ed25519");
        let token = ed.sign(claims()).unwrap();
        let public = ed.public_key();
        assert_published_public_key::<Ed25519PublicKey>(
            &Key::try_from(&public).unwrap(),
            Algorithm::EdDsa,
            "ed25519",
            &public.jwk_thumbprint(),
            &token,
        );

        // Owned conversions take the same path.
        let owned: Key = es256.public_key().try_into().unwrap();
        assert_eq!(owned.kid(), Some("es256"));

        // Without a key id, no `kid`.
        let anonymous: Key = Key::try_from(&ES256KeyPair::generate().public_key()).unwrap();
        assert_eq!(anonymous.kid(), None);
    }

    #[test]
    fn key_from_jwt_simple_key_pairs_round_trip() {
        let claims = || Claims::create(Duration::from_hours(1));

        let es256 = ES256KeyPair::generate().with_key_id("es256-pair");
        let jwk = Key::try_from(&es256).unwrap();
        assert!(jwk.has_private_key());
        assert_eq!(jwk.kid(), Some("es256-pair"));
        assert_eq!(jwk.thumbprint(), es256.jwk_thumbprint());
        let back: ES256KeyPair = (&jwk).try_into().unwrap();
        let token = back.sign(claims()).unwrap();
        assert!(
            es256
                .public_key()
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );
        // `to_public` strips `d` and the result is the published form.
        let public = jwk.to_public().unwrap();
        assert!(public.is_public_key_only());
        assert_eq!(public.thumbprint(), jwk.thumbprint());

        let ed = Ed25519KeyPair::generate().with_key_id("ed-pair");
        let jwk = Key::try_from(&ed).unwrap();
        assert!(jwk.has_private_key());
        let back: Ed25519KeyPair = (&jwk).try_into().unwrap();
        let token = back.sign(claims()).unwrap();
        assert!(
            ed.public_key()
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );

        let rsa = RS256KeyPair::generate(2048)
            .unwrap()
            .with_key_id("rsa-pair");
        let jwk = Key::try_from(&rsa).unwrap();
        assert!(jwk.has_private_key());
        let back: RS256KeyPair = (&jwk).try_into().unwrap();
        let token = back.sign(claims()).unwrap();
        assert!(
            rsa.public_key()
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );
    }

    #[test]
    fn key_from_jwt_simple_hmac_keys() {
        let hs256 = HS256Key::generate().with_key_id("hs256");
        let jwk = Key::try_from(&hs256).unwrap();
        assert_eq!(jwk.kty(), crate::KeyType::Symmetric);
        assert_eq!(jwk.alg(), Some(&Algorithm::Hs256));
        assert_eq!(jwk.key_use(), Some(&KeyUse::Signature));
        assert_eq!(jwk.kid(), Some("hs256"));
        match jwk.params() {
            KeyParams::Symmetric(params) => assert_eq!(params.k.as_bytes(), hs256.to_bytes()),
            other => panic!("expected oct params, got {other:?}"),
        }

        // Round trip: the converted key authenticates and verifies the same tokens.
        let back: HS256Key = (&jwk).try_into().unwrap();
        let token = hs256
            .authenticate(Claims::create(Duration::from_hours(1)))
            .unwrap();
        assert!(back.verify_token::<NoCustomClaims>(&token, None).is_ok());

        // HS384/HS512 need 48/64-byte keys (RFC 7518 §3.2).
        let jwk = Key::try_from(&HS384Key::from_bytes(&[2u8; 48])).unwrap();
        assert_eq!(jwk.alg(), Some(&Algorithm::Hs384));
        assert_eq!(jwk.kid(), None);
        let jwk = Key::try_from(HS512Key::from_bytes(&[3u8; 64])).unwrap();
        assert_eq!(jwk.alg(), Some(&Algorithm::Hs512));

        // jwt-simple's `generate()` yields 32 bytes for every HS* type, which is
        // under the RFC 7518 minimum for HS384/HS512; the error says so.
        let result = Key::try_from(&HS384Key::generate());
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::InsufficientKeyStrength {
                    minimum_bits: 384,
                    actual_bits: 256,
                    ..
                }
            ))
        ));

        // A salt has no JWK member; refusing beats publishing a key that verifies nothing.
        let salted = HS256Key::generate_with_salt();
        let result = Key::try_from(&salted);
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::Unrepresentable {
                reason: "HMAC key has a salt attached"
            })
        ));

        // jwt-simple takes HMAC keys of any length; a JWK declaring HS256 must not
        // be shorter than SHA-256's output (RFC 7518 §3.2), so the strength policy
        // is applied here rather than left for the consumer to discover.
        let weak = HS256Key::from_bytes(&[1u8; 4]);
        let result = Key::try_from(&weak);
        assert!(matches!(
            result,
            Err(JwtSimpleKeyConversionError::IncompatibleKey(
                IncompatibleKeyError::InsufficientKeyStrength {
                    minimum_bits: 256,
                    actual_bits: 32,
                    ..
                }
            ))
        ));
        // The boundary passes.
        assert!(Key::try_from(&HS256Key::from_bytes(&[1u8; 32])).is_ok());
    }

    #[test]
    fn publish_and_consume_a_key_set() {
        // Issuer side: generate with jwt-simple, publish the public keys as a JWKS.
        let current = ES256KeyPair::generate().with_key_id("2026-10");
        let previous = ES256KeyPair::generate().with_key_id("2026-04");
        let mut jwks = KeySet::new();
        jwks.add_key(Key::try_from(&current.public_key()).unwrap())
            .unwrap();
        jwks.add_key(Key::try_from(&previous.public_key()).unwrap())
            .unwrap();
        let published = serde_json::to_string(&jwks).unwrap();
        assert!(!published.contains("\"d\""));

        // Verifier side: fetch, select by the token's `kid`, convert, verify.
        let token = current
            .sign(Claims::create(Duration::from_hours(1)))
            .unwrap();
        let kid = Token::decode_metadata(&token)
            .unwrap()
            .key_id()
            .unwrap()
            .to_owned();
        let jwks: KeySet = serde_json::from_str(&published).unwrap();
        let key = jwks
            .selector(&[Algorithm::Es256])
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Es256).with_kid(&kid))
            .unwrap();
        let verifier: ES256PublicKey = key.try_into().unwrap();
        assert!(
            verifier
                .verify_token::<NoCustomClaims>(&token, None)
                .is_ok()
        );
    }
}

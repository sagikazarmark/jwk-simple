//! JSON Web Key (JWK) types as defined in RFC 7517.
//!
//! This module provides the core [`Key`] type and related enums for
//! representing cryptographic keys in JSON format.
//!
//! # Supported Key Types
//!
//! - **RSA** (`kty: "RSA"`) - RSA public and private keys
//! - **EC** (`kty: "EC"`) - Elliptic Curve keys (P-256, P-384, P-521, secp256k1)
//! - **oct** (`kty: "oct"`) - Symmetric keys (HMAC, AES)
//! - **OKP** (`kty: "OKP"`) - Octet Key Pairs (Ed25519, Ed448, X25519, X448)
//!
//! # Examples
//!
//! Parse a JWK from JSON:
//!
//! ```
//! use jwk_simple::jwk::Key;
//!
//! let json = r#"{
//!     "kty": "RSA",
//!     "kid": "my-key-id",
//!     "use": "sig",
//!     "alg": "RS256",
//!     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
//!     "e": "AQAB"
//! }"#;
//!
//! let jwk: Key = serde_json::from_str(json).unwrap();
//! assert_eq!(jwk.kid.as_deref(), Some("my-key-id"));
//! ```

mod ec;
mod okp;
mod rsa;
mod symmetric;
pub(crate) mod thumbprint;

pub use ec::{EcCurve, EcParams};
pub use okp::{OkpCurve, OkpParams};
pub use rsa::{RsaOtherPrime, RsaParams, RsaParamsBuilder};
pub use symmetric::SymmetricParams;

use std::collections::HashSet;
use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use url::Url;
use x509_parser::prelude::parse_x509_certificate;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{Error, ParseError, Result, ValidationError};

/// Key type identifier (RFC 7517 Section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// RSA key type.
    Rsa,
    /// Elliptic Curve key type.
    Ec,
    /// Symmetric key type (octet sequence).
    Symmetric,
    /// Octet Key Pair (Edwards/Montgomery curves).
    Okp,
}

impl KeyType {
    /// Returns the key type as the JWK `kty` string.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Rsa => "RSA",
            KeyType::Ec => "EC",
            KeyType::Symmetric => "oct",
            KeyType::Okp => "OKP",
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "RSA" => Ok(KeyType::Rsa),
            "EC" => Ok(KeyType::Ec),
            "oct" => Ok(KeyType::Symmetric),
            "OKP" => Ok(KeyType::Okp),
            _ => Err(Error::Parse(ParseError::UnknownKeyType(s.to_string()))),
        }
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Key use (RFC 7517 Section 4.2).
///
/// Per RFC 7517, the "use" parameter is intended to identify the intended use
/// of the public key. While "sig" and "enc" are the defined values, the
/// specification allows for other values via registration or collision-resistant
/// names for private use.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyUse {
    /// Key is used for signatures.
    Signature,
    /// Key is used for encryption.
    Encryption,
    /// Unknown or private-use key use.
    ///
    /// Per RFC 7517, key use values should either be registered in IANA
    /// or be a collision-resistant name. Unknown values are preserved.
    Unknown(String),
}

impl KeyUse {
    /// Returns the key use as a string.
    pub fn as_str(&self) -> &str {
        match self {
            KeyUse::Signature => "sig",
            KeyUse::Encryption => "enc",
            KeyUse::Unknown(s) => s.as_str(),
        }
    }
}

impl Display for KeyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for KeyUse {
    type Err = std::convert::Infallible;

    /// Parses a key use string.
    ///
    /// Per RFC 7517, unknown key use values are accepted and stored as `Unknown`.
    /// This function never fails - unrecognized values become `KeyUse::Unknown(s)`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "sig" => KeyUse::Signature,
            "enc" => KeyUse::Encryption,
            _ => KeyUse::Unknown(s.to_string()),
        })
    }
}

impl Serialize for KeyUse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyUse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Infallible, so unwrap is safe
        Ok(s.parse().unwrap())
    }
}

/// Key operation (RFC 7517 Section 4.3).
///
/// Per RFC 7517, unknown key operation values should be accepted to support
/// collision-resistant names and future extensions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    /// Compute digital signature or MAC.
    Sign,
    /// Verify digital signature or MAC.
    Verify,
    /// Encrypt content.
    Encrypt,
    /// Decrypt content.
    Decrypt,
    /// Encrypt key.
    WrapKey,
    /// Decrypt key.
    UnwrapKey,
    /// Derive key.
    DeriveKey,
    /// Derive bits not to be used as a key.
    DeriveBits,
    /// Unknown or private-use key operation.
    ///
    /// Per RFC 7517, key operation values should either be registered in IANA
    /// or be a collision-resistant name. Unknown values are preserved.
    Unknown(String),
}

impl KeyOperation {
    /// Returns the key operation as a string.
    pub fn as_str(&self) -> &str {
        match self {
            KeyOperation::Sign => "sign",
            KeyOperation::Verify => "verify",
            KeyOperation::Encrypt => "encrypt",
            KeyOperation::Decrypt => "decrypt",
            KeyOperation::WrapKey => "wrapKey",
            KeyOperation::UnwrapKey => "unwrapKey",
            KeyOperation::DeriveKey => "deriveKey",
            KeyOperation::DeriveBits => "deriveBits",
            KeyOperation::Unknown(s) => s.as_str(),
        }
    }
}

impl Display for KeyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for KeyOperation {
    type Err = std::convert::Infallible;

    /// Parses a key operation string.
    ///
    /// Per RFC 7517, unknown key operation values are accepted and stored as `Unknown`.
    /// This function never fails - unrecognized values become `KeyOperation::Unknown(s)`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "sign" => KeyOperation::Sign,
            "verify" => KeyOperation::Verify,
            "encrypt" => KeyOperation::Encrypt,
            "decrypt" => KeyOperation::Decrypt,
            "wrapKey" => KeyOperation::WrapKey,
            "unwrapKey" => KeyOperation::UnwrapKey,
            "deriveKey" => KeyOperation::DeriveKey,
            "deriveBits" => KeyOperation::DeriveBits,
            _ => KeyOperation::Unknown(s.to_string()),
        })
    }
}

impl Serialize for KeyOperation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyOperation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Infallible, so unwrap is safe
        Ok(s.parse().unwrap())
    }
}

/// JWK Algorithm (RFC 7518).
///
/// Per RFC 7517, unknown algorithm values should be accepted and preserved
/// to allow for future extensions and private-use algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    // HMAC
    /// HMAC using SHA-256.
    Hs256,
    /// HMAC using SHA-384.
    Hs384,
    /// HMAC using SHA-512.
    Hs512,

    // RSA PKCS#1
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    Rs512,

    // RSA-PSS
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    Ps256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    Ps384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    Ps512,

    // ECDSA
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// ECDSA using P-521 and SHA-512.
    Es512,
    /// ECDSA using secp256k1 and SHA-256.
    Es256k,

    // EdDSA
    /// Edwards-curve Digital Signature Algorithm (legacy JOSE identifier).
    ///
    /// RFC 9864 deprecates this generic identifier in favor of the fully
    /// specified [`Algorithm::Ed25519`] and [`Algorithm::Ed448`] values.
    EdDsa,
    /// Ed25519 signature algorithm (RFC 9864 JOSE algorithm identifier).
    Ed25519,
    /// Ed448 signature algorithm (RFC 9864 JOSE algorithm identifier).
    Ed448,

    // RSA Encryption
    /// RSAES-OAEP using default parameters.
    RsaOaep,
    /// RSAES-OAEP using SHA-256 and MGF1 with SHA-256.
    RsaOaep256,
    /// RSAES-OAEP using SHA-384 and MGF1 with SHA-384.
    RsaOaep384,
    /// RSAES-OAEP using SHA-512 and MGF1 with SHA-512.
    RsaOaep512,
    /// RSAES-PKCS1-v1_5.
    Rsa1_5,

    // AES Key Wrap
    /// AES Key Wrap with 128-bit key.
    A128kw,
    /// AES Key Wrap with 192-bit key.
    A192kw,
    /// AES Key Wrap with 256-bit key.
    A256kw,

    // Direct
    /// Direct use of a shared symmetric key.
    Dir,

    // ECDH-ES
    /// ECDH-ES using Concat KDF.
    EcdhEs,
    /// ECDH-ES using Concat KDF and A128KW wrapping.
    EcdhEsA128kw,
    /// ECDH-ES using Concat KDF and A192KW wrapping.
    EcdhEsA192kw,
    /// ECDH-ES using Concat KDF and A256KW wrapping.
    EcdhEsA256kw,

    // AES-GCM Key Wrap
    /// Key wrapping with AES-GCM using 128-bit key.
    A128gcmkw,
    /// Key wrapping with AES-GCM using 192-bit key.
    A192gcmkw,
    /// Key wrapping with AES-GCM using 256-bit key.
    A256gcmkw,

    // PBES2
    /// PBES2 with HMAC SHA-256 and A128KW wrapping.
    Pbes2Hs256A128kw,
    /// PBES2 with HMAC SHA-384 and A192KW wrapping.
    Pbes2Hs384A192kw,
    /// PBES2 with HMAC SHA-512 and A256KW wrapping.
    Pbes2Hs512A256kw,

    // Content Encryption
    /// AES-CBC with HMAC SHA-256 using 128-bit keys.
    A128cbcHs256,
    /// AES-CBC with HMAC SHA-384 using 192-bit keys.
    A192cbcHs384,
    /// AES-CBC with HMAC SHA-512 using 256-bit keys.
    A256cbcHs512,
    /// AES-GCM using 128-bit key.
    A128gcm,
    /// AES-GCM using 192-bit key.
    A192gcm,
    /// AES-GCM using 256-bit key.
    A256gcm,

    /// Unknown or private-use algorithm.
    ///
    /// Per RFC 7517, implementations should accept unknown algorithm values
    /// to support future extensions and collision-resistant names.
    Unknown(String),
}

impl Algorithm {
    /// Returns the algorithm as a string.
    ///
    /// For unknown algorithms, this returns the original algorithm name.
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::Hs256 => "HS256",
            Algorithm::Hs384 => "HS384",
            Algorithm::Hs512 => "HS512",
            Algorithm::Rs256 => "RS256",
            Algorithm::Rs384 => "RS384",
            Algorithm::Rs512 => "RS512",
            Algorithm::Ps256 => "PS256",
            Algorithm::Ps384 => "PS384",
            Algorithm::Ps512 => "PS512",
            Algorithm::Es256 => "ES256",
            Algorithm::Es384 => "ES384",
            Algorithm::Es512 => "ES512",
            Algorithm::Es256k => "ES256K",
            Algorithm::EdDsa => "EdDSA",
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::Ed448 => "Ed448",
            Algorithm::RsaOaep => "RSA-OAEP",
            Algorithm::RsaOaep256 => "RSA-OAEP-256",
            Algorithm::RsaOaep384 => "RSA-OAEP-384",
            Algorithm::RsaOaep512 => "RSA-OAEP-512",
            Algorithm::Rsa1_5 => "RSA1_5",
            Algorithm::A128kw => "A128KW",
            Algorithm::A192kw => "A192KW",
            Algorithm::A256kw => "A256KW",
            Algorithm::Dir => "dir",
            Algorithm::EcdhEs => "ECDH-ES",
            Algorithm::EcdhEsA128kw => "ECDH-ES+A128KW",
            Algorithm::EcdhEsA192kw => "ECDH-ES+A192KW",
            Algorithm::EcdhEsA256kw => "ECDH-ES+A256KW",
            Algorithm::A128gcmkw => "A128GCMKW",
            Algorithm::A192gcmkw => "A192GCMKW",
            Algorithm::A256gcmkw => "A256GCMKW",
            Algorithm::Pbes2Hs256A128kw => "PBES2-HS256+A128KW",
            Algorithm::Pbes2Hs384A192kw => "PBES2-HS384+A192KW",
            Algorithm::Pbes2Hs512A256kw => "PBES2-HS512+A256KW",
            Algorithm::A128cbcHs256 => "A128CBC-HS256",
            Algorithm::A192cbcHs384 => "A192CBC-HS384",
            Algorithm::A256cbcHs512 => "A256CBC-HS512",
            Algorithm::A128gcm => "A128GCM",
            Algorithm::A192gcm => "A192GCM",
            Algorithm::A256gcm => "A256GCM",
            Algorithm::Unknown(s) => s.as_str(),
        }
    }

    /// Returns `true` if this is an unknown/unrecognized algorithm.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Algorithm::Unknown(_))
    }

    /// Returns `true` if this algorithm identifier is deprecated.
    ///
    /// Per RFC 9864, `EdDSA` is deprecated in JOSE in favor of the fully
    /// specified `Ed25519` and `Ed448` identifiers.
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Algorithm::EdDsa)
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = std::convert::Infallible;

    /// Parses an algorithm string.
    ///
    /// Per RFC 7517, unknown algorithm values are accepted and stored as `Unknown`.
    /// This function never fails - unrecognized values become `Algorithm::Unknown(s)`.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "HS256" => Algorithm::Hs256,
            "HS384" => Algorithm::Hs384,
            "HS512" => Algorithm::Hs512,
            "RS256" => Algorithm::Rs256,
            "RS384" => Algorithm::Rs384,
            "RS512" => Algorithm::Rs512,
            "PS256" => Algorithm::Ps256,
            "PS384" => Algorithm::Ps384,
            "PS512" => Algorithm::Ps512,
            "ES256" => Algorithm::Es256,
            "ES384" => Algorithm::Es384,
            "ES512" => Algorithm::Es512,
            "ES256K" => Algorithm::Es256k,
            "EdDSA" => Algorithm::EdDsa,
            "Ed25519" => Algorithm::Ed25519,
            "Ed448" => Algorithm::Ed448,
            "RSA-OAEP" => Algorithm::RsaOaep,
            "RSA-OAEP-256" => Algorithm::RsaOaep256,
            "RSA-OAEP-384" => Algorithm::RsaOaep384,
            "RSA-OAEP-512" => Algorithm::RsaOaep512,
            "RSA1_5" => Algorithm::Rsa1_5,
            "A128KW" => Algorithm::A128kw,
            "A192KW" => Algorithm::A192kw,
            "A256KW" => Algorithm::A256kw,
            "dir" => Algorithm::Dir,
            "ECDH-ES" => Algorithm::EcdhEs,
            "ECDH-ES+A128KW" => Algorithm::EcdhEsA128kw,
            "ECDH-ES+A192KW" => Algorithm::EcdhEsA192kw,
            "ECDH-ES+A256KW" => Algorithm::EcdhEsA256kw,
            "A128GCMKW" => Algorithm::A128gcmkw,
            "A192GCMKW" => Algorithm::A192gcmkw,
            "A256GCMKW" => Algorithm::A256gcmkw,
            "PBES2-HS256+A128KW" => Algorithm::Pbes2Hs256A128kw,
            "PBES2-HS384+A192KW" => Algorithm::Pbes2Hs384A192kw,
            "PBES2-HS512+A256KW" => Algorithm::Pbes2Hs512A256kw,
            "A128CBC-HS256" => Algorithm::A128cbcHs256,
            "A192CBC-HS384" => Algorithm::A192cbcHs384,
            "A256CBC-HS512" => Algorithm::A256cbcHs512,
            "A128GCM" => Algorithm::A128gcm,
            "A192GCM" => Algorithm::A192gcm,
            "A256GCM" => Algorithm::A256gcm,
            _ => Algorithm::Unknown(s.to_string()),
        })
    }
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Key-type-specific parameters.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum KeyParams {
    /// RSA key parameters.
    Rsa(RsaParams),
    /// Elliptic Curve key parameters.
    Ec(EcParams),
    /// Symmetric key parameters.
    Symmetric(SymmetricParams),
    /// Octet Key Pair parameters.
    Okp(OkpParams),
}

impl KeyParams {
    /// Returns the [`KeyType`] corresponding to this variant.
    pub fn key_type(&self) -> KeyType {
        match self {
            KeyParams::Rsa(_) => KeyType::Rsa,
            KeyParams::Ec(_) => KeyType::Ec,
            KeyParams::Symmetric(_) => KeyType::Symmetric,
            KeyParams::Okp(_) => KeyType::Okp,
        }
    }

    /// Returns `true` if this contains only public key parameters.
    pub fn is_public_key_only(&self) -> bool {
        match self {
            KeyParams::Rsa(p) => p.is_public_key_only(),
            KeyParams::Ec(p) => p.is_public_key_only(),
            KeyParams::Symmetric(p) => p.is_public_key_only(),
            KeyParams::Okp(p) => p.is_public_key_only(),
        }
    }

    /// Returns `true` if this contains private key parameters.
    pub fn has_private_key(&self) -> bool {
        !self.is_public_key_only()
    }

    /// Validates the key parameters.
    pub fn validate(&self) -> Result<()> {
        match self {
            KeyParams::Rsa(p) => p.validate(),
            KeyParams::Ec(p) => p.validate(),
            KeyParams::Symmetric(p) => p.validate(),
            KeyParams::Okp(p) => p.validate(),
        }
    }
}

impl From<&KeyParams> for KeyType {
    fn from(params: &KeyParams) -> Self {
        params.key_type()
    }
}

impl From<KeyParams> for KeyType {
    fn from(params: KeyParams) -> Self {
        (&params).into()
    }
}

impl From<RsaParams> for KeyParams {
    fn from(p: RsaParams) -> Self {
        KeyParams::Rsa(p)
    }
}

impl From<EcParams> for KeyParams {
    fn from(p: EcParams) -> Self {
        KeyParams::Ec(p)
    }
}

impl From<SymmetricParams> for KeyParams {
    fn from(p: SymmetricParams) -> Self {
        KeyParams::Symmetric(p)
    }
}

impl From<OkpParams> for KeyParams {
    fn from(p: OkpParams) -> Self {
        KeyParams::Okp(p)
    }
}

impl PartialEq for KeyParams {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (KeyParams::Rsa(a), KeyParams::Rsa(b)) => a == b,
            (KeyParams::Ec(a), KeyParams::Ec(b)) => a == b,
            (KeyParams::Symmetric(a), KeyParams::Symmetric(b)) => a == b,
            (KeyParams::Okp(a), KeyParams::Okp(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for KeyParams {}

impl Hash for KeyParams {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            KeyParams::Rsa(p) => p.hash(state),
            KeyParams::Ec(p) => p.hash(state),
            KeyParams::Symmetric(p) => p.hash(state),
            KeyParams::Okp(p) => p.hash(state),
        }
    }
}

/// A JSON Web Key (RFC 7517).
///
/// Represents a single cryptographic key with its parameters and metadata.
///
/// # Examples
///
/// ```
/// use jwk_simple::jwk::{Key, KeyType};
///
/// // Parse from JSON
/// let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
/// let jwk: Key = serde_json::from_str(json).unwrap();
///
/// // Check key properties
/// assert_eq!(jwk.kty(), KeyType::Rsa);
/// assert!(jwk.is_public_key_only());
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    /// The key ID.
    #[zeroize(skip)]
    pub kid: Option<String>,

    /// The intended use of the key.
    #[zeroize(skip)]
    pub key_use: Option<KeyUse>,

    /// The permitted operations for the key.
    #[zeroize(skip)]
    pub key_ops: Option<Vec<KeyOperation>>,

    /// The algorithm intended for use with the key.
    #[zeroize(skip)]
    pub alg: Option<Algorithm>,

    /// The key-type-specific parameters.
    pub params: KeyParams,

    /// X.509 certificate chain (base64-encoded DER).
    #[zeroize(skip)]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint (base64url-encoded).
    #[zeroize(skip)]
    pub x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint (base64url-encoded).
    #[zeroize(skip)]
    #[allow(non_snake_case)]
    pub x5t_s256: Option<String>,

    /// X.509 URL.
    #[zeroize(skip)]
    pub x5u: Option<String>,
}

impl Key {
    /// Creates a new `Key` from key-type-specific parameters.
    ///
    /// The key type is automatically derived from the [`KeyParams`] variant via
    /// the [`kty()`](Key::kty) accessor, which makes it impossible to construct
    /// a `Key` with a mismatched key type.
    ///
    /// Use the `with_*` methods to set optional metadata fields:
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::jwk::{Key, KeyType, KeyParams, RsaParams, KeyUse, Algorithm};
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
    ///     Base64UrlBytes::new(vec![1, 2, 3]),
    ///     Base64UrlBytes::new(vec![1, 0, 1]),
    /// )))
    /// .with_kid("my-key-id")
    /// .with_alg(Algorithm::Rs256)
    /// .with_use(KeyUse::Signature);
    ///
    /// assert_eq!(key.kty(), KeyType::Rsa);
    /// assert_eq!(key.kid.as_deref(), Some("my-key-id"));
    /// ```
    #[must_use]
    pub fn new(params: KeyParams) -> Self {
        Self {
            kid: None,
            key_use: None,
            key_ops: None,
            alg: None,
            params,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            x5u: None,
        }
    }

    /// Returns the key type, derived from the [`KeyParams`] variant.
    ///
    /// This is always consistent with the key's parameters:
    /// - [`KeyParams::Rsa`] → [`KeyType::Rsa`]
    /// - [`KeyParams::Ec`] → [`KeyType::Ec`]
    /// - [`KeyParams::Symmetric`] → [`KeyType::Symmetric`]
    /// - [`KeyParams::Okp`] → [`KeyType::Okp`]
    #[inline]
    #[must_use]
    pub fn kty(&self) -> KeyType {
        self.params.key_type()
    }

    /// Sets the key ID (`kid`).
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Sets the intended use of the key (`use`).
    #[must_use]
    pub fn with_use(mut self, key_use: KeyUse) -> Self {
        self.key_use = Some(key_use);
        self
    }

    /// Sets the permitted key operations (`key_ops`).
    #[must_use]
    pub fn with_key_ops(mut self, key_ops: Vec<KeyOperation>) -> Self {
        self.key_ops = Some(key_ops);
        self
    }

    /// Sets the algorithm intended for use with the key (`alg`).
    #[must_use]
    pub fn with_alg(mut self, alg: Algorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Sets the X.509 certificate chain (`x5c`).
    #[must_use]
    pub fn with_x5c(mut self, x5c: Vec<String>) -> Self {
        self.x5c = Some(x5c);
        self
    }

    /// Sets the X.509 certificate SHA-1 thumbprint (`x5t`).
    #[must_use]
    pub fn with_x5t(mut self, x5t: impl Into<String>) -> Self {
        self.x5t = Some(x5t.into());
        self
    }

    /// Sets the X.509 certificate SHA-256 thumbprint (`x5t#S256`).
    #[must_use]
    pub fn with_x5t_s256(mut self, x5t_s256: impl Into<String>) -> Self {
        self.x5t_s256 = Some(x5t_s256.into());
        self
    }

    /// Sets the X.509 URL (`x5u`).
    #[must_use]
    pub fn with_x5u(mut self, x5u: impl Into<String>) -> Self {
        self.x5u = Some(x5u.into());
        self
    }

    /// Returns `true` if this contains only public key parameters.
    pub fn is_public_key_only(&self) -> bool {
        self.params.is_public_key_only()
    }

    /// Returns `true` if this contains private key parameters.
    pub fn has_private_key(&self) -> bool {
        self.params.has_private_key()
    }

    /// Validates the JWK.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key parameters are invalid
    /// - The algorithm doesn't match the key type
    /// - Both `use` and `key_ops` are specified with inconsistent values
    ///   (RFC 7517 Section 4.3)
    pub fn validate(&self) -> Result<()> {
        // RFC 7517 Section 4.3: "The 'use' and 'key_ops' JWK members SHOULD NOT
        // be used together; however, if both are used, the information they convey
        // MUST be consistent."
        if let (Some(key_use), Some(key_ops)) = (&self.key_use, &self.key_ops)
            && !is_use_consistent_with_ops(key_use, key_ops) {
                return Err(Error::Validation(ValidationError::InconsistentParameters(
                    "RFC 7517: 'use' and 'key_ops' are both present but inconsistent".to_string(),
                )));
            }

        // RFC 7517 Section 4.3: key_ops values MUST be unique (no duplicates)
        if let Some(ref ops) = self.key_ops {
            let mut seen = HashSet::new();
            for op in ops {
                if !seen.insert(op) {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        format!(
                            "RFC 7517: key_ops array contains duplicate value '{:?}'",
                            op
                        ),
                    )));
                }
            }
        }

        // RFC 7517 Section 4.6: x5u MUST use TLS (HTTPS)
        if let Some(ref x5u) = self.x5u {
            let parsed = Url::parse(x5u).map_err(|_| {
                Error::Validation(ValidationError::InvalidParameter {
                    name: "x5u",
                    reason: "RFC 7517: x5u must be a valid absolute URL".to_string(),
                })
            })?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(Error::Validation(ValidationError::InvalidParameter {
                    name: "x5u",
                    reason: "RFC 7517: x5u URL must use HTTPS and include a host".to_string(),
                }));
            }
        }

        let mut first_cert_der: Option<Vec<u8>> = None;

        // RFC 7517 Section 4.7: x5c contains "a chain of one or more PKIX certificates"
        if let Some(ref certs) = self.x5c {
            if certs.is_empty() {
                return Err(Error::Validation(ValidationError::InvalidParameter {
                    name: "x5c",
                    reason: "RFC 7517: x5c must contain one or more certificates".to_string(),
                }));
            }

            // RFC 7517 Section 4.7: x5c values are base64 encoded (NOT base64url)
            for (i, cert) in certs.iter().enumerate() {
                // Standard base64 uses '+' and '/' which are NOT valid in base64url
                // base64url uses '-' and '_' instead
                // We validate it's proper base64 by checking for base64url-only chars
                // and attempting to decode
                if cert.contains('-') || cert.contains('_') {
                    return Err(Error::Validation(ValidationError::InvalidParameter {
                        name: "x5c",
                        reason: format!(
                            "RFC 7517: x5c[{}] appears to be base64url encoded; must be standard base64",
                            i
                        ),
                    }));
                }

                // Validate it's valid base64 by checking character set and padding
                if !is_valid_base64(cert) {
                    return Err(Error::Validation(ValidationError::InvalidParameter {
                        name: "x5c",
                        reason: format!("RFC 7517: x5c[{}] is not valid base64 encoding", i),
                    }));
                }

                // RFC 7517 Section 4.7: Each certificate value MUST be a DER-encoded X.509 certificate
                // Decode and validate basic DER certificate structure
                use base64ct::{Base64, Encoding};
                if let Ok(der_bytes) = Base64::decode_vec(cert) {
                    if i == 0 {
                        first_cert_der = Some(der_bytes.clone());
                    }

                    if parse_x509_certificate(&der_bytes).is_err() {
                        return Err(Error::Validation(ValidationError::InvalidParameter {
                            name: "x5c",
                            reason: format!(
                                "RFC 7517: x5c[{}] is not a valid DER-encoded X.509 certificate",
                                i
                            ),
                        }));
                    }
                } else {
                    return Err(Error::Validation(ValidationError::InvalidParameter {
                        name: "x5c",
                        reason: format!("RFC 7517: x5c[{}] failed base64 decoding", i),
                    }));
                }
            }

            // RFC 7517 Section 4.7: the key in the first certificate MUST match
            // the public key represented by other JWK members.
            if let Some(ref first_der) = first_cert_der {
                self.validate_x5c_public_key_match(first_der)?;
            }
        }

        // RFC 7517 Section 4.8: x5t is base64url-encoded SHA-1 thumbprint (20 bytes)
        if let Some(ref x5t) = self.x5t {
            validate_x509_thumbprint(x5t, "x5t", 20)?;
        }

        // RFC 7517 Section 4.9: x5t#S256 is base64url-encoded SHA-256 thumbprint (32 bytes)
        if let Some(ref x5t_s256) = self.x5t_s256 {
            validate_x509_thumbprint(x5t_s256, "x5t#S256", 32)?;
        }

        // RFC 7517 Section 4.8/4.9 with 4.7 consistency: if x5c and thumbprints
        // are both present, thumbprints must match the first certificate.
        if let Some(ref first_der) = first_cert_der {
            if let Some(ref x5t) = self.x5t {
                let mut hasher = Sha1::new();
                hasher.update(first_der);
                let expected = Base64UrlUnpadded::encode_string(&hasher.finalize());

                if x5t != &expected {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5t does not match SHA-1 thumbprint of x5c[0]".to_string(),
                    )));
                }
            }

            if let Some(ref x5t_s256) = self.x5t_s256 {
                let mut hasher = Sha256::new();
                hasher.update(first_der);
                let expected = Base64UrlUnpadded::encode_string(&hasher.finalize());

                if x5t_s256 != &expected {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5t#S256 does not match SHA-256 thumbprint of x5c[0]"
                            .to_string(),
                    )));
                }
            }
        }

        // Validate algorithm matches key type if specified
        if let Some(ref alg) = self.alg {
            self.validate_algorithm_key_type_match(alg)?;
            self.validate_algorithm_key_strength(alg)?;
        }

        // Validate key parameters
        self.params.validate()
    }

    /// Returns `true` if this key's type (and curve, where applicable) is
    /// compatible with the given algorithm per RFC 7518.
    ///
    /// This checks that the key type matches what the algorithm requires.
    /// For example, an RSA key is compatible with RS256 but not with ES256.
    /// For EC keys, the curve is also checked (e.g., P-256 for ES256).
    ///
    /// Unknown algorithms always return `false` since their requirements
    /// cannot be determined.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Key, Algorithm};
    ///
    /// let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
    /// let key: Key = serde_json::from_str(json).unwrap();
    ///
    /// assert!(key.is_algorithm_compatible(&Algorithm::Rs256));
    /// assert!(!key.is_algorithm_compatible(&Algorithm::Es256));
    /// ```
    pub fn is_algorithm_compatible(&self, alg: &Algorithm) -> bool {
        // Unknown algorithms cannot be validated against key types
        if alg.is_unknown() {
            return false;
        }

        match (&self.params, alg) {
            // RSA algorithms require RSA keys
            (KeyParams::Rsa(_), Algorithm::Rs256)
            | (KeyParams::Rsa(_), Algorithm::Rs384)
            | (KeyParams::Rsa(_), Algorithm::Rs512)
            | (KeyParams::Rsa(_), Algorithm::Ps256)
            | (KeyParams::Rsa(_), Algorithm::Ps384)
            | (KeyParams::Rsa(_), Algorithm::Ps512)
            | (KeyParams::Rsa(_), Algorithm::RsaOaep)
            | (KeyParams::Rsa(_), Algorithm::RsaOaep256)
            | (KeyParams::Rsa(_), Algorithm::RsaOaep384)
            | (KeyParams::Rsa(_), Algorithm::RsaOaep512)
            | (KeyParams::Rsa(_), Algorithm::Rsa1_5) => true,

            // HMAC algorithms require symmetric keys
            (KeyParams::Symmetric(_), Algorithm::Hs256)
            | (KeyParams::Symmetric(_), Algorithm::Hs384)
            | (KeyParams::Symmetric(_), Algorithm::Hs512) => true,

            // AES key wrap algorithms require symmetric keys
            (KeyParams::Symmetric(_), Algorithm::A128kw)
            | (KeyParams::Symmetric(_), Algorithm::A192kw)
            | (KeyParams::Symmetric(_), Algorithm::A256kw)
            | (KeyParams::Symmetric(_), Algorithm::A128gcmkw)
            | (KeyParams::Symmetric(_), Algorithm::A192gcmkw)
            | (KeyParams::Symmetric(_), Algorithm::A256gcmkw)
            | (KeyParams::Symmetric(_), Algorithm::Dir) => true,

            // AES content encryption algorithms require symmetric keys
            (KeyParams::Symmetric(_), Algorithm::A128cbcHs256)
            | (KeyParams::Symmetric(_), Algorithm::A192cbcHs384)
            | (KeyParams::Symmetric(_), Algorithm::A256cbcHs512)
            | (KeyParams::Symmetric(_), Algorithm::A128gcm)
            | (KeyParams::Symmetric(_), Algorithm::A192gcm)
            | (KeyParams::Symmetric(_), Algorithm::A256gcm) => true,

            // PBES2 algorithms require symmetric keys
            (KeyParams::Symmetric(_), Algorithm::Pbes2Hs256A128kw)
            | (KeyParams::Symmetric(_), Algorithm::Pbes2Hs384A192kw)
            | (KeyParams::Symmetric(_), Algorithm::Pbes2Hs512A256kw) => true,

            // EC algorithms require EC keys
            (KeyParams::Ec(ec), Algorithm::Es256) => ec.crv == EcCurve::P256,
            (KeyParams::Ec(ec), Algorithm::Es384) => ec.crv == EcCurve::P384,
            (KeyParams::Ec(ec), Algorithm::Es512) => ec.crv == EcCurve::P521,
            (KeyParams::Ec(ec), Algorithm::Es256k) => ec.crv == EcCurve::Secp256k1,

            // ECDH algorithms require EC keys
            (KeyParams::Ec(_), Algorithm::EcdhEs)
            | (KeyParams::Ec(_), Algorithm::EcdhEsA128kw)
            | (KeyParams::Ec(_), Algorithm::EcdhEsA192kw)
            | (KeyParams::Ec(_), Algorithm::EcdhEsA256kw) => true,

            // EdDSA (legacy identifier) requires OKP keys with Ed25519 or Ed448 curves
            (KeyParams::Okp(okp), Algorithm::EdDsa) => {
                okp.crv == OkpCurve::Ed25519 || okp.crv == OkpCurve::Ed448
            }

            // RFC 9864 fully specified JOSE identifiers
            (KeyParams::Okp(okp), Algorithm::Ed25519) => okp.crv == OkpCurve::Ed25519,
            (KeyParams::Okp(okp), Algorithm::Ed448) => okp.crv == OkpCurve::Ed448,

            // ECDH with OKP keys (X25519, X448)
            (KeyParams::Okp(okp), Algorithm::EcdhEs)
            | (KeyParams::Okp(okp), Algorithm::EcdhEsA128kw)
            | (KeyParams::Okp(okp), Algorithm::EcdhEsA192kw)
            | (KeyParams::Okp(okp), Algorithm::EcdhEsA256kw) => {
                okp.crv == OkpCurve::X25519 || okp.crv == OkpCurve::X448
            }

            // All other combinations are invalid
            _ => false,
        }
    }

    /// Validates that the algorithm matches the key type.
    fn validate_algorithm_key_type_match(&self, alg: &Algorithm) -> Result<()> {
        // Unknown algorithms cannot be validated against key types
        // Per RFC 7517, we accept them but cannot verify compatibility
        if alg.is_unknown() {
            return Ok(());
        }

        if !self.is_algorithm_compatible(alg) {
            return Err(Error::Validation(ValidationError::InconsistentParameters(
                format!(
                    "algorithm '{}' is not compatible with key type '{}'",
                    alg.as_str(),
                    self.kty().as_str()
                ),
            )));
        }

        Ok(())
    }

    /// Validates algorithm-specific key strength requirements.
    fn validate_algorithm_key_strength(&self, alg: &Algorithm) -> Result<()> {
        match (&self.params, alg) {
            (
                KeyParams::Rsa(rsa),
                Algorithm::Rs256
                | Algorithm::Rs384
                | Algorithm::Rs512
                | Algorithm::Ps256
                | Algorithm::Ps384
                | Algorithm::Ps512
                | Algorithm::Rsa1_5
                | Algorithm::RsaOaep
                | Algorithm::RsaOaep256
                | Algorithm::RsaOaep384
                | Algorithm::RsaOaep512,
            ) => rsa.validate_key_size(2048),
            (KeyParams::Symmetric(sym), Algorithm::Hs256) => sym.validate_min_size(256),
            (KeyParams::Symmetric(sym), Algorithm::Hs384) => sym.validate_min_size(384),
            (KeyParams::Symmetric(sym), Algorithm::Hs512) => sym.validate_min_size(512),
            (KeyParams::Symmetric(sym), Algorithm::A128kw)
            | (KeyParams::Symmetric(sym), Algorithm::A128gcmkw)
            | (KeyParams::Symmetric(sym), Algorithm::A128gcm) => {
                sym.validate_exact_size(128, "AES-128")
            }
            (KeyParams::Symmetric(sym), Algorithm::A192kw)
            | (KeyParams::Symmetric(sym), Algorithm::A192gcmkw)
            | (KeyParams::Symmetric(sym), Algorithm::A192gcm) => {
                sym.validate_exact_size(192, "AES-192")
            }
            (KeyParams::Symmetric(sym), Algorithm::A256kw)
            | (KeyParams::Symmetric(sym), Algorithm::A256gcmkw)
            | (KeyParams::Symmetric(sym), Algorithm::A256gcm) => {
                sym.validate_exact_size(256, "AES-256")
            }
            (KeyParams::Symmetric(sym), Algorithm::A128cbcHs256) => {
                // Per RFC 7518, this composite algorithm uses a 256-bit key
                // (128-bit MAC key + 128-bit ENC key).
                sym.validate_exact_size(256, "A128CBC-HS256")
            }
            (KeyParams::Symmetric(sym), Algorithm::A192cbcHs384) => {
                // Per RFC 7518, this composite algorithm uses a 384-bit key
                // (192-bit MAC key + 192-bit ENC key).
                sym.validate_exact_size(384, "A192CBC-HS384")
            }
            (KeyParams::Symmetric(sym), Algorithm::A256cbcHs512) => {
                // Per RFC 7518, this composite algorithm uses a 512-bit key
                // (256-bit MAC key + 256-bit ENC key).
                sym.validate_exact_size(512, "A256CBC-HS512")
            }
            _ => Ok(()),
        }
    }

    /// Validates that the first `x5c` certificate public key matches JWK key material.
    fn validate_x5c_public_key_match(&self, cert_der: &[u8]) -> Result<()> {
        let (_, cert) = parse_x509_certificate(cert_der).map_err(|_| {
            Error::Validation(ValidationError::InvalidParameter {
                name: "x5c",
                reason: "RFC 7517: x5c[0] is not a parseable X.509 certificate".to_string(),
            })
        })?;

        let spki = &cert.tbs_certificate.subject_pki;
        let cert_alg_oid = spki.algorithm.algorithm.to_id_string();
        let cert_key = spki.subject_public_key.data.as_ref();

        match &self.params {
            KeyParams::Rsa(rsa) => {
                if cert_alg_oid != "1.2.840.113549.1.1.1" {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK RSA key"
                            .to_string(),
                    )));
                }

                let expected_der = encode_rsa_public_key_der(rsa.n.as_bytes(), rsa.e.as_bytes());
                if cert_key != expected_der.as_slice() {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK RSA key parameters"
                            .to_string(),
                    )));
                }
            }
            KeyParams::Ec(ec) => {
                if cert_alg_oid != "1.2.840.10045.2.1" {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK EC key"
                            .to_string(),
                    )));
                }

                let expected_curve_oid = match ec.crv {
                    EcCurve::P256 => "1.2.840.10045.3.1.7",
                    EcCurve::P384 => "1.3.132.0.34",
                    EcCurve::P521 => "1.3.132.0.35",
                    EcCurve::Secp256k1 => "1.3.132.0.10",
                };

                let cert_curve_oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .map(|oid| oid.to_id_string());

                if cert_curve_oid.as_deref() != Some(expected_curve_oid) {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] EC curve does not match JWK crv".to_string(),
                    )));
                }

                let expected_point = ec.to_uncompressed_point();
                if cert_key != expected_point.as_slice() {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK EC key parameters"
                            .to_string(),
                    )));
                }
            }
            KeyParams::Okp(okp) => {
                let expected_oid = match okp.crv {
                    OkpCurve::Ed25519 => "1.3.101.112",
                    OkpCurve::Ed448 => "1.3.101.113",
                    OkpCurve::X25519 => "1.3.101.110",
                    OkpCurve::X448 => "1.3.101.111",
                };

                if cert_alg_oid != expected_oid {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK OKP key"
                            .to_string(),
                    )));
                }

                if cert_key != okp.x.as_bytes() {
                    return Err(Error::Validation(ValidationError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK OKP key parameters"
                            .to_string(),
                    )));
                }
            }
            KeyParams::Symmetric(_) => {
                return Err(Error::Validation(ValidationError::InconsistentParameters(
                    "RFC 7517: x5c is not valid for symmetric (oct) keys".to_string(),
                )));
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn validate_algorithm_strength_for_test(&self, alg: &Algorithm) -> Result<()> {
        self.validate_algorithm_key_strength(alg)
    }

    /// Calculates the JWK thumbprint (RFC 7638).
    ///
    /// The thumbprint is a base64url-encoded SHA-256 hash of the key's
    /// required members.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint::calculate_thumbprint(self)
    }

    /// Returns the key as RSA parameters, if applicable.
    pub fn as_rsa(&self) -> Option<&RsaParams> {
        match &self.params {
            KeyParams::Rsa(p) => Some(p),
            _ => None,
        }
    }

    /// Returns the key as EC parameters, if applicable.
    pub fn as_ec(&self) -> Option<&EcParams> {
        match &self.params {
            KeyParams::Ec(p) => Some(p),
            _ => None,
        }
    }

    /// Returns the key as symmetric parameters, if applicable.
    pub fn as_symmetric(&self) -> Option<&SymmetricParams> {
        match &self.params {
            KeyParams::Symmetric(p) => Some(p),
            _ => None,
        }
    }

    /// Returns the key as OKP parameters, if applicable.
    pub fn as_okp(&self) -> Option<&OkpParams> {
        match &self.params {
            KeyParams::Okp(p) => Some(p),
            _ => None,
        }
    }

    /// Extracts only the public key components, removing any private key material.
    ///
    /// For symmetric keys, this returns `None` since symmetric keys don't have
    /// a separate public component.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::KeySet;
    ///
    /// let json = r#"{"keys": [{
    ///     "kty": "RSA",
    ///     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///     "e": "AQAB",
    ///     "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
    /// }]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    /// let private_key = jwks.first().unwrap();
    ///
    /// // Extract public key
    /// let public_key = private_key.to_public().expect("RSA keys have public components");
    /// assert!(public_key.is_public_key_only());
    /// ```
    #[must_use]
    pub fn to_public(&self) -> Option<Key> {
        let public_params = match &self.params {
            KeyParams::Rsa(p) => KeyParams::Rsa(p.to_public()),
            KeyParams::Ec(p) => KeyParams::Ec(p.to_public()),
            KeyParams::Okp(p) => KeyParams::Okp(p.to_public()),
            KeyParams::Symmetric(_) => return None, // No public component for symmetric keys
        };

        Some(Key {
            kid: self.kid.clone(),
            key_use: self.key_use.clone(),
            key_ops: self.key_ops.clone(),
            alg: self.alg.clone(),
            params: public_params,
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
            x5u: self.x5u.clone(),
        })
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("kty", &self.kty())
            .field("kid", &self.kid)
            .field("key_use", &self.key_use)
            .field("alg", &self.alg)
            .field("params", &self.params)
            .finish()
    }
}

/// Equality is based on the key type, key ID, use, operations, algorithm,
/// and key material parameters. X.509 certificate fields (`x5c`, `x5t`,
/// `x5t#S256`, `x5u`) are **not** compared, because two representations
/// of the same cryptographic key may carry different certificate metadata.
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.kty() == other.kty()
            && self.kid == other.kid
            && self.key_use == other.key_use
            && self.key_ops == other.key_ops
            && self.alg == other.alg
            && self.params == other.params
    }
}

impl Eq for Key {}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Same fields as PartialEq: kty, kid, key_use, key_ops, alg, params
        // Excludes X.509 fields, consistent with the PartialEq contract.
        self.kty().hash(state);
        self.kid.hash(state);
        self.key_use.hash(state);
        self.key_ops.hash(state);
        self.alg.hash(state);
        self.params.hash(state);
    }
}

// Custom serialization for Key that flattens the params
impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        // Count the number of fields to serialize
        let mut field_count = 1; // kty is always present
        if self.kid.is_some() {
            field_count += 1;
        }
        if self.key_use.is_some() {
            field_count += 1;
        }
        if self.key_ops.is_some() {
            field_count += 1;
        }
        if self.alg.is_some() {
            field_count += 1;
        }
        if self.x5c.is_some() {
            field_count += 1;
        }
        if self.x5t.is_some() {
            field_count += 1;
        }
        if self.x5t_s256.is_some() {
            field_count += 1;
        }
        if self.x5u.is_some() {
            field_count += 1;
        }

        // Add params fields
        field_count += match &self.params {
            KeyParams::Rsa(p) => {
                2 + if p.d.is_some() { 1 } else { 0 }
                    + if p.p.is_some() { 1 } else { 0 }
                    + if p.q.is_some() { 1 } else { 0 }
                    + if p.dp.is_some() { 1 } else { 0 }
                    + if p.dq.is_some() { 1 } else { 0 }
                    + if p.qi.is_some() { 1 } else { 0 }
                    + if p.oth.is_some() { 1 } else { 0 }
            }
            KeyParams::Ec(p) => 3 + if p.d.is_some() { 1 } else { 0 },
            KeyParams::Symmetric(_) => 1,
            KeyParams::Okp(p) => 2 + if p.d.is_some() { 1 } else { 0 },
        };

        let mut map = serializer.serialize_map(Some(field_count))?;

        // Serialize kty first
        map.serialize_entry("kty", self.kty().as_str())?;

        // Serialize optional common fields
        if let Some(ref kid) = self.kid {
            map.serialize_entry("kid", kid)?;
        }
        if let Some(ref use_) = self.key_use {
            map.serialize_entry("use", use_)?;
        }
        if let Some(ref key_ops) = self.key_ops {
            map.serialize_entry("key_ops", key_ops)?;
        }
        if let Some(ref alg) = self.alg {
            map.serialize_entry("alg", alg)?;
        }

        // Serialize key-specific parameters
        match &self.params {
            KeyParams::Rsa(p) => {
                map.serialize_entry("n", &p.n)?;
                map.serialize_entry("e", &p.e)?;
                if let Some(ref d) = p.d {
                    map.serialize_entry("d", d)?;
                }
                if let Some(ref p_val) = p.p {
                    map.serialize_entry("p", p_val)?;
                }
                if let Some(ref q) = p.q {
                    map.serialize_entry("q", q)?;
                }
                if let Some(ref dp) = p.dp {
                    map.serialize_entry("dp", dp)?;
                }
                if let Some(ref dq) = p.dq {
                    map.serialize_entry("dq", dq)?;
                }
                if let Some(ref qi) = p.qi {
                    map.serialize_entry("qi", qi)?;
                }
                if let Some(ref oth) = p.oth {
                    map.serialize_entry("oth", oth)?;
                }
            }
            KeyParams::Ec(p) => {
                map.serialize_entry("crv", &p.crv)?;
                map.serialize_entry("x", &p.x)?;
                map.serialize_entry("y", &p.y)?;
                if let Some(ref d) = p.d {
                    map.serialize_entry("d", d)?;
                }
            }
            KeyParams::Symmetric(p) => {
                map.serialize_entry("k", &p.k)?;
            }
            KeyParams::Okp(p) => {
                map.serialize_entry("crv", &p.crv)?;
                map.serialize_entry("x", &p.x)?;
                if let Some(ref d) = p.d {
                    map.serialize_entry("d", d)?;
                }
            }
        }

        // Serialize X.509 fields
        if let Some(ref x5c) = self.x5c {
            map.serialize_entry("x5c", x5c)?;
        }
        if let Some(ref x5t) = self.x5t {
            map.serialize_entry("x5t", x5t)?;
        }
        if let Some(ref x5t_s256) = self.x5t_s256 {
            map.serialize_entry("x5t#S256", x5t_s256)?;
        }
        if let Some(ref x5u) = self.x5u {
            map.serialize_entry("x5u", x5u)?;
        }

        map.end()
    }
}

// Custom deserialization for Key that handles flattened params
impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawJwk {
            kty: String,
            kid: Option<String>,
            #[serde(rename = "use")]
            key_use: Option<KeyUse>,
            key_ops: Option<Vec<KeyOperation>>,
            alg: Option<Algorithm>,

            // RSA parameters
            n: Option<Base64UrlBytes>,
            e: Option<Base64UrlBytes>,

            // EC and OKP parameters
            crv: Option<String>,
            x: Option<Base64UrlBytes>,
            y: Option<Base64UrlBytes>,

            // Private key parameter (RSA, EC, OKP)
            d: Option<Base64UrlBytes>,

            // RSA CRT parameters
            p: Option<Base64UrlBytes>,
            q: Option<Base64UrlBytes>,
            dp: Option<Base64UrlBytes>,
            dq: Option<Base64UrlBytes>,
            qi: Option<Base64UrlBytes>,

            // RSA multi-prime parameter
            oth: Option<Vec<rsa::RsaOtherPrime>>,

            // Symmetric key
            k: Option<Base64UrlBytes>,

            // X.509 fields
            x5c: Option<Vec<String>>,
            x5t: Option<String>,
            #[serde(rename = "x5t#S256")]
            x5t_s256: Option<String>,
            x5u: Option<String>,
        }

        let raw = RawJwk::deserialize(deserializer)?;

        let kty: KeyType = raw.kty.parse().map_err(serde::de::Error::custom)?;

        let params = match kty {
            KeyType::Rsa => {
                let n = raw.n.ok_or_else(|| serde::de::Error::missing_field("n"))?;
                let e = raw.e.ok_or_else(|| serde::de::Error::missing_field("e"))?;

                KeyParams::Rsa(RsaParams {
                    n,
                    e,
                    d: raw.d,
                    p: raw.p,
                    q: raw.q,
                    dp: raw.dp,
                    dq: raw.dq,
                    qi: raw.qi,
                    oth: raw.oth,
                })
            }
            KeyType::Ec => {
                let crv_str = raw
                    .crv
                    .ok_or_else(|| serde::de::Error::missing_field("crv"))?;
                let crv: EcCurve = crv_str.parse().map_err(serde::de::Error::custom)?;
                let x = raw.x.ok_or_else(|| serde::de::Error::missing_field("x"))?;
                let y = raw.y.ok_or_else(|| serde::de::Error::missing_field("y"))?;

                KeyParams::Ec(EcParams {
                    crv,
                    x,
                    y,
                    d: raw.d,
                })
            }
            KeyType::Symmetric => {
                let k = raw.k.ok_or_else(|| serde::de::Error::missing_field("k"))?;

                KeyParams::Symmetric(SymmetricParams { k })
            }
            KeyType::Okp => {
                let crv_str = raw
                    .crv
                    .ok_or_else(|| serde::de::Error::missing_field("crv"))?;
                let crv: OkpCurve = crv_str.parse().map_err(serde::de::Error::custom)?;
                let x = raw.x.ok_or_else(|| serde::de::Error::missing_field("x"))?;

                KeyParams::Okp(OkpParams { crv, x, d: raw.d })
            }
        };

        Ok(Key {
            kid: raw.kid,
            key_use: raw.key_use,
            key_ops: raw.key_ops,
            alg: raw.alg,
            params,
            x5c: raw.x5c,
            x5t: raw.x5t,
            x5t_s256: raw.x5t_s256,
            x5u: raw.x5u,
        })
    }
}

/// Checks whether a `use` value is consistent with a set of `key_ops` values.
///
/// Per RFC 7517 Section 4.3, if both `use` and `key_ops` are present, the information
/// they convey MUST be consistent. The natural mapping is:
/// - `sig` is consistent with `sign` and `verify`
/// - `enc` is consistent with `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`,
///   `deriveKey`, and `deriveBits`
///
/// For unknown `use` values, consistency cannot be determined, so we accept them.
fn is_use_consistent_with_ops(key_use: &KeyUse, key_ops: &[KeyOperation]) -> bool {
    // Empty key_ops is trivially consistent (no operations claimed).
    if key_ops.is_empty() {
        return true;
    }

    match key_use {
        KeyUse::Signature => key_ops.iter().all(|op| {
            matches!(
                op,
                KeyOperation::Sign | KeyOperation::Verify | KeyOperation::Unknown(_)
            )
        }),
        KeyUse::Encryption => key_ops.iter().all(|op| {
            matches!(
                op,
                KeyOperation::Encrypt
                    | KeyOperation::Decrypt
                    | KeyOperation::WrapKey
                    | KeyOperation::UnwrapKey
                    | KeyOperation::DeriveKey
                    | KeyOperation::DeriveBits
                    | KeyOperation::Unknown(_)
            )
        }),
        // Unknown use values: we can't determine consistency, so accept.
        KeyUse::Unknown(_) => true,
    }
}

/// Encodes a byte slice as a DER INTEGER.
fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0x02, 0x01, 0x00];
    }

    let bytes = {
        let mut start = 0;
        while start < bytes.len() - 1 && bytes[start] == 0 {
            start += 1;
        }
        &bytes[start..]
    };

    let needs_padding = (bytes[0] & 0x80) != 0;
    let len = bytes.len() + if needs_padding { 1 } else { 0 };

    let mut der = Vec::with_capacity(2 + len + 2);
    der.push(0x02);
    encode_der_length(&mut der, len);
    if needs_padding {
        der.push(0);
    }
    der.extend_from_slice(bytes);
    der
}

/// Encodes a DER length value.
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

/// Encodes PKCS#1 RSAPublicKey DER (`SEQUENCE { n INTEGER, e INTEGER }`).
fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let n_der = encode_der_integer(n);
    let e_der = encode_der_integer(e);

    let content_len = n_der.len() + e_der.len();
    let mut der = Vec::with_capacity(4 + content_len);
    der.push(0x30);
    encode_der_length(&mut der, content_len);
    der.extend_from_slice(&n_der);
    der.extend_from_slice(&e_der);
    der
}

/// Validates that a string is valid standard base64 encoding.
/// This checks the character set (A-Z, a-z, 0-9, +, /) and padding (=).
fn is_valid_base64(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let bytes = s.as_bytes();
    let mut padding_started = false;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                if padding_started {
                    return false; // No data after padding
                }
            }
            b'=' => {
                padding_started = true;
                // Padding can only be at the end, max 2 characters
                let remaining = bytes.len() - i;
                if remaining > 2 {
                    return false;
                }
            }
            _ => return false, // Invalid character
        }
    }

    // Valid base64 length is multiple of 4 when padded
    // Or when unpadded, (len % 4) should be 0, 2, or 3
    let len = s.len();
    if padding_started {
        len.is_multiple_of(4)
    } else {
        // Unpadded base64 can have len % 4 of 0, 2, or 3 (not 1)
        len % 4 != 1
    }
}

/// Validates an X.509 certificate thumbprint (x5t or x5t#S256).
///
/// RFC 7517 Section 4.8 and 4.9: These are base64url-encoded certificate digests.
/// - x5t: SHA-1 digest (20 bytes)
/// - x5t#S256: SHA-256 digest (32 bytes)
fn validate_x509_thumbprint(
    thumbprint: &str,
    param_name: &'static str,
    expected_bytes: usize,
) -> Result<()> {
    use base64ct::{Base64UrlUnpadded, Encoding};

    // Validate it's valid base64url
    if !is_valid_base64url(thumbprint) {
        return Err(Error::Validation(ValidationError::InvalidParameter {
            name: param_name,
            reason: format!(
                "RFC 7517: {} must be base64url-encoded (invalid characters found)",
                param_name
            ),
        }));
    }

    // Try to decode and check the length
    match Base64UrlUnpadded::decode_vec(thumbprint) {
        Ok(decoded) => {
            if decoded.len() != expected_bytes {
                return Err(Error::Validation(ValidationError::InvalidParameter {
                    name: param_name,
                    reason: format!(
                        "RFC 7517: {} must be {} bytes when decoded (got {} bytes)",
                        param_name,
                        expected_bytes,
                        decoded.len()
                    ),
                }));
            }
            Ok(())
        }
        Err(_) => Err(Error::Validation(ValidationError::InvalidParameter {
            name: param_name,
            reason: format!("RFC 7517: {} failed base64url decoding", param_name),
        })),
    }
}

/// Validates that a string is valid base64url encoding.
/// This checks the character set (A-Z, a-z, 0-9, -, _) without padding.
fn is_valid_base64url(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {}
            _ => return false,
        }
    }

    // Valid base64url without padding has len % 4 of 0, 2, or 3 (not 1)
    s.len() % 4 != 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rsa_public_key() {
        let json = r#"{
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Rsa);
        assert_eq!(jwk.kid, Some("test-key".to_string()));
        assert_eq!(jwk.key_use, Some(KeyUse::Signature));
        assert_eq!(jwk.alg, Some(Algorithm::Rs256));
        assert!(jwk.is_public_key_only());
    }

    #[test]
    fn test_parse_ec_public_key() {
        let json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Ec);

        let ec = jwk.as_ec().unwrap();
        assert_eq!(ec.crv, EcCurve::P256);
        assert!(jwk.is_public_key_only());
    }

    #[test]
    fn test_parse_symmetric_key() {
        let json = r#"{
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Symmetric);
        assert!(jwk.as_symmetric().is_some());
    }

    #[test]
    fn test_parse_okp_key() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Okp);

        let okp = jwk.as_okp().unwrap();
        assert_eq!(okp.crv, OkpCurve::Ed25519);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let json = r#"{"kty":"RSA","kid":"test","use":"sig","n":"AQAB","e":"AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        let deserialized: Key = serde_json::from_str(&serialized).unwrap();
        assert_eq!(jwk, deserialized);
    }

    #[test]
    fn test_is_algorithm_compatible_rsa() {
        let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        // RSA key should be compatible with RSA algorithms
        assert!(key.is_algorithm_compatible(&Algorithm::Rs256));
        assert!(key.is_algorithm_compatible(&Algorithm::Rs384));
        assert!(key.is_algorithm_compatible(&Algorithm::Rs512));
        assert!(key.is_algorithm_compatible(&Algorithm::Ps256));
        assert!(key.is_algorithm_compatible(&Algorithm::Ps384));
        assert!(key.is_algorithm_compatible(&Algorithm::Ps512));
        assert!(key.is_algorithm_compatible(&Algorithm::RsaOaep));
        assert!(key.is_algorithm_compatible(&Algorithm::RsaOaep256));

        // RSA key should NOT be compatible with other algorithms
        assert!(!key.is_algorithm_compatible(&Algorithm::Es256));
        assert!(!key.is_algorithm_compatible(&Algorithm::Hs256));
        assert!(!key.is_algorithm_compatible(&Algorithm::EdDsa));
        assert!(!key.is_algorithm_compatible(&Algorithm::Ed25519));
        assert!(!key.is_algorithm_compatible(&Algorithm::Ed448));
    }

    #[test]
    fn test_is_algorithm_compatible_ec() {
        let p256_json = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let p256: Key = serde_json::from_str(p256_json).unwrap();

        assert!(p256.is_algorithm_compatible(&Algorithm::Es256));
        assert!(!p256.is_algorithm_compatible(&Algorithm::Es384));
        assert!(!p256.is_algorithm_compatible(&Algorithm::Rs256));
        assert!(!p256.is_algorithm_compatible(&Algorithm::Hs256));
    }

    #[test]
    fn test_is_algorithm_compatible_symmetric() {
        let json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        assert!(key.is_algorithm_compatible(&Algorithm::Hs256));
        assert!(key.is_algorithm_compatible(&Algorithm::Hs384));
        assert!(key.is_algorithm_compatible(&Algorithm::Hs512));
        assert!(key.is_algorithm_compatible(&Algorithm::A128kw));

        assert!(!key.is_algorithm_compatible(&Algorithm::Rs256));
        assert!(!key.is_algorithm_compatible(&Algorithm::Es256));
    }

    #[test]
    fn test_is_algorithm_compatible_okp() {
        let json =
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        assert!(key.is_algorithm_compatible(&Algorithm::EdDsa));
        assert!(key.is_algorithm_compatible(&Algorithm::Ed25519));
        assert!(!key.is_algorithm_compatible(&Algorithm::Ed448));
        assert!(!key.is_algorithm_compatible(&Algorithm::Rs256));
        assert!(!key.is_algorithm_compatible(&Algorithm::Es256));
    }

    #[test]
    fn test_is_algorithm_compatible_okp_ed448() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed448",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }"#;
        let key: Key = serde_json::from_str(json).unwrap();

        assert!(key.is_algorithm_compatible(&Algorithm::EdDsa));
        assert!(!key.is_algorithm_compatible(&Algorithm::Ed25519));
        assert!(key.is_algorithm_compatible(&Algorithm::Ed448));
    }

    #[test]
    fn test_parse_rfc9864_ed_algorithms() {
        assert_eq!("Ed25519".parse::<Algorithm>().unwrap(), Algorithm::Ed25519);
        assert_eq!("Ed448".parse::<Algorithm>().unwrap(), Algorithm::Ed448);
        assert_eq!(Algorithm::Ed25519.as_str(), "Ed25519");
        assert_eq!(Algorithm::Ed448.as_str(), "Ed448");
    }

    #[test]
    fn test_algorithm_deprecation_status() {
        assert!(Algorithm::EdDsa.is_deprecated());
        assert!(!Algorithm::Ed25519.is_deprecated());
        assert!(!Algorithm::Ed448.is_deprecated());
        assert!(!Algorithm::Rs256.is_deprecated());
    }

    #[test]
    fn test_is_algorithm_compatible_unknown_algorithm() {
        let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        assert!(!key.is_algorithm_compatible(&Algorithm::Unknown("CUSTOM".to_string())));
    }

    #[test]
    fn test_to_public_rsa() {
        let json = r#"{
            "kty": "RSA",
            "kid": "rsa-key",
            "use": "sig",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"
        }"#;
        let private_key: Key = serde_json::from_str(json).unwrap();
        assert!(private_key.has_private_key());

        let public_key = private_key.to_public().unwrap();
        assert!(public_key.is_public_key_only());
        assert_eq!(public_key.kty(), KeyType::Rsa);
        assert_eq!(public_key.kid, Some("rsa-key".to_string()));
        assert_eq!(public_key.key_use, Some(KeyUse::Signature));
        assert_eq!(public_key.alg, Some(Algorithm::Rs256));

        let rsa = public_key.as_rsa().unwrap();
        assert!(rsa.d.is_none());
        // Modulus should be preserved
        assert_eq!(rsa.n, private_key.as_rsa().unwrap().n);
    }

    #[test]
    fn test_to_public_ec() {
        let json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        }"#;
        let private_key: Key = serde_json::from_str(json).unwrap();
        assert!(private_key.has_private_key());

        let public_key = private_key.to_public().unwrap();
        assert!(public_key.is_public_key_only());
        assert_eq!(public_key.kty(), KeyType::Ec);

        let ec = public_key.as_ec().unwrap();
        assert!(ec.d.is_none());
        assert_eq!(ec.crv, EcCurve::P256);
    }

    #[test]
    fn test_to_public_okp() {
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        }"#;
        let private_key: Key = serde_json::from_str(json).unwrap();
        assert!(private_key.has_private_key());

        let public_key = private_key.to_public().unwrap();
        assert!(public_key.is_public_key_only());
        assert_eq!(public_key.kty(), KeyType::Okp);

        let okp = public_key.as_okp().unwrap();
        assert!(okp.d.is_none());
        assert_eq!(okp.crv, OkpCurve::Ed25519);
    }

    #[test]
    fn test_to_public_symmetric_returns_none() {
        let json = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
        let key: Key = serde_json::from_str(json).unwrap();
        assert!(key.to_public().is_none());
    }

    #[test]
    fn test_to_public_already_public() {
        let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();
        assert!(key.is_public_key_only());

        let public = key.to_public().unwrap();
        assert!(public.is_public_key_only());
        assert_eq!(key, public);
    }

    #[test]
    fn test_validate_algorithm_strength_enforces_cbc_hs_sizes() {
        let k256 = Base64UrlBytes::new(vec![0u8; 32]);
        let k384 = Base64UrlBytes::new(vec![0u8; 48]);
        let k512 = Base64UrlBytes::new(vec![0u8; 64]);

        let key_256 = Key::new(KeyParams::Symmetric(SymmetricParams::new(k256)));
        assert!(
            key_256
                .validate_algorithm_strength_for_test(&Algorithm::A128cbcHs256)
                .is_ok()
        );
        assert!(
            key_256
                .validate_algorithm_strength_for_test(&Algorithm::A192cbcHs384)
                .is_err()
        );

        let key_384 = Key::new(KeyParams::Symmetric(SymmetricParams::new(k384)));
        assert!(
            key_384
                .validate_algorithm_strength_for_test(&Algorithm::A192cbcHs384)
                .is_ok()
        );
        assert!(
            key_384
                .validate_algorithm_strength_for_test(&Algorithm::A256cbcHs512)
                .is_err()
        );

        let key_512 = Key::new(KeyParams::Symmetric(SymmetricParams::new(k512)));
        assert!(
            key_512
                .validate_algorithm_strength_for_test(&Algorithm::A256cbcHs512)
                .is_ok()
        );
    }
}

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
//! use jwk_simple::Key;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let json = r#"{
//!     "kty": "RSA",
//!     "kid": "my-key-id",
//!     "use": "sig",
//!     "alg": "RS256",
//!     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
//!     "e": "AQAB"
//! }"#;
//!
//! let jwk: Key = serde_json::from_str(json)?;
//! assert_eq!(jwk.kid(), Some("my-key-id"));
//! # Ok(())
//! # }
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
use std::convert::Infallible;
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
use crate::error::{Error, IncompatibleKeyError, InvalidKeyError, ParseError, Result};

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
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
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

impl From<&str> for KeyUse {
    /// Parses a key use string.
    ///
    /// Per RFC 7517, unknown key use values are accepted and stored as `Unknown`.
    fn from(s: &str) -> Self {
        match s {
            "sig" => KeyUse::Signature,
            "enc" => KeyUse::Encryption,
            _ => KeyUse::Unknown(s.to_string()),
        }
    }
}

impl FromStr for KeyUse {
    type Err = Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::from(s))
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
        Ok(KeyUse::from(String::deserialize(deserializer)?.as_str()))
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

    /// Returns `true` if this is an unknown/unrecognized key operation.
    pub fn is_unknown(&self) -> bool {
        matches!(self, KeyOperation::Unknown(_))
    }
}

impl Display for KeyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for KeyOperation {
    /// Parses a key operation string.
    ///
    /// Per RFC 7517, unknown key operation values are accepted and stored as `Unknown`.
    fn from(s: &str) -> Self {
        match s {
            "sign" => KeyOperation::Sign,
            "verify" => KeyOperation::Verify,
            "encrypt" => KeyOperation::Encrypt,
            "decrypt" => KeyOperation::Decrypt,
            "wrapKey" => KeyOperation::WrapKey,
            "unwrapKey" => KeyOperation::UnwrapKey,
            "deriveKey" => KeyOperation::DeriveKey,
            "deriveBits" => KeyOperation::DeriveBits,
            _ => KeyOperation::Unknown(s.to_string()),
        }
    }
}

impl FromStr for KeyOperation {
    type Err = Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::from(s))
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
        Ok(KeyOperation::from(
            String::deserialize(deserializer)?.as_str(),
        ))
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

impl From<&str> for Algorithm {
    /// Parses an algorithm string.
    ///
    /// Per RFC 7517, unknown algorithm values are accepted and stored as `Unknown`.
    fn from(s: &str) -> Self {
        match s {
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
        }
    }
}

impl FromStr for Algorithm {
    type Err = Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::from(s))
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
        Ok(Algorithm::from(String::deserialize(deserializer)?.as_str()))
    }
}

/// Key-type-specific parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
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

/// A JSON Web Key (RFC 7517).
///
/// Represents a single cryptographic key with its parameters and metadata.
///
/// # Examples
///
/// ```
/// use jwk_simple::{Key, KeyType};
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
    kid: Option<String>,

    /// The intended use of the key.
    #[zeroize(skip)]
    key_use: Option<KeyUse>,

    /// The permitted operations for the key.
    #[zeroize(skip)]
    key_ops: Option<Vec<KeyOperation>>,

    /// The algorithm intended for use with the key.
    #[zeroize(skip)]
    alg: Option<Algorithm>,

    /// The key-type-specific parameters.
    params: KeyParams,

    /// X.509 certificate chain (base64-encoded DER).
    #[zeroize(skip)]
    x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint (base64url-encoded).
    #[zeroize(skip)]
    x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint (base64url-encoded).
    #[zeroize(skip)]
    #[allow(non_snake_case)]
    x5t_s256: Option<String>,

    /// X.509 URL.
    #[zeroize(skip)]
    x5u: Option<String>,
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
    /// use jwk_simple::{Key, KeyType, KeyParams, RsaParams, KeyUse, Algorithm};
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
    /// assert_eq!(key.kid(), Some("my-key-id"));
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

    /// Returns the key ID (`kid`), if present.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Returns the intended key use (`use`), if present.
    #[must_use]
    pub fn key_use(&self) -> Option<&KeyUse> {
        self.key_use.as_ref()
    }

    /// Returns the permitted operations (`key_ops`), if present.
    #[must_use]
    pub fn key_ops(&self) -> Option<&[KeyOperation]> {
        self.key_ops.as_deref()
    }

    /// Returns the declared algorithm (`alg`), if present.
    #[must_use]
    pub fn alg(&self) -> Option<&Algorithm> {
        self.alg.as_ref()
    }

    /// Returns the key-type-specific parameters.
    #[must_use]
    pub fn params(&self) -> &KeyParams {
        &self.params
    }

    /// Returns the X.509 certificate chain (`x5c`), if present.
    #[must_use]
    pub fn x5c(&self) -> Option<&[String]> {
        self.x5c.as_deref()
    }

    /// Returns the X.509 SHA-1 certificate thumbprint (`x5t`), if present.
    #[must_use]
    pub fn x5t(&self) -> Option<&str> {
        self.x5t.as_deref()
    }

    /// Returns the X.509 SHA-256 certificate thumbprint (`x5t#S256`), if present.
    #[must_use]
    #[allow(non_snake_case)]
    pub fn x5t_s256(&self) -> Option<&str> {
        self.x5t_s256.as_deref()
    }

    /// Returns the X.509 URL (`x5u`), if present.
    #[must_use]
    pub fn x5u(&self) -> Option<&str> {
        self.x5u.as_deref()
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
    pub fn with_key_ops(mut self, key_ops: impl IntoIterator<Item = KeyOperation>) -> Self {
        self.key_ops = Some(key_ops.into_iter().collect());
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

    /// Validates the JWK structure and metadata consistency.
    ///
    /// This is a context-free structural check: it verifies the key material
    /// is well-formed, metadata fields are internally consistent, and X.509
    /// fields are properly encoded and match the key material.
    ///
    /// This method does **not** check algorithm suitability, key strength for
    /// a specific algorithm, or operation intent, even if the `alg` field is
    /// set on the key. A key with `"alg": "RS256"` on a symmetric key type
    /// passes `validate()` because the key material itself is structurally
    /// valid; the algorithm mismatch is a suitability concern.
    /// Use [`Key::validate_for_use`] for those checks.
    ///
    /// In other words, `validate()` is the context-free gate: it validates the
    /// key's own parameters and metadata (`use`, `key_ops`, `x5u`, `x5c`,
    /// `x5t`, `x5t#S256`) without deciding whether the key is acceptable for a
    /// particular algorithm or operation.
    ///
    /// This method does **not** perform PKIX trust/path validation for `x5c`
    /// chains (trust anchors, validity period, key usage/EKU, revocation, etc.).
    /// PKIX trust validation is application-defined and out of scope for this crate.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<()> {
        // Structural key-material validation (key-type-specific).
        self.params.validate()?;

        // RFC 7517 Section 4.3 metadata constraints.
        self.validate_use_key_ops_consistency()?;
        self.validate_key_ops_unique()?;

        self.validate_certificate_metadata()?;

        Ok(())
    }

    pub(crate) fn validate_certificate_metadata(&self) -> Result<()> {
        // RFC 7517 Section 4.6: x5u MUST use TLS (HTTPS)
        if let Some(ref x5u) = self.x5u {
            let parsed = Url::parse(x5u).map_err(|_| {
                Error::from(InvalidKeyError::InvalidParameter {
                    name: "x5u",
                    reason: "RFC 7517: x5u must be a valid absolute URL".to_string(),
                })
            })?;

            if parsed.scheme() != "https" || parsed.host_str().is_none() {
                return Err(InvalidKeyError::InvalidParameter {
                    name: "x5u",
                    reason: "RFC 7517: x5u URL must use HTTPS and include a host".to_string(),
                }
                .into());
            }
        }

        let first_x5c_der = self.decode_and_validate_x5c_first_der()?;

        // RFC 7517 Section 4.7: the key in the first certificate MUST match
        // the public key represented by other JWK members.
        if let Some(first_der) = first_x5c_der.as_ref() {
            self.validate_x5c_public_key_match(first_der)?;
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
        if let Some(first_der) = first_x5c_der.as_ref() {
            if let Some(ref x5t) = self.x5t {
                let mut hasher = Sha1::new();
                hasher.update(first_der);
                let expected = Base64UrlUnpadded::encode_string(&hasher.finalize());

                if x5t != &expected {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5t does not match SHA-1 thumbprint of x5c[0]".to_string(),
                    )
                    .into());
                }
            }

            if let Some(ref x5t_s256) = self.x5t_s256 {
                let mut hasher = Sha256::new();
                hasher.update(first_der);
                let expected = Base64UrlUnpadded::encode_string(&hasher.finalize());

                if x5t_s256 != &expected {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5t#S256 does not match SHA-256 thumbprint of x5c[0]"
                            .to_string(),
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    fn validate_use_key_ops_consistency(&self) -> Result<()> {
        if let (Some(key_use), Some(key_ops)) = (&self.key_use, &self.key_ops)
            && !is_use_consistent_with_ops(key_use, key_ops)
        {
            return Err(InvalidKeyError::InconsistentParameters(
                "RFC 7517: 'use' and 'key_ops' are both present but inconsistent".to_string(),
            )
            .into());
        }

        Ok(())
    }

    fn validate_key_ops_unique(&self) -> Result<()> {
        if let Some(ref ops) = self.key_ops {
            let mut seen = HashSet::new();
            for op in ops {
                if !seen.insert(op) {
                    return Err(InvalidKeyError::InconsistentParameters(format!(
                        "RFC 7517: key_ops array contains duplicate value '{}'",
                        op.as_str()
                    ))
                    .into());
                }
            }
        }

        Ok(())
    }

    fn decode_and_validate_x5c_first_der(&self) -> Result<Option<Vec<u8>>> {
        // RFC 7517 Section 4.7: x5c contains "a chain of one or more PKIX certificates"
        let Some(ref certs) = self.x5c else {
            return Ok(None);
        };

        if certs.is_empty() {
            return Err(InvalidKeyError::InvalidParameter {
                name: "x5c",
                reason: "RFC 7517: x5c must contain one or more certificates".to_string(),
            }
            .into());
        }

        let mut first_der = None;

        // RFC 7517 Section 4.7: x5c values are base64 encoded (NOT base64url)
        for (i, cert) in certs.iter().enumerate() {
            // Standard base64 uses '+' and '/' which are NOT valid in base64url
            // base64url uses '-' and '_' instead
            // We validate it's proper base64 by checking for base64url-only chars
            // and attempting to decode
            if cert.contains('-') || cert.contains('_') {
                return Err(InvalidKeyError::InvalidParameter {
                    name: "x5c",
                    reason: format!(
                        "RFC 7517: x5c[{}] appears to be base64url encoded; must be standard base64",
                        i
                    ),
                }
                .into());
            }

            // Validate it's valid base64 by checking character set and padding
            if !is_valid_base64(cert) {
                return Err(InvalidKeyError::InvalidParameter {
                    name: "x5c",
                    reason: format!("RFC 7517: x5c[{}] is not valid base64 encoding", i),
                }
                .into());
            }

            // RFC 7517 Section 4.7: Each certificate value MUST be a DER-encoded X.509 certificate
            // Decode and validate basic DER certificate structure
            use base64ct::{Base64, Encoding};
            let der_bytes = Base64::decode_vec(cert).map_err(|_| {
                Error::from(InvalidKeyError::InvalidParameter {
                    name: "x5c",
                    reason: format!("RFC 7517: x5c[{}] failed base64 decoding", i),
                })
            })?;

            let (remaining, _) = parse_x509_certificate(&der_bytes).map_err(|_| {
                InvalidKeyError::InvalidParameter {
                    name: "x5c",
                    reason: format!(
                        "RFC 7517: x5c[{}] is not a valid DER-encoded X.509 certificate",
                        i
                    ),
                }
            })?;

            if !remaining.is_empty() {
                return Err(InvalidKeyError::InvalidParameter {
                    name: "x5c",
                    reason: format!(
                        "RFC 7517: x5c[{}] contains trailing data after DER certificate",
                        i
                    ),
                }
                .into());
            }

            if i == 0 {
                first_der = Some(der_bytes);
            }
        }

        Ok(first_der)
    }

    /// Validates this key for a specific algorithm and operation(s).
    ///
    /// This is the full pre-use gate: it performs structural validation
    /// ([`Key::validate`]) followed by algorithm suitability checks
    /// (type compatibility, key strength), algorithm-operation compatibility
    /// checks (requested operation is valid for the algorithm), operation
    /// capability checks (key material can actually perform the operation),
    /// and operation-intent enforcement (metadata permits the requested
    /// operations).
    ///
    /// The `alg` parameter controls which algorithm constraints are applied
    /// (key type, minimum strength). If the key declares its own `alg`, it must
    /// match the requested algorithm. Unknown algorithms are rejected because
    /// suitability (type compatibility and strength) cannot be validated for
    /// them.
    ///
    /// At least one operation must be provided. Passing an empty iterator
    /// returns an error (this is a caller precondition, not a key problem).
    ///
    /// This method calls [`Key::validate`] internally, so callers do not
    /// need to call it separately.
    ///
    /// This is the full pre-use gate for direct key use. It layers algorithm
    /// suitability, operation/algorithm compatibility, key-material capability,
    /// and operation intent on top of [`Key::validate`].
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Key, Algorithm, KeyOperation};
    ///
    /// let json = r#"{"kty":"oct","k":"c2VjcmV0LWtleS1tYXRlcmlhbC10aGF0LWlzLWxvbmctZW5vdWdo"}"#;
    /// let key: Key = serde_json::from_str(json).unwrap();
    ///
    /// // Validate for HMAC signing
    /// assert!(key.validate_for_use(&Algorithm::Hs256, [KeyOperation::Sign]).is_ok());
    /// ```
    #[must_use = "validation result must be checked"]
    pub fn validate_for_use(
        &self,
        alg: &Algorithm,
        ops: impl IntoIterator<Item = KeyOperation>,
    ) -> Result<()> {
        let ops: Vec<KeyOperation> = ops.into_iter().collect();
        if ops.is_empty() {
            return Err(Error::InvalidInput(
                "at least one requested operation is required",
            ));
        }

        // Structural validation first (belt-and-suspenders).
        self.validate()?;

        self.validate_declared_algorithm_match(alg)?;

        // Algorithm suitability: type match + strength.
        // `validate()` above already ran `params.validate()`, so we call the
        // algorithm-specific checks directly to avoid redundant structural work.
        self.validate_algorithm_key_type_match(alg)?;
        self.validate_algorithm_key_strength(alg)?;
        self.validate_operation_algorithm_compatibility_for_all(alg, &ops)?;

        // Operation capability: key material can perform requested operations.
        self.validate_operation_capability_for_all(&ops)?;

        // Operation intent: use/key_ops metadata permits the requested operations.
        // `validate()` above already enforced `use`/`key_ops` consistency and
        // uniqueness, so we call the intent-only helper directly.
        self.validate_operation_intent_for_all(&ops)
    }

    /// Checks whether this key's metadata permits the requested operation(s).
    ///
    /// This enforces RFC 7517 operation-intent semantics:
    /// - If `use` is present, it must be compatible with all requested operations.
    /// - If `key_ops` is present, it must include all requested operations.
    /// - If both are present, they must be mutually consistent.
    /// - `key_ops` values must be unique.
    ///
    /// Metadata members are optional in RFC 7517. If both `use` and `key_ops`
    /// are absent, this check succeeds.
    ///
    /// At least one operation must be provided. Passing an empty slice
    /// returns an error (this is a caller precondition, not a key problem).
    ///
    /// This does **not** perform key-material or algorithm-suitability checks.
    /// It does enforce `use`/`key_ops` metadata consistency (RFC 7517 §4.3),
    /// which may return [`Error::InvalidKey`] if the key's own metadata is
    /// self-contradictory. Use [`Key::validate_for_use`] for the full pre-use
    /// gate.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Key, KeyOperation};
    ///
    /// let json = r#"{"kty":"oct","use":"sig","k":"c2VjcmV0LWtleS1tYXRlcmlhbC10aGF0LWlzLWxvbmctZW5vdWdo"}"#;
    /// let key: Key = serde_json::from_str(json).unwrap();
    ///
    /// // Signing is permitted by use="sig"
    /// assert!(key.check_operations_permitted(&[KeyOperation::Sign]).is_ok());
    ///
    /// // Encryption is not permitted by use="sig"
    /// assert!(key.check_operations_permitted(&[KeyOperation::Encrypt]).is_err());
    /// ```
    pub fn check_operations_permitted(&self, operations: impl AsRef<[KeyOperation]>) -> Result<()> {
        let operations = operations.as_ref();
        if operations.is_empty() {
            return Err(Error::InvalidInput(
                "at least one requested operation is required",
            ));
        }
        // Consistency and uniqueness checks must run here since this is a
        // standalone public method: callers may not have called `validate()`.
        self.validate_use_key_ops_consistency()?;
        self.validate_key_ops_unique()?;
        self.validate_operation_intent_for_all(operations)
    }

    /// Checks algorithm suitability: structural validity, key-type
    /// compatibility, and key strength.
    ///
    /// This does **not** perform operation-intent checks (`use`/`key_ops`)
    /// and does not enforce selection policy. Certificate metadata checks are
    /// handled separately by strict selection. It is intended
    /// for internal use by [`KeySelector`](crate::KeySelector).
    /// [`Key::validate_for_use`] calls the underlying helpers directly to
    /// avoid redundant structural validation.
    pub(crate) fn check_algorithm_suitability(&self, alg: &Algorithm) -> Result<()> {
        // Structural validation first: reject malformed key material before
        // checking algorithm-specific constraints.
        self.params.validate()?;
        self.validate_algorithm_key_type_match(alg)?;
        self.validate_algorithm_key_strength(alg)
    }

    /// Checks operation-intent metadata for requested operations.
    ///
    /// This enforces RFC 7517 operation intent semantics:
    /// - If `use` is present, it must be compatible with all requested operations.
    /// - If `key_ops` is present, it must include all requested operations.
    /// - If both are present, they must be mutually consistent.
    ///
    /// Metadata members are optional in RFC 7517. If both are absent, this
    /// check succeeds.
    ///
    /// This does **not** perform key-material or algorithm-suitability checks.
    /// It does enforce `use`/`key_ops` metadata consistency (RFC 7517 §4.3),
    /// which may return [`Error::InvalidKey`] if the key's own metadata is
    /// self-contradictory. It is intended for internal use by
    /// [`KeySelector`](crate::KeySelector).
    pub(crate) fn check_operation_intent(&self, operations: &[KeyOperation]) -> Result<()> {
        debug_assert!(!operations.is_empty());
        self.validate_use_key_ops_consistency()?;
        self.validate_key_ops_unique()?;
        self.validate_operation_intent_for_all(operations)
    }

    /// Checks whether this key material can actually perform requested operations.
    ///
    /// This is separate from metadata intent checks (`use`/`key_ops`):
    /// a key may declare an operation but still lack required private material.
    pub(crate) fn check_operation_capability(&self, operations: &[KeyOperation]) -> Result<()> {
        debug_assert!(!operations.is_empty());
        self.validate_operation_capability_for_all(operations)
    }

    /// Validates only operation-intent compatibility for all requested operations.
    ///
    /// Unlike [`Key::check_operation_intent`], this does not run
    /// `use`/`key_ops` structural consistency or uniqueness pre-checks.
    pub(crate) fn validate_operation_intent_for_all(
        &self,
        operations: &[KeyOperation],
    ) -> Result<()> {
        debug_assert!(!operations.is_empty());

        if let Some(key_use) = &self.key_use {
            let disallowed: Vec<KeyOperation> = operations
                .iter()
                .filter(|op| !is_operation_allowed_by_use(key_use, op))
                .cloned()
                .collect();

            if !disallowed.is_empty() {
                return Err(IncompatibleKeyError::OperationNotPermitted {
                    operations: disallowed,
                    reason: format!(
                        "RFC 7517: key 'use' '{}' does not permit requested operation(s)",
                        key_use
                    ),
                }
                .into());
            }
        }

        if let Some(key_ops) = &self.key_ops {
            // `key_ops` is an explicit allow-list. Unknown operations are
            // accepted only when explicitly listed in the key metadata.
            let disallowed: Vec<KeyOperation> = operations
                .iter()
                .filter(|op| !key_ops.contains(op))
                .cloned()
                .collect();

            if !disallowed.is_empty() {
                return Err(IncompatibleKeyError::OperationNotPermitted {
                    operations: disallowed,
                    reason: "RFC 7517: key_ops does not permit requested operation(s)".to_string(),
                }
                .into());
            }
        }

        Ok(())
    }

    fn validate_operation_capability_for_all(&self, operations: &[KeyOperation]) -> Result<()> {
        debug_assert!(!operations.is_empty());

        // Symmetric keys always carry secret material and do not have a
        // public/private split. Private-material capability checks apply only
        // to asymmetric key types.
        if matches!(self.params, KeyParams::Symmetric(_)) || self.has_private_key() {
            return Ok(());
        }

        let requires_private: Vec<KeyOperation> = operations
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    KeyOperation::Sign
                        | KeyOperation::Decrypt
                        | KeyOperation::UnwrapKey
                        | KeyOperation::DeriveKey
                        | KeyOperation::DeriveBits
                )
            })
            .cloned()
            .collect();

        if requires_private.is_empty() {
            return Ok(());
        }

        Err(IncompatibleKeyError::OperationNotPermitted {
            operations: requires_private,
            reason: "requested operation(s) require private key material, but key contains only public parameters".to_string(),
        }
        .into())
    }

    fn validate_operation_algorithm_compatibility_for_all(
        &self,
        alg: &Algorithm,
        operations: &[KeyOperation],
    ) -> Result<()> {
        debug_assert!(!operations.is_empty());

        let incompatible: Vec<KeyOperation> = operations
            .iter()
            .filter(|op| !is_operation_compatible_with_algorithm(op, alg))
            .cloned()
            .collect();

        if incompatible.is_empty() {
            return Ok(());
        }

        Err(IncompatibleKeyError::OperationNotPermitted {
            operations: incompatible,
            reason: format!(
                "requested operation(s) are not compatible with algorithm '{}'",
                alg.as_str()
            ),
        }
        .into())
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
        if !self.is_algorithm_compatible(alg) {
            return Err(IncompatibleKeyError::IncompatibleAlgorithm {
                algorithm: alg.as_str().to_string(),
                key_type: self.kty().as_str().to_string(),
            }
            .into());
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
            (KeyParams::Symmetric(sym), Algorithm::Hs256) => sym.validate_min_size(256, "HS256"),
            (KeyParams::Symmetric(sym), Algorithm::Hs384) => sym.validate_min_size(384, "HS384"),
            (KeyParams::Symmetric(sym), Algorithm::Hs512) => sym.validate_min_size(512, "HS512"),
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
        let (remaining, cert) = parse_x509_certificate(cert_der).map_err(|_| {
            Error::from(InvalidKeyError::InvalidParameter {
                name: "x5c",
                reason: "RFC 7517: x5c[0] is not a parseable X.509 certificate".to_string(),
            })
        })?;

        if !remaining.is_empty() {
            return Err(InvalidKeyError::InvalidParameter {
                name: "x5c",
                reason: "RFC 7517: x5c[0] contains trailing data after DER certificate".to_string(),
            }
            .into());
        }

        let spki = &cert.tbs_certificate.subject_pki;
        let cert_alg_oid = spki.algorithm.algorithm.to_id_string();
        let cert_key = spki.subject_public_key.data.as_ref();

        match &self.params {
            KeyParams::Rsa(rsa) => {
                if cert_alg_oid != "1.2.840.113549.1.1.1" {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK RSA key"
                            .to_string(),
                    )
                    .into());
                }

                let expected_der = encode_rsa_public_key_der(rsa.n.as_bytes(), rsa.e.as_bytes());
                if cert_key != expected_der.as_slice() {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK RSA key parameters"
                            .to_string(),
                    )
                    .into());
                }
            }
            KeyParams::Ec(ec) => {
                if cert_alg_oid != "1.2.840.10045.2.1" {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK EC key"
                            .to_string(),
                    )
                    .into());
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
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] EC curve does not match JWK crv".to_string(),
                    )
                    .into());
                }

                let expected_point = ec.to_uncompressed_point();
                if cert_key != expected_point.as_slice() {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK EC key parameters"
                            .to_string(),
                    )
                    .into());
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
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key algorithm does not match JWK OKP key"
                            .to_string(),
                    )
                    .into());
                }

                if cert_key != okp.x.as_bytes() {
                    return Err(InvalidKeyError::InconsistentParameters(
                        "RFC 7517: x5c[0] public key does not match JWK OKP key parameters"
                            .to_string(),
                    )
                    .into());
                }
            }
            KeyParams::Symmetric(_) => {
                return Err(InvalidKeyError::InconsistentParameters(
                    "RFC 7517: x5c is not valid for symmetric (oct) keys".to_string(),
                )
                .into());
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
    /// Public projection also normalizes `key_ops` to the subset that remains
    /// meaningful for a public key (`verify`, `encrypt`, `wrapKey`). Operations
    /// that require private or secret key material are removed.
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
            key_ops: self
                .key_ops
                .as_ref()
                .map(|ops| {
                    ops.iter()
                        .filter(|op| operation_survives_public_projection(op))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .filter(|ops| !ops.is_empty()),
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
///
/// # Security Note
///
/// This comparison is **not** constant-time. It uses short-circuit
/// byte-by-byte comparison of key material, including private key
/// components. Do not use `==` on [`Key`] values in security-sensitive
/// decisions where one side is attacker-controlled, as timing differences
/// may leak information about secret key material (CWE-208).
///
/// For constant-time comparison of symmetric key material, use
/// [`SymmetricParams::ct_eq`]. For the underlying byte buffers, use
/// [`Base64UrlBytes::ct_eq`](crate::encoding::Base64UrlBytes::ct_eq).
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

fn is_operation_allowed_by_use(key_use: &KeyUse, operation: &KeyOperation) -> bool {
    if matches!(operation, KeyOperation::Unknown(_)) {
        return true;
    }

    match key_use {
        KeyUse::Signature => is_signature_operation(operation),
        KeyUse::Encryption => is_encryption_operation(operation),
        KeyUse::Unknown(_) => true,
    }
}

fn is_signature_operation(operation: &KeyOperation) -> bool {
    matches!(operation, KeyOperation::Sign | KeyOperation::Verify)
}

fn is_encryption_operation(operation: &KeyOperation) -> bool {
    matches!(
        operation,
        KeyOperation::Encrypt
            | KeyOperation::Decrypt
            | KeyOperation::WrapKey
            | KeyOperation::UnwrapKey
            | KeyOperation::DeriveKey
            | KeyOperation::DeriveBits
    )
}

fn operation_survives_public_projection(operation: &KeyOperation) -> bool {
    matches!(
        operation,
        KeyOperation::Verify | KeyOperation::Encrypt | KeyOperation::WrapKey
    )
}

impl Key {
    fn validate_declared_algorithm_match(&self, requested_alg: &Algorithm) -> Result<()> {
        if let Some(declared_alg) = self.alg()
            && declared_alg != requested_alg
        {
            return Err(Error::IncompatibleKey(
                IncompatibleKeyError::AlgorithmMismatch {
                    requested: requested_alg.as_str().to_string(),
                    declared: declared_alg.as_str().to_string(),
                },
            ));
        }

        Ok(())
    }
}

pub(crate) fn is_operation_compatible_with_algorithm(
    operation: &KeyOperation,
    alg: &Algorithm,
) -> bool {
    if matches!(operation, KeyOperation::Unknown(_)) {
        return true;
    }

    debug_assert!(
        !alg.is_unknown(),
        "unknown algorithms should be rejected before operation/algorithm compatibility checks"
    );

    match alg {
        Algorithm::Rs256
        | Algorithm::Rs384
        | Algorithm::Rs512
        | Algorithm::Ps256
        | Algorithm::Ps384
        | Algorithm::Ps512
        | Algorithm::Es256
        | Algorithm::Es384
        | Algorithm::Es512
        | Algorithm::Es256k
        | Algorithm::EdDsa
        | Algorithm::Ed25519
        | Algorithm::Ed448
        | Algorithm::Hs256
        | Algorithm::Hs384
        | Algorithm::Hs512 => matches!(operation, KeyOperation::Sign | KeyOperation::Verify),
        Algorithm::RsaOaep
        | Algorithm::RsaOaep256
        | Algorithm::RsaOaep384
        | Algorithm::RsaOaep512
        | Algorithm::Rsa1_5 => matches!(
            operation,
            KeyOperation::Encrypt
                | KeyOperation::Decrypt
                | KeyOperation::WrapKey
                | KeyOperation::UnwrapKey
        ),
        Algorithm::A128kw
        | Algorithm::A192kw
        | Algorithm::A256kw
        | Algorithm::A128gcmkw
        | Algorithm::A192gcmkw
        | Algorithm::A256gcmkw
        | Algorithm::Pbes2Hs256A128kw
        | Algorithm::Pbes2Hs384A192kw
        | Algorithm::Pbes2Hs512A256kw => {
            matches!(operation, KeyOperation::WrapKey | KeyOperation::UnwrapKey)
        }
        Algorithm::Dir
        | Algorithm::A128cbcHs256
        | Algorithm::A192cbcHs384
        | Algorithm::A256cbcHs512
        | Algorithm::A128gcm
        | Algorithm::A192gcm
        | Algorithm::A256gcm => matches!(operation, KeyOperation::Encrypt | KeyOperation::Decrypt),
        Algorithm::EcdhEs
        | Algorithm::EcdhEsA128kw
        | Algorithm::EcdhEsA192kw
        | Algorithm::EcdhEsA256kw => {
            matches!(
                operation,
                KeyOperation::DeriveKey | KeyOperation::DeriveBits
            )
        }
        // Defensive fallback for future callers; current strict validation paths
        // reject unknown algorithms before reaching this helper.
        Algorithm::Unknown(_) => false,
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
        return Err(InvalidKeyError::InvalidParameter {
            name: param_name,
            reason: format!(
                "RFC 7517: {} must be base64url-encoded (invalid characters found)",
                param_name
            ),
        }
        .into());
    }

    // Try to decode and check the length
    match Base64UrlUnpadded::decode_vec(thumbprint) {
        Ok(decoded) => {
            if decoded.len() != expected_bytes {
                return Err(InvalidKeyError::InvalidParameter {
                    name: param_name,
                    reason: format!(
                        "RFC 7517: {} must be {} bytes when decoded (got {} bytes)",
                        param_name,
                        expected_bytes,
                        decoded.len()
                    ),
                }
                .into());
            }
            Ok(())
        }
        Err(_) => Err(InvalidKeyError::InvalidParameter {
            name: param_name,
            reason: format!("RFC 7517: {} failed base64url decoding", param_name),
        }
        .into()),
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
        assert_eq!(Algorithm::from("Ed25519"), Algorithm::Ed25519);
        assert_eq!(Algorithm::from("Ed448"), Algorithm::Ed448);
        assert_eq!("Ed25519".parse::<Algorithm>().unwrap(), Algorithm::Ed25519);
        assert_eq!("Ed448".parse::<Algorithm>().unwrap(), Algorithm::Ed448);
        assert_eq!(Algorithm::Ed25519.as_str(), "Ed25519");
        assert_eq!(Algorithm::Ed448.as_str(), "Ed448");
    }

    #[test]
    fn test_parse_key_use_and_operation_with_from_str() {
        assert_eq!("sig".parse::<KeyUse>().unwrap(), KeyUse::Signature);
        assert_eq!("enc".parse::<KeyUse>().unwrap(), KeyUse::Encryption);
        assert_eq!(
            "private-use".parse::<KeyUse>().unwrap(),
            KeyUse::Unknown("private-use".to_string())
        );

        assert_eq!("sign".parse::<KeyOperation>().unwrap(), KeyOperation::Sign);
        assert_eq!(
            "verify".parse::<KeyOperation>().unwrap(),
            KeyOperation::Verify
        );
        assert_eq!(
            "custom-op".parse::<KeyOperation>().unwrap(),
            KeyOperation::Unknown("custom-op".to_string())
        );
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
    fn test_to_public_filters_private_only_key_ops() {
        let key = Key::new(KeyParams::Rsa(RsaParams::new_private(
            Base64UrlBytes::new(vec![0x01; 256]),
            Base64UrlBytes::new(vec![0x01, 0x00, 0x01]),
            Base64UrlBytes::new(vec![0x02; 256]),
            None,
            None,
            None,
            None,
            None,
        )))
        .with_key_ops([
            KeyOperation::Sign,
            KeyOperation::Verify,
            KeyOperation::Decrypt,
            KeyOperation::Encrypt,
            KeyOperation::WrapKey,
            KeyOperation::UnwrapKey,
            KeyOperation::DeriveKey,
            KeyOperation::Unknown("custom".into()),
        ]);

        let public = key.to_public().unwrap();

        assert_eq!(
            public.key_ops(),
            Some(
                &[
                    KeyOperation::Verify,
                    KeyOperation::Encrypt,
                    KeyOperation::WrapKey,
                ][..]
            )
        );
    }

    #[test]
    fn test_to_public_clears_empty_key_ops_after_projection() {
        let key = Key::new(KeyParams::Ec(EcParams::new_private(
            EcCurve::P256,
            Base64UrlBytes::new(vec![0x01; 32]),
            Base64UrlBytes::new(vec![0x02; 32]),
            Base64UrlBytes::new(vec![0x03; 32]),
        )))
        .with_key_ops([KeyOperation::Sign]);

        let public = key.to_public().unwrap();

        assert_eq!(public.key_ops(), None);
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
    #[test]
    fn test_check_algorithm_suitability_enforces_strength_without_key_alg() {
        let weak_hmac_key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 31]),
        )));

        // Baseline JWK validation (structure) still passes: key is structurally valid.
        assert!(weak_hmac_key.validate().is_ok());

        // Algorithm suitability check enforces HS256 minimum key strength.
        assert!(
            weak_hmac_key
                .check_algorithm_suitability(&Algorithm::Hs256)
                .is_err()
        );
    }

    #[test]
    fn test_check_operation_intent_enforces_use_when_present() {
        let key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 32]),
        )))
        .with_use(KeyUse::Encryption);

        assert!(key.check_operation_intent(&[KeyOperation::Encrypt]).is_ok());
        assert!(key.check_operation_intent(&[KeyOperation::Sign]).is_err());
    }

    #[test]
    fn test_check_operation_intent_enforces_key_ops_when_present() {
        let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )))
        .with_key_ops(vec![KeyOperation::Verify]);

        assert!(key.check_operation_intent(&[KeyOperation::Verify]).is_ok());
        assert!(key.check_operation_intent(&[KeyOperation::Sign]).is_err());
    }

    #[test]
    fn test_check_operation_intent_allows_missing_optional_fields() {
        let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )));

        assert!(key.check_operation_intent(&[KeyOperation::Verify]).is_ok());
        assert!(key.check_operation_intent(&[KeyOperation::Sign]).is_ok());
    }

    #[test]
    fn test_validate_for_use_rejects_empty_operation_set() {
        let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )));

        let result = key.validate_for_use(&Algorithm::Rs256, vec![]);
        assert!(matches!(result, Err(Error::InvalidInput(_))));
    }

    #[test]
    fn test_validate_for_use_rejects_sign_with_public_rsa_key() {
        let mut n = vec![0xff; 256];
        n[255] = 0x01;
        let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(n),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )));

        let result = key.validate_for_use(&Algorithm::Rs256, [KeyOperation::Sign]);
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_validate_for_use_rejects_sign_with_public_okp_key() {
        let key = Key::new(KeyParams::Okp(OkpParams::new_public(
            OkpCurve::Ed25519,
            Base64UrlBytes::new(vec![0u8; 32]),
        )));

        let result = key.validate_for_use(&Algorithm::Ed25519, [KeyOperation::Sign]);
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_validate_for_use_rejects_sign_with_public_ec_key() {
        let key = Key::new(KeyParams::Ec(EcParams::new_public(
            EcCurve::P256,
            Base64UrlBytes::new(vec![0u8; 32]),
            Base64UrlBytes::new(vec![0u8; 32]),
        )));

        let result = key.validate_for_use(&Algorithm::Es256, [KeyOperation::Sign]);
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_validate_for_use_rejects_unknown_algorithm() {
        let key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 32]),
        )));

        let result = key.validate_for_use(
            &Algorithm::Unknown("CUSTOM-ALG".to_string()),
            [KeyOperation::Sign],
        );
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::IncompatibleAlgorithm { .. }
            ))
        ));
    }

    #[test]
    fn test_validate_for_use_rejects_operation_algorithm_mismatch() {
        let key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 32]),
        )));

        let result = key.validate_for_use(&Algorithm::Hs256, [KeyOperation::Encrypt]);
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::OperationNotPermitted { .. }
            ))
        ));
    }

    #[test]
    fn test_validate_for_use_rejects_declared_algorithm_mismatch() {
        let key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 32]),
        )))
        .with_alg(Algorithm::Hs256);

        let result = key.validate_for_use(&Algorithm::Hs384, [KeyOperation::Sign]);
        assert!(matches!(
            result,
            Err(Error::IncompatibleKey(
                IncompatibleKeyError::AlgorithmMismatch { .. }
            ))
        ));
    }

    #[test]
    fn test_check_operation_intent_rejects_inconsistent_use_and_key_ops() {
        let key = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )))
        .with_use(KeyUse::Signature)
        .with_key_ops(vec![KeyOperation::Encrypt]);

        assert!(key.check_operation_intent(&[KeyOperation::Verify]).is_err());
    }

    #[test]
    fn test_check_operation_intent_allows_unknown_operation_with_use() {
        let key = Key::new(KeyParams::Symmetric(SymmetricParams::new(
            Base64UrlBytes::new(vec![0u8; 32]),
        )))
        .with_use(KeyUse::Signature);

        let result = key.check_operation_intent(&[KeyOperation::Unknown("custom-op".into())]);
        assert!(result.is_ok());
    }
}

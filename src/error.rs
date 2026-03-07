//! Error types for JWK/JWKS operations.
//!
//! This module provides the crate's core error taxonomy.
//!
//! Most fallible operations return `Result<T, Error>`. Feature-gated
//! integration adapters may expose dedicated conversion error types when that
//! yields clearer API boundaries.
//!
//! Key validation errors are split into two categories:
//!
//! - [`InvalidKeyError`] - the JWK is malformed (invalid encoding, missing
//!   parameters, inconsistent fields). These mean "reject this key entirely."
//!
//! - [`IncompatibleKeyError`] - the JWK is well-formed but incompatible with
//!   the requested use (wrong key type for algorithm, insufficient strength,
//!   operation not permitted by metadata). These mean "valid key, wrong context."

use std::fmt::{self, Display};

use crate::jwk::KeyOperation;

/// The main error type for core JWK/JWKS operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Failed to parse JSON.
    Parse(ParseError),

    /// Invalid URL input.
    InvalidUrl(String),

    /// The JWK is malformed: missing parameters, invalid encoding, or
    /// inconsistent fields.
    InvalidKey(InvalidKeyError),

    /// The JWK is well-formed but incompatible with the requested use.
    IncompatibleKey(IncompatibleKeyError),

    /// Base64 decoding failed.
    Base64(base64ct::Error),

    /// HTTP request error.
    #[cfg(feature = "http")]
    Http(reqwest::Error),

    /// Cache operation failed.
    Cache(String),

    /// Other error (for platform-specific or miscellaneous errors).
    Other(String),

    /// Key type or curve not supported by WebCrypto.
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    UnsupportedForWebCrypto {
        /// Why it's unsupported.
        reason: &'static str,
    },

    /// WebCrypto operation failed.
    #[cfg(feature = "web-crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "web-crypto")))]
    WebCrypto(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(e) => write!(f, "parse error: {}", e),
            Error::InvalidUrl(msg) => write!(f, "invalid URL: {}", msg),
            Error::InvalidKey(e) => write!(f, "invalid key: {}", e),
            Error::IncompatibleKey(e) => write!(f, "incompatible key: {}", e),
            Error::Base64(e) => write!(f, "base64 decoding error: {:?}", e),
            #[cfg(feature = "http")]
            Error::Http(e) => write!(f, "HTTP error: {}", e),
            Error::Cache(msg) => write!(f, "cache error: {}", msg),
            Error::Other(msg) => write!(f, "{}", msg),
            #[cfg(feature = "web-crypto")]
            Error::UnsupportedForWebCrypto { reason } => {
                write!(f, "unsupported for WebCrypto: {}", reason)
            }
            #[cfg(feature = "web-crypto")]
            Error::WebCrypto(msg) => write!(f, "WebCrypto error: {}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Parse(e) => Some(e),
            Error::InvalidKey(e) => Some(e),
            Error::IncompatibleKey(e) => Some(e),
            #[cfg(feature = "http")]
            Error::Http(e) => Some(e),
            _ => None,
        }
    }
}

impl From<InvalidKeyError> for Error {
    fn from(e: InvalidKeyError) -> Self {
        Error::InvalidKey(e)
    }
}

impl From<IncompatibleKeyError> for Error {
    fn from(e: IncompatibleKeyError) -> Self {
        Error::IncompatibleKey(e)
    }
}

impl From<base64ct::Error> for Error {
    fn from(e: base64ct::Error) -> Self {
        Error::Base64(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(ParseError::Json(e.to_string()))
    }
}

#[cfg(feature = "http")]
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

/// Errors that occur during JSON parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Invalid JSON syntax.
    Json(String),
    /// Unknown key type.
    UnknownKeyType(String),
    /// Unknown curve.
    UnknownCurve(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Json(msg) => write!(f, "invalid JSON: {}", msg),
            ParseError::UnknownKeyType(kty) => write!(f, "unknown key type: {}", kty),
            ParseError::UnknownCurve(crv) => write!(f, "unknown curve: {}", crv),
        }
    }
}

impl std::error::Error for ParseError {}

/// The JWK is malformed.
///
/// These errors indicate the key material or metadata is invalid regardless
/// of how the key is used. A key producing an `InvalidKeyError` should be
/// rejected entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidKeyError {
    /// Invalid key size for the key type or curve.
    InvalidKeySize {
        /// Expected size in bytes.
        expected: usize,
        /// Actual size in bytes.
        actual: usize,
        /// What was being validated.
        context: &'static str,
    },
    /// Missing required parameter for key type.
    MissingParameter(&'static str),
    /// Inconsistent key parameters (e.g., public and private parts don't match).
    InconsistentParameters(String),
    /// Invalid parameter value.
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Why it's invalid.
        reason: String,
    },
}

impl Display for InvalidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidKeyError::InvalidKeySize {
                expected,
                actual,
                context,
            } => {
                write!(
                    f,
                    "invalid key size for {}: expected {} bytes, got {}",
                    context, expected, actual
                )
            }
            InvalidKeyError::MissingParameter(param) => {
                write!(f, "missing required parameter: {}", param)
            }
            InvalidKeyError::InconsistentParameters(msg) => {
                write!(f, "inconsistent key parameters: {}", msg)
            }
            InvalidKeyError::InvalidParameter { name, reason } => {
                write!(f, "invalid parameter '{}': {}", name, reason)
            }
        }
    }
}

impl std::error::Error for InvalidKeyError {}

/// The JWK is well-formed but incompatible with the requested use.
///
/// These errors indicate the key is structurally valid but cannot be used
/// in the requested context. A key producing an `IncompatibleKeyError` may
/// be perfectly valid for a different algorithm or operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompatibleKeyError {
    /// Algorithm is not compatible with the key type or curve.
    IncompatibleAlgorithm {
        /// The algorithm that was requested.
        algorithm: String,
        /// The key type that is incompatible.
        key_type: String,
    },
    /// Key is too weak for the requested algorithm.
    InsufficientKeyStrength {
        /// Minimum required size in bits.
        minimum_bits: usize,
        /// Actual key size in bits.
        actual_bits: usize,
        /// What was being validated.
        context: &'static str,
    },
    /// Key size does not match the exact size required by the algorithm.
    KeySizeMismatch {
        /// Required size in bits.
        required_bits: usize,
        /// Actual key size in bits.
        actual_bits: usize,
        /// What was being validated.
        context: &'static str,
    },
    /// Requested operation(s) are not permitted by key metadata or key material
    /// capability (for example, a public-only key used for signing).
    OperationNotPermitted {
        /// The disallowed operations.
        operations: Vec<KeyOperation>,
        /// Why the operations are not permitted.
        reason: String,
    },
}

impl Display for IncompatibleKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncompatibleKeyError::IncompatibleAlgorithm {
                algorithm,
                key_type,
            } => {
                write!(
                    f,
                    "algorithm '{}' is not compatible with key type '{}'",
                    algorithm, key_type
                )
            }
            IncompatibleKeyError::InsufficientKeyStrength {
                minimum_bits,
                actual_bits,
                context,
            } => {
                write!(
                    f,
                    "insufficient key strength for {}: need {} bits, got {}",
                    context, minimum_bits, actual_bits
                )
            }
            IncompatibleKeyError::KeySizeMismatch {
                required_bits,
                actual_bits,
                context,
            } => {
                write!(
                    f,
                    "key size mismatch for {}: expected {} bits, got {}",
                    context, required_bits, actual_bits
                )
            }
            IncompatibleKeyError::OperationNotPermitted { operations, reason } => {
                let ops: Vec<&str> = operations.iter().map(|op| op.as_str()).collect();
                write!(
                    f,
                    "operation(s) not permitted ({}): {}",
                    ops.join(", "),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for IncompatibleKeyError {}

/// Errors that occur when converting a JWK into a `jwt-simple` key type.
#[cfg(feature = "jwt-simple")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt-simple")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtSimpleConversionError {
    /// The JWK itself is malformed.
    InvalidKey(InvalidKeyError),
    /// The JWK is valid but unsuitable for the requested conversion.
    IncompatibleKey(IncompatibleKeyError),
    /// The conversion expects a different JWK key type.
    KeyTypeMismatch {
        /// Expected JWK `kty`.
        expected: &'static str,
        /// Actual JWK `kty`.
        actual: String,
    },
    /// The conversion expects a different curve.
    CurveMismatch {
        /// Expected curve.
        expected: &'static str,
        /// Actual curve.
        actual: String,
    },
    /// The conversion requires a specific JWK member that is absent.
    MissingComponent {
        /// JWK member name.
        field: &'static str,
    },
    /// The conversion requires private key material, but the JWK is public-only.
    MissingPrivateKey,
    /// Core pre-conversion validation failed in a way that does not map to a
    /// structured conversion variant.
    Validation(String),
    /// Encoding the source key into an intermediate representation failed.
    Encoding(String),
    /// Importing the encoded key into `jwt-simple` failed.
    Import(String),
}

#[cfg(feature = "jwt-simple")]
impl Display for JwtSimpleConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtSimpleConversionError::InvalidKey(e) => write!(f, "invalid key: {}", e),
            JwtSimpleConversionError::IncompatibleKey(e) => {
                write!(f, "incompatible key: {}", e)
            }
            JwtSimpleConversionError::KeyTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "key type mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            JwtSimpleConversionError::CurveMismatch { expected, actual } => {
                write!(f, "curve mismatch: expected {}, got {}", expected, actual)
            }
            JwtSimpleConversionError::MissingComponent { field } => {
                write!(f, "missing required field: {}", field)
            }
            JwtSimpleConversionError::MissingPrivateKey => {
                write!(f, "private key parameters required but not present")
            }
            JwtSimpleConversionError::Validation(msg) => write!(f, "validation error: {}", msg),
            JwtSimpleConversionError::Encoding(msg) => write!(f, "encoding error: {}", msg),
            JwtSimpleConversionError::Import(msg) => write!(f, "import error: {}", msg),
        }
    }
}

#[cfg(feature = "jwt-simple")]
impl std::error::Error for JwtSimpleConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JwtSimpleConversionError::InvalidKey(e) => Some(e),
            JwtSimpleConversionError::IncompatibleKey(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "jwt-simple")]
impl From<InvalidKeyError> for JwtSimpleConversionError {
    fn from(e: InvalidKeyError) -> Self {
        JwtSimpleConversionError::InvalidKey(e)
    }
}

#[cfg(feature = "jwt-simple")]
impl From<IncompatibleKeyError> for JwtSimpleConversionError {
    fn from(e: IncompatibleKeyError) -> Self {
        JwtSimpleConversionError::IncompatibleKey(e)
    }
}

/// A type alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

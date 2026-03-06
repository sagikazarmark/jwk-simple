//! Error types for JWK/JWKS operations.
//!
//! This module provides a comprehensive error type that covers all failure
//! modes in the library. All fallible operations return `Result<T, Error>`.
//!
//! Key validation errors are split into two categories:
//!
//! - [`InvalidKeyError`] - the JWK is malformed (invalid encoding, missing
//!   parameters, inconsistent fields). These mean "reject this key entirely."
//!
//! - [`IncompatibleKeyError`] - the JWK is well-formed but incompatible with
//!   the requested use (wrong key type for algorithm, insufficient strength,
//!   operation not permitted by metadata). These mean "valid key, wrong context."

use std::fmt;

use crate::jwk::KeyOperation;

/// The main error type for this crate.
///
/// All fallible operations return `Result<T, Error>`.
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

    /// Key type mismatch during conversion.
    KeyTypeMismatch {
        /// Expected.
        expected: &'static str,
        /// Actual.
        actual: String,
    },

    /// Curve mismatch during conversion.
    CurveMismatch {
        /// Expected.
        expected: &'static str,
        /// Actual.
        actual: String,
    },

    /// Missing required field.
    MissingField {
        /// Field name.
        field: &'static str,
    },

    /// Private key parameters missing when required.
    MissingPrivateKey,

    /// HTTP request error.
    #[cfg(feature = "http")]
    Http(reqwest::Error),

    /// Cache operation failed.
    Cache(String),

    /// Upstream payload exceeded configured size limit.
    PayloadTooLarge {
        /// Maximum number of bytes allowed.
        max_bytes: usize,
        /// Actual payload size in bytes.
        actual_bytes: usize,
    },

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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(e) => write!(f, "parse error: {}", e),
            Error::InvalidUrl(msg) => write!(f, "invalid URL: {}", msg),
            Error::InvalidKey(e) => write!(f, "invalid key: {}", e),
            Error::IncompatibleKey(e) => write!(f, "incompatible key: {}", e),
            Error::Base64(e) => write!(f, "base64 decoding error: {:?}", e),
            Error::KeyTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "key type mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Error::CurveMismatch { expected, actual } => {
                write!(f, "curve mismatch: expected {}, got {}", expected, actual)
            }
            Error::MissingField { field } => {
                write!(f, "missing required field: {}", field)
            }
            Error::MissingPrivateKey => {
                write!(f, "private key parameters required but not present")
            }
            #[cfg(feature = "http")]
            Error::Http(e) => write!(f, "HTTP error: {}", e),
            Error::Cache(msg) => write!(f, "cache error: {}", msg),
            Error::PayloadTooLarge {
                max_bytes,
                actual_bytes,
            } => write!(
                f,
                "payload too large: {} bytes (max {})",
                actual_bytes, max_bytes
            ),
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
#[derive(Debug)]
pub enum ParseError {
    /// Invalid JSON syntax.
    Json(String),
    /// Unknown key type.
    UnknownKeyType(String),
    /// Unknown curve.
    UnknownCurve(String),
}

impl fmt::Display for ParseError {
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
#[derive(Debug, PartialEq)]
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

impl fmt::Display for InvalidKeyError {
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
#[derive(Debug, PartialEq)]
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
    /// Key metadata does not permit the requested operation(s).
    OperationNotPermitted {
        /// The disallowed operations.
        operations: Vec<KeyOperation>,
        /// Why the operations are not permitted.
        reason: String,
    },
}

impl fmt::Display for IncompatibleKeyError {
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

/// A type alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

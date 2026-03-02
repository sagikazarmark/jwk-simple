//! Error types for JWK/JWKS operations.
//!
//! This module provides a comprehensive error type that covers all failure
//! modes in the library. All public functions return `Result<T, Error>` to
//! maintain the no-panic guarantee.

use std::fmt;

/// The main error type for this crate.
///
/// All public functions return `Result<T, Error>` to ensure no panics occur
/// in library code.
#[derive(Debug)]
pub enum Error {
    /// Failed to parse JSON.
    Parse(ParseError),

    /// Key validation failed.
    Validation(ValidationError),

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
            Error::Validation(e) => write!(f, "validation error: {}", e),
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
            Error::Validation(e) => Some(e),
            #[cfg(feature = "http")]
            Error::Http(e) => Some(e),
            _ => None,
        }
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

/// Errors that occur during key validation.
#[derive(Debug)]
pub enum ValidationError {
    /// Invalid key size for the specified algorithm.
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

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidKeySize {
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
            ValidationError::MissingParameter(param) => {
                write!(f, "missing required parameter: {}", param)
            }
            ValidationError::InconsistentParameters(msg) => {
                write!(f, "inconsistent key parameters: {}", msg)
            }
            ValidationError::InvalidParameter { name, reason } => {
                write!(f, "invalid parameter '{}': {}", name, reason)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// A type alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

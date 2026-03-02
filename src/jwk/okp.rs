//! Octet Key Pair parameters as defined in RFC 8037.
//!
//! This module contains the [`OkpParams`] type which holds key material for
//! Edwards-curve and Montgomery-curve keys (Ed25519, Ed448, X25519, X448).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{Error, ParseError, Result, ValidationError};

/// Supported OKP curves (RFC 8037).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OkpCurve {
    /// Ed25519 signature algorithm (EdDSA).
    Ed25519,

    /// Ed448 signature algorithm (EdDSA).
    Ed448,

    /// X25519 key agreement algorithm.
    X25519,

    /// X448 key agreement algorithm.
    X448,
}

impl OkpCurve {
    /// Returns the public key size in bytes for this curve.
    pub fn public_key_size(&self) -> usize {
        match self {
            OkpCurve::Ed25519 | OkpCurve::X25519 => 32,
            OkpCurve::Ed448 | OkpCurve::X448 => 57,
        }
    }

    /// Returns the standard private key (seed) size in bytes for this curve.
    pub fn private_key_size(&self) -> usize {
        match self {
            OkpCurve::Ed25519 | OkpCurve::X25519 => 32,
            OkpCurve::Ed448 | OkpCurve::X448 => 57,
        }
    }

    /// Returns the extended private key size in bytes for this curve.
    ///
    /// Some implementations store the private key as seed + public key.
    /// For Ed448, this is 114 bytes (57 + 57).
    pub fn extended_private_key_size(&self) -> usize {
        self.private_key_size() + self.public_key_size()
    }

    /// Returns `true` if the given size is a valid private key size for this curve.
    ///
    /// Accepts both standard seed format and extended (seed + public) format.
    pub fn is_valid_private_key_size(&self, size: usize) -> bool {
        size == self.private_key_size() || size == self.extended_private_key_size()
    }

    /// Returns the curve name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            OkpCurve::Ed25519 => "Ed25519",
            OkpCurve::Ed448 => "Ed448",
            OkpCurve::X25519 => "X25519",
            OkpCurve::X448 => "X448",
        }
    }
}

impl std::str::FromStr for OkpCurve {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "Ed25519" => Ok(OkpCurve::Ed25519),
            "Ed448" => Ok(OkpCurve::Ed448),
            "X25519" => Ok(OkpCurve::X25519),
            "X448" => Ok(OkpCurve::X448),
            _ => Err(Error::Parse(ParseError::UnknownCurve(s.to_string()))),
        }
    }
}

impl std::fmt::Display for OkpCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Octet Key Pair parameters (RFC 8037).
///
/// Contains the curve identifier, public key `x`, and optionally the private key `d`.
///
/// # Examples
///
/// ```
/// use jwk_simple::jwk::{OkpParams, OkpCurve};
///
/// // Parse from JSON
/// let json = r#"{
///     "crv": "Ed25519",
///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
/// }"#;
///
/// let params: OkpParams = serde_json::from_str(json).unwrap();
/// assert_eq!(params.crv, OkpCurve::Ed25519);
/// assert!(params.is_public_key_only());
/// ```
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OkpParams {
    /// The OKP curve.
    #[zeroize(skip)]
    pub crv: OkpCurve,

    /// The public key.
    pub x: Base64UrlBytes,

    /// The private key (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<Base64UrlBytes>,
}

impl OkpParams {
    /// Creates new OKP public key parameters.
    pub fn new_public(crv: OkpCurve, x: Base64UrlBytes) -> Self {
        Self { crv, x, d: None }
    }

    /// Creates new OKP private key parameters.
    pub fn new_private(crv: OkpCurve, x: Base64UrlBytes, d: Base64UrlBytes) -> Self {
        Self { crv, x, d: Some(d) }
    }

    /// Returns `true` if this contains only public key parameters.
    pub fn is_public_key_only(&self) -> bool {
        self.d.is_none()
    }

    /// Returns `true` if this contains private key parameters.
    pub fn has_private_key(&self) -> bool {
        self.d.is_some()
    }

    /// Validates the OKP parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key size doesn't match the curve
    /// - The private key size doesn't match the curve (if present)
    ///
    /// # Note
    ///
    /// For Ed448 private keys, both 57-byte (seed only) and 114-byte (seed + public)
    /// formats are accepted, as different implementations use different representations.
    pub fn validate(&self) -> Result<()> {
        let expected_public_size = self.crv.public_key_size();

        // Validate public key size
        if self.x.len() != expected_public_size {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: expected_public_size,
                actual: self.x.len(),
                context: "OKP public key x",
            }));
        }

        // Validate private key size if present
        // Accept both standard and extended formats
        if let Some(ref d) = self.d
            && !self.crv.is_valid_private_key_size(d.len())
        {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: self.crv.private_key_size(),
                actual: d.len(),
                context: "OKP private key d (accepts seed or seed+public format)",
            }));
        }

        Ok(())
    }

    /// Returns the seed portion of the private key.
    ///
    /// If the private key is in extended format (seed + public), this returns
    /// only the seed portion. If it's already in seed format, returns the full key.
    ///
    /// Returns `None` if no private key is present.
    pub fn private_key_seed(&self) -> Option<&[u8]> {
        self.d.as_ref().map(|d| {
            let seed_size = self.crv.private_key_size();
            if d.len() > seed_size {
                &d.as_bytes()[..seed_size]
            } else {
                d.as_bytes()
            }
        })
    }

    /// Extracts only the public key parameters.
    #[must_use]
    pub fn to_public(&self) -> Self {
        Self {
            crv: self.crv,
            x: self.x.clone(),
            d: None,
        }
    }
}

impl std::fmt::Debug for OkpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OkpParams")
            .field("crv", &self.crv)
            .field("x", &format!("[{} bytes]", self.x.len()))
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl PartialEq for OkpParams {
    fn eq(&self, other: &Self) -> bool {
        self.crv == other.crv && self.x == other.x && self.d == other.d
    }
}

impl Eq for OkpParams {}

impl std::hash::Hash for OkpParams {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.crv.hash(state);
        self.x.hash(state);
        self.d.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_key_sizes() {
        assert_eq!(OkpCurve::Ed25519.public_key_size(), 32);
        assert_eq!(OkpCurve::Ed25519.private_key_size(), 32);
        assert_eq!(OkpCurve::Ed448.public_key_size(), 57);
        assert_eq!(OkpCurve::X25519.public_key_size(), 32);
        assert_eq!(OkpCurve::X448.public_key_size(), 57);
    }

    #[test]
    fn test_public_key_only() {
        let params = OkpParams::new_public(OkpCurve::Ed25519, Base64UrlBytes::new(vec![0; 32]));
        assert!(params.is_public_key_only());
        assert!(!params.has_private_key());
    }

    #[test]
    fn test_validate_wrong_size() {
        let params = OkpParams::new_public(
            OkpCurve::Ed25519,
            Base64UrlBytes::new(vec![0; 31]), // Wrong size
        );
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_curve_parsing() {
        assert_eq!("Ed25519".parse::<OkpCurve>().unwrap(), OkpCurve::Ed25519);
        assert_eq!("Ed448".parse::<OkpCurve>().unwrap(), OkpCurve::Ed448);
        assert_eq!("X25519".parse::<OkpCurve>().unwrap(), OkpCurve::X25519);
        assert_eq!("X448".parse::<OkpCurve>().unwrap(), OkpCurve::X448);
        assert!("unknown".parse::<OkpCurve>().is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let original = OkpParams::new_public(OkpCurve::Ed25519, Base64UrlBytes::new(vec![1; 32]));
        let json = serde_json::to_string(&original).unwrap();
        let decoded: OkpParams = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_ed448_extended_private_key() {
        // Ed448 can have 57-byte (seed) or 114-byte (seed + public) private key
        assert_eq!(OkpCurve::Ed448.private_key_size(), 57);
        assert_eq!(OkpCurve::Ed448.extended_private_key_size(), 114);
        assert!(OkpCurve::Ed448.is_valid_private_key_size(57));
        assert!(OkpCurve::Ed448.is_valid_private_key_size(114));
        assert!(!OkpCurve::Ed448.is_valid_private_key_size(32));
        assert!(!OkpCurve::Ed448.is_valid_private_key_size(100));
    }

    #[test]
    fn test_ed448_seed_format_validates() {
        // 57-byte seed format
        let params = OkpParams::new_private(
            OkpCurve::Ed448,
            Base64UrlBytes::new(vec![0; 57]),
            Base64UrlBytes::new(vec![1; 57]),
        );
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_ed448_extended_format_validates() {
        // 114-byte extended format (seed + public)
        let params = OkpParams::new_private(
            OkpCurve::Ed448,
            Base64UrlBytes::new(vec![0; 57]),
            Base64UrlBytes::new(vec![1; 114]),
        );
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_private_key_seed_extraction() {
        // Test seed extraction from extended format
        let seed = vec![1u8; 57];
        let public = vec![2u8; 57];
        let mut extended = seed.clone();
        extended.extend_from_slice(&public);

        let params = OkpParams::new_private(
            OkpCurve::Ed448,
            Base64UrlBytes::new(vec![0; 57]),
            Base64UrlBytes::new(extended),
        );

        let extracted_seed = params.private_key_seed().unwrap();
        assert_eq!(extracted_seed, &seed[..]);
    }

    #[test]
    fn test_ed25519_extended_key_sizes() {
        // Ed25519 also supports extended format
        assert_eq!(OkpCurve::Ed25519.private_key_size(), 32);
        assert_eq!(OkpCurve::Ed25519.extended_private_key_size(), 64);
        assert!(OkpCurve::Ed25519.is_valid_private_key_size(32));
        assert!(OkpCurve::Ed25519.is_valid_private_key_size(64));
    }
}

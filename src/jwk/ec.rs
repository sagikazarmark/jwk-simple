//! Elliptic Curve key parameters as defined in RFC 7518 Section 6.2.
//!
//! This module contains the [`EcParams`] type which holds EC public and
//! private key components.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{Error, ParseError, Result, ValidationError};

/// Supported elliptic curves (RFC 7518 Section 6.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcCurve {
    /// NIST P-256 curve (secp256r1).
    #[serde(rename = "P-256")]
    P256,

    /// NIST P-384 curve (secp384r1).
    #[serde(rename = "P-384")]
    P384,

    /// NIST P-521 curve (secp521r1).
    #[serde(rename = "P-521")]
    P521,

    /// secp256k1 curve (Bitcoin/Ethereum).
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

impl EcCurve {
    /// Returns the coordinate size in bytes for this curve.
    pub fn coordinate_size(&self) -> usize {
        match self {
            EcCurve::P256 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66, // 521 bits = 66 bytes (rounded up)
            EcCurve::Secp256k1 => 32,
        }
    }

    /// Returns the curve name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
            EcCurve::P384 => "P-384",
            EcCurve::P521 => "P-521",
            EcCurve::Secp256k1 => "secp256k1",
        }
    }
}

impl std::str::FromStr for EcCurve {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "P-256" => Ok(EcCurve::P256),
            "P-384" => Ok(EcCurve::P384),
            "P-521" => Ok(EcCurve::P521),
            "secp256k1" => Ok(EcCurve::Secp256k1),
            _ => Err(Error::Parse(ParseError::UnknownCurve(s.to_string()))),
        }
    }
}

impl std::fmt::Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Elliptic Curve key parameters (RFC 7518 Section 6.2).
///
/// Contains the curve identifier and the public key coordinates `x` and `y`,
/// and optionally the private key scalar `d`.
///
/// # Examples
///
/// ```
/// use jwk_simple::jwk::{EcParams, EcCurve};
///
/// // Parse from JSON
/// let json = r#"{
///     "crv": "P-256",
///     "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
///     "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
/// }"#;
///
/// let params: EcParams = serde_json::from_str(json).unwrap();
/// assert_eq!(params.crv, EcCurve::P256);
/// assert!(params.is_public_key_only());
/// ```
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EcParams {
    /// The elliptic curve.
    #[zeroize(skip)]
    pub crv: EcCurve,

    /// The x coordinate of the public key point.
    pub x: Base64UrlBytes,

    /// The y coordinate of the public key point.
    pub y: Base64UrlBytes,

    /// The private key scalar (ECC private key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<Base64UrlBytes>,
}

impl EcParams {
    /// Creates new EC public key parameters.
    ///
    /// # Arguments
    ///
    /// * `crv` - The elliptic curve.
    /// * `x` - The x coordinate.
    /// * `y` - The y coordinate.
    pub fn new_public(crv: EcCurve, x: Base64UrlBytes, y: Base64UrlBytes) -> Self {
        Self { crv, x, y, d: None }
    }

    /// Creates new EC private key parameters.
    ///
    /// # Arguments
    ///
    /// * `crv` - The elliptic curve.
    /// * `x` - The x coordinate.
    /// * `y` - The y coordinate.
    /// * `d` - The private key scalar.
    pub fn new_private(
        crv: EcCurve,
        x: Base64UrlBytes,
        y: Base64UrlBytes,
        d: Base64UrlBytes,
    ) -> Self {
        Self {
            crv,
            x,
            y,
            d: Some(d),
        }
    }

    /// Returns `true` if this contains only public key parameters.
    pub fn is_public_key_only(&self) -> bool {
        self.d.is_none()
    }

    /// Returns `true` if this contains private key parameters.
    pub fn has_private_key(&self) -> bool {
        self.d.is_some()
    }

    /// Validates the EC parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The x coordinate size doesn't match the curve
    /// - The y coordinate size doesn't match the curve
    /// - The d parameter size doesn't match the curve (if present)
    pub fn validate(&self) -> Result<()> {
        let expected_size = self.crv.coordinate_size();

        // Validate x coordinate size
        if self.x.len() != expected_size {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: expected_size,
                actual: self.x.len(),
                context: "EC x coordinate",
            }));
        }

        // Validate y coordinate size
        if self.y.len() != expected_size {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: expected_size,
                actual: self.y.len(),
                context: "EC y coordinate",
            }));
        }

        // Validate d parameter size if present
        if let Some(ref d) = self.d
            && d.len() != expected_size
        {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: expected_size,
                actual: d.len(),
                context: "EC private key d",
            }));
        }

        Ok(())
    }

    /// Extracts only the public key parameters.
    #[must_use]
    pub fn to_public(&self) -> Self {
        Self {
            crv: self.crv,
            x: self.x.clone(),
            y: self.y.clone(),
            d: None,
        }
    }

    /// Returns the uncompressed public key point (0x04 || x || y).
    ///
    /// This format is commonly used for key import in cryptographic libraries.
    #[must_use]
    pub fn to_uncompressed_point(&self) -> Vec<u8> {
        let mut point = Vec::with_capacity(1 + self.x.len() + self.y.len());
        point.push(0x04); // Uncompressed point indicator
        point.extend_from_slice(self.x.as_bytes());
        point.extend_from_slice(self.y.as_bytes());
        point
    }
}

impl std::fmt::Debug for EcParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcParams")
            .field("crv", &self.crv)
            .field("x", &format!("[{} bytes]", self.x.len()))
            .field("y", &format!("[{} bytes]", self.y.len()))
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl PartialEq for EcParams {
    fn eq(&self, other: &Self) -> bool {
        self.crv == other.crv && self.x == other.x && self.y == other.y && self.d == other.d
    }
}

impl Eq for EcParams {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_coordinate_sizes() {
        assert_eq!(EcCurve::P256.coordinate_size(), 32);
        assert_eq!(EcCurve::P384.coordinate_size(), 48);
        assert_eq!(EcCurve::P521.coordinate_size(), 66);
        assert_eq!(EcCurve::Secp256k1.coordinate_size(), 32);
    }

    #[test]
    fn test_public_key_only() {
        let params = EcParams::new_public(
            EcCurve::P256,
            Base64UrlBytes::new(vec![0; 32]),
            Base64UrlBytes::new(vec![0; 32]),
        );
        assert!(params.is_public_key_only());
        assert!(!params.has_private_key());
    }

    #[test]
    fn test_validate_wrong_size() {
        let params = EcParams::new_public(
            EcCurve::P256,
            Base64UrlBytes::new(vec![0; 31]), // Wrong size
            Base64UrlBytes::new(vec![0; 32]),
        );
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_uncompressed_point() {
        let x = vec![1; 32];
        let y = vec![2; 32];
        let params = EcParams::new_public(
            EcCurve::P256,
            Base64UrlBytes::new(x.clone()),
            Base64UrlBytes::new(y.clone()),
        );

        let point = params.to_uncompressed_point();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], &x);
        assert_eq!(&point[33..], &y);
    }

    #[test]
    fn test_curve_parsing() {
        assert_eq!("P-256".parse::<EcCurve>().unwrap(), EcCurve::P256);
        assert_eq!("P-384".parse::<EcCurve>().unwrap(), EcCurve::P384);
        assert_eq!("P-521".parse::<EcCurve>().unwrap(), EcCurve::P521);
        assert_eq!("secp256k1".parse::<EcCurve>().unwrap(), EcCurve::Secp256k1);
        assert!("unknown".parse::<EcCurve>().is_err());
    }
}

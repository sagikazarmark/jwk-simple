//! Symmetric key parameters as defined in RFC 7518 Section 6.4.
//!
//! This module contains the [`SymmetricParams`] type which holds symmetric
//! key material for algorithms like HMAC and AES.

use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{Error, Result, ValidationError};

/// Symmetric key parameters (RFC 7518 Section 6.4).
///
/// Contains the raw symmetric key value `k`.
///
/// # Security Note
///
/// The key material is automatically zeroed from memory when this type is dropped.
/// For secret comparisons, prefer [`SymmetricParams::ct_eq`] over [`PartialEq`].
///
/// # Examples
///
/// ```
/// use jwk_simple::jwk::SymmetricParams;
///
/// // Parse from JSON
/// let json = r#"{"k": "GawgguFyGrWKav7AX4VKUg"}"#;
///
/// let params: SymmetricParams = serde_json::from_str(json).unwrap();
/// assert_eq!(params.key_size_bits(), 128);
/// ```
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricParams {
    /// The symmetric key value.
    pub k: Base64UrlBytes,
}

impl SymmetricParams {
    /// Creates new symmetric key parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::jwk::SymmetricParams;
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// // Create a 256-bit key
    /// let key_bytes = vec![0u8; 32];
    /// let params = SymmetricParams::new(Base64UrlBytes::new(key_bytes));
    /// assert_eq!(params.key_size_bits(), 256);
    /// ```
    pub fn new(k: Base64UrlBytes) -> Self {
        Self { k }
    }

    /// Returns `false` because symmetric keys are always considered "private".
    ///
    /// Symmetric keys don't have separate public and private components -
    /// the key material itself is always secret.
    pub fn is_public_key_only(&self) -> bool {
        false
    }

    /// Returns `true` because symmetric keys always contain the secret key material.
    pub fn has_private_key(&self) -> bool {
        true
    }

    /// Returns the key size in bits.
    pub fn key_size_bits(&self) -> usize {
        self.k.len() * 8
    }

    /// Validates the symmetric key parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::jwk::SymmetricParams;
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let valid_params = SymmetricParams::new(Base64UrlBytes::new(vec![1, 2, 3]));
    /// assert!(valid_params.validate().is_ok());
    ///
    /// let invalid_params = SymmetricParams::new(Base64UrlBytes::new(vec![]));
    /// assert!(invalid_params.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.k.is_empty() {
            return Err(Error::Validation(ValidationError::MissingParameter("k")));
        }
        Ok(())
    }

    /// Validates that the key size is appropriate for the given algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is smaller than required.
    pub fn validate_min_size(&self, min_bits: usize) -> Result<()> {
        self.validate()?;

        let actual_bits = self.key_size_bits();
        if actual_bits < min_bits {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: min_bits / 8,
                actual: self.k.len(),
                context: "symmetric key",
            }));
        }
        Ok(())
    }

    /// Validates that the key has exactly the required size.
    ///
    /// # Errors
    ///
    /// Returns an error if the key size differs from the required size.
    pub fn validate_exact_size(&self, exact_bits: usize, context: &'static str) -> Result<()> {
        self.validate()?;

        let actual_bits = self.key_size_bits();
        if actual_bits != exact_bits {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: exact_bits / 8,
                actual: self.k.len(),
                context,
            }));
        }

        Ok(())
    }

    /// Performs a constant-time equality comparison of the key material.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.k.ct_eq(&other.k)
    }
}

impl Debug for SymmetricParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never show the actual key value in debug output
        f.debug_struct("SymmetricParams")
            .field("key_size_bits", &self.key_size_bits())
            .finish()
    }
}

impl PartialEq for SymmetricParams {
    fn eq(&self, other: &Self) -> bool {
        self.k == other.k
    }
}

impl Eq for SymmetricParams {}

impl Hash for SymmetricParams {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.k.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_size() {
        let params = SymmetricParams::new(Base64UrlBytes::new(vec![0; 32]));
        assert_eq!(params.key_size_bits(), 256);
    }

    #[test]
    fn test_validate_empty() {
        let params = SymmetricParams::new(Base64UrlBytes::new(vec![]));
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_min_size() {
        let small_key = SymmetricParams::new(Base64UrlBytes::new(vec![0; 16]));
        assert!(small_key.validate_min_size(128).is_ok());
        assert!(small_key.validate_min_size(256).is_err());
    }

    #[test]
    fn test_validate_exact_size() {
        let key_128 = SymmetricParams::new(Base64UrlBytes::new(vec![0; 16]));
        assert!(key_128.validate_exact_size(128, "AES-128").is_ok());
        assert!(key_128.validate_exact_size(256, "AES-256").is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let original = SymmetricParams::new(Base64UrlBytes::new(vec![1, 2, 3, 4, 5]));
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SymmetricParams = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_constant_time_equality() {
        let a = SymmetricParams::new(Base64UrlBytes::new(vec![0; 32]));
        let b = SymmetricParams::new(Base64UrlBytes::new(vec![0; 32]));
        let mut different = vec![0; 32];
        different[31] = 1;
        let c = SymmetricParams::new(Base64UrlBytes::new(different));

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}

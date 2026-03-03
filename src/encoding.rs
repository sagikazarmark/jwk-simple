//! Base64URL encoding utilities with security features.
//!
//! This module provides a [`Base64UrlBytes`] wrapper type that handles
//! base64url encoding/decoding (as required by RFC 7517) with automatic memory
//! zeroing for sensitive data.

use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Result;

/// A wrapper around raw bytes that serializes to/from base64url encoding.
///
/// This type provides:
/// - Base64url encoding without padding (per RFC 7517)
/// - Constant-time base64 operations via `base64ct`
/// - Automatic memory zeroing on drop via `zeroize`
/// - Explicit constant-time byte comparison via [`Base64UrlBytes::ct_eq`]
///
/// # Security Note
///
/// [`PartialEq`] for this type is a regular byte equality check and is not
/// guaranteed to be constant-time. For secret-dependent comparisons, use
/// [`Base64UrlBytes::ct_eq`].
///
/// # Examples
///
/// ```
/// use jwk_simple::encoding::Base64UrlBytes;
///
/// // Create from raw bytes
/// let bytes = Base64UrlBytes::new(vec![1, 2, 3, 4]);
///
/// // Serialize to JSON (base64url encoded)
/// let json = serde_json::to_string(&bytes).unwrap();
/// assert_eq!(json, "\"AQIDBA\"");
///
/// // Deserialize from JSON
/// let decoded: Base64UrlBytes = serde_json::from_str(&json).unwrap();
/// assert_eq!(decoded.as_bytes(), &[1, 2, 3, 4]);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Base64UrlBytes(Vec<u8>);

impl Base64UrlBytes {
    /// Creates a new `Base64UrlBytes` from raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::new(vec![0x01, 0x02, 0x03]);
    /// assert_eq!(bytes.len(), 3);
    /// ```
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Creates a `Base64UrlBytes` by decoding a base64url string.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not valid base64url.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::from_base64url("AQIDBA").unwrap();
    /// assert_eq!(bytes.as_bytes(), &[1, 2, 3, 4]);
    /// ```
    pub fn from_base64url(encoded: &str) -> Result<Self> {
        let decoded = Base64UrlUnpadded::decode_vec(encoded)?;
        Ok(Self(decoded))
    }

    /// Encodes the bytes as a base64url string (without padding).
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::new(vec![1, 2, 3, 4]);
    /// assert_eq!(bytes.to_base64url(), "AQIDBA");
    /// ```
    pub fn to_base64url(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    /// Returns a reference to the underlying bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::new(vec![1, 2, 3]);
    /// assert_eq!(bytes.as_bytes(), &[1, 2, 3]);
    /// ```
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the underlying bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::new(vec![1, 2, 3]);
    /// assert_eq!(bytes.len(), 3);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the underlying bytes are empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let empty = Base64UrlBytes::new(vec![]);
    /// assert!(empty.is_empty());
    ///
    /// let not_empty = Base64UrlBytes::new(vec![1]);
    /// assert!(!not_empty.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns the underlying bytes.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] to ensure they are
    /// zeroized on drop, preserving the security guarantees of this type.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let bytes = Base64UrlBytes::new(vec![1, 2, 3]);
    /// let raw = bytes.into_bytes();
    /// assert_eq!(&*raw, &vec![1, 2, 3]);
    /// ```
    #[inline]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        let mut s = self;
        Zeroizing::new(std::mem::take(&mut s.0))
    }

    /// Performs a constant-time equality comparison.
    ///
    /// Use this method for secret-dependent decisions.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl Debug for Base64UrlBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't print the actual bytes in debug output for security
        f.debug_tuple("Base64UrlBytes")
            .field(&format!("[{} bytes]", self.0.len()))
            .finish()
    }
}

impl PartialEq for Base64UrlBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Base64UrlBytes {}

impl ConstantTimeEq for Base64UrlBytes {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl Hash for Base64UrlBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<Vec<u8>> for Base64UrlBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for Base64UrlBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl AsRef<[u8]> for Base64UrlBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Base64UrlBytes {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for Base64UrlBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_base64url(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let bytes = Base64UrlBytes::new(original.clone());
        let encoded = bytes.to_base64url();
        let decoded = Base64UrlBytes::from_base64url(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), &original);
    }

    #[test]
    fn test_json_roundtrip() {
        let original = Base64UrlBytes::new(vec![1, 2, 3, 4]);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Base64UrlBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_empty_bytes() {
        let empty = Base64UrlBytes::new(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.to_base64url(), "");
    }

    #[test]
    fn test_constant_time_equality() {
        let a = Base64UrlBytes::new(vec![1, 2, 3, 4]);
        let b = Base64UrlBytes::new(vec![1, 2, 3, 4]);
        let c = Base64UrlBytes::new(vec![1, 2, 3, 5]);
        let d = Base64UrlBytes::new(vec![1, 2, 3]);

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d));
    }

    #[test]
    fn test_known_value() {
        // Test vector: "AQAB" is base64url for [1, 0, 1] (common RSA exponent 65537 in 3 bytes)
        // Actually [1, 0, 1] = 65537 = 0x010001
        let bytes = Base64UrlBytes::from_base64url("AQAB").unwrap();
        assert_eq!(bytes.as_bytes(), &[0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_from_base64url_invalid() {
        // Standard base64 padding is not valid base64url-unpadded
        assert!(Base64UrlBytes::from_base64url("AQAB==").is_err());
        // Invalid characters
        assert!(Base64UrlBytes::from_base64url("!!!").is_err());
    }
}

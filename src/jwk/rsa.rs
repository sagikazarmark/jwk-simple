//! RSA key parameters as defined in RFC 7518 Section 6.3.
//!
//! This module contains the [`RsaParams`] type which holds RSA public and
//! private key components, including support for multi-prime RSA keys.

use std::fmt::{self, Debug};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{IncompatibleKeyError, InvalidKeyError, Result};

/// Validates that a Base64urlUInt value uses canonical encoding.
///
/// RFC 7518 Section 2 defines Base64urlUInt as the base64url encoding of an
/// unsigned big-endian integer, which "MUST utilize the minimum number of
/// octets needed to represent the value." This means no leading zero bytes,
/// except for the value zero itself which is represented as a single zero byte.
fn validate_base64url_uint(value: &Base64UrlBytes, name: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(InvalidKeyError::InvalidParameter {
            name: "Base64urlUInt",
            reason: format!(
                "RFC 7518: '{}' must be a non-empty Base64urlUInt value",
                name
            ),
        }
        .into());
    }
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(InvalidKeyError::InvalidParameter {
            name: "Base64urlUInt",
            reason: format!(
                "RFC 7518: '{}' has non-canonical Base64urlUInt encoding (leading zero bytes)",
                name
            ),
        }
        .into());
    }
    Ok(())
}

/// Other primes info for multi-prime RSA keys (RFC 7518 Section 6.3.2.7).
///
/// When more than two prime factors are used, this structure holds the
/// additional prime factor information.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct RsaOtherPrime {
    /// Prime factor.
    pub r: Base64UrlBytes,

    /// Factor CRT exponent (d mod (r - 1)).
    pub d: Base64UrlBytes,

    /// Factor CRT coefficient (inverse of all preceding primes mod r).
    pub t: Base64UrlBytes,
}

impl RsaOtherPrime {
    /// Creates a new other prime info structure.
    pub fn new(r: Base64UrlBytes, d: Base64UrlBytes, t: Base64UrlBytes) -> Self {
        Self { r, d, t }
    }

    /// Validates the other prime parameters.
    pub fn validate(&self) -> Result<()> {
        if self.r.is_empty() {
            return Err(InvalidKeyError::MissingParameter("oth.r").into());
        }
        if self.d.is_empty() {
            return Err(InvalidKeyError::MissingParameter("oth.d").into());
        }
        if self.t.is_empty() {
            return Err(InvalidKeyError::MissingParameter("oth.t").into());
        }
        validate_base64url_uint(&self.r, "oth.r")?;
        validate_base64url_uint(&self.d, "oth.d")?;
        validate_base64url_uint(&self.t, "oth.t")?;
        Ok(())
    }
}

impl Debug for RsaOtherPrime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaOtherPrime")
            .field("r", &format!("[{} bytes]", self.r.len()))
            .field("d", &"[REDACTED]")
            .field("t", &"[REDACTED]")
            .finish()
    }
}

/// RSA key parameters (RFC 7518 Section 6.3).
///
/// Contains the public key parameters `n` (modulus) and `e` (exponent),
/// and optionally the private key parameters.
///
/// # Examples
///
/// ```
/// use jwk_simple::RsaParams;
///
/// // Parse from JSON
/// let json = r#"{
///     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
///     "e": "AQAB"
/// }"#;
///
/// let params: RsaParams = serde_json::from_str(json).unwrap();
/// assert!(params.is_public_key_only());
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct RsaParams {
    /// The modulus value for the RSA key.
    pub n: Base64UrlBytes,

    /// The exponent value for the RSA key.
    pub e: Base64UrlBytes,

    /// The private exponent value for the RSA private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<Base64UrlBytes>,

    /// The first prime factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<Base64UrlBytes>,

    /// The second prime factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Base64UrlBytes>,

    /// The first factor CRT exponent (d mod (p-1)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<Base64UrlBytes>,

    /// The second factor CRT exponent (d mod (q-1)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<Base64UrlBytes>,

    /// The first CRT coefficient (q^-1 mod p).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<Base64UrlBytes>,

    /// Other primes info for multi-prime RSA (RFC 7518 Section 6.3.2.7).
    ///
    /// This field is only used when the RSA key has more than two prime factors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oth: Option<Vec<RsaOtherPrime>>,
}

impl RsaParams {
    /// Creates new RSA public key parameters.
    #[must_use]
    pub fn new_public(n: Base64UrlBytes, e: Base64UrlBytes) -> Self {
        Self {
            n,
            e,
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            oth: None,
        }
    }

    /// Returns a builder for constructing RSA private key parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::RsaParams;
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let params = RsaParams::builder(
    ///     Base64UrlBytes::new(vec![1; 256]),
    ///     Base64UrlBytes::new(vec![1, 0, 1]),
    ///     Base64UrlBytes::new(vec![2; 256]),
    /// )
    /// .p(Base64UrlBytes::new(vec![3; 128]))
    /// .q(Base64UrlBytes::new(vec![4; 128]))
    /// .build();
    /// ```
    #[must_use]
    pub fn builder(n: Base64UrlBytes, e: Base64UrlBytes, d: Base64UrlBytes) -> RsaParamsBuilder {
        RsaParamsBuilder::new(n, e, d)
    }

    /// Creates new RSA private key parameters.
    ///
    /// For more complex key construction, prefer using [`RsaParams::builder`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_private(
        n: Base64UrlBytes,
        e: Base64UrlBytes,
        d: Base64UrlBytes,
        p: Option<Base64UrlBytes>,
        q: Option<Base64UrlBytes>,
        dp: Option<Base64UrlBytes>,
        dq: Option<Base64UrlBytes>,
        qi: Option<Base64UrlBytes>,
    ) -> Self {
        Self {
            n,
            e,
            d: Some(d),
            p,
            q,
            dp,
            dq,
            qi,
            oth: None,
        }
    }

    /// Creates new multi-prime RSA private key parameters.
    ///
    /// For more complex key construction, prefer using [`RsaParams::builder`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_multi_prime(
        n: Base64UrlBytes,
        e: Base64UrlBytes,
        d: Base64UrlBytes,
        p: Base64UrlBytes,
        q: Base64UrlBytes,
        dp: Base64UrlBytes,
        dq: Base64UrlBytes,
        qi: Base64UrlBytes,
        oth: Vec<RsaOtherPrime>,
    ) -> Self {
        Self {
            n,
            e,
            d: Some(d),
            p: Some(p),
            q: Some(q),
            dp: Some(dp),
            dq: Some(dq),
            qi: Some(qi),
            oth: Some(oth),
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

    /// Returns the key size in bits.
    ///
    /// This is calculated from the modulus `n`.
    pub fn key_size_bits(&self) -> usize {
        let bytes = self.n.as_bytes();
        if bytes.is_empty() {
            return 0;
        }

        let mut idx = 0;
        while idx < bytes.len() && bytes[idx] == 0 {
            idx += 1;
        }
        if idx == bytes.len() {
            return 0;
        }

        let first = bytes[idx];
        let leading_zeros = first.leading_zeros() as usize;
        ((bytes.len() - idx - 1) * 8) + (8 - leading_zeros)
    }

    /// Validates the RSA parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The modulus `n` is empty
    /// - The exponent `e` is empty
    /// - Any integer field uses non-canonical Base64urlUInt encoding (leading zero bytes)
    /// - Private key parameters are partially present
    /// - Multi-prime `oth` parameter present without CRT parameters
    pub fn validate(&self) -> Result<()> {
        // Modulus must not be empty
        if self.n.is_empty() {
            return Err(InvalidKeyError::MissingParameter("n").into());
        }

        // Exponent must not be empty
        if self.e.is_empty() {
            return Err(InvalidKeyError::MissingParameter("e").into());
        }

        // RFC 7518 Section 2: Base64urlUInt values MUST use the minimum number
        // of octets to represent the value. Reject non-canonical encodings
        // (leading zero bytes) which could cause thumbprint mismatches.
        validate_base64url_uint(&self.n, "n")?;
        validate_base64url_uint(&self.e, "e")?;

        // Basic RSA public parameter sanity checks.
        // n must be non-zero; e must be odd and at least 3.
        if self.n.as_bytes().iter().all(|&b| b == 0) {
            return Err(InvalidKeyError::InvalidParameter {
                name: "n",
                reason: "RSA modulus must be non-zero".to_string(),
            }
            .into());
        }

        let e_bytes = self.e.as_bytes();
        let is_odd = (e_bytes[e_bytes.len() - 1] & 1) == 1;
        let ge_three = if e_bytes.len() > 1 {
            true
        } else {
            e_bytes[0] >= 3
        };

        if !ge_three || !is_odd {
            return Err(InvalidKeyError::InvalidParameter {
                name: "e",
                reason: "RSA public exponent must be odd and >= 3".to_string(),
            }
            .into());
        }

        if let Some(ref d) = self.d {
            validate_base64url_uint(d, "d")?;
        }
        if let Some(ref p) = self.p {
            validate_base64url_uint(p, "p")?;
        }
        if let Some(ref q) = self.q {
            validate_base64url_uint(q, "q")?;
        }
        if let Some(ref dp) = self.dp {
            validate_base64url_uint(dp, "dp")?;
        }
        if let Some(ref dq) = self.dq {
            validate_base64url_uint(dq, "dq")?;
        }
        if let Some(ref qi) = self.qi {
            validate_base64url_uint(qi, "qi")?;
        }

        // If d is present, validate consistency
        if self.d.is_some() {
            // If any CRT parameter is present, all should be present (RFC 7518 recommendation)
            let has_crt = self.p.is_some()
                || self.q.is_some()
                || self.dp.is_some()
                || self.dq.is_some()
                || self.qi.is_some();

            let has_all_crt = self.p.is_some()
                && self.q.is_some()
                && self.dp.is_some()
                && self.dq.is_some()
                && self.qi.is_some();

            if has_crt && !has_all_crt {
                return Err(InvalidKeyError::InconsistentParameters(
                    "RSA CRT parameters must all be present or all be absent".to_string(),
                )
                .into());
            }

            // RFC 7518 Section 6.3.2.7: oth requires all CRT parameters
            if self.oth.is_some() && !has_all_crt {
                return Err(InvalidKeyError::InconsistentParameters(
                    "RSA 'oth' parameter requires all CRT parameters (p, q, dp, dq, qi)"
                        .to_string(),
                )
                .into());
            }

            // Validate each entry in oth
            if let Some(ref oth) = self.oth {
                if oth.is_empty() {
                    return Err(InvalidKeyError::InvalidParameter {
                        name: "oth",
                        reason: "RFC 7518: 'oth' must contain one or more entries when present"
                            .to_string(),
                    }
                    .into());
                }
                for (i, prime) in oth.iter().enumerate() {
                    prime.validate().map_err(|e| {
                        if let crate::Error::InvalidKey(source) = e {
                            InvalidKeyError::InvalidOtherPrime {
                                index: i,
                                source: Box::new(source),
                            }
                        } else {
                            InvalidKeyError::InconsistentParameters(format!(
                                "Invalid oth[{}]: {}",
                                i, e
                            ))
                        }
                    })?;
                }
            }
        } else {
            // If d is not present, no other private params should be present
            if self.p.is_some()
                || self.q.is_some()
                || self.dp.is_some()
                || self.dq.is_some()
                || self.qi.is_some()
                || self.oth.is_some()
            {
                return Err(InvalidKeyError::InconsistentParameters(
                    "CRT parameters present without private exponent d".to_string(),
                )
                .into());
            }
        }

        Ok(())
    }

    /// Validates the RSA key size meets minimum requirements.
    ///
    /// RFC 7518 recommends RSA keys be at least 2048 bits.
    ///
    /// # Errors
    ///
    /// Returns an error if the key size is below the minimum.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::RsaParams;
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let mut modulus = vec![0; 256];
    /// modulus[0] = 0x80;
    /// let params = RsaParams::new_public(
    ///     Base64UrlBytes::new(modulus), // 2048 bits
    ///     Base64UrlBytes::new(vec![1, 0, 1]),
    /// );
    /// assert!(params.validate_key_size(2048).is_ok());
    /// assert!(params.validate_key_size(4096).is_err());
    /// ```
    pub fn validate_key_size(&self, min_bits: usize) -> Result<()> {
        let actual_bits = self.key_size_bits();
        if actual_bits < min_bits {
            return Err(IncompatibleKeyError::InsufficientKeyStrength {
                minimum_bits: min_bits,
                actual_bits,
                context: "RSA modulus",
            }
            .into());
        }
        Ok(())
    }

    /// Returns `true` if this is a multi-prime RSA key.
    ///
    /// Multi-prime RSA keys have more than two prime factors, indicated
    /// by the presence of the `oth` parameter.
    pub fn is_multi_prime(&self) -> bool {
        self.oth.is_some()
    }

    /// Extracts only the public key parameters.
    #[must_use]
    pub fn to_public(&self) -> Self {
        Self {
            n: self.n.clone(),
            e: self.e.clone(),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            oth: None,
        }
    }
}

/// Builder for constructing RSA private key parameters.
///
/// This builder provides a fluent API for constructing RSA private keys
/// with optional CRT (Chinese Remainder Theorem) parameters.
///
/// # Examples
///
/// ```
/// use jwk_simple::RsaParams;
/// use jwk_simple::encoding::Base64UrlBytes;
///
/// // Build a private key with CRT parameters
/// let params = RsaParams::builder(
///     Base64UrlBytes::new(vec![1; 256]),  // n (modulus)
///     Base64UrlBytes::new(vec![1, 0, 1]), // e (exponent)
///     Base64UrlBytes::new(vec![2; 256]),  // d (private exponent)
/// )
/// .p(Base64UrlBytes::new(vec![3; 128]))
/// .q(Base64UrlBytes::new(vec![4; 128]))
/// .dp(Base64UrlBytes::new(vec![5; 128]))
/// .dq(Base64UrlBytes::new(vec![6; 128]))
/// .qi(Base64UrlBytes::new(vec![7; 128]))
/// .build();
///
/// assert!(params.has_private_key());
/// ```
// Safety: `Base64UrlBytes` implements a redacted `Debug` that only prints
// the byte count (e.g. `Base64UrlBytes([32 bytes])`), so derived `Debug`
// here will never expose private key material (d, p, q, dp, dq, qi).
#[derive(Clone, Debug)]
pub struct RsaParamsBuilder {
    n: Base64UrlBytes,
    e: Base64UrlBytes,
    d: Base64UrlBytes,
    p: Option<Base64UrlBytes>,
    q: Option<Base64UrlBytes>,
    dp: Option<Base64UrlBytes>,
    dq: Option<Base64UrlBytes>,
    qi: Option<Base64UrlBytes>,
    oth: Option<Vec<RsaOtherPrime>>,
}

impl RsaParamsBuilder {
    /// Creates a new builder with required parameters.
    #[must_use]
    fn new(n: Base64UrlBytes, e: Base64UrlBytes, d: Base64UrlBytes) -> Self {
        Self {
            n,
            e,
            d,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            oth: None,
        }
    }

    /// Sets the first prime factor.
    #[must_use]
    pub fn p(mut self, p: Base64UrlBytes) -> Self {
        self.p = Some(p);
        self
    }

    /// Sets the second prime factor.
    #[must_use]
    pub fn q(mut self, q: Base64UrlBytes) -> Self {
        self.q = Some(q);
        self
    }

    /// Sets the first factor CRT exponent (d mod (p-1)).
    #[must_use]
    pub fn dp(mut self, dp: Base64UrlBytes) -> Self {
        self.dp = Some(dp);
        self
    }

    /// Sets the second factor CRT exponent (d mod (q-1)).
    #[must_use]
    pub fn dq(mut self, dq: Base64UrlBytes) -> Self {
        self.dq = Some(dq);
        self
    }

    /// Sets the first CRT coefficient (q^-1 mod p).
    #[must_use]
    pub fn qi(mut self, qi: Base64UrlBytes) -> Self {
        self.qi = Some(qi);
        self
    }

    /// Sets all CRT parameters at once.
    #[must_use]
    pub fn crt(
        mut self,
        p: Base64UrlBytes,
        q: Base64UrlBytes,
        dp: Base64UrlBytes,
        dq: Base64UrlBytes,
        qi: Base64UrlBytes,
    ) -> Self {
        self.p = Some(p);
        self.q = Some(q);
        self.dp = Some(dp);
        self.dq = Some(dq);
        self.qi = Some(qi);
        self
    }

    /// Sets the other primes info for multi-prime RSA keys.
    ///
    /// Note: Using `oth` requires all CRT parameters to be set.
    #[must_use]
    pub fn oth(mut self, oth: Vec<RsaOtherPrime>) -> Self {
        self.oth = Some(oth);
        self
    }

    /// Builds the RSA parameters.
    #[must_use]
    pub fn build(self) -> RsaParams {
        RsaParams {
            n: self.n,
            e: self.e,
            d: Some(self.d),
            p: self.p,
            q: self.q,
            dp: self.dp,
            dq: self.dq,
            qi: self.qi,
            oth: self.oth,
        }
    }
}

impl Debug for RsaParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaParams")
            .field("n", &format!("[{} bytes]", self.n.len()))
            .field("e", &self.e)
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_only() {
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params.is_public_key_only());
        assert!(!params.has_private_key());
    }

    #[test]
    fn test_validate_empty_modulus() {
        let params =
            RsaParams::new_public(Base64UrlBytes::new(vec![]), Base64UrlBytes::new(vec![1]));
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_zero_modulus_rejected() {
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![0]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_exponent_constraints() {
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1]),
        );
        assert!(params.validate().is_err(), "e=1 should be rejected");

        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![2]),
        );
        assert!(
            params.validate().is_err(),
            "even exponent should be rejected"
        );

        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![3]),
        );
        assert!(params.validate().is_ok(), "e=3 should be accepted");
    }

    #[test]
    fn test_validate_partial_crt() {
        let params = RsaParams {
            n: Base64UrlBytes::new(vec![1]),
            e: Base64UrlBytes::new(vec![1]),
            d: Some(Base64UrlBytes::new(vec![1])),
            p: Some(Base64UrlBytes::new(vec![1])),
            q: None, // Missing
            dp: None,
            dq: None,
            qi: None,
            oth: None,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_empty_private_integer() {
        let params = RsaParams {
            n: Base64UrlBytes::new(vec![1]),
            e: Base64UrlBytes::new(vec![1]),
            d: Some(Base64UrlBytes::new(vec![])),
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            oth: None,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_empty_oth_array() {
        let params = RsaParams {
            n: Base64UrlBytes::new(vec![1]),
            e: Base64UrlBytes::new(vec![1]),
            d: Some(Base64UrlBytes::new(vec![1])),
            p: Some(Base64UrlBytes::new(vec![1])),
            q: Some(Base64UrlBytes::new(vec![1])),
            dp: Some(Base64UrlBytes::new(vec![1])),
            dq: Some(Base64UrlBytes::new(vec![1])),
            qi: Some(Base64UrlBytes::new(vec![1])),
            oth: Some(vec![]),
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validate_preserves_typed_oth_errors_with_index() {
        let params = RsaParams {
            n: Base64UrlBytes::new(vec![1]),
            e: Base64UrlBytes::new(vec![3]),
            d: Some(Base64UrlBytes::new(vec![1])),
            p: Some(Base64UrlBytes::new(vec![1])),
            q: Some(Base64UrlBytes::new(vec![1])),
            dp: Some(Base64UrlBytes::new(vec![1])),
            dq: Some(Base64UrlBytes::new(vec![1])),
            qi: Some(Base64UrlBytes::new(vec![1])),
            oth: Some(vec![RsaOtherPrime::new(
                Base64UrlBytes::new(vec![]),
                Base64UrlBytes::new(vec![1]),
                Base64UrlBytes::new(vec![1]),
            )]),
        };

        let err = params.validate().unwrap_err();
        assert!(matches!(
            err,
            crate::Error::InvalidKey(InvalidKeyError::InvalidOtherPrime {
                index: 0,
                source
            }) if matches!(*source, InvalidKeyError::MissingParameter("oth.r"))
        ));
    }

    #[test]
    fn test_validate_canonical_base64url_uint() {
        // RFC 7518 Section 2: Base64urlUInt values MUST use minimum octets.
        // A modulus with a leading zero byte is non-canonical.
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![0, 1, 2, 3]), // leading zero = non-canonical
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        let result = params.validate();
        assert!(result.is_err(), "Leading zero byte in n should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Base64urlUInt") || err.contains("canonical"),
            "Error should mention canonical encoding: {}",
            err
        );

        // An exponent with a leading zero byte is also non-canonical
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![0, 1, 0, 1]), // leading zero = non-canonical
        );
        assert!(
            params.validate().is_err(),
            "Leading zero byte in e should be rejected"
        );

        // Single zero byte is canonical encoding for 0, but RSA modulus 0 is
        // semantically invalid and should be rejected.
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![0]), // single zero = canonical representation of 0
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(
            params.validate().is_err(),
            "RSA modulus 0 should be rejected as semantically invalid"
        );

        // Canonical values should pass
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(
            params.validate().is_ok(),
            "Canonical values should pass validation"
        );
    }

    #[test]
    fn test_validate_key_size() {
        // 2048-bit key (256 bytes)
        let mut n_2048 = vec![0; 256];
        n_2048[0] = 0x80; // ensure exact 2048-bit length
        let params_2048 = RsaParams::new_public(
            Base64UrlBytes::new(n_2048),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params_2048.validate_key_size(2048).is_ok());
        assert!(params_2048.validate_key_size(4096).is_err());

        // 1024-bit key (128 bytes) - too small
        let mut n_1024 = vec![0; 128];
        n_1024[0] = 0x80; // ensure exact 1024-bit length
        let params_1024 = RsaParams::new_public(
            Base64UrlBytes::new(n_1024),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params_1024.validate_key_size(2048).is_err());
    }

    #[test]
    fn test_multi_prime_detection() {
        let public_key =
            RsaParams::new_public(Base64UrlBytes::new(vec![1]), Base64UrlBytes::new(vec![1]));
        assert!(!public_key.is_multi_prime());

        let standard_private = RsaParams::new_private(
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Some(Base64UrlBytes::new(vec![1])),
            Some(Base64UrlBytes::new(vec![1])),
            Some(Base64UrlBytes::new(vec![1])),
            Some(Base64UrlBytes::new(vec![1])),
            Some(Base64UrlBytes::new(vec![1])),
        );
        assert!(!standard_private.is_multi_prime());

        let multi_prime = RsaParams::new_multi_prime(
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            Base64UrlBytes::new(vec![1]),
            vec![RsaOtherPrime::new(
                Base64UrlBytes::new(vec![1]),
                Base64UrlBytes::new(vec![1]),
                Base64UrlBytes::new(vec![1]),
            )],
        );
        assert!(multi_prime.is_multi_prime());
    }
}

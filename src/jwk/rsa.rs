//! RSA key parameters as defined in RFC 7518 Section 6.3.
//!
//! This module contains the [`RsaParams`] type which holds RSA public and
//! private key components, including support for multi-prime RSA keys.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::Base64UrlBytes;
use crate::error::{Error, Result, ValidationError};

/// Other primes info for multi-prime RSA keys (RFC 7518 Section 6.3.2.7).
///
/// When more than two prime factors are used, this structure holds the
/// additional prime factor information.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
            return Err(Error::Validation(ValidationError::MissingParameter(
                "oth.r",
            )));
        }
        if self.d.is_empty() {
            return Err(Error::Validation(ValidationError::MissingParameter(
                "oth.d",
            )));
        }
        if self.t.is_empty() {
            return Err(Error::Validation(ValidationError::MissingParameter(
                "oth.t",
            )));
        }
        Ok(())
    }
}

impl std::fmt::Debug for RsaOtherPrime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaOtherPrime")
            .field("r", &format!("[{} bytes]", self.r.len()))
            .field("d", &"[REDACTED]")
            .field("t", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for RsaOtherPrime {
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.d == other.d && self.t == other.t
    }
}

impl Eq for RsaOtherPrime {}

impl std::hash::Hash for RsaOtherPrime {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.r.hash(state);
        self.d.hash(state);
        self.t.hash(state);
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
/// use jwk_simple::jwk::RsaParams;
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
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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
    ///
    /// # Arguments
    ///
    /// * `n` - The modulus.
    /// * `e` - The public exponent.
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
    /// # Arguments
    ///
    /// * `n` - The modulus.
    /// * `e` - The public exponent.
    /// * `d` - The private exponent.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::jwk::RsaParams;
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
        self.n.len() * 8
    }

    /// Validates the RSA parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The modulus `n` is empty
    /// - The exponent `e` is empty
    /// - Private key parameters are partially present
    /// - Multi-prime `oth` parameter present without CRT parameters
    pub fn validate(&self) -> Result<()> {
        // Modulus must not be empty
        if self.n.is_empty() {
            return Err(Error::Validation(ValidationError::MissingParameter("n")));
        }

        // Exponent must not be empty
        if self.e.is_empty() {
            return Err(Error::Validation(ValidationError::MissingParameter("e")));
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
                return Err(Error::Validation(ValidationError::InconsistentParameters(
                    "RSA CRT parameters must all be present or all be absent".to_string(),
                )));
            }

            // RFC 7518 Section 6.3.2.7: oth requires all CRT parameters
            if self.oth.is_some() && !has_all_crt {
                return Err(Error::Validation(ValidationError::InconsistentParameters(
                    "RSA 'oth' parameter requires all CRT parameters (p, q, dp, dq, qi)"
                        .to_string(),
                )));
            }

            // Validate each entry in oth
            if let Some(ref oth) = self.oth {
                for (i, prime) in oth.iter().enumerate() {
                    prime.validate().map_err(|e| {
                        Error::Validation(ValidationError::InconsistentParameters(format!(
                            "Invalid oth[{}]: {}",
                            i, e
                        )))
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
                return Err(Error::Validation(ValidationError::InconsistentParameters(
                    "CRT parameters present without private exponent d".to_string(),
                )));
            }
        }

        Ok(())
    }

    /// Validates the RSA key size meets minimum requirements.
    ///
    /// RFC 7518 recommends RSA keys be at least 2048 bits.
    ///
    /// # Arguments
    ///
    /// * `min_bits` - Minimum required key size in bits.
    ///
    /// # Errors
    ///
    /// Returns an error if the key size is below the minimum.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::jwk::RsaParams;
    /// use jwk_simple::encoding::Base64UrlBytes;
    ///
    /// let params = RsaParams::new_public(
    ///     Base64UrlBytes::new(vec![0; 256]), // 2048 bits
    ///     Base64UrlBytes::new(vec![1, 0, 1]),
    /// );
    /// assert!(params.validate_key_size(2048).is_ok());
    /// assert!(params.validate_key_size(4096).is_err());
    /// ```
    pub fn validate_key_size(&self, min_bits: usize) -> Result<()> {
        let actual_bits = self.key_size_bits();
        if actual_bits < min_bits {
            return Err(Error::Validation(ValidationError::InvalidKeySize {
                expected: min_bits / 8,
                actual: self.n.len(),
                context: "RSA modulus",
            }));
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

    /// Returns the number of prime factors.
    ///
    /// - Returns 0 for public keys (no prime factors present)
    /// - Returns 2 for standard private keys
    /// - Returns 2 + len(oth) for multi-prime keys
    pub fn prime_count(&self) -> usize {
        if self.p.is_none() || self.q.is_none() {
            0
        } else {
            2 + self.oth.as_ref().map_or(0, |o| o.len())
        }
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
/// use jwk_simple::jwk::RsaParams;
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
#[derive(Clone)]
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

impl std::fmt::Debug for RsaParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaParams")
            .field("n", &format!("[{} bytes]", self.n.len()))
            .field("e", &self.e)
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl PartialEq for RsaParams {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n
            && self.e == other.e
            && self.d == other.d
            && self.p == other.p
            && self.q == other.q
            && self.dp == other.dp
            && self.dq == other.dq
            && self.qi == other.qi
            && self.oth == other.oth
    }
}

impl Eq for RsaParams {}

impl std::hash::Hash for RsaParams {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.n.hash(state);
        self.e.hash(state);
        self.d.hash(state);
        self.p.hash(state);
        self.q.hash(state);
        self.dp.hash(state);
        self.dq.hash(state);
        self.qi.hash(state);
        self.oth.hash(state);
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
    fn test_validate_key_size() {
        // 2048-bit key (256 bytes)
        let params_2048 = RsaParams::new_public(
            Base64UrlBytes::new(vec![0; 256]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params_2048.validate_key_size(2048).is_ok());
        assert!(params_2048.validate_key_size(4096).is_err());

        // 1024-bit key (128 bytes) - too small
        let params_1024 = RsaParams::new_public(
            Base64UrlBytes::new(vec![0; 128]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        assert!(params_1024.validate_key_size(2048).is_err());
    }

    #[test]
    fn test_multi_prime_detection() {
        let public_key =
            RsaParams::new_public(Base64UrlBytes::new(vec![1]), Base64UrlBytes::new(vec![1]));
        assert!(!public_key.is_multi_prime());
        assert_eq!(public_key.prime_count(), 0);

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
        assert_eq!(standard_private.prime_count(), 2);

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
        assert_eq!(multi_prime.prime_count(), 3);
    }
}

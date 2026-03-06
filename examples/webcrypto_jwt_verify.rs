//! Example: JWT verification using jwk-simple + WebCrypto
//!
//! This example demonstrates how to use jwk-simple for JWK/JWKS management
//! while using the browser's native WebCrypto API for JWT signature verification.
//!
//! This approach is useful when you want:
//! - Lightweight JWT verification without a full JWT library
//! - Browser-native cryptographic operations (better performance, security)
//! - Full control over the verification process
//!
//! # Running this example
//!
//! This example is designed for WASM environments. To run it:
//!
//! 1. Build with wasm-pack:
//!    ```sh
//!    wasm-pack build --target web --features web-crypto
//!    ```
//!
//! 2. Use in a web page or with wasm-bindgen-test
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │   JWKS      │────►│  jwk-simple  │────►│  web_sys::      │
//! │  (JSON)     │     │  (parsing)   │     │  CryptoKey      │
//! └─────────────┘     └──────────────┘     └────────┬────────┘
//!                                                   │
//! ┌─────────────┐     ┌──────────────┐              │
//! │    JWT      │────►│  Hand-craft  │              │
//! │  (token)    │     │  (parsing)   │              │
//! └─────────────┘     └──────┬───────┘              │
//!                            │                      │
//!                            ▼                      ▼
//!                     ┌──────────────────────────────────┐
//!                     │  SubtleCrypto.verify()           │
//!                     │  (browser-native verification)   │
//!                     └──────────────────────────────────┘
//! ```

// This example only works on wasm32 targets.
// On native targets, we provide an empty main so the crate still compiles.
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("This example only runs on wasm32 targets.");
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(target_arch = "wasm32")]
mod wasm_example {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use js_sys::Uint8Array;
    use jwk_simple::{
        Algorithm, Key, KeyMatcher, KeyOperation, KeySet, SelectionError, web_crypto,
    };
    use serde::{Deserialize, Serialize};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    // ============================================================================
    // JWT Types (hand-crafted, minimal)
    // ============================================================================

    /// JWT Header (minimal fields for verification)
    #[derive(Debug, Deserialize)]
    pub struct JwtHeader {
        /// Algorithm used for signing
        pub alg: String,
        /// Key ID (used to find the right key in JWKS)
        pub kid: Option<String>,
        /// Token type (usually "JWT")
        #[serde(default)]
        #[allow(dead_code)]
        pub typ: Option<String>,
    }

    /// Standard JWT claims (minimal set)
    #[derive(Debug, Serialize, Deserialize)]
    pub struct JwtClaims {
        /// Issuer
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        /// Subject
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub: Option<String>,
        /// Audience
        #[serde(skip_serializing_if = "Option::is_none")]
        pub aud: Option<StringOrArray>,
        /// Expiration time (Unix timestamp)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub exp: Option<u64>,
        /// Not before (Unix timestamp)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nbf: Option<u64>,
        /// Issued at (Unix timestamp)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iat: Option<u64>,
        /// JWT ID
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
    }

    /// Audience can be a string or array of strings
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum StringOrArray {
        String(String),
        Array(Vec<String>),
    }

    impl StringOrArray {
        pub fn contains(&self, value: &str) -> bool {
            match self {
                StringOrArray::String(s) => s == value,
                StringOrArray::Array(arr) => arr.iter().any(|s| s == value),
            }
        }
    }

    /// Parsed JWT with all three parts
    #[derive(Debug)]
    pub struct ParsedJwt {
        pub header: JwtHeader,
        pub claims: JwtClaims,
        /// The signing input (header.payload in base64url)
        pub signing_input: String,
        /// The decoded signature bytes
        pub signature: Vec<u8>,
    }

    /// JWT verification error
    #[derive(Debug)]
    pub enum JwtError {
        /// Invalid JWT format (not 3 parts)
        InvalidFormat,
        /// Base64 decoding failed
        Base64Error(String),
        /// JSON parsing failed
        JsonError(String),
        /// No matching key found in JWKS
        KeyNotFound,
        /// Key type not supported by WebCrypto
        UnsupportedKey(String),
        /// Signature verification failed
        InvalidSignature,
        /// WebCrypto operation failed
        CryptoError(String),
        /// Token has expired
        Expired,
        /// Token not yet valid (nbf)
        NotYetValid,
        /// Issuer mismatch
        InvalidIssuer,
        /// Audience mismatch
        InvalidAudience,
    }

    impl std::fmt::Display for JwtError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                JwtError::InvalidFormat => write!(f, "invalid JWT format"),
                JwtError::Base64Error(e) => write!(f, "base64 decode error: {}", e),
                JwtError::JsonError(e) => write!(f, "JSON parse error: {}", e),
                JwtError::KeyNotFound => write!(f, "no matching key found in JWKS"),
                JwtError::UnsupportedKey(reason) => write!(f, "unsupported key: {}", reason),
                JwtError::InvalidSignature => write!(f, "invalid signature"),
                JwtError::CryptoError(e) => write!(f, "crypto error: {}", e),
                JwtError::Expired => write!(f, "token has expired"),
                JwtError::NotYetValid => write!(f, "token is not yet valid"),
                JwtError::InvalidIssuer => write!(f, "invalid issuer"),
                JwtError::InvalidAudience => write!(f, "invalid audience"),
            }
        }
    }

    // ============================================================================
    // JWT Parsing (hand-crafted)
    // ============================================================================

    /// Decodes a base64url string (no padding)
    fn base64url_decode(input: &str) -> Result<Vec<u8>, JwtError> {
        Base64UrlUnpadded::decode_vec(input).map_err(|e| JwtError::Base64Error(format!("{:?}", e)))
    }

    /// Parses a JWT string into its components
    pub fn parse_jwt(token: &str) -> Result<ParsedJwt, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        let header_bytes = base64url_decode(parts[0])?;
        let payload_bytes = base64url_decode(parts[1])?;
        let signature = base64url_decode(parts[2])?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| JwtError::JsonError(e.to_string()))?;

        let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| JwtError::JsonError(e.to_string()))?;

        // The signing input is the first two parts joined by '.'
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        Ok(ParsedJwt {
            header,
            claims,
            signing_input,
            signature,
        })
    }

    // ============================================================================
    // WebCrypto Verification
    // ============================================================================

    /// Verifies a JWT signature using WebCrypto
    pub async fn verify_signature(
        jwt: &ParsedJwt,
        crypto_key: &web_sys::CryptoKey,
    ) -> Result<bool, JwtError> {
        let alg = Algorithm::from(jwt.header.alg.as_str());
        let algorithm = web_crypto::build_verify_algorithm(&alg)
            .map_err(|e| JwtError::CryptoError(e.to_string()))?;

        let subtle =
            web_crypto::get_subtle_crypto().map_err(|e| JwtError::CryptoError(e.to_string()))?;

        // Convert data to Uint8Array
        let data = jwt.signing_input.as_bytes();
        let data_array = Uint8Array::new_with_length(data.len() as u32);
        data_array.copy_from(data);

        // Convert signature to Uint8Array
        let sig_array = Uint8Array::new_with_length(jwt.signature.len() as u32);
        sig_array.copy_from(&jwt.signature);

        // Call SubtleCrypto.verify()
        let promise = subtle
            .verify_with_object_and_buffer_source_and_buffer_source(
                &algorithm,
                crypto_key,
                &sig_array,
                &data_array,
            )
            .map_err(|e| JwtError::CryptoError(format!("{:?}", e)))?;

        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JwtError::CryptoError(format!("{:?}", e)))?;

        Ok(result.as_bool().unwrap_or(false))
    }

    // ============================================================================
    // High-Level Verification API
    // ============================================================================

    /// Options for JWT verification
    pub struct VerifyOptions<'a> {
        /// Expected issuer (if set, must match)
        pub issuer: Option<&'a str>,
        /// Expected audience (if set, must be present)
        pub audience: Option<&'a str>,
        /// Whether to validate expiration (default: true)
        pub validate_exp: bool,
        /// Whether to validate not-before (default: true)
        pub validate_nbf: bool,
        /// Clock skew tolerance in seconds (default: 60)
        pub clock_skew: u64,
    }

    impl<'a> Default for VerifyOptions<'a> {
        fn default() -> Self {
            Self {
                issuer: None,
                audience: None,
                validate_exp: true,
                validate_nbf: true,
                clock_skew: 60,
            }
        }
    }

    impl<'a> VerifyOptions<'a> {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn with_issuer(mut self, issuer: &'a str) -> Self {
            self.issuer = Some(issuer);
            self
        }

        pub fn with_audience(mut self, audience: &'a str) -> Self {
            self.audience = Some(audience);
            self
        }
    }

    /// Gets the current Unix timestamp (seconds since epoch)
    fn current_timestamp() -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }

    /// Validates the JWT claims (expiration, issuer, audience, etc.)
    fn validate_claims(claims: &JwtClaims, options: &VerifyOptions) -> Result<(), JwtError> {
        let now = current_timestamp();

        // Check expiration
        if options.validate_exp {
            if let Some(exp) = claims.exp {
                let exp_with_skew = exp.saturating_add(options.clock_skew);
                if now > exp_with_skew {
                    return Err(JwtError::Expired);
                }
            }
        }

        // Check not-before
        if options.validate_nbf {
            if let Some(nbf) = claims.nbf {
                let now_with_skew = now.saturating_add(options.clock_skew);
                if now_with_skew < nbf {
                    return Err(JwtError::NotYetValid);
                }
            }
        }

        // Check issuer
        if let Some(expected_iss) = options.issuer {
            match &claims.iss {
                Some(iss) if iss == expected_iss => {}
                _ => return Err(JwtError::InvalidIssuer),
            }
        }

        // Check audience
        if let Some(expected_aud) = options.audience {
            match &claims.aud {
                Some(aud) if aud.contains(expected_aud) => {}
                _ => return Err(JwtError::InvalidAudience),
            }
        }

        Ok(())
    }

    /// Finds the appropriate key from a JWKS for verifying a JWT
    fn find_key_for_jwt<'a>(jwks: &'a KeySet, jwt: &ParsedJwt) -> Result<&'a Key, JwtError> {
        let alg = Algorithm::from(jwt.header.alg.as_str());

        // Strict selector path for JWT verification.
        let selector = jwks.selector(&[alg.clone()]);
        let matcher = KeyMatcher::new(KeyOperation::Verify, alg);

        let result = if let Some(kid) = jwt.header.kid.as_deref() {
            selector.select(matcher.with_kid(kid))
        } else {
            selector.select(matcher)
        };

        result.map_err(|err| match err {
            SelectionError::UnknownAlgorithm => {
                JwtError::UnsupportedKey("unsupported jwt alg".to_string())
            }
            SelectionError::NoMatchingKey => JwtError::KeyNotFound,
            SelectionError::AlgorithmNotAllowed => {
                JwtError::UnsupportedKey("jwt alg is not allowed for verification".to_string())
            }
            SelectionError::UnknownOperation => {
                JwtError::UnsupportedKey("unsupported key operation".to_string())
            }
            SelectionError::IncompatibleKeyType | SelectionError::KeySuitabilityFailed(_) => {
                JwtError::UnsupportedKey("no compatible key for jwt alg".to_string())
            }
            SelectionError::AmbiguousSelection { .. }
            | SelectionError::AlgorithmMismatch { .. }
            | SelectionError::IntentMismatch
            | SelectionError::InvalidKeyMetadata(_)
            | SelectionError::EmptyVerifyAllowlist
            | _ => JwtError::KeyNotFound,
        })
    }

    /// Verifies a JWT token using a JWKS
    ///
    /// This is the main entry point for JWT verification.
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT string (header.payload.signature)
    /// * `jwks` - The JSON Web Key Set to find the verification key
    /// * `options` - Verification options (issuer, audience, etc.)
    ///
    /// # Returns
    ///
    /// The verified JWT claims on success.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use jwk_simple::KeySet;
    ///
    /// let jwks: KeySet = serde_json::from_str(jwks_json)?;
    /// let options = VerifyOptions::new()
    ///     .with_issuer("https://auth.example.com")
    ///     .with_audience("my-app");
    ///
    /// let claims = verify_jwt(token, &jwks, &options).await?;
    /// println!("Subject: {:?}", claims.sub);
    /// ```
    pub async fn verify_jwt(
        token: &str,
        jwks: &KeySet,
        options: &VerifyOptions<'_>,
    ) -> Result<JwtClaims, JwtError> {
        // 1. Parse the JWT
        let jwt = parse_jwt(token)?;

        // 2. Find the appropriate key
        let key = find_key_for_jwt(jwks, &jwt)?;

        // 3. Check if the key is WebCrypto compatible
        if !key.is_web_crypto_compatible() {
            return Err(JwtError::UnsupportedKey(
                "key type not supported by WebCrypto".to_string(),
            ));
        }

        // 4. Import the key for verification using jwk-simple
        //    Use the algorithm from the JWT header to ensure the correct hash is used
        //    at import time, even if the key's `alg` field is absent.
        let alg = Algorithm::from(jwt.header.alg.as_str());
        let crypto_key = web_crypto::import_verify_key_for_alg(key, &alg)
            .await
            .map_err(|e| JwtError::CryptoError(e.to_string()))?;

        // 5. Verify the signature
        let valid = verify_signature(&jwt, &crypto_key).await?;
        if !valid {
            return Err(JwtError::InvalidSignature);
        }

        // 6. Validate claims
        validate_claims(&jwt.claims, options)?;

        Ok(jwt.claims)
    }

    // ============================================================================
    // Example Usage (for documentation)
    // ============================================================================

    /// Example: Verify a JWT from an OIDC provider
    #[wasm_bindgen]
    pub async fn example_verify_oidc_token(
        token: &str,
        jwks_json: &str,
    ) -> Result<String, JsValue> {
        // Parse the JWKS using jwk-simple
        let jwks: KeySet = serde_json::from_str(jwks_json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JWKS: {}", e)))?;

        // Set up verification options
        let options = VerifyOptions::new()
            .with_issuer("https://auth.example.com")
            .with_audience("my-application");

        // Verify the token
        let claims = verify_jwt(token, &jwks, &options)
            .await
            .map_err(|e| JsValue::from_str(&format!("Verification failed: {}", e)))?;

        // Return the subject claim
        Ok(claims.sub.unwrap_or_else(|| "unknown".to_string()))
    }

    // ============================================================================
    // Tests
    // ============================================================================

    #[cfg(test)]
    mod tests {
        use super::*;

        // Example JWKS (Google's public keys format)
        const EXAMPLE_JWKS: &str = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }
        ]
    }"#;

        #[test]
        fn test_parse_jwt_format() {
            // This is a structurally valid JWT (signature is fake)
            let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.fake_signature";

            // Just test that parsing doesn't panic on invalid signature base64
            // (the signature part "fake_signature" is not valid base64url but won't crash)
            let _ = parse_jwt(token);
        }

        #[test]
        fn test_invalid_jwt_format() {
            assert!(matches!(
                parse_jwt("not.a.valid.jwt.token"),
                Err(JwtError::InvalidFormat)
            ));
            assert!(matches!(
                parse_jwt("only-one-part"),
                Err(JwtError::InvalidFormat)
            ));
            assert!(matches!(
                parse_jwt("two.parts"),
                Err(JwtError::InvalidFormat)
            ));
        }

        #[test]
        fn test_find_key_by_kid() {
            let jwks: KeySet = serde_json::from_str(EXAMPLE_JWKS).unwrap();

            let jwt = ParsedJwt {
                header: JwtHeader {
                    alg: "RS256".to_string(),
                    kid: Some("test-key-1".to_string()),
                    typ: Some("JWT".to_string()),
                },
                claims: JwtClaims {
                    iss: None,
                    sub: None,
                    aud: None,
                    exp: None,
                    nbf: None,
                    iat: None,
                    jti: None,
                },
                signing_input: String::new(),
                signature: vec![],
            };

            let key = find_key_for_jwt(&jwks, &jwt).unwrap();
            assert_eq!(key.kid(), Some("test-key-1"));
        }

        #[test]
        fn test_unknown_alg_is_not_reported_as_key_not_found() {
            let jwks: KeySet = serde_json::from_str(EXAMPLE_JWKS).unwrap();

            let jwt = ParsedJwt {
                header: JwtHeader {
                    alg: "BADALG".to_string(),
                    kid: Some("test-key-1".to_string()),
                    typ: Some("JWT".to_string()),
                },
                claims: JwtClaims {
                    iss: None,
                    sub: None,
                    aud: None,
                    exp: None,
                    nbf: None,
                    iat: None,
                    jti: None,
                },
                signing_input: String::new(),
                signature: vec![],
            };

            let err = find_key_for_jwt(&jwks, &jwt).unwrap_err();
            assert!(matches!(err, JwtError::UnsupportedKey(_)));
        }
    }
}

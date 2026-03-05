//! RFC 7517 Compliance Tests
//!
//! These tests verify strict compliance with RFC 7517 (JSON Web Key)
//! requirements, particularly Section 4 parameter validation.

use jwk_simple::error::ValidationError;
use jwk_simple::{Algorithm, Error, Key, KeyOperation, KeySet, KeyType, KeyUse};

// ============================================================================
// Section 4.1: "kty" (Key Type) Parameter - REQUIRED
// ============================================================================

mod kty_parameter {
    use super::*;

    #[test]
    fn test_kty_is_required() {
        // Missing kty should fail to parse
        let json = r#"{"n": "AQAB", "e": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_kty_fails() {
        let json = r#"{"kty": "UNKNOWN", "n": "AQAB", "e": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_kty_case_sensitive() {
        // RFC 7517: kty values are case-sensitive
        let json = r#"{"kty": "rsa", "n": "AQAB", "e": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "kty should be case-sensitive ('RSA' not 'rsa')"
        );
    }

    #[test]
    fn test_valid_kty_values() {
        // RSA
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Rsa);

        // EC
        let json = r#"{"kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Ec);

        // oct (symmetric)
        let json = r#"{"kty": "oct", "k": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Symmetric);

        // OKP
        let json = r#"{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Okp);
    }
}

// ============================================================================
// Section 4.2: "use" (Public Key Use) Parameter
// ============================================================================

mod use_parameter {
    use super::*;

    #[test]
    fn test_use_sig() {
        let json = r#"{"kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.key_use, Some(KeyUse::Signature));
    }

    #[test]
    fn test_use_enc() {
        let json = r#"{"kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.key_use, Some(KeyUse::Encryption));
    }

    #[test]
    fn test_use_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.key_use, None);
    }
}

// ============================================================================
// Section 4.3: "key_ops" (Key Operations) Parameter
// ============================================================================

mod key_ops_parameter {
    use super::*;

    #[test]
    fn test_key_ops_array() {
        let json = r#"{"kty": "RSA", "key_ops": ["sign", "verify"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let ops = jwk.key_ops.as_ref().unwrap();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&KeyOperation::Sign));
        assert!(ops.contains(&KeyOperation::Verify));
    }

    #[test]
    fn test_key_ops_all_values() {
        let json = r#"{"kty": "oct", "key_ops": ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"], "k": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let ops = jwk.key_ops.as_ref().unwrap();
        let expected = [
            KeyOperation::Sign,
            KeyOperation::Verify,
            KeyOperation::Encrypt,
            KeyOperation::Decrypt,
            KeyOperation::WrapKey,
            KeyOperation::UnwrapKey,
            KeyOperation::DeriveKey,
            KeyOperation::DeriveBits,
        ];

        assert_eq!(ops.len(), expected.len());
        for op in expected {
            assert!(
                ops.contains(&op),
                "missing expected key_ops value: {:?}",
                op
            );
        }
    }

    #[test]
    fn test_key_ops_duplicates_rejected() {
        // RFC 7517 Section 4.3: "Duplicate key operation values MUST NOT be present in the array"
        let json = r#"{"kty": "RSA", "key_ops": ["sign", "sign"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Duplicate key_ops values should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InconsistentParameters(
                _
            )))
        ));
    }

    #[test]
    fn test_key_ops_and_use_consistent_accepted() {
        // RFC 7517 Section 4.3: "The 'use' and 'key_ops' JWK members SHOULD NOT
        // be used together; however, if both are used, the information they convey
        // MUST be consistent."
        // Consistent: use=sig with key_ops containing only sign/verify
        let json = r#"{"kty": "RSA", "use": "sig", "key_ops": ["sign", "verify"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Consistent 'use' and 'key_ops' should be accepted"
        );
    }

    #[test]
    fn test_key_ops_and_use_inconsistent_rejected() {
        // RFC 7517 Section 4.3: if both are used, they MUST be consistent.
        // Inconsistent: use=sig with key_ops containing encrypt
        let json =
            r#"{"kty": "RSA", "use": "sig", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Inconsistent 'use' and 'key_ops' should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InconsistentParameters(
                _
            )))
        ));
    }

    #[test]
    fn test_key_ops_and_use_enc_consistent_accepted() {
        // use=enc with key_ops containing only encryption-related operations
        let json = r#"{"kty": "RSA", "use": "enc", "key_ops": ["encrypt", "decrypt", "wrapKey", "unwrapKey"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Consistent 'use':'enc' and encryption key_ops should be accepted"
        );
    }

    #[test]
    fn test_key_ops_and_use_enc_inconsistent_rejected() {
        // use=enc with key_ops containing sign (a signature operation)
        let json = r#"{"kty": "RSA", "use": "enc", "key_ops": ["sign"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_err(),
            "Inconsistent 'use':'enc' with 'key_ops':['sign'] should be rejected"
        );
    }

    #[test]
    fn test_key_ops_empty_array_allowed() {
        let json = r#"{"kty": "RSA", "key_ops": [], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(jwk.key_ops.as_ref().unwrap().is_empty());
        // Empty key_ops is technically allowed (just means no operations permitted)
        assert!(jwk.validate_structure().is_ok());
    }
}

// ============================================================================
// Section 4.4: "alg" (Algorithm) Parameter
// ============================================================================

mod alg_parameter {
    use super::*;

    const RSA_2048_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    #[test]
    fn test_alg_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.alg, None);
    }

    #[test]
    fn test_alg_rsa_signing() {
        for (alg_str, alg_enum) in [
            ("RS256", Algorithm::Rs256),
            ("RS384", Algorithm::Rs384),
            ("RS512", Algorithm::Rs512),
            ("PS256", Algorithm::Ps256),
            ("PS384", Algorithm::Ps384),
            ("PS512", Algorithm::Ps512),
        ] {
            let json = format!(
                r#"{{"kty": "RSA", "alg": "{}", "n": "{}", "e": "AQAB"}}"#,
                alg_str, RSA_2048_N
            );
            let jwk: Key = serde_json::from_str(&json).unwrap();
            assert_eq!(jwk.alg, Some(alg_enum));
            assert!(
                jwk.validate_structure().is_ok(),
                "RSA key with {} should validate",
                alg_str
            );
        }
    }

    #[test]
    fn test_alg_ec_curve_mismatch_rejected() {
        // ES256 requires P-256 curve
        let json = r#"{"kty": "EC", "alg": "ES256", "crv": "P-384", "x": "iLyL6MBI9yiKz53NAu9zLRAL2F6MbEH5ElfsZ9bQGpAR9LfYP5p7Bz9p96pv1vyD", "y": "bOkP17tTpKmrbfmBdxUj6K4DFZ9LT99KyDyUjTjwbqq-Gd8MSNFTuuWJxBIqaIQW"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "ES256 with P-384 curve should be rejected");
    }

    #[test]
    fn test_alg_symmetric_type_mismatch_rejected() {
        // RS256 requires RSA key, not symmetric
        let json = r#"{"kty": "oct", "alg": "RS256", "k": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "RS256 with symmetric key should be rejected"
        );
    }

    #[test]
    fn test_alg_rsa_key_size_minimum_enforced() {
        // RS256 requires RSA modulus >= 2048 bits.
        let json = r#"{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_err(),
            "RS256 should reject RSA keys smaller than 2048 bits"
        );
    }

    #[test]
    fn test_alg_hs256_key_size_minimum_enforced() {
        // HS256 requires key length >= 256 bits.
        let json = r#"{"kty": "oct", "alg": "HS256", "k": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_err(),
            "HS256 should reject keys smaller than 256 bits"
        );
    }

    #[test]
    fn test_alg_ed25519_okp_ed25519_accepted() {
        let json = r#"{"kty": "OKP", "alg": "Ed25519", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.alg, Some(Algorithm::Ed25519));
        assert!(jwk.validate_structure().is_ok());
    }

    #[test]
    fn test_alg_ed448_okp_ed448_accepted() {
        let json = r#"{"kty": "OKP", "alg": "Ed448", "crv": "Ed448", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.alg, Some(Algorithm::Ed448));
        assert!(jwk.validate_structure().is_ok());
    }

    #[test]
    fn test_alg_ed25519_with_ed448_curve_mismatch_rejected() {
        let json = r#"{"kty": "OKP", "alg": "Ed25519", "crv": "Ed448", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Ed25519 algorithm with Ed448 key should fail"
        );
    }

    #[test]
    fn test_alg_ed448_with_ed25519_curve_mismatch_rejected() {
        let json = r#"{"kty": "OKP", "alg": "Ed448", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Ed448 algorithm with Ed25519 key should fail"
        );
    }

    #[test]
    fn test_alg_eddsa_is_deprecated_but_still_valid() {
        let json = r#"{"kty": "OKP", "alg": "EdDSA", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.alg, Some(Algorithm::EdDsa));
        assert!(jwk.alg.as_ref().unwrap().is_deprecated());
        assert!(jwk.validate_structure().is_ok());
    }
}

// ============================================================================
// Section 4.5: "kid" (Key ID) Parameter
// ============================================================================

mod kid_parameter {
    use super::*;

    #[test]
    fn test_kid_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kid, None);
    }

    #[test]
    fn test_kid_arbitrary_string() {
        let json = r#"{"kty": "RSA", "kid": "my-key-2024-01", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kid, Some("my-key-2024-01".to_string()));
    }

    #[test]
    fn test_kid_unicode() {
        let json = r#"{"kty": "RSA", "kid": "密钥-🔑", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kid, Some("密钥-🔑".to_string()));
    }
}

// ============================================================================
// Section 4.6: "x5u" (X.509 URL) Parameter
// ============================================================================

mod x5u_parameter {
    use super::*;

    #[test]
    fn test_x5u_https_required() {
        // RFC 7517 Section 4.6: "The protocol used to acquire the resource MUST
        // provide integrity protection; an HTTP GET request to retrieve the
        // certificate MUST use TLS"
        let json =
            r#"{"kty": "RSA", "x5u": "http://example.com/cert.pem", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "HTTP x5u URL should be rejected");
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5u",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5u_https_allowed() {
        let json =
            r#"{"kty": "RSA", "x5u": "https://example.com/cert.pem", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(jwk.validate_structure().is_ok());
    }

    #[test]
    fn test_x5u_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.x5u, None);
        assert!(jwk.validate_structure().is_ok());
    }
}

// ============================================================================
// Section 4.7: "x5c" (X.509 Certificate Chain) Parameter
// ============================================================================

mod x5c_parameter {
    use super::*;

    #[test]
    fn test_x5c_must_be_base64_not_base64url_hyphen() {
        // RFC 7517 Section 4.7: "Each string in the array is a base64-encoded
        // (Section 4 of [RFC4648] -- not base64url-encoded) DER"
        //
        // base64url uses '-' instead of '+', so a '-' indicates base64url (wrong)
        // This string contains a literal hyphen character
        let json = r#"{"kty": "RSA", "x5c": ["SGVs-G8="], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "base64url-encoded x5c (with hyphen) should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5c",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5c_must_be_base64_not_base64url_underscore() {
        // base64url uses '_' instead of '/', so a '_' indicates base64url (wrong)
        let json = r#"{"kty": "RSA", "x5c": ["SGVs_G8="], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "base64url-encoded x5c (with underscore) should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5c",
                ..
            }))
        ));
    }

    // A minimal self-signed X.509 certificate (DER-encoded, base64)
    // This is a valid certificate structure for testing purposes
    // Generated with: openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 -subj "/CN=test" -outform DER | base64
    const TEST_CERT: &str = "MIIBczCCARmgAwIBAgIUEZ4zOagIq49DPWyEEFfn0Q325qkwCgYIKoZIzj0EAwIwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMTkxODI1MTZaFw0yNzAxMTkxODI1MTZaMA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5eBAaA0NLl5d8mCtJNGHbnDUOdh27yD/NiFPij/tOYG4LJzblnvxO/pQPtuVbRV5pLUCK6fNGMhqIrRrGst8+o1MwUTAdBgNVHQ4EFgQUCifkjvMQSt/gmQ9h/4O8g8nqlF0wHwYDVR0jBBgwFoAUCifkjvMQSt/gmQ9h/4O8g8nqlF0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBW1y43qzwzG9MRIK5K6L9gPX4LBfjIjTbTyBYTctl1zQIhAIcqe6Be/xtw9bB+GEgA6LlSamnYJL56zNdPIciQDuMM";

    #[test]
    fn test_x5c_valid_der_certificate() {
        // RFC 7517: x5c must contain base64-encoded DER certificates
        let json = format!(
            r#"{{"kty": "RSA", "x5c": ["{}"], "n": "AQAB", "e": "AQAB"}}"#,
            TEST_CERT
        );
        let jwk: Key = serde_json::from_str(&json).unwrap();
        assert!(
            jwk.validate_structure().is_err(),
            "x5c certificate public key MUST match JWK key material"
        );
    }

    #[test]
    fn test_x5c_valid_der_certificate_with_matching_key() {
        // Same TEST_CERT, but with matching EC P-256 key material extracted from cert.
        let json = format!(
            r#"{{
                "kty": "EC",
                "crv": "P-256",
                "x5c": ["{}"],
                "x": "eXgQGgNDS5eXfJgrSTRh25w1DnYdu8g_zYhT4o_7TmA",
                "y": "bgsnNuWe_E7-lA-25VtFXmktQIrp80YyGoitGsay3z4"
            }}"#,
            TEST_CERT
        );
        let jwk: Key = serde_json::from_str(&json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Matching cert and JWK public key should validate"
        );
    }

    #[test]
    fn test_x5c_valid_base64_but_invalid_der() {
        // Valid base64 but NOT a valid DER certificate
        // "Hello" encoded as base64
        let json = r#"{"kty": "RSA", "x5c": ["SGVsbG8="], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "Non-DER data should be rejected");
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5c",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5c_valid_base64_with_plus_and_slash() {
        // Standard base64 uses '+' and '/' - the test cert contains these characters
        // Just verify parsing succeeds (the cert above naturally contains + and /)
        let json = format!(
            r#"{{
                "kty": "EC",
                "crv": "P-256",
                "x5c": ["{}"],
                "x": "eXgQGgNDS5eXfJgrSTRh25w1DnYdu8g_zYhT4o_7TmA",
                "y": "bgsnNuWe_E7-lA-25VtFXmktQIrp80YyGoitGsay3z4"
            }}"#,
            TEST_CERT
        );
        let jwk: Key = serde_json::from_str(&json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Standard base64 with + and / should be valid"
        );
    }

    #[test]
    fn test_x5c_invalid_base64_characters() {
        // Contains invalid characters for any base64
        let json = r#"{"kty": "RSA", "x5c": ["Invalid!@#$%"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Invalid base64 characters should be rejected"
        );
    }

    #[test]
    fn test_x5c_array_multiple_certs() {
        // Array can contain certificate chain - use same cert twice for simplicity
        let json = format!(
            r#"{{
                "kty": "EC",
                "crv": "P-256",
                "x5c": ["{}", "{}"],
                "x": "eXgQGgNDS5eXfJgrSTRh25w1DnYdu8g_zYhT4o_7TmA",
                "y": "bgsnNuWe_E7-lA-25VtFXmktQIrp80YyGoitGsay3z4"
            }}"#,
            TEST_CERT, TEST_CERT
        );
        let jwk: Key = serde_json::from_str(&json).unwrap();
        assert_eq!(jwk.x5c.as_ref().unwrap().len(), 2);
        assert!(jwk.validate_structure().is_ok());
    }

    #[test]
    fn test_x5c_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.x5c, None);
    }

    #[test]
    fn test_x5c_empty_array_rejected() {
        // RFC 7517 Section 4.7: x5c contains "a chain of one or more PKIX certificates"
        // An empty array violates this requirement.
        let json = r#"{"kty": "RSA", "x5c": [], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "Empty x5c array should be rejected");
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5c",
                ..
            }))
        ));
    }
}

// ============================================================================
// Section 4.8 & 4.9: "x5t" and "x5t#S256" (X.509 Thumbprint) Parameters
// ============================================================================

mod x5t_parameters {
    use super::*;

    #[test]
    fn test_x5t_optional() {
        let json = r#"{"kty": "RSA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.x5t, None);
        assert_eq!(jwk.x5t_s256, None);
    }

    #[test]
    fn test_x5t_parsed() {
        let json = r#"{"kty": "RSA", "x5t": "abc123", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.x5t, Some("abc123".to_string()));
    }

    #[test]
    fn test_x5t_s256_parsed() {
        let json = r#"{"kty": "RSA", "x5t#S256": "sha256thumbprint", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.x5t_s256, Some("sha256thumbprint".to_string()));
    }
}

// ============================================================================
// Section 5: JWK Set Format
// ============================================================================

mod jwk_set {
    use super::*;

    #[test]
    fn test_jwks_keys_required() {
        // "keys" member is required
        let json = r#"{}"#;
        let result = serde_json::from_str::<KeySet>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwks_keys_array() {
        let json = r#"{"keys": []}"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert!(jwks.is_empty());
    }

    #[test]
    fn test_jwks_multiple_keys() {
        let json = r#"{
            "keys": [
                {"kty": "RSA", "kid": "1", "n": "AQAB", "e": "AQAB"},
                {"kty": "RSA", "kid": "2", "n": "AQAB", "e": "AQAB"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn test_jwks_unknown_members_ignored() {
        // RFC 7517 Section 5: "Additional members can be present in the JWK Set;
        // if not understood by implementations encountering them, they MUST be ignored"
        let json = r#"{
            "keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}],
            "unknown_member": "should be ignored",
            "another_unknown": 123
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert_eq!(jwks.len(), 1);
    }

    #[test]
    fn test_jwks_validate_all_keys_consistent() {
        // KeySet::validate() should accept keys where use and key_ops are consistent
        let json = r#"{
            "keys": [
                {"kty": "RSA", "use": "sig", "key_ops": ["sign"], "n": "AQAB", "e": "AQAB"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert!(
            jwks.validate().is_ok(),
            "JWKS with consistent use and key_ops should pass validation"
        );
    }

    #[test]
    fn test_jwks_validate_all_keys_inconsistent() {
        // KeySet::validate() should reject keys where use and key_ops are inconsistent
        let json = r#"{
            "keys": [
                {"kty": "RSA", "use": "sig", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert!(
            jwks.validate().is_err(),
            "JWKS with inconsistent use and key_ops should fail validation"
        );
    }
}

// ============================================================================
// Unknown Members (General)
// ============================================================================

mod unknown_members {
    use super::*;

    #[test]
    fn test_jwk_unknown_members_ignored() {
        // RFC 7517 Section 4: "Additional members can be present in the JWK;
        // if not understood by implementations encountering them, they MUST be ignored"
        let json = r#"{
            "kty": "RSA",
            "n": "AQAB",
            "e": "AQAB",
            "unknown_param": "ignored",
            "another_unknown": [1, 2, 3],
            "nested_unknown": {"foo": "bar"}
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Rsa);
        assert!(jwk.validate_structure().is_ok());
    }
}

// ============================================================================
// Key Type Specific Validation (RFC 7518)
// ============================================================================

mod key_type_validation {
    use super::*;

    #[test]
    fn test_rsa_requires_n_and_e() {
        // Missing n
        let json = r#"{"kty": "RSA", "e": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Missing e
        let json = r#"{"kty": "RSA", "n": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_ec_requires_crv_x_y() {
        // Missing crv
        let json = r#"{"kty": "EC", "x": "AQAB", "y": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Missing x
        let json = r#"{"kty": "EC", "crv": "P-256", "y": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Missing y
        let json = r#"{"kty": "EC", "crv": "P-256", "x": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_symmetric_requires_k() {
        let json = r#"{"kty": "oct"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_okp_requires_crv_x() {
        // Missing crv
        let json = r#"{"kty": "OKP", "x": "AQAB"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Missing x
        let json = r#"{"kty": "OKP", "crv": "Ed25519"}"#;
        let result: Result<Key, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_crt_all_or_nothing() {
        // RFC 7518: If any CRT parameter is present, all must be present
        // Partial CRT parameters should fail validation
        let json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"
        }"#;
        // Has d and p, but missing q, dp, dq, qi
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "Partial RSA CRT parameters should be rejected"
        );
    }
}

// ============================================================================
// Serialization Roundtrip
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_roundtrip_preserves_all_fields() {
        let json = r#"{
            "kty": "RSA",
            "kid": "test-key",
            "use": "sig",
            "alg": "RS256",
            "x5u": "https://example.com/cert",
            "x5t": "thumbprint",
            "x5t#S256": "sha256thumb",
            "n": "AQAB",
            "e": "AQAB"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        let roundtrip: Key = serde_json::from_str(&serialized).unwrap();

        assert_eq!(jwk.kty(), roundtrip.kty());
        assert_eq!(jwk.kid, roundtrip.kid);
        assert_eq!(jwk.key_use, roundtrip.key_use);
        assert_eq!(jwk.alg, roundtrip.alg);
        assert_eq!(jwk.x5u, roundtrip.x5u);
        assert_eq!(jwk.x5t, roundtrip.x5t);
        assert_eq!(jwk.x5t_s256, roundtrip.x5t_s256);
    }
}

// ============================================================================
// RFC 7518 Section 6.3.2.7: RSA Multi-Prime Keys
// ============================================================================

mod rsa_multi_prime {
    use super::*;

    #[test]
    fn test_multi_prime_rsa_parsing() {
        // Multi-prime RSA key with "oth" parameter
        let json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjb37qSjnPzmVDG4RLGPi_7MqKgTNX-aDZNb-z7D32dNBDU_-VjCGUv4NWzG19eGn9j7C39GvhpQhUTyF1YZdA-KV7TnRCMDYlH1tIJHrJXiTKpcPXwl0",
            "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6hXjmpmr5BP_c3WLt8oCYwcNEo7Rt2I6hxT8qx6QIBWMB0B0lXAKKC1Fbc5UVIr_sSgK5rqsJhLwPCvCQ0FGhMg-L-TQcA2E4lmLqlLEk",
            "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
            "oth": [
                {
                    "r": "AQAB",
                    "d": "AQAB",
                    "t": "AQAB"
                }
            ]
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kty(), KeyType::Rsa);

        let rsa = jwk.as_rsa().unwrap();
        assert!(rsa.oth.is_some());
        assert_eq!(rsa.oth.as_ref().unwrap().len(), 1);
        assert!(rsa.is_multi_prime());
    }

    #[test]
    fn test_oth_requires_crt_params() {
        // oth without CRT parameters should fail validation
        let json = r#"{
            "kty": "RSA",
            "n": "AQAB",
            "e": "AQAB",
            "d": "AQAB",
            "oth": [{"r": "AQAB", "d": "AQAB", "t": "AQAB"}]
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "oth without CRT params should fail");
    }

    #[test]
    fn test_oth_serialization_roundtrip() {
        let json = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB","p":"AQAB","q":"AQAB","dp":"AQAB","dq":"AQAB","qi":"AQAB","oth":[{"r":"AQAB","d":"AQAB","t":"AQAB"}]}"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        let parsed: Key = serde_json::from_str(&serialized).unwrap();

        let rsa = parsed.as_rsa().unwrap();
        assert!(rsa.oth.is_some());
    }
}

// ============================================================================
// RFC 7518: RSA Key Size Validation
// ============================================================================

mod rsa_key_size {
    use super::*;

    #[test]
    fn test_key_size_calculation() {
        // 2048-bit key (256 bytes modulus)
        let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let rsa = jwk.as_rsa().unwrap();

        assert_eq!(rsa.key_size_bits(), 2048);
    }

    #[test]
    fn test_key_size_validation() {
        let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let rsa = jwk.as_rsa().unwrap();

        // Should pass 2048-bit minimum
        assert!(rsa.validate_key_size(2048).is_ok());

        // Should fail 4096-bit minimum
        assert!(rsa.validate_key_size(4096).is_err());
    }
}

// ============================================================================
// RFC 8037: OKP Extended Private Key Format
// ============================================================================

mod okp_extended_format {
    use super::*;
    use jwk_simple::OkpCurve;

    #[test]
    fn test_ed448_accepts_57_byte_seed() {
        // Create Ed448 key with 57-byte private key (seed only)
        // 57 bytes encodes to 76 base64url characters without padding
        let json = r#"{
            "kty": "OKP",
            "crv": "Ed448",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "d": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
        }"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(jwk.validate_structure().is_ok());
    }

    #[test]
    fn test_ed448_accepts_114_byte_extended() {
        // Ed448 with 114-byte private key (seed + public)
        // This is accepted by some implementations
        let params = jwk_simple::jwk::OkpParams::new_private(
            OkpCurve::Ed448,
            jwk_simple::encoding::Base64UrlBytes::new(vec![0; 57]),
            jwk_simple::encoding::Base64UrlBytes::new(vec![1; 114]),
        );
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_seed_extraction_from_extended() {
        let params = jwk_simple::jwk::OkpParams::new_private(
            OkpCurve::Ed448,
            jwk_simple::encoding::Base64UrlBytes::new(vec![0; 57]),
            jwk_simple::encoding::Base64UrlBytes::new(vec![1; 114]),
        );

        let seed = params.private_key_seed().unwrap();
        assert_eq!(seed.len(), 57);
        assert!(seed.iter().all(|&b| b == 1));
    }
}

// ============================================================================
// RFC 7638: JWK Thumbprint
// ============================================================================

mod thumbprint_rfc7638 {
    use super::*;

    #[test]
    fn test_rfc7638_section_3_1_example() {
        // Exact example from RFC 7638 Section 3.1
        let json = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;

        let jwk: Key = serde_json::from_str(json).unwrap();
        let thumbprint = jwk.thumbprint();

        // Expected value from RFC 7638 Section 3.1
        assert_eq!(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn test_thumbprint_ignores_kid() {
        let json1 = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
        let json2 = r#"{"kty":"RSA","kid":"different-kid","n":"AQAB","e":"AQAB"}"#;

        let jwk1: Key = serde_json::from_str(json1).unwrap();
        let jwk2: Key = serde_json::from_str(json2).unwrap();

        assert_eq!(jwk1.thumbprint(), jwk2.thumbprint());
    }

    #[test]
    fn test_thumbprint_ignores_use_and_alg() {
        let json1 = r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#;
        let json2 = r#"{"kty":"RSA","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}"#;

        let jwk1: Key = serde_json::from_str(json1).unwrap();
        let jwk2: Key = serde_json::from_str(json2).unwrap();

        assert_eq!(jwk1.thumbprint(), jwk2.thumbprint());
    }
}

// ============================================================================
// RFC 7517 Permissive Parsing (Unknown Values)
// ============================================================================

mod permissive_parsing {
    use super::*;
    use jwk_simple::{Algorithm, KeyOperation};

    // RFC 7517 Section 4.4: Algorithm values should be accepted even if unknown
    // This allows for future extensions and collision-resistant private-use names

    #[test]
    fn test_unknown_algorithm_accepted() {
        // Unknown algorithm should be parsed successfully
        let json = r#"{"kty": "RSA", "alg": "CUSTOM-ALG-256", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(
            jwk.alg,
            Some(Algorithm::Unknown("CUSTOM-ALG-256".to_string()))
        );
    }

    #[test]
    fn test_unknown_algorithm_validates() {
        // JWK with unknown algorithm should still validate (we can't check key type match)
        let json = r#"{"kty": "RSA", "alg": "FUTURE-ALG", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Unknown algorithm should not cause validation failure"
        );
    }

    #[test]
    fn test_unknown_algorithm_roundtrip() {
        // Unknown algorithm should survive JSON roundtrip
        let json = r#"{"kty":"RSA","alg":"MY-PRIVATE-ALG","n":"AQAB","e":"AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        assert!(
            serialized.contains("MY-PRIVATE-ALG"),
            "Unknown algorithm should be preserved in serialization"
        );
    }

    #[test]
    fn test_algorithm_is_unknown_method() {
        // Test the is_unknown() helper method
        assert!(Algorithm::Unknown("test".to_string()).is_unknown());
        assert!(!Algorithm::Rs256.is_unknown());
    }

    // RFC 7517 Section 4.3: key_ops values can include collision-resistant names

    #[test]
    fn test_unknown_key_ops_accepted() {
        // Unknown key operation should be parsed successfully
        let json =
            r#"{"kty": "RSA", "key_ops": ["sign", "custom-operation"], "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let key_ops = jwk.key_ops.as_ref().unwrap();
        assert_eq!(key_ops.len(), 2);
        assert!(key_ops.contains(&KeyOperation::Sign));
        assert!(key_ops.contains(&KeyOperation::Unknown("custom-operation".to_string())));
    }

    #[test]
    fn test_unknown_key_ops_roundtrip() {
        // Unknown key operation should survive JSON roundtrip
        let json = r#"{"kty":"RSA","key_ops":["sign","my-custom-op"],"n":"AQAB","e":"AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        assert!(
            serialized.contains("my-custom-op"),
            "Unknown key_ops should be preserved"
        );
    }

    // RFC 7517 Section 5: KeySet should ignore JWKs with unknown kty values

    #[test]
    fn test_jwks_skips_unknown_kty() {
        // JWKS containing keys with unknown kty should skip those keys
        let json = r#"{
            "keys": [
                {"kty": "RSA", "kid": "known-key", "n": "AQAB", "e": "AQAB"},
                {"kty": "FUTURE-KEY-TYPE", "kid": "unknown-key", "data": "something"},
                {"kty": "oct", "kid": "symmetric-key", "k": "AQAB"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();

        // Only 2 keys should be parsed (RSA and oct)
        assert_eq!(jwks.len(), 2, "JWKS should skip keys with unknown kty");

        // Verify the known keys are present
        assert!(jwks.get_by_kid("known-key").is_some());
        assert!(jwks.get_by_kid("symmetric-key").is_some());

        // The unknown key should be skipped
        assert!(jwks.get_by_kid("unknown-key").is_none());
    }

    #[test]
    fn test_jwks_all_unknown_kty_results_in_empty() {
        // If all keys have unknown kty, result should be empty JWKS
        let json = r#"{
            "keys": [
                {"kty": "UNKNOWN1", "data": "a"},
                {"kty": "UNKNOWN2", "data": "b"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert!(jwks.is_empty(), "JWKS with all unknown kty should be empty");
    }

    #[test]
    fn test_jwks_malformed_known_kty_is_skipped() {
        // RFC 7517 Section 5: Implementations SHOULD ignore JWKs that are
        // "missing required members, or for which values are out of the
        // supported ranges." Malformed keys with known kty are silently
        // skipped, preserving the valid keys.

        // RSA key missing required "n" and "e" parameters — should be skipped
        let json = r#"{
            "keys": [
                {"kty": "RSA", "kid": "valid", "n": "AQAB", "e": "AQAB"},
                {"kty": "RSA", "kid": "missing-params"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert_eq!(jwks.len(), 1, "Only the valid RSA key should be included");
        assert!(
            jwks.get_by_kid("valid").is_some(),
            "Valid key should be present"
        );
        assert!(
            jwks.get_by_kid("missing-params").is_none(),
            "Malformed key should be skipped"
        );

        // EC key missing required "crv" parameter — should result in empty set
        let json = r#"{
            "keys": [
                {"kty": "EC", "kid": "missing-curve", "x": "AQAB", "y": "AQAB"}
            ]
        }"#;
        let jwks = serde_json::from_str::<KeySet>(json).unwrap();
        assert!(jwks.is_empty(), "Malformed EC key should be skipped");
    }

    // RFC 7517 Section 4.2: "use" parameter can have other values

    #[test]
    fn test_unknown_use_accepted() {
        // Unknown use value should be parsed successfully
        let json = r#"{"kty": "RSA", "use": "custom-purpose", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert_eq!(
            jwk.key_use,
            Some(KeyUse::Unknown("custom-purpose".to_string()))
        );
    }

    #[test]
    fn test_unknown_use_validates() {
        // JWK with unknown use should still validate
        let json = r#"{"kty": "RSA", "use": "future-purpose", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Unknown use should not cause validation failure"
        );
    }

    #[test]
    fn test_unknown_use_roundtrip() {
        // Unknown use should survive JSON roundtrip
        let json = r#"{"kty":"RSA","use":"my-private-use","n":"AQAB","e":"AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&jwk).unwrap();
        assert!(
            serialized.contains("my-private-use"),
            "Unknown use should be preserved in serialization"
        );
    }
}

// ============================================================================
// Section 4.8 & 4.9: x5t and x5t#S256 Validation
// ============================================================================

mod x5t_validation {
    use super::*;

    #[test]
    fn test_x5t_valid_sha1_thumbprint() {
        // SHA-1 = 20 bytes = 27 base64url characters (unpadded)
        // 20 bytes of zeros encoded: AAAAAAAAAAAAAAAAAAAAAAAAAAA (27 A's)
        let json =
            r#"{"kty": "RSA", "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Valid x5t (27 chars, 20 bytes) should pass"
        );
    }

    #[test]
    fn test_x5t_wrong_length_rejected() {
        // This is 32 bytes (SHA-256 length), not 20 bytes (SHA-1 length)
        let json = r#"{"kty": "RSA", "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "x5t with wrong length should be rejected");
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5t",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5t_invalid_base64url_rejected() {
        // Contains '+' which is base64 but not base64url (27 chars for SHA-1)
        let json =
            r#"{"kty": "RSA", "x5t": "AAAAAAAAAAAAAAAAAAAAAAAA+AA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "x5t with base64 (not base64url) characters should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5t",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5t_s256_valid_sha256_thumbprint() {
        // SHA-256 = 32 bytes = 43 base64url characters (unpadded)
        let json = r#"{"kty": "RSA", "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Valid x5t#S256 (43 chars, 32 bytes) should pass"
        );
    }

    #[test]
    fn test_x5t_s256_wrong_length_rejected() {
        // This is 20 bytes (SHA-1 length, 27 chars), not 32 bytes (SHA-256 length)
        let json = r#"{"kty": "RSA", "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "x5t#S256 with wrong length should be rejected"
        );
        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidParameter {
                name: "x5t#S256",
                ..
            }))
        ));
    }

    #[test]
    fn test_x5t_s256_invalid_base64url_rejected() {
        // Contains '/' which is base64 but not base64url
        let json = r#"{"kty": "RSA", "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/AAA", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(
            result.is_err(),
            "x5t#S256 with base64 (not base64url) characters should be rejected"
        );
    }

    #[test]
    fn test_x5t_empty_rejected() {
        let json = r#"{"kty": "RSA", "x5t": "", "n": "AQAB", "e": "AQAB"}"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        let result = jwk.validate_structure();
        assert!(result.is_err(), "Empty x5t should be rejected");
    }

    #[test]
    fn test_both_x5t_and_x5t_s256_valid() {
        // Both can be present simultaneously
        // x5t = 20 bytes (27 chars), x5t#S256 = 32 bytes (43 chars)
        let json = r#"{
            "kty": "RSA",
            "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "n": "AQAB",
            "e": "AQAB"
        }"#;
        let jwk: Key = serde_json::from_str(json).unwrap();
        assert!(
            jwk.validate_structure().is_ok(),
            "Both x5t and x5t#S256 should be allowed"
        );
    }
}

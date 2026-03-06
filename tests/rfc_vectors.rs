//! Tests using RFC 7517 Appendix A test vectors.
//!
//! These tests verify that the library correctly parses the example keys
//! from the JWK specification.

use jwk_simple::{Algorithm, EcCurve, KeySet, KeyType, KeyUse};

/// RFC 7517 Appendix A.1 - Example Public Keys
mod public_keys {
    use super::*;

    const EXAMPLE_JWKS: &str = r#"{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "use": "enc",
                "kid": "1"
            },
            {
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "kid": "2011-04-29"
            }
        ]
    }"#;

    #[test]
    fn test_parse_example_jwks() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_JWKS).unwrap();
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn test_ec_key_properties() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_JWKS).unwrap();
        let ec_key = jwks.get_by_kid("1").unwrap();

        assert_eq!(ec_key.kty(), KeyType::Ec);
        assert_eq!(ec_key.key_use(), Some(&KeyUse::Encryption));
        assert!(ec_key.is_public_key_only());

        let ec_params = ec_key.as_ec().unwrap();
        assert_eq!(ec_params.crv, EcCurve::P256);
        assert_eq!(ec_params.x.len(), 32); // P-256 coordinate size
        assert_eq!(ec_params.y.len(), 32);
    }

    #[test]
    fn test_rsa_key_properties() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_JWKS).unwrap();
        let rsa_key = jwks.get_by_kid("2011-04-29").unwrap();

        assert_eq!(rsa_key.kty(), KeyType::Rsa);
        assert_eq!(rsa_key.alg(), Some(&Algorithm::Rs256));
        assert!(rsa_key.is_public_key_only());

        let rsa_params = rsa_key.as_rsa().unwrap();
        // RSA 2048-bit key = 256 bytes modulus
        assert_eq!(rsa_params.n.len(), 256);
        // e = 65537 = 0x010001 = 3 bytes
        assert_eq!(rsa_params.e.len(), 3);
    }
}

/// RFC 7517 Appendix A.2 - Example Private Keys
mod private_keys {
    use super::*;

    const EXAMPLE_PRIVATE_JWKS: &str = r#"{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                "use": "enc",
                "kid": "1"
            },
            {
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
                "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
                "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjb37qSjnPzmVDG4RLGPi_7MqKgTNX-aDZNb-z7D32dNBDU_-VjCGUv4NWzG19eGn9j7C39GvhpQhUTyF1YZdA-KV7TnRCMDYlH1tIJHrJXiTKpcPXwl0",
                "dp": "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
                "dq": "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6hXjmpmr5BP_c3WLt8oCYwcNEo7Rt2I6hxT8qx6QIBWMB0B0lXAKKC1Fbc5UVIr_sSgK5rqsJhLwPCvCQ0FGhMg-L-TQcA2E4lmLqlLEk",
                "qi": "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
                "alg": "RS256",
                "kid": "2011-04-29"
            }
        ]
    }"#;

    #[test]
    fn test_parse_private_keys() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_PRIVATE_JWKS).unwrap();
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn test_ec_private_key() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_PRIVATE_JWKS).unwrap();
        let ec_key = jwks.get_by_kid("1").unwrap();

        assert!(!ec_key.is_public_key_only());
        assert!(ec_key.has_private_key());

        let ec_params = ec_key.as_ec().unwrap();
        assert!(ec_params.d.is_some());
        assert_eq!(ec_params.d.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_rsa_private_key() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_PRIVATE_JWKS).unwrap();
        let rsa_key = jwks.get_by_kid("2011-04-29").unwrap();

        assert!(!rsa_key.is_public_key_only());
        assert!(rsa_key.has_private_key());

        let rsa_params = rsa_key.as_rsa().unwrap();
        assert!(rsa_params.d.is_some());
        assert!(rsa_params.p.is_some());
        assert!(rsa_params.q.is_some());
        assert!(rsa_params.dp.is_some());
        assert!(rsa_params.dq.is_some());
        assert!(rsa_params.qi.is_some());
    }
}

/// RFC 7517 Appendix A.3 - Example Symmetric Keys
mod symmetric_keys {
    use super::*;

    const EXAMPLE_SYMMETRIC_JWKS: &str = r#"{
        "keys": [
            {
                "kty": "oct",
                "alg": "A128KW",
                "k": "GawgguFyGrWKav7AX4VKUg"
            },
            {
                "kty": "oct",
                "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q",
                "kid": "HMAC key used in JWS A.1 example"
            }
        ]
    }"#;

    #[test]
    fn test_parse_symmetric_keys() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_SYMMETRIC_JWKS).unwrap();
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn test_symmetric_key_properties() {
        let jwks = serde_json::from_str::<KeySet>(EXAMPLE_SYMMETRIC_JWKS).unwrap();

        // First key (A128KW)
        let first = &jwks[0];
        assert_eq!(first.kty(), KeyType::Symmetric);
        assert_eq!(first.alg(), Some(&Algorithm::A128kw));

        let params = first.as_symmetric().unwrap();
        assert_eq!(params.key_size_bits(), 128); // 16 bytes * 8

        // Second key (HMAC)
        let hmac_key = jwks.get_by_kid("HMAC key used in JWS A.1 example").unwrap();
        assert_eq!(hmac_key.kty(), KeyType::Symmetric);

        let hmac_params = hmac_key.as_symmetric().unwrap();
        assert_eq!(hmac_params.key_size_bits(), 512); // 64 bytes * 8
    }
}

/// RFC 8037 - OKP keys (Ed25519, X25519)
mod okp_keys {
    use super::*;
    use jwk_simple::OkpCurve;

    const ED25519_PUBLIC_KEY: &str = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }"#;

    const ED25519_PRIVATE_KEY: &str = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }"#;

    const X25519_KEY: &str = r#"{
        "kty": "OKP",
        "crv": "X25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
    }"#;

    #[test]
    fn test_ed25519_public_key() {
        let jwks_json = format!(r#"{{"keys": [{}]}}"#, ED25519_PUBLIC_KEY);
        let jwks = serde_json::from_str::<KeySet>(&jwks_json).unwrap();
        let key = jwks.first().unwrap();

        assert_eq!(key.kty(), KeyType::Okp);
        assert!(key.is_public_key_only());

        let params = key.as_okp().unwrap();
        assert_eq!(params.crv, OkpCurve::Ed25519);
        assert_eq!(params.x.len(), 32);
        assert!(params.d.is_none());
    }

    #[test]
    fn test_ed25519_private_key() {
        let jwks_json = format!(r#"{{"keys": [{}]}}"#, ED25519_PRIVATE_KEY);
        let jwks = serde_json::from_str::<KeySet>(&jwks_json).unwrap();
        let key = jwks.first().unwrap();

        assert!(!key.is_public_key_only());
        assert!(key.has_private_key());

        let params = key.as_okp().unwrap();
        assert!(params.d.is_some());
        assert_eq!(params.d.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_x25519_key() {
        let jwks_json = format!(r#"{{"keys": [{}]}}"#, X25519_KEY);
        let jwks = serde_json::from_str::<KeySet>(&jwks_json).unwrap();
        let key = jwks.first().unwrap();

        let params = key.as_okp().unwrap();
        assert_eq!(params.crv, OkpCurve::X25519);
    }
}

/// Serialization roundtrip tests
mod serialization {
    use super::*;

    #[test]
    fn test_roundtrip_rsa() {
        let original = r#"{"keys":[{"kty":"RSA","kid":"test","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

        let jwks: KeySet = serde_json::from_str(original).unwrap();
        let serialized = serde_json::to_string(&jwks).unwrap();
        let parsed: KeySet = serde_json::from_str(&serialized).unwrap();

        assert_eq!(jwks.len(), parsed.len());
        assert_eq!(
            jwks.first().unwrap().thumbprint(),
            parsed.first().unwrap().thumbprint()
        );
    }

    #[test]
    fn test_roundtrip_ec() {
        let original = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;

        let jwks: KeySet = serde_json::from_str(original).unwrap();
        let serialized = serde_json::to_string(&jwks).unwrap();
        let parsed: KeySet = serde_json::from_str(&serialized).unwrap();

        assert_eq!(jwks.len(), parsed.len());
        let ec = parsed.first().unwrap().as_ec().unwrap();
        assert_eq!(ec.crv, EcCurve::P256);
    }
}

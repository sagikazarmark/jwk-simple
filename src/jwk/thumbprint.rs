//! JWK Thumbprint calculation as defined in RFC 7638.
//!
//! This module provides functionality to calculate the thumbprint (hash)
//! of a JWK for use as a key identifier.
//!
//! # Security Considerations
//!
//! **Symmetric Keys**: Per RFC 7638, the thumbprint of a symmetric key includes
//! the key value `k` in the hash input. While the thumbprint itself is a hash
//! and doesn't directly expose the key, it does mean:
//!
//! 1. The thumbprint is deterministically derived from the secret key material
//! 2. Two parties with the same key will compute identical thumbprints
//! 3. The thumbprint could potentially be used as an oracle in certain scenarios
//!
//! For symmetric keys, consider whether exposing the thumbprint is appropriate
//! for your security model. In many cases, using a separate key identifier
//! (the `kid` field) is preferable to computing thumbprints of symmetric keys.

use base64ct::Encoding;
use sha2::{Digest, Sha256};

use crate::jwk::{EcParams, Key, KeyParams, OkpParams, RsaParams, SymmetricParams};

/// Calculates the JWK thumbprint as defined in RFC 7638.
///
/// The thumbprint is a base64url-encoded SHA-256 hash of a canonical JSON
/// representation of the key's required members.
///
/// Prefer using [`Key::thumbprint()`] instead of calling this function directly.
pub(crate) fn calculate_thumbprint(jwk: &Key) -> String {
    let canonical_json = build_canonical_json(jwk);
    let hash = Sha256::digest(canonical_json.as_bytes());
    base64ct::Base64UrlUnpadded::encode_string(&hash)
}

/// Builds the canonical JSON representation for thumbprint calculation.
///
/// Per RFC 7638, the JSON must contain only the required members for the
/// key type, in lexicographic order, with no whitespace.
fn build_canonical_json(jwk: &Key) -> String {
    match &jwk.params {
        KeyParams::Rsa(params) => build_rsa_canonical(params),
        KeyParams::Ec(params) => build_ec_canonical(params),
        KeyParams::Symmetric(params) => build_symmetric_canonical(params),
        KeyParams::Okp(params) => build_okp_canonical(params),
    }
}

/// Builds canonical JSON for RSA keys.
/// Required members: e, kty, n (in lexicographic order)
fn build_rsa_canonical(params: &RsaParams) -> String {
    format!(
        r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
        params.e.to_base64url(),
        params.n.to_base64url()
    )
}

/// Builds canonical JSON for EC keys.
/// Required members: crv, kty, x, y (in lexicographic order)
fn build_ec_canonical(params: &EcParams) -> String {
    format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        params.crv.as_str(),
        params.x.to_base64url(),
        params.y.to_base64url()
    )
}

/// Builds canonical JSON for symmetric keys.
/// Required members: k, kty (in lexicographic order)
fn build_symmetric_canonical(params: &SymmetricParams) -> String {
    format!(r#"{{"k":"{}","kty":"oct"}}"#, params.k.to_base64url())
}

/// Builds canonical JSON for OKP keys.
/// Required members: crv, kty, x (in lexicographic order)
fn build_okp_canonical(params: &OkpParams) -> String {
    format!(
        r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
        params.crv.as_str(),
        params.x.to_base64url()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Base64UrlBytes;
    use crate::{EcCurve, OkpCurve};

    #[test]
    fn test_rsa_canonical_order() {
        let params = RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        );
        let canonical = build_rsa_canonical(&params);
        // e comes before kty comes before n (lexicographic order)
        assert!(canonical.starts_with(r#"{"e":"#));
        assert!(canonical.contains(r#","kty":"RSA","#));
    }

    #[test]
    fn test_ec_canonical_order() {
        let params = EcParams::new_public(
            EcCurve::P256,
            Base64UrlBytes::new(vec![0; 32]),
            Base64UrlBytes::new(vec![0; 32]),
        );
        let canonical = build_ec_canonical(&params);
        // crv comes before kty comes before x comes before y
        assert!(canonical.starts_with(r#"{"crv":"#));
    }

    #[test]
    fn test_symmetric_canonical_order() {
        let params = SymmetricParams::new(Base64UrlBytes::new(vec![1, 2, 3]));
        let canonical = build_symmetric_canonical(&params);
        // k comes before kty
        assert!(canonical.starts_with(r#"{"k":"#));
    }

    #[test]
    fn test_okp_canonical_order() {
        let params = OkpParams::new_public(OkpCurve::Ed25519, Base64UrlBytes::new(vec![0; 32]));
        let canonical = build_okp_canonical(&params);
        // crv comes before kty comes before x
        assert!(canonical.starts_with(r#"{"crv":"#));
    }

    #[test]
    fn test_thumbprint_deterministic() {
        let jwk = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3, 4, 5]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )))
        .with_kid("test-kid");

        let t1 = calculate_thumbprint(&jwk);
        let t2 = calculate_thumbprint(&jwk);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_thumbprint_ignores_optional_fields() {
        let jwk1 = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )));

        let jwk2 = Key::new(KeyParams::Rsa(RsaParams::new_public(
            Base64UrlBytes::new(vec![1, 2, 3]),
            Base64UrlBytes::new(vec![1, 0, 1]),
        )))
        .with_kid("different-kid")
        .with_use(crate::KeyUse::Signature)
        .with_alg(crate::Algorithm::Rs256);

        // Same key material, different optional fields = same thumbprint
        assert_eq!(calculate_thumbprint(&jwk1), calculate_thumbprint(&jwk2));
    }

    #[test]
    fn test_rfc7638_rsa_vector() {
        let jwk_json = r#"{
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }"#;

        let jwk: Key = serde_json::from_str(jwk_json).unwrap();
        assert_eq!(
            calculate_thumbprint(&jwk),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn test_rfc7638_ec_vector() {
        let jwk_json = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        }"#;

        let jwk: Key = serde_json::from_str(jwk_json).unwrap();
        assert_eq!(
            calculate_thumbprint(&jwk),
            "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
        );
    }
}

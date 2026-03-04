//! Basic usage example for jwk-simple.
//!
//! This example demonstrates parsing a JWKS and looking up keys.

use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet, KeyType};

fn main() {
    // Example JWKS with multiple keys
    let jwks_json = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "rsa-signing-key",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            },
            {
                "kty": "EC",
                "kid": "ec-signing-key",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            },
            {
                "kty": "oct",
                "kid": "hmac-key",
                "use": "sig",
                "alg": "HS256",
                "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
            }
        ]
    }"#;

    // Parse the JWKS
    let jwks = serde_json::from_str::<KeySet>(jwks_json).expect("Failed to parse JWKS");

    println!("Loaded {} keys from JWKS", jwks.len());

    // Find a key by its ID
    if let Some(key) = jwks.get_by_kid("rsa-signing-key") {
        println!("\nFound RSA key:");
        println!("  Key type: {:?}", key.kty());
        println!("  Key use: {:?}", key.key_use);
        println!("  Algorithm: {:?}", key.alg);
        println!("  Is public key only: {}", key.is_public_key_only());
    }

    // Strict selection for security-sensitive verification paths
    let allowed_verify_algs = [Algorithm::Rs256, Algorithm::Es256];
    let selected = jwks
        .selector(&allowed_verify_algs)
        .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("rsa-signing-key"))
        .expect("strict key selection failed");
    println!(
        "\nStrictly selected verify key: {}",
        selected.kid.as_deref().unwrap_or("no kid")
    );

    // Find all signing keys
    let signing_keys: Vec<_> = jwks.signing_keys().collect();
    println!("\nFound {} signing keys:", signing_keys.len());
    for key in signing_keys {
        println!(
            "  - {} ({:?})",
            key.kid.as_deref().unwrap_or("no kid"),
            key.kty()
        );
    }

    // Find keys by type
    println!(
        "\nFound {} RSA keys",
        jwks.find_by_kty(KeyType::Rsa).count()
    );

    // Get the first signing key (common pattern)
    if let Some(first_signing) = jwks.first_signing_key() {
        println!(
            "\nFirst signing key: {}",
            first_signing.kid.as_deref().unwrap_or("no kid")
        );

        // Calculate thumbprint
        let thumbprint = first_signing.thumbprint();
        println!("  Thumbprint: {}", thumbprint);
    }

    // Iterate over all keys
    println!("\nAll keys:");
    for key in &jwks {
        println!(
            "  - kid={:?}, kty={:?}, use={:?}",
            key.kid,
            key.kty(),
            key.key_use
        );
    }
}

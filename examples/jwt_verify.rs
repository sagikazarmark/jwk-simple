//! JWT verification example using jwk-simple with jwt-simple.
//!
//! This example demonstrates how to load keys from a JWKS and use them
//! to verify JWTs.
//!
//! Run with: `cargo run --example jwt_verify --features jwt-simple`

use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
use jwt_simple::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example JWKS (in production, this would come from an identity provider)
    let jwks_json = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "my-signing-key",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }
        ]
    }"#;

    // Parse the JWKS
    let jwks = serde_json::from_str::<KeySet>(jwks_json)?;
    println!("Loaded JWKS with {} keys", jwks.len());

    // Strict selection for verification (security-sensitive path)
    let jwk = jwks
        .selector(&[Algorithm::Rs256])
        .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-signing-key"))
        .map_err(|e| format!("strict key selection failed: {e}"))?;

    println!("Found key: {:?}", jwk.kid());
    println!("Key type: {:?}", jwk.kty());
    println!("Algorithm: {:?}", jwk.alg());

    // Convert to jwt-simple key type
    // Method 1: Using TryFrom/TryInto
    let key: RS256PublicKey = jwk.try_into()?;
    println!("\nSuccessfully converted to RS256PublicKey");
    println!("Key size: {} bytes", key.to_der()?.len());

    // Example: Verifying a JWT (if you had a real token)
    // let claims = key.verify_token::<NoCustomClaims>(&token, None)?;

    println!("\nKey is ready for JWT verification!");

    // Demonstrate HMAC key conversion
    let hmac_jwks_json = r#"{
        "keys": [{
            "kty": "oct",
            "kid": "hmac-key",
            "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
        }]
    }"#;

    let hmac_jwks = serde_json::from_str::<KeySet>(hmac_jwks_json)?;
    let hmac_jwk = hmac_jwks
        .selector(&[Algorithm::Hs256])
        .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Hs256).with_kid("hmac-key"))
        .map_err(|e| format!("strict HMAC key selection failed: {e}"))?;
    let hmac_key: HS256Key = hmac_jwk.try_into()?;
    println!("\nSuccessfully converted to HS256Key");

    // Create and verify a test token with HMAC
    let claims = Claims::create(Duration::from_hours(1));
    let token = hmac_key.authenticate(claims)?;
    println!("Created test token: {}...", &token[..50]);

    let verified_claims = hmac_key.verify_token::<NoCustomClaims>(&token, None)?;
    println!("Token verified successfully!");
    println!("Token expires at: {:?}", verified_claims.expires_at);

    Ok(())
}

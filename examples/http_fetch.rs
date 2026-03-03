//! HTTP fetching example for jwk-simple.
//!
//! This example demonstrates how to fetch JWKS from HTTP endpoints,
//! which is the typical way to get keys from identity providers.
//!
//! Run with: `cargo run --example http_fetch --features http`

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use jwk_simple::{HttpKeyStore, KeyStore};
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use std::time::Duration;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: Fetch Google's JWKS (used for verifying Google ID tokens)
    let google_jwks_url = "https://www.googleapis.com/oauth2/v3/certs";

    println!("Fetching JWKS from: {}", google_jwks_url);

    // Create remote key set with a custom HTTP client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let remote = HttpKeyStore::new_with_client(google_jwks_url, client);

    // Fetch the JWKS
    let jwks = remote.get_keyset().await?;

    println!("\nFetched {} keys from Google:", jwks.len());
    for key in &jwks {
        println!(
            "  - kid: {}, kty: {:?}, alg: {:?}",
            key.kid.as_deref().unwrap_or("(none)"),
            key.kty(),
            key.alg
        );
    }

    // You can also look up a specific key by kid
    if let Some(key) = jwks.first() {
        if let Some(kid) = &key.kid {
            println!("\n--- Looking up key by kid ---");
            let found = remote.get_key(kid).await?;
            println!("Found key: {:?}", found.is_some());
        }
    }

    #[cfg(feature = "moka")]
    {
        // For production use, wrap with CachedKeyStore + MokaKeyCache for TTL-based caching
        println!("\n--- Using CachedKeyStore + MokaKeyCache for production ---");
        use jwk_simple::{CachedKeyStore, MokaKeyCache};

        let cache = MokaKeyCache::new(Duration::from_secs(300));
        let cached = CachedKeyStore::new(cache, HttpKeyStore::new(google_jwks_url)?);

        // First call fetches from network
        let _jwks = cached.get_keyset().await?;
        println!("First call: fetched from network");

        // Second call uses cache
        let _jwks = cached.get_keyset().await?;
        println!("Second call: served from cache");
    }

    #[cfg(not(feature = "moka"))]
    {
        println!("\nTip: enable 'moka' to use MokaKeyCache.");
        println!("Run with: cargo run --example http_fetch --features \"http moka\"");
    }

    Ok(())
}

#[cfg(all(feature = "http", target_arch = "wasm32"))]
fn main() {
    eprintln!("This example is native-only because it uses tokio + timeout configuration.");
    eprintln!("Use `http_fetch_wasm` for a wasm-compatible variant.");
}

#[cfg(not(feature = "http"))]
fn main() {
    eprintln!("This example requires the 'http' feature.");
    eprintln!("Run with: cargo run --example http_fetch --features http");
}

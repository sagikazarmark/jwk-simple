//! WASM-friendly HTTP fetching example for jwk-simple.
//!
//! This variant avoids tokio and timeout customization so it can compile on wasm.

#[cfg(all(feature = "http", target_arch = "wasm32"))]
use jwk_simple::{HttpKeyStore, KeyStore};

#[cfg(all(feature = "http", target_arch = "wasm32"))]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Example: Fetch Google's JWKS (used for verifying Google ID tokens)
    let google_jwks_url = "https://www.googleapis.com/oauth2/v3/certs";

    // Use default client configuration (works on wasm via fetch backend)
    let remote = HttpKeyStore::new(google_jwks_url)?;

    // Fetch the JWKS
    let jwks = remote.get_keyset().await?;

    println!("Fetched {} keys from Google", jwks.len());

    Ok(())
}

#[cfg(all(feature = "http", target_arch = "wasm32"))]
fn main() {
    eprintln!("This example is intended to be called from a wasm runtime.");
    eprintln!("Call `http_fetch_wasm::run().await` from your wasm entrypoint.");
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
fn main() {
    eprintln!("This example is wasm-only. Use `http_fetch` on native targets.");
}

#[cfg(not(feature = "http"))]
fn main() {
    eprintln!("This example requires the 'http' feature.");
}

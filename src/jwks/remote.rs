//! Remote JWKS fetching without caching.
//!
//! This module provides [`RemoteKeyStore`], which fetches keys from an HTTP endpoint
//! on every request. For production use, consider wrapping with [`CachedKeyStore`](super::CachedKeyStore).

use std::time::Duration;

use crate::error::Result;

use super::{KeySet, KeyStore};

/// Default timeout for HTTP requests (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A key store that fetches from an HTTP endpoint on every request.
///
/// This implementation does **not** cache keys. Every call to [`get_key`](KeyStore::get_key)
/// or [`get_keyset`](KeyStore::get_keyset) will make an HTTP request.
///
/// For production use with high request volumes, wrap this in [`CachedKeyStore`](super::CachedKeyStore):
///
/// ```ignore
/// use jwk_simple::{RemoteKeyStore, CachedKeyStore};
/// use std::time::Duration;
///
/// let remote = RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
/// let cached = CachedKeyStore::new(remote, Duration::from_secs(300));
/// ```
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeyStore, RemoteKeyStore};
///
/// let store = RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
/// let key = store.get_key("my-key-id").await?;
/// ```
///
/// # Custom HTTP Client
///
/// You can provide a custom [`reqwest::Client`] for full control over HTTP behavior:
///
/// ```ignore
/// use jwk_simple::RemoteKeyStore;
/// use std::time::Duration;
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()
///     .unwrap();
///
/// let store = RemoteKeyStore::new_with_client(
///     "https://example.com/.well-known/jwks.json",
///     client,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RemoteKeyStore {
    url: String,
    client: reqwest::Client,
}

impl RemoteKeyStore {
    /// Creates a new `RemoteKeyStore` from a URL.
    ///
    /// Uses a default HTTP client with a 30-second timeout. To customize the client,
    /// use [`new_with_client`](Self::new_with_client).
    pub fn new(url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .expect("failed to build default HTTP client");

        Self {
            url: url.into(),
            client,
        }
    }

    /// Creates a new `RemoteKeyStore` with a custom HTTP client.
    ///
    /// Use this to configure custom timeouts, headers, proxies, TLS settings, etc.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use jwk_simple::RemoteKeyStore;
    /// use std::time::Duration;
    ///
    /// let client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .unwrap();
    ///
    /// let store = RemoteKeyStore::new_with_client(
    ///     "https://example.com/.well-known/jwks.json",
    ///     client,
    /// );
    /// ```
    pub fn new_with_client(url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            url: url.into(),
            client,
        }
    }

    /// Fetches the JWKS from the remote endpoint.
    async fn fetch(&self) -> Result<KeySet> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?;
        let json = response.text().await?;

        Ok(serde_json::from_str::<KeySet>(&json)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyStore for RemoteKeyStore {
    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

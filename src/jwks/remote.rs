//! Remote JWKS fetching without caching.
//!
//! This module provides [`RemoteKeySet`], which fetches keys from an HTTP endpoint
//! on every request. For production use, consider wrapping with [`CachedKeySet`](super::CachedKeySet).

use std::time::Duration;

use crate::error::Result;
use crate::jwk::Key;

use super::{KeySet, KeySource};

/// Default timeout for HTTP requests (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A JWKS source that fetches from an HTTP endpoint on every request.
///
/// This implementation does **not** cache keys. Every call to [`get_key`](KeySource::get_key)
/// or [`get_keyset`](KeySource::get_keyset) will make an HTTP request.
///
/// For production use with high request volumes, wrap this in [`CachedKeySet`](super::CachedKeySet):
///
/// ```ignore
/// use jwk_simple::{RemoteKeySet, CachedKeySet};
/// use std::time::Duration;
///
/// let remote = RemoteKeySet::new("https://example.com/.well-known/jwks.json");
/// let cached = CachedKeySet::new(remote, Duration::from_secs(300));
/// ```
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeySource, RemoteKeySet};
///
/// let jwks = RemoteKeySet::new("https://example.com/.well-known/jwks.json");
/// let key = jwks.get_key("my-key-id").await?;
/// ```
///
/// # Custom HTTP Client
///
/// You can provide a custom [`reqwest::Client`] for full control over HTTP behavior:
///
/// ```ignore
/// use jwk_simple::RemoteKeySet;
/// use std::time::Duration;
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()
///     .unwrap();
///
/// let jwks = RemoteKeySet::new_with_client(
///     "https://example.com/.well-known/jwks.json",
///     client,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RemoteKeySet {
    url: String,
    client: reqwest::Client,
}

impl RemoteKeySet {
    /// Creates a new `RemoteKeySet` from a URL.
    ///
    /// Uses a default HTTP client with a 30-second timeout. To customize the client,
    /// use [`new_with_client`](Self::new_with_client).
    ///
    /// # Arguments
    ///
    /// * `url` - The JWKS endpoint URL.
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

    /// Creates a new `RemoteKeySet` with a custom HTTP client.
    ///
    /// Use this to configure custom timeouts, headers, proxies, TLS settings, etc.
    ///
    /// # Arguments
    ///
    /// * `url` - The JWKS endpoint URL.
    /// * `client` - A configured [`reqwest::Client`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use jwk_simple::RemoteKeySet;
    /// use std::time::Duration;
    ///
    /// let client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .unwrap();
    ///
    /// let jwks = RemoteKeySet::new_with_client(
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
        let response = self.client.get(&self.url).send().await?;
        let json = response.text().await?;

        Ok(serde_json::from_str::<KeySet>(&json)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeySource for RemoteKeySet {
    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        let keyset = self.fetch().await?;

        Ok(keyset.find_by_kid(kid).cloned())
    }

    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_jwks_new() {
        let _jwks = RemoteKeySet::new("https://example.com/jwks");
    }

    #[test]
    fn test_remote_jwks_new_with_client() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        let _jwks = RemoteKeySet::new_with_client("https://example.com/jwks", client);
    }
}

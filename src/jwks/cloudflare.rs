//! Cloudflare Workers support for JWKS.
//!
//! This module provides:
//! - [`FetchKeyStore`]: A key store that uses Cloudflare Worker's Fetch API
//! - [`KvKeyCache`]: A cache implementation backed by Cloudflare KV
//!
//! # Examples
//!
//! Using `FetchKeyStore` to fetch JWKS in a Cloudflare Worker:
//!
//! ```ignore
//! use jwk_simple::jwks::cloudflare;
//! use jwk_simple::jwks::KeyStore;
//!
//! let store = cloudflare::FetchKeyStore::new("https://example.com/.well-known/jwks.json")?;
//! let key = store.get_key("my-key-id").await?;
//! ```
//!
//! Using `KvKeyCache` with KV storage:
//!
//! ```ignore
//! use jwk_simple::jwks::cloudflare;
//! use jwk_simple::jwks::CachedKeyStore;
//! use worker::kv::KvStore;
//!
//! let kv: KvStore = env.kv("JWKS_CACHE")?;
//! let cache = cloudflare::KvKeyCache::new(kv);
//! let store = cloudflare::FetchKeyStore::new("https://example.com/.well-known/jwks.json")?;
//! let cached = CachedKeyStore::new(cache, store);
//! ```

use futures::TryStreamExt;
use url::Url;
use worker::kv::KvStore;

use crate::error::{Error, Result};
use crate::jwks::{KeyCache, KeySet, KeyStore};

/// Default TTL for KV cache entries (5 minutes).
pub const DEFAULT_KV_TTL_SECONDS: u64 = 300;

/// A key store that fetches from an HTTP endpoint using Cloudflare Worker's Fetch API.
///
/// This implementation is designed for use in Cloudflare Workers where `reqwest` is not
/// available. It uses the Worker's built-in Fetch API to make HTTP requests.
///
/// Like [`crate::jwks::HttpKeyStore`], this does **not** cache keys. Every call
/// to [`get_key`](KeyStore::get_key) or [`get_keyset`](KeyStore::get_keyset) will make
/// an HTTP request.
///
/// For production use, wrap this in [`crate::jwks::CachedKeyStore`] with a [`KvKeyCache`] for
/// KV-backed caching.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::jwks::cloudflare;
/// use jwk_simple::jwks::KeyStore;
///
/// let store = cloudflare::FetchKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let key = store.get_key("my-key-id").await?;
/// ```
#[derive(Debug, Clone)]
pub struct FetchKeyStore {
    url: Url,
}

fn require_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(Error::InvalidUrlScheme(
            "URL scheme must be 'https'; use new_insecure() to allow HTTP for local development or testing",
        ));
    }
    Ok(())
}

impl FetchKeyStore {
    /// Creates a new `FetchKeyStore` from a URL.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP (e.g. in local development
    /// or testing), use [`new_insecure`](Self::new_insecure).
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(url.as_ref()).map_err(Error::InvalidUrl)?;
        require_https(&url)?;

        Ok(Self { url })
    }

    /// Creates a new `FetchKeyStore` without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    pub fn new_insecure(url: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(url.as_ref()).map_err(Error::InvalidUrl)?;

        Ok(Self { url })
    }

    /// Fetches the JWKS from the remote endpoint using Cloudflare Worker's Fetch API.
    async fn fetch(&self) -> Result<KeySet> {
        let mut response = worker::Fetch::Url(self.url.clone())
            .send()
            .await
            .map_err(|e| Error::Fetch(format!("fetch failed: {}", e)))?;

        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(Error::Fetch(format!(
                "JWKS endpoint returned HTTP {}",
                status
            )));
        }

        let mut bytes = Vec::new();
        let mut stream = response
            .stream()
            .map_err(|e| Error::Fetch(format!("failed to read response body: {}", e)))?;

        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|e| Error::Fetch(format!("failed to read response body: {}", e)))?
        {
            bytes.extend_from_slice(&chunk);
        }

        Ok(serde_json::from_slice::<KeySet>(&bytes)?)
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl KeyStore for FetchKeyStore {
    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

/// A key cache backed by Cloudflare Workers KV.
///
/// This implementation stores the serialized key set in Cloudflare KV with optional TTL support.
///
/// # KV Storage Format
///
/// The key set is stored under a single KV key (configurable via `with_key`).
/// The value is the JSON-serialized [`KeySet`](crate::KeySet).
///
/// # TTL Behavior
///
/// TTL is handled by KV's native expiration mechanism. When a key set is stored with a TTL,
/// KV will automatically delete it after the specified time.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::jwks::cloudflare;
/// use std::time::Duration;
///
/// let kv = env.kv("JWKS_CACHE")?;
/// let cache = cloudflare::KvKeyCache::new(kv)
///     .with_ttl(Duration::from_secs(600))
///     .with_key("my-app:jwks");
/// ```
#[derive(Debug)]
pub struct KvKeyCache {
    kv: KvStore,
    key: String,
    ttl_seconds: Option<u64>,
}

impl KvKeyCache {
    /// Creates a new KV-backed cache with default settings.
    ///
    /// Default settings:
    /// - Key: `"jwks"`
    /// - TTL: 5 minutes (300 seconds)
    pub fn new(kv: KvStore) -> Self {
        Self {
            kv,
            key: "jwks".to_string(),
            ttl_seconds: Some(DEFAULT_KV_TTL_SECONDS),
        }
    }

    /// Sets the TTL for the cached key set.
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl_seconds = Some(ttl.as_secs());
        self
    }

    /// Disables TTL, making the cached key set persist indefinitely.
    pub fn without_ttl(mut self) -> Self {
        self.ttl_seconds = None;
        self
    }

    /// Sets the KV key used to store the key set.
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }

    /// Returns the configured TTL in seconds, if any.
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    /// Returns the configured KV key.
    pub fn key(&self) -> &str {
        &self.key
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl KeyCache for KvKeyCache {
    async fn get(&self) -> Result<Option<KeySet>> {
        let value = self
            .kv
            .get(&self.key)
            .text()
            .await
            .map_err(|e| Error::Cache(format!("read failed: {}", e)))?;

        match value {
            Some(json) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| Error::Cache(format!("deserialize failed: {}", e))),
            None => Ok(None),
        }
    }

    async fn set(&self, keyset: KeySet) -> Result<()> {
        let json = serde_json::to_string(&keyset)
            .map_err(|e| Error::Cache(format!("serialize failed: {}", e)))?;

        let builder = self
            .kv
            .put(&self.key, json)
            .map_err(|e| Error::Cache(format!("write setup failed: {}", e)))?;

        let builder = if let Some(ttl) = self.ttl_seconds {
            builder.expiration_ttl(ttl)
        } else {
            builder
        };

        builder
            .execute()
            .await
            .map_err(|e| Error::Cache(format!("write failed: {}", e)))?;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.kv
            .delete(&self.key)
            .await
            .map_err(|e| Error::Cache(format!("delete failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_keystore_new_rejects_invalid_url() {
        let err = FetchKeyStore::new("not a valid url").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn test_fetch_keystore_new_rejects_http_url() {
        let err = FetchKeyStore::new("http://example.com/.well-known/jwks.json").unwrap_err();
        assert!(matches!(err, Error::InvalidUrlScheme(_)));
    }

    #[test]
    fn test_fetch_keystore_new_accepts_https_url() {
        assert!(FetchKeyStore::new("https://example.com/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn test_fetch_keystore_new_insecure_accepts_http_url() {
        assert!(FetchKeyStore::new_insecure("http://example.com/.well-known/jwks.json").is_ok());
    }
}

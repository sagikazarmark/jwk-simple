//! Cloudflare Workers support for JWKS.
//!
//! This module provides:
//! - [`RemoteKeyStore`]: A key store that uses Cloudflare Worker's Fetch API
//! - [`KeyCache`]: A cache implementation backed by Cloudflare KV
//!
//! # Examples
//!
//! Using `RemoteKeyStore` to fetch JWKS in a Cloudflare Worker:
//!
//! ```ignore
//! use jwk_simple::cloudflare;
//! use jwk_simple::KeyStore;
//!
//! let store = cloudflare::RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
//! let key = store.get_key("my-key-id").await?;
//! ```
//!
//! Using `KeyCache` with KV storage:
//!
//! ```ignore
//! use jwk_simple::cloudflare;
//! use worker::kv::KvStore;
//!
//! let kv: KvStore = env.kv("JWKS_CACHE")?;
//! let cache = cloudflare::KeyCache::new(kv);
//! let source = cloudflare::RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
//! let cached = cloudflare::CachedKeyStore::new(cache, source);
//! ```

use worker::kv::KvStore;

use crate::error::Result;
use crate::jwk::Key;
use crate::jwks::KeyStore;

/// Default TTL for KV cache entries (5 minutes).
pub const DEFAULT_KV_TTL_SECONDS: u64 = 300;

/// A key store that fetches from an HTTP endpoint using Cloudflare Worker's Fetch API.
///
/// This implementation is designed for use in Cloudflare Workers where `reqwest` is not
/// available. It uses the Worker's built-in Fetch API to make HTTP requests.
///
/// Like [`RemoteKeyStore`](super::RemoteKeyStore), this does **not** cache keys. Every call
/// to [`get_key`](KeyStore::get_key) or [`get_keyset`](KeyStore::get_keyset) will make
/// an HTTP request.
///
/// For production use, wrap this in [`CachedKeyStore`] with a [`KeyCache`] for KV-backed caching.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::cloudflare;
/// use jwk_simple::KeyStore;
///
/// let store = cloudflare::RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
/// let key = store.get_key("my-key-id").await?;
/// ```
#[derive(Debug, Clone)]
pub struct RemoteKeyStore {
    url: String,
}

impl RemoteKeyStore {
    /// Creates a new `RemoteKeyStore` from a URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Returns the URL of the JWKS endpoint.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Fetches the JWKS from the remote endpoint using Cloudflare Worker's Fetch API.
    async fn fetch(&self) -> Result<crate::jwks::KeySet> {
        let mut response = worker::Fetch::Url(self.url.parse().map_err(|e| {
            crate::error::Error::Parse(crate::error::ParseError::Json(format!(
                "invalid URL: {}",
                e
            )))
        })?)
        .send()
        .await
        .map_err(|e| crate::error::Error::Other(format!("fetch failed: {}", e)))?;

        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(crate::error::Error::Other(format!(
                "JWKS endpoint returned HTTP {}",
                status
            )));
        }

        let text = response.text().await.map_err(|e| {
            crate::error::Error::Other(format!("failed to read response body: {}", e))
        })?;

        Ok(serde_json::from_str::<crate::jwks::KeySet>(&text)?)
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl KeyStore for RemoteKeyStore {
    async fn get_keyset(&self) -> Result<crate::jwks::KeySet> {
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
/// use jwk_simple::cloudflare;
/// use std::time::Duration;
///
/// let kv = env.kv("JWKS_CACHE")?;
/// let cache = cloudflare::KeyCache::new(kv)
///     .with_ttl(Duration::from_secs(600))
///     .with_key("my-app:jwks");
/// ```
pub struct KeyCache {
    kv: KvStore,
    key: String,
    ttl_seconds: Option<u64>,
}

impl KeyCache {
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

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("key", &self.key)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl crate::jwks::KeyCache for KeyCache {
    async fn get(&self) -> Option<crate::jwks::KeySet> {
        match self.kv.get(&self.key).text().await {
            Ok(Some(json)) => serde_json::from_str(&json).ok(),
            _ => None,
        }
    }

    async fn set(&self, keyset: crate::jwks::KeySet) {
        let json = match serde_json::to_string(&keyset) {
            Ok(j) => j,
            Err(_) => return,
        };

        let builder = match self.kv.put(&self.key, json) {
            Ok(b) => b,
            Err(_) => return,
        };

        let builder = if let Some(ttl) = self.ttl_seconds {
            builder.expiration_ttl(ttl)
        } else {
            builder
        };

        // Silently ignore write errors (cache is best-effort)
        let _ = builder.execute().await;
    }

    async fn clear(&self) {
        let _ = self.kv.delete(&self.key).await;
    }
}

/// Convenience type alias for a cached key store using Cloudflare KV caching.
pub type CachedKeyStore<S> = crate::jwks::CachedKeyStore<KeyCache, S>;

//! Cloudflare Workers support for JWKS.
//!
//! This module provides:
//! - [`KeySet`]: A JWKS source that uses Cloudflare Worker's Fetch API
//! - [`KeyCache`]: A cache implementation backed by Cloudflare KV
//!
//! # Examples
//!
//! Using `KeySet` to fetch JWKS in a Cloudflare Worker:
//!
//! ```ignore
//! use jwk_simple::cloudflare;
//! use jwk_simple::KeySource;
//!
//! let jwks = cloudflare::KeySet::new("https://example.com/.well-known/jwks.json");
//! let key = jwks.get_key("my-key-id").await?;
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
//! let source = cloudflare::KeySet::new("https://example.com/.well-known/jwks.json");
//! let cached = cloudflare::CachedKeySet::new(cache, source);
//! ```

use worker::kv::KvStore;

use crate::error::Result;
use crate::jwk::Key;
use crate::jwks::KeySource;

/// Default TTL for KV cache entries (5 minutes).
pub const DEFAULT_KV_TTL_SECONDS: u64 = 300;

/// A JWKS source that fetches from an HTTP endpoint using Cloudflare Worker's Fetch API.
///
/// This implementation is designed for use in Cloudflare Workers where `reqwest` is not
/// available. It uses the Worker's built-in Fetch API to make HTTP requests.
///
/// Like [`RemoteKeySet`](super::RemoteKeySet), this does **not** cache keys. Every call
/// to [`get_key`](KeySource::get_key) or [`get_keyset`](KeySource::get_keyset) will make
/// an HTTP request.
///
/// For production use, wrap this in [`CachedKeySet`] with a [`KeyCache`] for KV-backed caching.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::cloudflare;
/// use jwk_simple::KeySource;
///
/// let jwks = cloudflare::KeySet::new("https://example.com/.well-known/jwks.json");
/// let key = jwks.get_key("my-key-id").await?;
/// ```
#[derive(Debug, Clone)]
pub struct KeySet {
    url: String,
}

impl KeySet {
    /// Creates a new `KeySet` from a URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The JWKS endpoint URL.
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

        let text = response
            .text()
            .await
            .map_err(|e| crate::error::Error::Other(format!("failed to read response body: {}", e)))?;

        Ok(serde_json::from_str::<crate::jwks::KeySet>(&text)?)
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl KeySource for KeySet {
    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        let keyset = self.fetch().await?;
        Ok(keyset.find_by_kid(kid).cloned())
    }

    async fn get_keyset(&self) -> Result<crate::jwks::KeySet> {
        self.fetch().await
    }
}

/// A key cache backed by Cloudflare Workers KV.
///
/// This implementation stores serialized keys in Cloudflare KV with optional TTL support.
/// Keys are stored as JSON strings with a configurable prefix to avoid key collisions.
///
/// # KV Storage Format
///
/// Keys are stored with the format `{prefix}{kid}` where:
/// - `prefix` defaults to `"jwk:"` but can be customized
/// - `kid` is the key ID
///
/// The value is the JSON-serialized [`Key`](crate::Key) struct.
///
/// # TTL Behavior
///
/// TTL is handled by KV's native expiration mechanism. When a key is stored with a TTL,
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
///     .with_prefix("my-app:jwk:");
/// ```
pub struct KeyCache {
    kv: KvStore,
    prefix: String,
    ttl_seconds: Option<u64>,
}

impl KeyCache {
    /// Creates a new KV-backed cache with default settings.
    ///
    /// Default settings:
    /// - Prefix: `"jwk:"`
    /// - TTL: 5 minutes (300 seconds)
    ///
    /// # Arguments
    ///
    /// * `kv` - The KV namespace to use for storage.
    pub fn new(kv: KvStore) -> Self {
        Self {
            kv,
            prefix: "jwk:".to_string(),
            ttl_seconds: Some(DEFAULT_KV_TTL_SECONDS),
        }
    }

    /// Sets the TTL for cached keys.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The duration after which cached keys expire.
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl_seconds = Some(ttl.as_secs());
        self
    }

    /// Disables TTL, making cached keys persist indefinitely.
    pub fn without_ttl(mut self) -> Self {
        self.ttl_seconds = None;
        self
    }

    /// Sets the key prefix for KV storage.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix to prepend to all key IDs in KV.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Returns the configured TTL in seconds, if any.
    pub fn ttl_seconds(&self) -> Option<u64> {
        self.ttl_seconds
    }

    /// Returns the configured key prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Constructs the full KV key for a given key ID.
    fn kv_key(&self, kid: &str) -> String {
        format!("{}{}", self.prefix, kid)
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("prefix", &self.prefix)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

// Note: This module is only compiled for wasm32 targets, so we use the ?Send variant
#[async_trait::async_trait(?Send)]
impl crate::jwks::KeyCache for KeyCache {
    async fn get(&self, kid: &str) -> Option<Key> {
        let kv_key = self.kv_key(kid);

        match self.kv.get(&kv_key).text().await {
            Ok(Some(json)) => serde_json::from_str(&json).ok(),
            _ => None,
        }
    }

    async fn set(&self, kid: &str, key: Key) {
        let kv_key = self.kv_key(kid);

        let json = match serde_json::to_string(&key) {
            Ok(j) => j,
            Err(_) => return,
        };

        let builder = match self.kv.put(&kv_key, json) {
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

    async fn remove(&self, kid: &str) {
        let kv_key = self.kv_key(kid);
        let _ = self.kv.delete(&kv_key).await;
    }

    async fn clear(&self) {
        // KV doesn't support bulk delete, so we list and delete keys with our prefix.
        // This is a best-effort operation - we may not clear all keys if there are
        // more than the list limit, but this is acceptable for cache invalidation.
        if let Ok(list) = self.kv.list().prefix(self.prefix.clone()).execute().await {
            for key in list.keys {
                let _ = self.kv.delete(&key.name).await;
            }
        }
    }
}

/// Convenience type alias for a cached key set using Cloudflare KV caching.
pub type CachedKeySet<S> = crate::jwks::CachedKeySet<KeyCache, S>;

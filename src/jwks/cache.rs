//! Caching traits and wrappers for JWKS key sources.
//!
//! This module provides a [`KeyCache`] trait for caching keys by their ID,
//! and a [`CachedKeySet`] wrapper that combines any cache with any key source.
//!
//! For a ready-to-use in-memory implementation, enable the `inmemory-cache` feature
//! and use [`InMemoryKeyCache`](super::InMemoryKeyCache).

use crate::error::Result;
use crate::jwk::Key;

use super::{KeySet, KeySource};

/// A trait for caching keys by their ID.
///
/// Implementations can provide different caching strategies (in-memory, Redis, etc.)
/// while the [`CachedKeySet`] handles the cache-aside pattern.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeyCache, InMemoryKeyCache};
/// use std::time::Duration;
///
/// let cache = InMemoryKeyCache::new(Duration::from_secs(300));
///
/// // Store a key
/// cache.set("my-kid", key).await;
///
/// // Retrieve a key
/// if let Some(key) = cache.get("my-kid").await {
///     // Use the cached key
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeyCache {
    /// Gets a key from the cache by its ID.
    ///
    /// Returns `None` if the key is not in the cache or has expired.
    async fn get(&self, kid: &str) -> Option<Key>;

    /// Stores a key in the cache.
    ///
    /// The key ID is extracted from the key's `kid` field if not provided explicitly.
    async fn set(&self, kid: &str, key: Key);

    /// Removes a key from the cache.
    async fn remove(&self, kid: &str);

    /// Clears all keys from the cache.
    async fn clear(&self);
}

/// A caching wrapper for any [`KeySource`] implementation.
///
/// This wrapper uses the cache-aside pattern: it first checks the cache for a key,
/// and only fetches from the underlying source on a cache miss. Retrieved keys
/// are then stored in the cache for future requests.
///
/// # Type Parameters
///
/// * `C` - The cache implementation (must implement [`KeyCache`])
/// * `S` - The underlying key source (must implement [`KeySource`])
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{CachedKeySet, InMemoryKeyCache, RemoteKeySet, KeySource};
/// use std::time::Duration;
/// use std::sync::Arc;
///
/// // Create a cached remote JWKS
/// let cache = InMemoryKeyCache::new(Duration::from_secs(300));
/// let remote = RemoteKeySet::new("https://example.com/.well-known/jwks.json");
/// let cached = CachedKeySet::new(cache, remote);
///
/// // First call fetches from remote, caches the key
/// let key = cached.get_key("kid").await?;
///
/// // Subsequent calls use the cache
/// let key = cached.get_key("kid").await?;
/// ```
pub struct CachedKeySet<C, S> {
    cache: C,
    source: S,
}

impl<C, S> CachedKeySet<C, S> {
    /// Creates a new cached key source.
    ///
    /// # Arguments
    ///
    /// * `cache` - The cache implementation to use.
    /// * `source` - The underlying key source to fetch from on cache misses.
    pub fn new(cache: C, source: S) -> Self {
        Self { cache, source }
    }

    /// Returns a reference to the cache.
    pub fn cache(&self) -> &C {
        &self.cache
    }

    /// Returns a reference to the underlying source.
    pub fn source(&self) -> &S {
        &self.source
    }
}

impl<C: std::fmt::Debug, S: std::fmt::Debug> std::fmt::Debug for CachedKeySet<C, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedKeySet")
            .field("cache", &self.cache)
            .field("source", &self.source)
            .finish()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<C, S> KeySource for CachedKeySet<C, S>
where
    C: KeyCache + Send + Sync,
    S: KeySource + Send + Sync,
{
    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        // Try cache first
        if let Some(key) = self.cache.get(kid).await {
            return Ok(Some(key));
        }

        // Cache miss: fetch from underlying source
        if let Some(key) = self.source.get_key(kid).await? {
            self.cache.set(kid, key.clone()).await;
            return Ok(Some(key));
        }

        Ok(None)
    }

    async fn get_keyset(&self) -> Result<KeySet> {
        // Fetch from source
        let keyset = self.source.get_keyset().await?;

        // Cache all keys that have a kid
        for key in &keyset.keys {
            if let Some(kid) = &key.kid {
                self.cache.set(kid, key.clone()).await;
            }
        }

        Ok(keyset)
    }
}

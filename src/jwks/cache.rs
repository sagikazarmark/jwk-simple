//! Caching traits and wrappers for key stores.
//!
//! This module provides a [`KeyCache`] trait for caching key sets,
//! and a [`CachedKeyStore`] wrapper that combines any cache with any key store.
//!
//! For a ready-to-use in-memory implementation, enable the `cache-inmemory` feature
//! and use [`InMemoryKeyCache`](super::InMemoryKeyCache).

use crate::error::Result;
use crate::jwk::Key;

use super::{KeySet, KeyStore};

/// A trait for caching key sets.
///
/// Implementations can provide different caching strategies (in-memory, KV store, etc.)
/// while the [`CachedKeyStore`] handles the cache-aside pattern.
///
/// The cache stores the entire [`KeySet`] as a single unit, which matches how JWKS
/// endpoints work (they always return the full set). This avoids the N+1 fetch problem
/// that per-key caching would cause.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeyCache, InMemoryKeyCache};
/// use std::time::Duration;
///
/// let cache = InMemoryKeyCache::new(Duration::from_secs(300));
///
/// // Store a key set
/// cache.set(keyset).await;
///
/// // Retrieve the cached key set
/// if let Some(keyset) = cache.get().await {
///     // Use the cached key set
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeyCache {
    /// Gets the cached key set.
    ///
    /// Returns `None` if the cache is empty or has expired.
    async fn get(&self) -> Option<KeySet>;

    /// Stores a key set in the cache.
    async fn set(&self, keyset: KeySet);

    /// Clears the cache.
    async fn clear(&self);
}

/// A caching wrapper for any [`KeyStore`] implementation.
///
/// This wrapper uses the cache-aside pattern: it first checks the cache for the key set,
/// and only fetches from the underlying store on a cache miss. Retrieved key sets
/// are then stored in the cache for future requests.
///
/// When looking up a key by ID, if the cached key set doesn't contain the requested key,
/// the store refetches from the underlying source. This handles key rotation gracefully:
/// newly added keys are discovered automatically without waiting for cache expiration.
///
/// # Type Parameters
///
/// * `C` - The cache implementation (must implement [`KeyCache`])
/// * `S` - The underlying key store (must implement [`KeyStore`])
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{CachedKeyStore, InMemoryKeyCache, RemoteKeyStore, KeyStore};
/// use std::time::Duration;
///
/// // Create a cached remote key store
/// let cache = InMemoryKeyCache::new(Duration::from_secs(300));
/// let remote = RemoteKeyStore::new("https://example.com/.well-known/jwks.json");
/// let cached = CachedKeyStore::new(cache, remote);
///
/// // First call fetches from remote, caches the key set
/// let key = cached.get_key("kid").await?;
///
/// // Subsequent calls use the cache
/// let key = cached.get_key("kid").await?;
/// ```
pub struct CachedKeyStore<C, S> {
    cache: C,
    source: S,
}

impl<C, S> CachedKeyStore<C, S> {
    /// Creates a new cached key store.
    ///
    /// # Arguments
    ///
    /// * `cache` - The cache implementation to use.
    /// * `source` - The underlying key store to fetch from on cache misses.
    pub fn new(cache: C, source: S) -> Self {
        Self { cache, source }
    }

    /// Returns a reference to the cache.
    pub fn cache(&self) -> &C {
        &self.cache
    }

    /// Returns a reference to the underlying store.
    pub fn source(&self) -> &S {
        &self.source
    }
}

impl<C: std::fmt::Debug, S: std::fmt::Debug> std::fmt::Debug for CachedKeyStore<C, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedKeyStore")
            .field("cache", &self.cache)
            .field("source", &self.source)
            .finish()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<C, S> KeyStore for CachedKeyStore<C, S>
where
    C: KeyCache + Send + Sync,
    S: KeyStore + Send + Sync,
{
    async fn get_keyset(&self) -> Result<KeySet> {
        // Check cache first
        if let Some(keyset) = self.cache.get().await {
            return Ok(keyset);
        }

        // Cache miss: fetch from underlying store
        let keyset = self.source.get_keyset().await?;
        self.cache.set(keyset.clone()).await;
        Ok(keyset)
    }

    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        // Try cache first
        if let Some(keyset) = self.cache.get().await
            && let Some(key) = keyset.find_by_kid(kid)
        {
            return Ok(Some(key.clone()));
        }
        // Key not in cached set — could be a newly added key, refetch

        // Cache miss or key not found: fetch from underlying store
        let keyset = self.source.get_keyset().await?;
        let result = keyset.find_by_kid(kid).cloned();
        self.cache.set(keyset).await;
        Ok(result)
    }
}

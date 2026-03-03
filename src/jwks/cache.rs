//! Caching traits and wrappers for key stores.
//!
//! This module provides a [`KeyCache`] trait for caching key sets,
//! and a [`CachedKeyStore`] wrapper that combines any cache with any key store.
//!
//! For a ready-to-use Moka implementation, enable the `moka` feature
//! and use [`MokaKeyCache`](super::MokaKeyCache).

#[cfg(all(feature = "moka", not(target_arch = "wasm32")))]
pub mod moka;

use crate::error::Result;
use crate::jwk::Key;

use super::{KeySet, KeyStore};

/// A trait for caching key sets used by [`CachedKeyStore`].
///
/// This trait is primarily an extension point for library integrators who need a
/// custom cache backend (in-memory, KV store, persistent storage, etc.). Most users
/// should use [`CachedKeyStore`] with a provided cache implementation, such as
/// [`MokaKeyCache`](super::MokaKeyCache).
///
/// `CachedKeyStore` does not coordinate concurrent refreshes. Cache backends used in
/// concurrent contexts should provide their own internal synchronization and atomicity
/// guarantees for `get`/`set`/`clear` operations.
///
/// The cache stores the entire [`KeySet`] as a single unit, which matches how JWKS
/// endpoints work (they always return the full set). This avoids the N+1 fetch problem
/// that per-key caching would cause.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeyCache {
    /// Gets the cached key set.
    ///
    /// Returns `None` if the cache is empty or has expired.
    async fn get(&self) -> Result<Option<KeySet>>;

    /// Stores a key set in the cache.
    async fn set(&self, keyset: KeySet) -> Result<()>;

    /// Clears the cache.
    async fn clear(&self) -> Result<()>;
}

/// A caching wrapper for any [`KeyStore`] implementation.
///
/// This wrapper uses the cache-aside pattern: it first checks the cache for the key set,
/// and only fetches from the underlying store on a cache miss. Retrieved key sets
/// are then stored in the cache for future requests.
///
/// This is the recommended entry point for cached JWKS retrieval.
///
/// When looking up a key by ID, if the cached key set doesn't contain the requested key,
/// the store refetches from the underlying source. This handles key rotation gracefully:
/// newly added keys are discovered automatically without waiting for cache expiration.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{CachedKeyStore, HttpKeyStore, MokaKeyCache, KeyStore};
/// use std::time::Duration;
///
/// // Create a cached remote key store
/// let cache = MokaKeyCache::new(Duration::from_secs(300));
/// let remote = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let cached = CachedKeyStore::new(cache, remote);
///
/// // First call fetches from remote, caches the key set
/// let key = cached.get_key("kid").await?;
///
/// // Subsequent calls use the cache
/// let key = cached.get_key("kid").await?;
/// ```
#[derive(Debug)]
pub struct CachedKeyStore<C: KeyCache, S: KeyStore> {
    cache: C,
    store: S,
}

impl<C: KeyCache, S: KeyStore> CachedKeyStore<C, S> {
    /// Creates a cache wrapper around the provided key store.
    pub fn new(cache: C, store: S) -> Self {
        Self { cache, store }
    }

    /// Returns the configured cache backend for inspection or cache management.
    pub fn cache(&self) -> &C {
        &self.cache
    }

    /// Returns the underlying key store wrapped by this cache layer.
    pub fn store(&self) -> &S {
        &self.store
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
        // Try cache first
        if let Some(keyset) = self.cache.get().await? {
            return Ok(keyset);
        }

        // No cache hit: fetch from source and cache
        let keyset = self.store.get_keyset().await?;
        self.cache.set(keyset.clone()).await?;

        Ok(keyset)
    }

    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        // Try cache first
        if let Some(keyset) = self.cache.get().await?
            && let Some(key) = keyset.find_by_kid(kid)
        {
            return Ok(Some(key.clone()));
        }

        // Key not in cached set: refetch
        let keyset = self.store.get_keyset().await?;
        self.cache.set(keyset.clone()).await?;

        Ok(keyset.find_by_kid(kid).cloned())
    }
}

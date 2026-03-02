//! In-memory key cache implementation using Tokio.
//!
//! This module provides [`InMemoryKeyCache`], a thread-safe in-memory cache
//! with TTL-based expiration, and [`InMemoryCachedKeyStore`], a convenience type
//! for caching any key store with in-memory storage.

use std::time::Duration;

use tokio::sync::RwLock;

use crate::jwks::KeySet;

use super::cache::{CachedKeyStore, KeyCache};

/// Default cache TTL (5 minutes).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Internal cache entry with timestamp.
struct CacheEntry {
    keyset: KeySet,
    inserted_at: std::time::Instant,
}

/// An in-memory key cache with TTL-based expiration.
///
/// Key sets are stored in memory and automatically expire after the configured TTL.
/// This implementation is thread-safe and can be shared across tasks.
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::InMemoryKeyCache;
/// use std::time::Duration;
///
/// // Create a cache with 5-minute TTL
/// let cache = InMemoryKeyCache::new(Duration::from_secs(300));
///
/// // Or use the default TTL
/// let cache = InMemoryKeyCache::default();
/// ```
pub struct InMemoryKeyCache {
    entry: RwLock<Option<CacheEntry>>,
    ttl: Duration,
}

impl InMemoryKeyCache {
    /// Creates a new in-memory cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entry: RwLock::new(None),
            ttl,
        }
    }

    /// Creates a new in-memory cache with the default TTL (5 minutes).
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_CACHE_TTL)
    }

    /// Returns the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for InMemoryKeyCache {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

impl std::fmt::Debug for InMemoryKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKeyCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyCache for InMemoryKeyCache {
    async fn get(&self) -> Option<KeySet> {
        let entry = self.entry.read().await;
        entry.as_ref().and_then(|e| {
            if e.inserted_at.elapsed() < self.ttl {
                Some(e.keyset.clone())
            } else {
                None
            }
        })
    }

    async fn set(&self, keyset: KeySet) {
        let mut entry = self.entry.write().await;
        *entry = Some(CacheEntry {
            keyset,
            inserted_at: std::time::Instant::now(),
        });
    }

    async fn clear(&self) {
        let mut entry = self.entry.write().await;
        *entry = None;
    }
}

/// Convenience type alias for a cached key store using in-memory caching.
pub type InMemoryCachedKeyStore<S> = CachedKeyStore<InMemoryKeyCache, S>;

impl<S> InMemoryCachedKeyStore<S> {
    /// Creates a new cached key store with in-memory caching and the specified TTL.
    pub fn with_ttl(source: S, ttl: Duration) -> Self {
        Self::new(InMemoryKeyCache::new(ttl), source)
    }

    /// Creates a new cached key store with in-memory caching and the default TTL.
    pub fn with_default_ttl(source: S) -> Self {
        Self::new(InMemoryKeyCache::with_default_ttl(), source)
    }

    /// Invalidates the cache, forcing fresh fetches on subsequent requests.
    pub async fn invalidate(&self) {
        self.cache().clear().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::KeyStore;

    #[tokio::test]
    async fn test_in_memory_cache_basic() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        let cache = InMemoryKeyCache::new(Duration::from_secs(300));

        // Initially empty
        assert!(cache.get().await.is_none());

        // Set and get
        cache.set(keyset.clone()).await;
        let cached = cache.get().await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);

        // Clear
        cache.clear().await;
        assert!(cache.get().await.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_cache_expiration() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        // Very short TTL
        let cache = InMemoryKeyCache::new(Duration::from_millis(50));

        cache.set(keyset).await;
        assert!(cache.get().await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cache.get().await.is_none());
    }

    #[tokio::test]
    async fn test_cached_key_store() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeyStore::with_default_ttl(static_source);

        // First call should fetch from source and cache
        let key = cached.get_key("test-key").await.unwrap();
        assert!(key.is_some());

        // Verify it's cached
        let cached_keyset = cached.cache().get().await;
        assert!(cached_keyset.is_some());

        // Second call should use cache
        let key2 = cached.get_key("test-key").await.unwrap();
        assert!(key2.is_some());
    }

    #[tokio::test]
    async fn test_cached_key_store_miss() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeyStore::with_default_ttl(static_source);

        // Request a non-existent key
        let key = cached.get_key("nonexistent").await.unwrap();
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_cached_key_store_get_keyset() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "key1", "k": "AQAB"},
            {"kty": "oct", "kid": "key2", "k": "AQAB"}
        ]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeyStore::with_default_ttl(static_source);

        // Fetch keyset should cache it
        let keyset = cached.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 2);

        // Should be cached now
        let cached_keyset = cached.cache().get().await;
        assert!(cached_keyset.is_some());
        assert_eq!(cached_keyset.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_cached_key_store_invalidate() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeyStore::with_default_ttl(static_source);

        // Populate cache
        let _ = cached.get_key("test-key").await.unwrap();
        assert!(cached.cache().get().await.is_some());

        // Invalidate
        cached.invalidate().await;
        assert!(cached.cache().get().await.is_none());
    }
}

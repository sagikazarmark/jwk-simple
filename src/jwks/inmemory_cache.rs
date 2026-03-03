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
    inserted_at: tokio::time::Instant,
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
    async fn get(&self) -> crate::error::Result<Option<KeySet>> {
        let entry = self.entry.read().await;
        Ok(entry.as_ref().and_then(|e| {
            if e.inserted_at.elapsed() < self.ttl {
                Some(e.keyset.clone())
            } else {
                None
            }
        }))
    }

    async fn set(&self, keyset: KeySet) -> crate::error::Result<()> {
        let mut entry = self.entry.write().await;
        *entry = Some(CacheEntry {
            keyset,
            inserted_at: tokio::time::Instant::now(),
        });
        Ok(())
    }

    async fn clear(&self) -> crate::error::Result<()> {
        let mut entry = self.entry.write().await;
        *entry = None;
        Ok(())
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
        let _ = self.cache().clear().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::jwks::KeyStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_in_memory_cache_basic() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        let cache = InMemoryKeyCache::new(Duration::from_secs(300));

        // Initially empty
        assert!(cache.get().await.unwrap().is_none());

        // Set and get
        cache.set(keyset.clone()).await.unwrap();
        let cached = cache.get().await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);

        // Clear
        cache.clear().await.unwrap();
        assert!(cache.get().await.unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_memory_cache_expiration() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        let cache = InMemoryKeyCache::new(Duration::from_secs(300));

        cache.set(keyset).await.unwrap();
        assert!(cache.get().await.unwrap().is_some());

        // Advance time just before TTL — should still be cached
        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(cache.get().await.unwrap().is_some());

        // Advance past the TTL boundary — should be expired
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(cache.get().await.unwrap().is_none());
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
        let cached_keyset = cached.cache().get().await.unwrap();
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
        let cached_keyset = cached.cache().get().await.unwrap();
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
        assert!(cached.cache().get().await.unwrap().is_some());

        // Invalidate
        cached.invalidate().await;
        assert!(cached.cache().get().await.unwrap().is_none());
    }

    /// A mock KeyStore that returns different keysets on successive calls,
    /// simulating key rotation at the source.
    struct RotatingKeyStore {
        keysets: Vec<KeySet>,
        call_count: AtomicUsize,
    }

    impl RotatingKeyStore {
        fn new(keysets: Vec<KeySet>) -> Self {
            Self {
                keysets,
                call_count: AtomicUsize::new(0),
            }
        }

        /// Returns the number of times `get_keyset` has been called.
        fn fetch_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl KeyStore for RotatingKeyStore {
        async fn get_keyset(&self) -> crate::error::Result<KeySet> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            // Return the last keyset if we've exhausted the list
            let keyset = self
                .keysets
                .get(idx)
                .unwrap_or_else(|| self.keysets.last().unwrap());
            Ok(keyset.clone())
        }
    }

    struct FailingKeyStore;

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl KeyStore for FailingKeyStore {
        async fn get_keyset(&self) -> crate::error::Result<KeySet> {
            Err(Error::Other("mock source failure".to_string()))
        }
    }

    #[tokio::test]
    async fn test_cached_key_store_refetches_on_unknown_kid() {
        // Simulate key rotation: initial keyset has "old-key", rotated keyset adds "new-key"
        let initial: KeySet =
            serde_json::from_str(r#"{"keys": [{"kty": "oct", "kid": "old-key", "k": "AQAB"}]}"#)
                .unwrap();
        let rotated: KeySet = serde_json::from_str(
            r#"{"keys": [
                {"kty": "oct", "kid": "old-key", "k": "AQAB"},
                {"kty": "oct", "kid": "new-key", "k": "AQAB"}
            ]}"#,
        )
        .unwrap();

        let source = RotatingKeyStore::new(vec![initial, rotated]);
        let cached = CachedKeyStore::new(InMemoryKeyCache::new(Duration::from_secs(300)), source);

        // First lookup: populates cache from initial keyset
        let key = cached.get_key("old-key").await.unwrap();
        assert!(key.is_some(), "old-key should be found");
        assert_eq!(cached.source().fetch_count(), 1);

        // Second lookup for same key: should use cache, no refetch
        let key = cached.get_key("old-key").await.unwrap();
        assert!(key.is_some(), "old-key should still be found from cache");
        assert_eq!(
            cached.source().fetch_count(),
            1,
            "should not refetch for cached key"
        );

        // Lookup new-key: not in cache, should trigger refetch from rotated keyset
        let key = cached.get_key("new-key").await.unwrap();
        assert!(key.is_some(), "new-key should be found after refetch");
        assert_eq!(
            cached.source().fetch_count(),
            2,
            "should refetch when key not in cache"
        );

        // Verify new-key is now cached (no additional fetch)
        let key = cached.get_key("new-key").await.unwrap();
        assert!(key.is_some(), "new-key should be in cache now");
        assert_eq!(
            cached.source().fetch_count(),
            2,
            "should not refetch for newly cached key"
        );
    }

    #[tokio::test]
    async fn test_cached_key_store_miss_source_error_propagates() {
        let cached = CachedKeyStore::new(
            InMemoryKeyCache::new(Duration::from_secs(300)),
            FailingKeyStore,
        );

        let err = cached.get_keyset().await.unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }

    #[tokio::test]
    async fn test_cached_key_store_unknown_kid_refetch_error_propagates() {
        let initial: KeySet =
            serde_json::from_str(r#"{"keys": [{"kty": "oct", "kid": "old-key", "k": "AQAB"}]}"#)
                .unwrap();
        let cached = CachedKeyStore::new(
            InMemoryKeyCache::new(Duration::from_secs(300)),
            RotatingKeyStore::new(vec![initial]),
        );

        let _ = cached.get_key("old-key").await.unwrap();

        struct FailingAfterCache {
            initial: KeySet,
            calls: AtomicUsize,
        }

        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl KeyStore for FailingAfterCache {
            async fn get_keyset(&self) -> crate::error::Result<KeySet> {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    Ok(self.initial.clone())
                } else {
                    Err(Error::Other("refetch failed".to_string()))
                }
            }
        }

        let initial2: KeySet =
            serde_json::from_str(r#"{"keys": [{"kty": "oct", "kid": "old-key", "k": "AQAB"}]}"#)
                .unwrap();
        let cached = CachedKeyStore::new(
            InMemoryKeyCache::new(Duration::from_secs(300)),
            FailingAfterCache {
                initial: initial2,
                calls: AtomicUsize::new(0),
            },
        );

        let _ = cached.get_key("old-key").await.unwrap();
        let err = cached.get_key("new-key").await.unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }
}

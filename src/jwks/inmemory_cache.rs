//! In-memory key cache implementation using Tokio.
//!
//! This module provides [`InMemoryKeyCache`], a thread-safe in-memory cache
//! with TTL-based expiration, and [`InMemoryCachedKeySet`], a convenience type
//! for caching any key source with in-memory storage.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::jwk::Key;

use super::cache::{CachedKeySet, KeyCache};

/// Default cache TTL (5 minutes).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Internal cache entry with timestamp.
struct CacheEntry {
    key: Key,
    inserted_at: std::time::Instant,
}

/// An in-memory key cache with TTL-based expiration.
///
/// Keys are stored in memory and automatically expire after the configured TTL.
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
    entries: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl InMemoryKeyCache {
    /// Creates a new in-memory cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
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

    /// Returns the number of entries currently in the cache.
    ///
    /// Note: This count may include expired entries that haven't been cleaned up yet.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
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
    async fn get(&self, kid: &str) -> Option<Key> {
        let entries = self.entries.read().await;
        entries.get(kid).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.ttl {
                Some(entry.key.clone())
            } else {
                None
            }
        })
    }

    async fn set(&self, kid: &str, key: Key) {
        let mut entries = self.entries.write().await;
        entries.insert(
            kid.to_string(),
            CacheEntry {
                key,
                inserted_at: std::time::Instant::now(),
            },
        );
    }

    async fn remove(&self, kid: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(kid);
    }

    async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

/// Convenience type alias for a cached key set using in-memory caching.
pub type InMemoryCachedKeySet<S> = CachedKeySet<InMemoryKeyCache, S>;

impl<S> InMemoryCachedKeySet<S> {
    /// Creates a new cached key source with in-memory caching and the specified TTL.
    pub fn with_ttl(source: S, ttl: Duration) -> Self {
        Self::new(InMemoryKeyCache::new(ttl), source)
    }

    /// Creates a new cached key source with in-memory caching and the default TTL.
    pub fn with_default_ttl(source: S) -> Self {
        Self::new(InMemoryKeyCache::with_default_ttl(), source)
    }

    /// Invalidates the cache, forcing fresh fetches on subsequent requests.
    pub async fn invalidate(&self) {
        self.cache().clear().await;
    }

    /// Removes a specific key from the cache.
    pub async fn invalidate_key(&self, kid: &str) {
        self.cache().remove(kid).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::KeySource;

    #[tokio::test]
    async fn test_in_memory_cache_basic() {
        let json = r#"{"kty": "oct", "kid": "test-key", "k": "AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        let cache = InMemoryKeyCache::new(Duration::from_secs(300));

        // Initially empty
        assert!(cache.get("test-key").await.is_none());

        // Set and get
        cache.set("test-key", key.clone()).await;
        let cached = cache.get("test-key").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().kid, Some("test-key".to_string()));

        // Remove
        cache.remove("test-key").await;
        assert!(cache.get("test-key").await.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_cache_expiration() {
        let json = r#"{"kty": "oct", "kid": "test-key", "k": "AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        // Very short TTL
        let cache = InMemoryKeyCache::new(Duration::from_millis(50));

        cache.set("test-key", key).await;
        assert!(cache.get("test-key").await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cache.get("test-key").await.is_none());
    }

    #[tokio::test]
    async fn test_in_memory_cache_clear() {
        let json = r#"{"kty": "oct", "kid": "test-key", "k": "AQAB"}"#;
        let key: Key = serde_json::from_str(json).unwrap();

        let cache = InMemoryKeyCache::new(Duration::from_secs(300));

        cache.set("key1", key.clone()).await;
        cache.set("key2", key).await;

        assert_eq!(cache.len().await, 2);

        cache.clear().await;

        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cached_key_set() {
        use crate::jwks::KeySet;

        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeySet::with_default_ttl(static_source);

        // First call should fetch from source and cache
        let key = cached.get_key("test-key").await.unwrap();
        assert!(key.is_some());

        // Verify it's cached
        let cached_key = cached.cache().get("test-key").await;
        assert!(cached_key.is_some());

        // Second call should use cache
        let key2 = cached.get_key("test-key").await.unwrap();
        assert!(key2.is_some());
    }

    #[tokio::test]
    async fn test_cached_key_set_miss() {
        use crate::jwks::KeySet;

        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeySet::with_default_ttl(static_source);

        // Request a non-existent key
        let key = cached.get_key("nonexistent").await.unwrap();
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_cached_key_set_get_keyset() {
        use crate::jwks::KeySet;

        let json = r#"{"keys": [
            {"kty": "oct", "kid": "key1", "k": "AQAB"},
            {"kty": "oct", "kid": "key2", "k": "AQAB"}
        ]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeySet::with_default_ttl(static_source);

        // Fetch keyset should cache all keys
        let keyset = cached.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 2);

        // Both keys should be cached
        assert!(cached.cache().get("key1").await.is_some());
        assert!(cached.cache().get("key2").await.is_some());
    }

    #[tokio::test]
    async fn test_cached_key_set_invalidate() {
        use crate::jwks::KeySet;

        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeySet::with_default_ttl(static_source);

        // Populate cache
        let _ = cached.get_key("test-key").await.unwrap();
        assert!(cached.cache().get("test-key").await.is_some());

        // Invalidate
        cached.invalidate().await;
        assert!(cached.cache().get("test-key").await.is_none());
    }

    #[tokio::test]
    async fn test_cached_key_set_invalidate_key() {
        use crate::jwks::KeySet;

        let json = r#"{"keys": [
            {"kty": "oct", "kid": "key1", "k": "AQAB"},
            {"kty": "oct", "kid": "key2", "k": "AQAB"}
        ]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = InMemoryCachedKeySet::with_default_ttl(static_source);

        // Populate cache
        let _ = cached.get_keyset().await.unwrap();

        // Invalidate only one key
        cached.invalidate_key("key1").await;

        assert!(cached.cache().get("key1").await.is_none());
        assert!(cached.cache().get("key2").await.is_some());
    }
}

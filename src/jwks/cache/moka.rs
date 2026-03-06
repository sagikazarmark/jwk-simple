use std::time::Duration;

use moka::future::Cache;

use crate::error::Result;
use crate::jwks::KeySet;

use super::KeyCache;

const KEYSET_CACHE_KEY: &str = "jwks";

/// Default cache TTL for [`MokaKeyCache`] (5 minutes).
pub const DEFAULT_MOKA_CACHE_TTL: Duration = Duration::from_secs(300);

/// A Moka-backed in-memory key cache with TTL-based expiration.
#[derive(Debug)]
pub struct MokaKeyCache {
    cache: Cache<&'static str, KeySet>,
    ttl: Duration,
}

impl MokaKeyCache {
    /// Creates a new Moka-backed cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        let cache = Cache::builder().max_capacity(1).time_to_live(ttl).build();

        Self { cache, ttl }
    }

    /// Creates a new Moka-backed cache with the default TTL (5 minutes).
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_MOKA_CACHE_TTL)
    }

    /// Returns the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for MokaKeyCache {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyCache for MokaKeyCache {
    async fn get(&self) -> Result<Option<KeySet>> {
        Ok(self.cache.get(&KEYSET_CACHE_KEY).await)
    }

    async fn set(&self, keyset: KeySet) -> Result<()> {
        self.cache.insert(KEYSET_CACHE_KEY, keyset).await;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.cache.invalidate_all();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Key;
    use crate::error::Error;
    use crate::jwks::{CachedKeyStore, KeyStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn moka_cache_basic() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        let cache = MokaKeyCache::new(Duration::from_secs(300));

        assert!(cache.get().await.unwrap().is_none());

        cache.set(keyset.clone()).await.unwrap();
        let cached = cache.get().await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);

        cache.clear().await.unwrap();
        assert!(cache.get().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn moka_cache_expiration() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let keyset: KeySet = serde_json::from_str(json).unwrap();

        let cache = MokaKeyCache::new(Duration::from_millis(20));

        cache.set(keyset).await.unwrap();
        assert!(cache.get().await.unwrap().is_some());

        tokio::time::sleep(Duration::from_millis(40)).await;
        cache.cache.run_pending_tasks().await;

        assert!(cache.get().await.unwrap().is_none());
    }

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

        fn fetch_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl KeyStore for RotatingKeyStore {
        async fn get_keyset(&self) -> crate::error::Result<KeySet> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
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
    async fn cached_key_store_refetches_on_unknown_kid() {
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
        let cached = CachedKeyStore::new(MokaKeyCache::new(Duration::from_secs(300)), source);

        let key = cached.get_key("old-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(cached.store().fetch_count(), 1);

        let key = cached.get_key("old-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(cached.store().fetch_count(), 1);

        let key = cached.get_key("new-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(cached.store().fetch_count(), 2);

        let key = cached.get_key("new-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(cached.store().fetch_count(), 2);
    }

    #[tokio::test]
    async fn cached_key_store_source_error_propagates() {
        let cached =
            CachedKeyStore::new(MokaKeyCache::new(Duration::from_secs(300)), FailingKeyStore);

        let err = cached.get_keyset().await.unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }

    #[tokio::test]
    async fn cached_key_store_get_and_invalidate() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = CachedKeyStore::new(MokaKeyCache::with_default_ttl(), static_source);

        let key = cached.get_key("test-key").await.unwrap();
        assert!(key.is_some());

        let cached_keyset = cached.cache().get().await.unwrap();
        assert!(cached_keyset.is_some());

        cached.cache().clear().await.unwrap();
        let cleared = cached.cache().get().await.unwrap();
        assert!(cleared.is_none());
    }

    #[tokio::test]
    async fn cached_key_store_get_keyset() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "key1", "k": "AQAB"},
            {"kty": "oct", "kid": "key2", "k": "AQAB"}
        ]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = CachedKeyStore::new(MokaKeyCache::with_default_ttl(), static_source);

        let keyset = cached.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 2);

        let cached_keyset = cached.cache().get().await.unwrap();
        assert!(cached_keyset.is_some());
        assert_eq!(cached_keyset.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn cached_key_store_get_key_miss() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let static_source = serde_json::from_str::<KeySet>(json).unwrap();

        let cached = CachedKeyStore::new(MokaKeyCache::with_default_ttl(), static_source);

        let key: Option<Key> = cached.get_key("nonexistent").await.unwrap();
        assert!(key.is_none());
    }
}

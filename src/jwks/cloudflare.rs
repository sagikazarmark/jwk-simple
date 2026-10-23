//! Cloudflare Workers support for JWKS.
//!
//! This module provides [`KvKeyCache`], a [`KeyCache`] backed by Workers KV.
//!
//! For fetching the JWKS itself inside a Worker, use
//! `HttpKeyStore` (feature `http`) over a
//! `TowerTransport` (feature `tower`) wrapping
//! [`tower_worker_fetch::FetchService`](https://docs.rs/tower-worker-fetch):
//! it is a `Send + Sync` `tower::Service` over the Workers `fetch` API, so no
//! wrapping is needed, and a per-request timeout goes in the request extensions
//! (`tower_worker_fetch::Timeout`) since there is no tokio timer on Workers.
//!
//! # Examples
//!
//! ```ignore
//! use std::time::Duration;
//!
//! use bytes::Bytes;
//! use http::Request;
//! use http_body_util::Full;
//! use jwk_simple::jwks::{CachedKeyStore, HttpKeyStore, KeyStore, TowerTransport, cloudflare::KvKeyCache};
//! use tower::ServiceBuilder;
//! use tower_worker_fetch::{FetchService, Timeout};
//!
//! let transport = TowerTransport::new(
//!     ServiceBuilder::new()
//!         .map_request(|mut req: Request<Full<Bytes>>| {
//!             req.extensions_mut().insert(Timeout(Duration::from_secs(5)));
//!             req
//!         })
//!         .service(FetchService::new()),
//! );
//! let remote = HttpKeyStore::new_with_transport("https://example.com/.well-known/jwks.json", transport)?;
//! let cache = KvKeyCache::new(env.kv("JWKS_CACHE")?);
//! let store = CachedKeyStore::new(cache, remote);
//!
//! let key = store.get_key("my-key-id").await?;
//! ```

use worker::kv::KvStore;

use crate::error::{Error, Result};
use crate::jwks::{KeyCache, KeySet, assume_send};

/// Default TTL for KV cache entries (5 minutes).
pub const DEFAULT_KV_TTL_SECONDS: u64 = 300;

/// A key cache backed by Cloudflare Workers KV.
///
/// This implementation stores the serialized key set in Cloudflare KV with optional TTL support.
///
/// # KV Storage Format
///
/// The key set is stored under a single KV key (configurable via `with_key`).
/// The value is the JSON-serialized [`KeySet`].
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

// KV operations await JS promises, which are not `Send`; see `assume_send`.
#[async_trait::async_trait]
impl KeyCache for KvKeyCache {
    async fn get(&self) -> Result<Option<KeySet>> {
        assume_send(async {
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
        })
        .await
    }

    async fn set(&self, keyset: KeySet) -> Result<()> {
        let json = serde_json::to_string(&keyset)
            .map_err(|e| Error::Cache(format!("serialize failed: {}", e)))?;

        assume_send(async move {
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
        })
        .await
    }

    async fn clear(&self) -> Result<()> {
        assume_send(async {
            self.kv
                .delete(&self.key)
                .await
                .map_err(|e| Error::Cache(format!("delete failed: {}", e)))
        })
        .await
    }
}

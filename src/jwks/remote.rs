//! Remote JWKS fetching without caching.
//!
//! This module provides [`RemoteKeyStore`], which fetches keys from an HTTP endpoint
//! on every request. For production use, consider wrapping with [`CachedKeyStore`](super::CachedKeyStore).

use std::time::Duration;

use crate::error::Result;

use super::{KeySet, KeyStore};

/// Default timeout for HTTP requests (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum allowed JWKS response size (1 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A key store that fetches from an HTTP endpoint on every request.
///
/// This implementation does **not** cache keys. Every call to [`get_key`](KeyStore::get_key)
/// or [`get_keyset`](KeyStore::get_keyset) will make an HTTP request.
///
/// For production use with high request volumes, wrap this in
/// [`CachedKeyStore`](super::CachedKeyStore) with [`MokaKeyCache`](super::MokaKeyCache):
///
/// ```ignore
/// use jwk_simple::{CachedKeyStore, MokaKeyCache, RemoteKeyStore};
/// use std::time::Duration;
///
/// let remote = RemoteKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let cache = MokaKeyCache::new(Duration::from_secs(300));
/// let cached = CachedKeyStore::new(cache, remote);
/// ```
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{KeyStore, RemoteKeyStore};
///
/// let store = RemoteKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let key = store.get_key("my-key-id").await?;
/// ```
///
/// # Custom HTTP Client
///
/// You can provide a custom [`reqwest::Client`] for full control over HTTP behavior:
///
/// ```ignore
/// use jwk_simple::RemoteKeyStore;
/// use std::time::Duration;
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()
///     .unwrap();
///
/// let store = RemoteKeyStore::new_with_client(
///     "https://example.com/.well-known/jwks.json",
///     client,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RemoteKeyStore {
    url: String,
    client: reqwest::Client,
    max_response_bytes: usize,
}

impl RemoteKeyStore {
    /// Creates a new `RemoteKeyStore` from a URL.
    ///
    /// Uses a default HTTP client with a 30-second timeout. To customize the client,
    /// use [`new_with_client`](Self::new_with_client).
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()?;

        Ok(Self {
            url: url.into(),
            client,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Creates a new `RemoteKeyStore` with a custom HTTP client.
    ///
    /// Use this to configure custom timeouts, headers, proxies, TLS settings, etc.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use jwk_simple::RemoteKeyStore;
    /// use std::time::Duration;
    ///
    /// let client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .unwrap();
    ///
    /// let store = RemoteKeyStore::new_with_client(
    ///     "https://example.com/.well-known/jwks.json",
    ///     client,
    /// );
    /// ```
    pub fn new_with_client(url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            url: url.into(),
            client,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Sets the maximum allowed JWKS response size in bytes.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Fetches the JWKS from the remote endpoint.
    async fn fetch(&self) -> Result<KeySet> {
        let mut response = self
            .client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?;

        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .unwrap_or(usize::MAX);

            if next_len > self.max_response_bytes {
                return Err(crate::error::Error::PayloadTooLarge {
                    max_bytes: self.max_response_bytes,
                    actual_bytes: next_len,
                });
            }

            bytes.extend_from_slice(&chunk);
        }

        let json = std::str::from_utf8(&bytes).map_err(|e| {
            crate::error::Error::Parse(crate::error::ParseError::Json(format!(
                "invalid UTF-8 response body: {}",
                e
            )))
        })?;

        Ok(serde_json::from_str::<KeySet>(&json)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyStore for RemoteKeyStore {
    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration as TokioDuration, sleep};

    async fn spawn_single_response_server(response: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await;
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        });

        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_remote_keystore_fetch_success() {
        let body = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = RemoteKeyStore::new(url).unwrap();
        let keyset = store.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 1);
        assert!(keyset.find_by_kid("k1").is_some());
    }

    #[tokio::test]
    async fn test_remote_keystore_non_2xx_propagates_error() {
        let body = "not found";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = RemoteKeyStore::new(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            crate::error::Error::Http(e) => {
                assert_eq!(e.status(), Some(StatusCode::NOT_FOUND));
            }
            other => panic!("expected HTTP status error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_remote_keystore_invalid_json_error() {
        let body = "not json";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = RemoteKeyStore::new(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::Parse(crate::error::ParseError::Json(_))
        ));
    }

    #[tokio::test]
    async fn test_remote_keystore_network_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let store = RemoteKeyStore::new(format!("http://{}", addr)).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            crate::error::Error::Http(e) => {
                assert!(e.is_connect(), "expected connection error, got: {e}");
            }
            other => panic!("expected transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_remote_keystore_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await;
            sleep(TokioDuration::from_millis(200)).await;
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let store = RemoteKeyStore::new_with_client(format!("http://{}", addr), client);
        let err = store.get_keyset().await.unwrap_err();
        match err {
            crate::error::Error::Http(e) => {
                assert!(e.is_timeout(), "expected timeout error, got: {e}");
            }
            other => panic!("expected timeout transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_remote_keystore_payload_too_large() {
        let large_key = "A".repeat(DEFAULT_MAX_RESPONSE_BYTES + 1024);
        let body = format!(r#"{{"keys":[{{"kty":"oct","k":"{}"}}]}}"#, large_key);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = RemoteKeyStore::new(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        assert!(matches!(err, crate::error::Error::PayloadTooLarge { .. }));
    }
}

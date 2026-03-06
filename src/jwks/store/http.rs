//! Remote JWKS fetching without caching.
//!
//! This module provides [`HttpKeyStore`], which fetches keys from an HTTP endpoint
//! on every request. For production use, consider wrapping with
//! [`CachedKeyStore`](crate::jwks::CachedKeyStore).

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use crate::error::{Error, ParseError, Result};
use crate::jwks::{KeySet, KeyStore};
use url::Url;

/// Default timeout for HTTP requests (30 seconds).
#[cfg(not(target_arch = "wasm32"))]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A key store that fetches from an HTTP endpoint on every request.
///
/// This implementation does **not** cache keys. Every call to [`get_key`](KeyStore::get_key)
/// or [`get_keyset`](KeyStore::get_keyset) will make an HTTP request.
///
/// For production use with high request volumes, wrap this in
/// [`CachedKeyStore`](crate::jwks::CachedKeyStore) with [`MokaKeyCache`](crate::jwks::MokaKeyCache):
///
/// ```ignore
/// use jwk_simple::jwks::{CachedKeyStore, HttpKeyStore, MokaKeyCache};
/// use std::time::Duration;
///
/// let remote = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let cache = MokaKeyCache::new(Duration::from_secs(300));
/// let cached = CachedKeyStore::new(cache, remote);
/// ```
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::jwks::{HttpKeyStore, KeyStore};
///
/// let store = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;
/// let key = store.get_key("my-key-id").await?;
/// ```
///
/// # Custom HTTP Client
///
/// You can provide a custom [`reqwest::Client`] for full control over HTTP behavior:
///
/// ```ignore
/// use jwk_simple::jwks::HttpKeyStore;
/// use std::time::Duration;
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()
///     .unwrap();
///
/// let store = HttpKeyStore::new_with_client(
///     "https://example.com/.well-known/jwks.json",
///     client,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct HttpKeyStore {
    url: Url,
    client: reqwest::Client,
}

fn require_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(Error::InvalidUrl(
            "URL scheme must be 'https'; use new_insecure() or new_with_client_insecure() to allow HTTP for local development or testing".to_string(),
        ));
    }
    Ok(())
}

impl HttpKeyStore {
    /// Creates a new `HttpKeyStore` from a URL.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP (e.g. in local development
    /// or testing), use [`new_insecure`](Self::new_insecure).
    ///
    /// On native targets, uses a default HTTP client with a 30-second timeout.
    /// On `wasm32`, reqwest uses the browser/Fetch backend where client-level
    /// timeout configuration is not available.
    /// To customize the client, use [`new_with_client`](Self::new_with_client).
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_TIMEOUT);
        let client = builder.build()?;

        Self::new_with_client(url, client)
    }

    /// Creates a new `HttpKeyStore` with a custom HTTP client.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP, use
    /// [`new_with_client_insecure`](Self::new_with_client_insecure).
    ///
    /// Use this to configure custom headers, proxies, TLS settings, and (on native
    /// targets) custom timeouts.
    ///
    /// On `wasm32`, reqwest uses the browser/Fetch backend where client-level
    /// timeout configuration is not available.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use jwk_simple::jwks::HttpKeyStore;
    /// use std::time::Duration;
    ///
    /// let client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()
    ///     .unwrap();
    ///
    /// let store = HttpKeyStore::new_with_client(
    ///     "https://example.com/.well-known/jwks.json",
    ///     client,
    /// )?;
    /// ```
    pub fn new_with_client(url: impl AsRef<str>, client: reqwest::Client) -> Result<Self> {
        let url = Url::parse(url.as_ref()).map_err(|e| Error::InvalidUrl(e.to_string()))?;
        require_https(&url)?;

        Ok(Self { url, client })
    }

    /// Creates a new `HttpKeyStore` without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    pub fn new_insecure(url: impl AsRef<str>) -> Result<Self> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_TIMEOUT);
        let client = builder.build()?;

        Self::new_with_client_insecure(url, client)
    }

    /// Creates a new `HttpKeyStore` with a custom HTTP client, without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    pub fn new_with_client_insecure(url: impl AsRef<str>, client: reqwest::Client) -> Result<Self> {
        let url = Url::parse(url.as_ref()).map_err(|e| Error::InvalidUrl(e.to_string()))?;

        Ok(Self { url, client })
    }

    /// Fetches the JWKS from the remote endpoint.
    async fn fetch(&self) -> Result<KeySet> {
        let response = self
            .client
            .get(self.url.as_str())
            .send()
            .await?
            .error_for_status()?;

        let bytes = response.bytes().await?;

        let json = std::str::from_utf8(&bytes).map_err(|e| {
            Error::Parse(ParseError::Json(format!(
                "invalid UTF-8 response body: {}",
                e
            )))
        })?;

        Ok(serde_json::from_str::<KeySet>(json)?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyStore for HttpKeyStore {
    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
    async fn test_http_keystore_fetch_success() {
        let body = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let keyset = store.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 1);
        assert!(keyset.get_by_kid("k1").is_some());
    }

    #[tokio::test]
    async fn test_http_keystore_non_2xx_propagates_error() {
        let body = "not found";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Http(e) => {
                assert_eq!(e.status(), Some(StatusCode::NOT_FOUND));
            }
            other => panic!("expected HTTP status error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_http_keystore_invalid_json_error() {
        let body = "not json";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        assert!(matches!(err, Error::Parse(ParseError::Json(_))));
    }

    #[tokio::test]
    async fn test_http_keystore_network_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let store = HttpKeyStore::new_insecure(format!("http://{}", addr)).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Http(e) => {
                assert!(e.is_connect(), "expected connection error, got: {e}");
            }
            other => panic!("expected transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_http_keystore_timeout() {
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
        let store =
            HttpKeyStore::new_with_client_insecure(format!("http://{}", addr), client).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Http(e) => {
                assert!(e.is_timeout(), "expected timeout error, got: {e}");
            }
            other => panic!("expected timeout transport error, got: {}", other),
        }
    }

    #[test]
    fn test_http_keystore_new_rejects_invalid_url() {
        let err = HttpKeyStore::new("not a valid url").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn test_http_keystore_new_with_client_rejects_invalid_url() {
        let client = reqwest::Client::new();
        let err = HttpKeyStore::new_with_client("not a valid url", client).unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn test_http_keystore_new_rejects_http_url() {
        let err = HttpKeyStore::new("http://example.com/.well-known/jwks.json").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn test_http_keystore_new_with_client_rejects_http_url() {
        let client = reqwest::Client::new();
        let err = HttpKeyStore::new_with_client("http://example.com/.well-known/jwks.json", client)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn test_http_keystore_new_accepts_https_url() {
        // Construction succeeds; no network call is made here.
        assert!(HttpKeyStore::new("https://example.com/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn test_http_keystore_new_with_client_accepts_https_url() {
        let client = reqwest::Client::new();
        // Construction succeeds; no network call is made here.
        assert!(
            HttpKeyStore::new_with_client("https://example.com/.well-known/jwks.json", client)
                .is_ok()
        );
    }

    #[test]
    fn test_http_keystore_new_insecure_accepts_http_url() {
        assert!(HttpKeyStore::new_insecure("http://example.com/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn test_http_keystore_new_with_client_insecure_accepts_http_url() {
        let client = reqwest::Client::new();
        assert!(
            HttpKeyStore::new_with_client_insecure(
                "http://example.com/.well-known/jwks.json",
                client
            )
            .is_ok()
        );
    }
}

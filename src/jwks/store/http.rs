//! Remote JWKS fetching without caching.
//!
//! This module provides [`HttpKeyStore`], which fetches keys from an HTTP endpoint
//! on every request through an [`HttpTransport`]. For production use, consider
//! wrapping with [`CachedKeyStore`](crate::jwks::CachedKeyStore).

use std::{fmt, sync::Arc};

use bytes::Bytes;
use http::{Method, Request, Uri};
use url::Url;

use crate::error::{Error, Result};
use crate::jwks::{HttpTransport, KeySet, KeyStore, TransportError, TransportErrorKind};

/// Default cap on the size of a JWKS response body (1 MiB).
///
/// A JWKS is a few kilobytes, tens with `x5c` chains; the cap is a bound on
/// what a misbehaving endpoint can make the process allocate, not a sanity
/// check. See [`HttpKeyStore::with_max_body_size`].
pub const DEFAULT_MAX_BODY_SIZE: usize = 1024 * 1024;

/// A key store that fetches from an HTTP endpoint on every request.
///
/// This implementation does **not** cache keys. Every call to [`get_key`](KeyStore::get_key)
/// or [`get_keyset`](KeyStore::get_keyset) will make an HTTP request.
///
/// For production use with high request volumes, wrap this in
/// [`CachedKeyStore`](crate::jwks::CachedKeyStore) with `MokaKeyCache` (feature `moka`):
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
/// # Transports
///
/// HTTP goes through the [`HttpTransport`] trait. With the `reqwest` feature,
/// `HttpKeyStore::new` uses the default transport, a `reqwest::Client` with a
/// 30-second timeout on native targets (`ReqwestTransport`).
/// [`new_with_transport`](Self::new_with_transport) takes any other: a
/// `ReqwestTransport` over your own client (proxy, custom TLS roots), a
/// `TowerTransport` (feature `tower`) over a
/// `tower::Service` such as `tower-worker-fetch` on Cloudflare Workers, or
/// your own implementation.
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
/// With a custom `reqwest::Client` for full control over HTTP behavior:
///
/// ```ignore
/// use jwk_simple::jwks::HttpKeyStore;
/// use std::time::Duration;
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()?;
///
/// let store = HttpKeyStore::new_with_client(
///     "https://example.com/.well-known/jwks.json",
///     client,
/// )?;
/// ```
#[derive(Clone)]
pub struct HttpKeyStore {
    url: Url,
    uri: Uri,
    transport: Arc<dyn HttpTransport>,
    max_body_size: usize,
}

impl fmt::Debug for HttpKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpKeyStore")
            .field("url", &self.url.as_str())
            .field("max_body_size", &self.max_body_size)
            .finish_non_exhaustive()
    }
}

fn require_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(Error::InvalidUrlScheme(
            "URL scheme must be 'https'; use an *_insecure() constructor to allow HTTP for local development or testing",
        ));
    }
    Ok(())
}

/// `url` parsed twice: as a `Url` (the scheme check, display) and as the
/// `http::Uri` the request carries.
fn parse_url(url: &str) -> Result<(Url, Uri)> {
    let url = Url::parse(url).map_err(Error::InvalidUrl)?;
    let uri = url
        .as_str()
        .parse::<Uri>()
        .map_err(|_| Error::InvalidInput("URL cannot be used as an HTTP request URI"))?;
    Ok((url, uri))
}

#[cfg(feature = "reqwest")]
impl HttpKeyStore {
    /// Creates a new `HttpKeyStore` from a URL, over the default transport.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP (e.g. in local development
    /// or testing), use [`new_insecure`](Self::new_insecure).
    ///
    /// On native targets, uses a default HTTP client with a 30-second timeout
    /// (`DEFAULT_TIMEOUT`); it needs a TLS backend,
    /// so enable the `default-tls` feature (or `rustls` / `native-tls`). On `wasm32`,
    /// reqwest uses the browser/Fetch backend where client-level timeout configuration
    /// is not available. To customize the client, use [`new_with_client`](Self::new_with_client).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`], [`Error::InvalidInput`] or [`Error::InvalidUrlScheme`] for a
    /// bad URL, and [`Error::Transport`] if reqwest cannot build a client.
    pub fn new(url: impl AsRef<str>) -> Result<Self> {
        let transport = crate::jwks::ReqwestTransport::try_default().map_err(Error::Transport)?;
        Self::new_with_transport(url, transport)
    }

    /// Creates a new `HttpKeyStore` with a custom HTTP client.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP, use
    /// [`new_with_client_insecure`](Self::new_with_client_insecure).
    ///
    /// Use this to configure custom headers, proxies, TLS settings, and (on native
    /// targets) custom timeouts. Equivalent to
    /// [`new_with_transport`](Self::new_with_transport) over
    /// [`ReqwestTransport::new(client)`](crate::jwks::ReqwestTransport::new).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use jwk_simple::jwks::HttpKeyStore;
    /// use std::time::Duration;
    ///
    /// let client = reqwest::Client::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .build()?;
    ///
    /// let store = HttpKeyStore::new_with_client(
    ///     "https://example.com/.well-known/jwks.json",
    ///     client,
    /// )?;
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`], [`Error::InvalidInput`] or [`Error::InvalidUrlScheme`] for a bad URL.
    pub fn new_with_client(url: impl AsRef<str>, client: reqwest::Client) -> Result<Self> {
        Self::new_with_transport(url, crate::jwks::ReqwestTransport::new(client))
    }

    /// Creates a new `HttpKeyStore` over the default transport, without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] or [`Error::InvalidInput`] for a bad URL, and
    /// [`Error::Transport`] if reqwest cannot build a client.
    pub fn new_insecure(url: impl AsRef<str>) -> Result<Self> {
        let transport = crate::jwks::ReqwestTransport::try_default().map_err(Error::Transport)?;
        Self::new_with_transport_insecure(url, transport)
    }

    /// Creates a new `HttpKeyStore` with a custom HTTP client, without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] or [`Error::InvalidInput`] for a bad URL.
    pub fn new_with_client_insecure(url: impl AsRef<str>, client: reqwest::Client) -> Result<Self> {
        Self::new_with_transport_insecure(url, crate::jwks::ReqwestTransport::new(client))
    }
}

impl HttpKeyStore {
    /// Creates a new `HttpKeyStore` over `transport`.
    ///
    /// The URL must use the `https` scheme. To allow plain HTTP, use
    /// [`new_with_transport_insecure`](Self::new_with_transport_insecure).
    ///
    /// # Examples
    ///
    /// On Cloudflare Workers, with the `tower` feature:
    ///
    /// ```ignore
    /// use jwk_simple::jwks::{HttpKeyStore, TowerTransport};
    /// use tower_worker_fetch::FetchService;
    ///
    /// let store = HttpKeyStore::new_with_transport(
    ///     "https://example.com/.well-known/jwks.json",
    ///     TowerTransport::new(FetchService::new()),
    /// )?;
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if the URL does not parse, [`Error::InvalidInput`] if it
    /// parses but cannot be sent as an HTTP request URI, and [`Error::InvalidUrlScheme`]
    /// if it is not `https`.
    pub fn new_with_transport(url: impl AsRef<str>, transport: impl HttpTransport) -> Result<Self> {
        let (url, uri) = parse_url(url.as_ref())?;
        require_https(&url)?;

        Ok(Self::from_parts(url, uri, transport))
    }

    /// Creates a new `HttpKeyStore` over `transport`, without enforcing HTTPS.
    ///
    /// # Warning
    ///
    /// This constructor skips the HTTPS scheme check and is intended **only** for local
    /// development or testing where HTTPS is not available. Do **not** use this in
    /// production — plain HTTP connections allow network attackers to tamper with
    /// JWKS responses and inject attacker-controlled keys.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] if the URL does not parse, and [`Error::InvalidInput`] if it
    /// parses but cannot be sent as an HTTP request URI.
    pub fn new_with_transport_insecure(
        url: impl AsRef<str>,
        transport: impl HttpTransport,
    ) -> Result<Self> {
        let (url, uri) = parse_url(url.as_ref())?;

        Ok(Self::from_parts(url, uri, transport))
    }

    fn from_parts(url: Url, uri: Uri, transport: impl HttpTransport) -> Self {
        Self {
            url,
            uri,
            transport: Arc::new(transport),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }

    /// Caps the size of the response body (default: [`DEFAULT_MAX_BODY_SIZE`]).
    ///
    /// A response announcing (via `Content-Length`) or streaming more than
    /// `max_body_size` bytes fails with [`Error::Transport`] of kind
    /// [`TransportErrorKind::TooLarge`], and the transport stops reading at
    /// the limit.
    #[must_use]
    pub fn with_max_body_size(mut self, max_body_size: usize) -> Self {
        self.max_body_size = max_body_size;
        self
    }

    /// The JWKS URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The cap on the size of the response body.
    #[must_use]
    pub fn max_body_size(&self) -> usize {
        self.max_body_size
    }

    /// Fetches the JWKS from the remote endpoint.
    async fn fetch(&self) -> Result<KeySet> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(self.uri.clone())
            .body(Bytes::new())
            // Unreachable: the URI was validated at construction.
            .map_err(|e| {
                Error::Transport(TransportError::with_source(TransportErrorKind::Other, e))
            })?;

        let response = self
            .transport
            .send(request, self.max_body_size)
            .await
            .map_err(Error::Transport)?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::HttpStatus(status.as_u16()));
        }

        Ok(serde_json::from_slice::<KeySet>(response.body())?)
    }
}

#[async_trait::async_trait]
impl KeyStore for HttpKeyStore {
    async fn get_keyset(&self) -> Result<KeySet> {
        self.fetch().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport answering from memory.
    struct Static(http::StatusCode, &'static str);

    impl HttpTransport for Static {
        fn send(&self, req: Request<Bytes>, limit: usize) -> crate::jwks::TransportFuture<'_> {
            assert_eq!(req.method(), Method::GET);
            let body = Bytes::from_static(self.1.as_bytes());
            let status = self.0;
            Box::pin(async move {
                if body.len() > limit {
                    return Err(TransportError::new(TransportErrorKind::TooLarge));
                }
                let mut resp = http::Response::new(body);
                *resp.status_mut() = status;
                Ok(resp)
            })
        }
    }

    const JWKS: &str = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        // The in-memory transport never pends, so a noop waker is enough; this
        // keeps the tests free of any async runtime.
        let mut f = std::pin::pin!(f);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = f.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    #[test]
    fn fetches_and_parses_through_the_transport() {
        let store = HttpKeyStore::new_with_transport(
            "https://example.com/.well-known/jwks.json",
            Static(http::StatusCode::OK, JWKS),
        )
        .unwrap();
        let keyset = block_on(store.get_keyset()).unwrap();
        assert_eq!(keyset.len(), 1);
        assert!(keyset.get_by_kid("k1").is_some());
        assert!(block_on(store.get_key("k1")).unwrap().is_some());
        assert!(block_on(store.get_key("nope")).unwrap().is_none());
    }

    #[test]
    fn non_2xx_is_reported_by_status() {
        let store = HttpKeyStore::new_with_transport(
            "https://example.com/jwks",
            Static(http::StatusCode::NOT_FOUND, "not found"),
        )
        .unwrap();
        let err = block_on(store.get_keyset()).unwrap_err();
        assert!(matches!(err, Error::HttpStatus(404)), "{err}");
    }

    #[test]
    fn invalid_json_is_a_json_error() {
        let store = HttpKeyStore::new_with_transport(
            "https://example.com/jwks",
            Static(http::StatusCode::OK, "not json"),
        )
        .unwrap();
        let err = block_on(store.get_keyset()).unwrap_err();
        assert!(matches!(err, Error::Json(_)), "{err}");
    }

    #[test]
    fn the_body_limit_is_passed_to_the_transport() {
        let store = HttpKeyStore::new_with_transport(
            "https://example.com/jwks",
            Static(http::StatusCode::OK, JWKS),
        )
        .unwrap()
        .with_max_body_size(8);
        assert_eq!(store.max_body_size(), 8);
        let err = block_on(store.get_keyset()).unwrap_err();
        match err {
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::TooLarge),
            other => panic!("expected a transport error, got: {other}"),
        }
    }

    #[test]
    fn transport_errors_are_wrapped() {
        struct Failing;
        impl HttpTransport for Failing {
            fn send(&self, _: Request<Bytes>, _: usize) -> crate::jwks::TransportFuture<'_> {
                Box::pin(async {
                    Err(TransportError::with_source(
                        TransportErrorKind::Connect,
                        "refused",
                    ))
                })
            }
        }
        let store = HttpKeyStore::new_with_transport("https://example.com/jwks", Failing).unwrap();
        let err = block_on(store.get_keyset()).unwrap_err();
        match &err {
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::Connect),
            other => panic!("expected a transport error, got: {other}"),
        }
        assert_eq!(
            err.to_string(),
            "transport error: connection failed: refused"
        );
        let source = std::error::Error::source(&err).unwrap();
        assert!(source.downcast_ref::<TransportError>().is_some());
    }

    #[test]
    fn url_validation() {
        let ok = Static(http::StatusCode::OK, JWKS);
        let err = HttpKeyStore::new_with_transport("not a valid url", ok).unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));

        let ok = Static(http::StatusCode::OK, JWKS);
        let err = HttpKeyStore::new_with_transport("http://example.com/jwks", ok).unwrap_err();
        assert!(matches!(err, Error::InvalidUrlScheme(_)));

        let ok = Static(http::StatusCode::OK, JWKS);
        let store = HttpKeyStore::new_with_transport("https://example.com/jwks", ok).unwrap();
        assert_eq!(store.url().as_str(), "https://example.com/jwks");
        assert_eq!(store.max_body_size(), DEFAULT_MAX_BODY_SIZE);

        let ok = Static(http::StatusCode::OK, JWKS);
        assert!(HttpKeyStore::new_with_transport_insecure("http://example.com/jwks", ok).is_ok());
    }

    #[test]
    fn debug_does_not_require_a_debug_transport() {
        let store = HttpKeyStore::new_with_transport(
            "https://example.com/jwks",
            Static(http::StatusCode::OK, JWKS),
        )
        .unwrap();
        let debug = format!("{store:?}");
        assert!(debug.starts_with("HttpKeyStore {"), "{debug}");
        assert!(debug.contains("https://example.com/jwks"), "{debug}");
    }

    #[allow(dead_code)]
    fn assert_send_sync(store: &HttpKeyStore) {
        fn send<T: Send>(_: T) {}
        fn send_sync<T: Send + Sync>(_: T) {}
        send_sync(store.clone());
        send(store.get_keyset());
        send(store.get_key("kid"));
        send_sync(Arc::new(store.clone()) as Arc<dyn KeyStore>);
    }
}

#[cfg(all(test, feature = "reqwest", not(target_arch = "wasm32")))]
mod reqwest_tests {
    use super::*;

    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    async fn spawn_single_response_server(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await;
            stream.write_all(&response).await.unwrap();
            let _ = stream.shutdown().await;
        });

        format!("http://{}", addr)
    }

    fn with_content_length(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn test_http_keystore_fetch_success() {
        let body = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;
        let url = spawn_single_response_server(with_content_length("200 OK", body)).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let keyset = store.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 1);
        assert!(keyset.get_by_kid("k1").is_some());
    }

    #[tokio::test]
    async fn test_http_keystore_non_2xx_propagates_error() {
        let url =
            spawn_single_response_server(with_content_length("404 Not Found", "not found")).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        assert!(matches!(err, Error::HttpStatus(404)), "{err}");
    }

    #[tokio::test]
    async fn test_http_keystore_invalid_json_error() {
        let url = spawn_single_response_server(with_content_length("200 OK", "not json")).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        assert!(matches!(err, Error::Json(_)));
    }

    #[tokio::test]
    async fn test_http_keystore_network_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let store = HttpKeyStore::new_insecure(format!("http://{}", addr)).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Transport(e) => {
                assert_eq!(e.kind(), TransportErrorKind::Connect, "{e}");
                let source = std::error::Error::source(&e).unwrap();
                assert!(source.downcast_ref::<reqwest::Error>().is_some());
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
            sleep(Duration::from_millis(200)).await;
            let _ = stream
                .write_all(&with_content_length("200 OK", r#"{"keys":[]}"#))
                .await;
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
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::Timeout, "{e}"),
            other => panic!("expected timeout transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_http_keystore_rejects_announced_oversized_body_before_reading() {
        // `Content-Length` says 1 MiB + 1 but only a few bytes follow: the
        // transport must fail on the header, not wait for the body.
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{}}",
            DEFAULT_MAX_BODY_SIZE + 1
        )
        .into_bytes();
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::TooLarge, "{e}"),
            other => panic!("expected too-large transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_http_keystore_stops_reading_an_unannounced_oversized_body() {
        // No `Content-Length`: the body runs until the connection closes, so
        // the limit can only be enforced while reading.
        let limit = 4096;
        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b' ', limit * 4));
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url)
            .unwrap()
            .with_max_body_size(limit);
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::TooLarge, "{e}"),
            other => panic!("expected too-large transport error, got: {}", other),
        }
    }

    #[tokio::test]
    async fn test_http_keystore_accepts_an_unannounced_body_within_the_limit() {
        let body = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;
        let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}").into_bytes();
        let url = spawn_single_response_server(response).await;

        let store = HttpKeyStore::new_insecure(url).unwrap();
        assert_eq!(store.get_keyset().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_http_keystore_caps_error_pages_too() {
        // An oversized 5xx is reported as too large, not by its status.
        let limit = 64;
        let page = " ".repeat(limit * 2);
        let url =
            spawn_single_response_server(with_content_length("500 Internal Server Error", &page))
                .await;

        let store = HttpKeyStore::new_insecure(url)
            .unwrap()
            .with_max_body_size(limit);
        let err = store.get_keyset().await.unwrap_err();
        match err {
            Error::Transport(e) => assert_eq!(e.kind(), TransportErrorKind::TooLarge, "{e}"),
            other => panic!("expected too-large transport error, got: {}", other),
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
        assert!(matches!(err, Error::InvalidUrlScheme(_)));
    }

    #[test]
    fn test_http_keystore_new_with_client_rejects_http_url() {
        let client = reqwest::Client::new();
        let err = HttpKeyStore::new_with_client("http://example.com/.well-known/jwks.json", client)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidUrlScheme(_)));
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

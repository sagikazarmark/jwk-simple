//! [`ReqwestTransport`]: the default [`HttpTransport`], over a [`reqwest::Client`].

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};

use super::{
    HttpTransport, TransportError, TransportErrorKind, TransportFuture, content_length, push_capped,
};
use crate::jwks::assume_send;

/// Timeout of the client [`ReqwestTransport::try_default`] builds (30 seconds).
#[cfg(not(target_arch = "wasm32"))]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The default [`HttpTransport`]: a [`reqwest::Client`].
///
/// This is the only place `reqwest` shows in the crate's API. Bodies are read
/// in chunks and capped at the limit.
///
/// On native targets `reqwest` needs a TLS backend to fetch `https` URLs:
/// enable this crate's `default-tls` (or `rustls` / `native-tls`) feature, or
/// bring a client whose TLS you configured yourself to
/// [`ReqwestTransport::new`]. On `wasm32` the JS host does TLS.
///
/// # Examples
///
/// ```ignore
/// use std::time::Duration;
/// use jwk_simple::jwks::{HttpKeyStore, ReqwestTransport};
///
/// let client = reqwest::Client::builder()
///     .timeout(Duration::from_secs(10))
///     .user_agent("my-app/1.0")
///     .build()?;
/// let store = HttpKeyStore::new_with_transport(
///     "https://example.com/.well-known/jwks.json",
///     ReqwestTransport::new(client),
/// )?;
/// ```
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Creates a transport over `client` (e.g. one configured with a proxy,
    /// custom TLS roots, or a `User-Agent`).
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Creates a transport over a client with reqwest's defaults for this
    /// crate's feature set and, on native targets, a `DEFAULT_TIMEOUT` (30 s)
    /// request timeout. On `wasm32`, reqwest uses the browser/Fetch backend
    /// where client-level timeouts are not available.
    ///
    /// # Errors
    ///
    /// [`TransportErrorKind::Other`] if reqwest cannot build a client (its TLS
    /// backend failed to initialize).
    pub fn try_default() -> Result<Self, TransportError> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(DEFAULT_TIMEOUT);
        builder
            .build()
            .map(Self::new)
            .map_err(|e| TransportError::with_source(TransportErrorKind::Other, e))
    }
}

impl HttpTransport for ReqwestTransport {
    fn send(&self, req: Request<Bytes>, limit: usize) -> TransportFuture<'_> {
        // On wasm, reqwest's future awaits JS promises: see `assume_send`.
        Box::pin(assume_send(send(self.client.clone(), req, limit)))
    }
}

async fn send(
    client: reqwest::Client,
    req: Request<Bytes>,
    limit: usize,
) -> Result<Response<Bytes>, TransportError> {
    let req = reqwest::Request::try_from(req).map_err(classify)?;
    let mut resp = client.execute(req).await.map_err(classify)?;
    if content_length(resp.headers()).is_some_and(|n| n > limit as u64) {
        return Err(TransportError::new(TransportErrorKind::TooLarge));
    }
    let status = resp.status();
    let headers = std::mem::take(resp.headers_mut());
    let body = read_body(resp, limit).await?;
    let mut out = Response::new(body);
    *out.status_mut() = status;
    *out.headers_mut() = headers;
    Ok(out)
}

/// The body, read chunk by chunk and capped at `limit`.
#[cfg(not(target_arch = "wasm32"))]
async fn read_body(mut resp: reqwest::Response, limit: usize) -> Result<Bytes, TransportError> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(classify)? {
        push_capped(&mut out, &chunk, limit)?;
    }
    Ok(Bytes::from(out))
}

/// The body, read chunk by chunk and capped at `limit`. `chunk()` does not
/// exist on wasm; the stream is polled directly to avoid a `futures-util`
/// dependency.
#[cfg(target_arch = "wasm32")]
async fn read_body(resp: reqwest::Response, limit: usize) -> Result<Bytes, TransportError> {
    use futures_core::Stream;

    let mut stream = std::pin::pin!(resp.bytes_stream());
    let mut out = Vec::new();
    while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
        push_capped(&mut out, &chunk.map_err(classify)?, limit)?;
    }
    Ok(Bytes::from(out))
}

fn classify(e: reqwest::Error) -> TransportError {
    let kind = if e.is_timeout() {
        TransportErrorKind::Timeout
    } else if is_connect(&e) {
        TransportErrorKind::Connect
    } else if e.is_body() || e.is_decode() {
        TransportErrorKind::Body
    } else {
        TransportErrorKind::Other
    };
    TransportError::with_source(kind, e)
}

#[cfg(not(target_arch = "wasm32"))]
fn is_connect(e: &reqwest::Error) -> bool {
    e.is_connect()
}

/// `fetch` does not tell connection failures apart.
#[cfg(target_arch = "wasm32")]
fn is_connect(_: &reqwest::Error) -> bool {
    false
}

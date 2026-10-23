//! The HTTP leaf under [`HttpKeyStore`](super::HttpKeyStore): [`HttpTransport`]
//! and its implementations, `ReqwestTransport` (feature `reqwest`) and
//! `TowerTransport` (feature `tower`).
//!
//! Everything above the leaf (the request, HTTPS enforcement, status handling,
//! JSON parsing, caching) is the store's; a transport only sends one request
//! and buffers the response, capped at the store's body limit.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use bytes::Bytes;
use http::{Request, Response};

#[cfg(feature = "reqwest")]
mod reqwest_transport;
#[cfg(all(feature = "reqwest", not(target_arch = "wasm32")))]
pub use reqwest_transport::DEFAULT_TIMEOUT;
#[cfg(feature = "reqwest")]
pub use reqwest_transport::ReqwestTransport;
#[cfg(feature = "tower")]
mod tower_transport;
#[cfg(feature = "tower")]
pub use tower_transport::TowerTransport;

/// A boxed error, as tower services and transports return them.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The future [`HttpTransport::send`] returns.
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<Bytes>, TransportError>> + Send + 'a>>;

/// Sends one HTTP request and buffers the response.
///
/// [`HttpKeyStore`](super::HttpKeyStore) builds the request (`GET`, the JWKS
/// URL) and does everything else: HTTPS enforcement, status classification,
/// JSON parsing. A transport must:
///
/// - return non-2xx responses as `Ok`: the store reports the status;
/// - buffer at most `limit` bytes of body, failing with
///   [`TransportErrorKind::TooLarge`] beyond that, up front if `Content-Length`
///   says so and while reading otherwise (an endpoint must not be able to make
///   the process allocate without bound). The limit applies whatever the
///   status: an oversized error page is reported as too large, not by its status.
///
/// `ReqwestTransport` (feature `reqwest`) is the default; `TowerTransport`
/// (feature `tower`) adapts any `tower::Service` over `http` types, such as
/// `tower-reqwest` or, on Cloudflare Workers, `tower-worker-fetch`. Implement
/// this for anything else (a JS host's `fetch` directly, an in-memory fake in
/// tests).
///
/// The transport and its future are `Send` on every target, `wasm32` included.
/// A transport over a JS API wraps its future with
/// [`assume_send`](super::assume_send).
pub trait HttpTransport: Send + Sync + 'static {
    /// Sends `req`, buffering at most `limit` bytes of body.
    fn send(&self, req: Request<Bytes>, limit: usize) -> TransportFuture<'_>;
}

/// A shared transport (also `Arc<dyn HttpTransport>`).
impl<T: HttpTransport + ?Sized> HttpTransport for Arc<T> {
    fn send(&self, req: Request<Bytes>, limit: usize) -> TransportFuture<'_> {
        (**self).send(req, limit)
    }
}

/// What went wrong in a transport.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportErrorKind {
    /// The transport's own timeout fired.
    Timeout,
    /// No connection: DNS, TCP, TLS.
    Connect,
    /// The response body could not be read.
    Body,
    /// The response body exceeds the limit.
    TooLarge,
    /// Anything else.
    Other,
}

impl TransportErrorKind {
    fn message(self) -> &'static str {
        match self {
            Self::Timeout => "timed out",
            Self::Connect => "connection failed",
            Self::Body => "reading the response body failed",
            Self::TooLarge => "response too large",
            Self::Other => "transport error",
        }
    }
}

/// A transport failure: a [`TransportErrorKind`] and an optional cause.
#[non_exhaustive]
#[derive(Debug)]
pub struct TransportError {
    kind: TransportErrorKind,
    source: Option<BoxError>,
}

impl TransportError {
    /// An error of `kind` without a cause.
    #[must_use]
    pub fn new(kind: TransportErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// An error of `kind` caused by `source`.
    #[must_use]
    pub fn with_source(kind: TransportErrorKind, source: impl Into<BoxError>) -> Self {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    /// What went wrong.
    #[must_use]
    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }
}

impl fmt::Display for TransportError {
    /// The kind, and the cause if there is one (`connection failed: refused`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.message())?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// The `Content-Length` header, if present and a number.
#[cfg(any(feature = "reqwest", feature = "tower"))]
fn content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Appends `chunk` to `out` unless that would exceed `limit`, in which case
/// the body is too large and reading must stop.
#[cfg(any(feature = "reqwest", feature = "tower"))]
fn push_capped(out: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), TransportError> {
    if out.len() + chunk.len() > limit {
        return Err(TransportError::new(TransportErrorKind::TooLarge));
    }
    out.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_kind_then_source() {
        let e = TransportError::new(TransportErrorKind::TooLarge);
        assert_eq!(e.to_string(), "response too large");
        assert!(std::error::Error::source(&e).is_none());

        let e = TransportError::with_source(TransportErrorKind::Connect, "refused");
        assert_eq!(e.to_string(), "connection failed: refused");
        assert_eq!(e.kind(), TransportErrorKind::Connect);
        assert_eq!(
            std::error::Error::source(&e).unwrap().to_string(),
            "refused"
        );
    }

    #[cfg(any(feature = "reqwest", feature = "tower"))]
    #[test]
    fn content_length_parses_or_ignores() {
        use http::{HeaderMap, HeaderValue, header::CONTENT_LENGTH};

        let mut h = HeaderMap::new();
        assert_eq!(content_length(&h), None);
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
        assert_eq!(content_length(&h), Some(42));
        h.insert(CONTENT_LENGTH, HeaderValue::from_static(" 7 "));
        assert_eq!(content_length(&h), Some(7));
        h.insert(CONTENT_LENGTH, HeaderValue::from_static("many"));
        assert_eq!(content_length(&h), None);
    }

    #[cfg(any(feature = "reqwest", feature = "tower"))]
    #[test]
    fn push_capped_stops_at_the_limit() {
        let mut out = Vec::new();
        push_capped(&mut out, b"abc", 4).unwrap();
        let err = push_capped(&mut out, b"de", 4).unwrap_err();
        assert_eq!(err.kind(), TransportErrorKind::TooLarge);
        assert_eq!(out, b"abc", "the crossing chunk is not appended");
        push_capped(&mut out, b"d", 4).unwrap();
        assert_eq!(out, b"abcd", "exactly the limit is allowed");
    }

    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn HttpTransport) {}
}

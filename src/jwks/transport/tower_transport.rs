//! [`TowerTransport`]: an [`HttpTransport`] over a [`tower_service::Service`].

use std::{fmt, future::poll_fn, pin::pin};

use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use tower_service::Service;

use super::{
    BoxError, HttpTransport, TransportError, TransportErrorKind, TransportFuture, content_length,
    push_capped,
};

/// An [`HttpTransport`] over any [`tower_service::Service`] that takes an
/// `http::Request<Full<Bytes>>` and returns an `http::Response` with a
/// streaming [`http_body::Body`]: `tower-worker-fetch` on Cloudflare Workers
/// as is (it accepts any `http_body::Body`), `tower-reqwest` behind a
/// `map_request` that converts the body (it takes `Request<reqwest::Body>`;
/// `req.map(reqwest::Body::wrap)`), or your own stack of layers over either.
///
/// Each `send` clones the service and drives it once (`poll_ready`, then
/// `call`), the usual tower pattern: services are expected to be cheap to
/// clone. The response body is read frame by frame and capped at the store's
/// limit, up front when `Content-Length` (or the body's own size hint) says it
/// is too large, and while reading otherwise, so an endpoint cannot make the
/// process buffer without bound.
///
/// Errors from the service map to [`TransportErrorKind::Other`] and errors
/// while reading the body to [`TransportErrorKind::Body`], both keeping the
/// original error as the source. [`TowerTransport::with_classifier`] refines
/// that for a service whose error type says more.
///
/// The service, its future and its body must be `Send` (and the service
/// `Sync`), on `wasm32` too: this adapter does not wrap JS futures. Services
/// built for Workers (`tower-worker-fetch`) already are. There is no tokio
/// timer on Workers, so `tower::timeout` would panic there; put a
/// `tower_worker_fetch::Timeout` in the request extensions instead (via
/// `map_request`), or configure the timeout on the underlying client.
///
/// # Examples
///
/// On Cloudflare Workers:
///
/// ```ignore
/// use jwk_simple::jwks::{HttpKeyStore, TowerTransport};
/// use tower_worker_fetch::FetchService;
///
/// let transport = TowerTransport::new(FetchService::new());
/// let store = HttpKeyStore::new_with_transport(
///     "https://example.com/.well-known/jwks.json",
///     transport,
/// )?;
/// ```
///
/// Over `tower-reqwest` on native targets:
///
/// ```ignore
/// use bytes::Bytes;
/// use http::Request;
/// use http_body_util::Full;
/// use jwk_simple::jwks::{HttpKeyStore, TowerTransport};
/// use tower::ServiceBuilder;
/// use tower_reqwest::HttpClientService;
///
/// let service = ServiceBuilder::new()
///     .map_request(|req: Request<Full<Bytes>>| req.map(reqwest::Body::wrap))
///     .service(HttpClientService::new(reqwest::Client::new()));
/// let store = HttpKeyStore::new_with_transport(
///     "https://example.com/.well-known/jwks.json",
///     TowerTransport::new(service),
/// )?;
/// ```
#[derive(Clone)]
pub struct TowerTransport<S> {
    service: S,
    classify: Option<Classifier>,
}

/// See [`TowerTransport::with_classifier`].
type Classifier = fn(&BoxError) -> Option<TransportErrorKind>;

impl<S> TowerTransport<S> {
    /// Creates a transport over `service`.
    #[must_use]
    pub fn new(service: S) -> Self {
        Self {
            service,
            classify: None,
        }
    }

    /// Classifies the service's (and its body's) errors.
    ///
    /// `classify` sees each error boxed, as the service returned it, and
    /// returns the [`TransportErrorKind`] to report, or `None` for the default
    /// ([`TransportErrorKind::Other`] from the service,
    /// [`TransportErrorKind::Body`] while reading the body). Downcast to the
    /// service's error type to tell its timeouts and connection failures apart:
    ///
    /// ```ignore
    /// use jwk_simple::jwks::{BoxError, TowerTransport, TransportErrorKind};
    ///
    /// let transport = TowerTransport::new(service).with_classifier(|e: &BoxError| {
    ///     let e = e.downcast_ref::<tower_worker_fetch::Error>()?;
    ///     Some(if e.is_timeout() {
    ///         TransportErrorKind::Timeout
    ///     } else if e.stage() == tower_worker_fetch::Stage::Body {
    ///         TransportErrorKind::Body
    ///     } else {
    ///         TransportErrorKind::Other
    ///     })
    /// });
    /// ```
    ///
    /// Only diagnostics depend on it: the store treats every transport error
    /// the same.
    #[must_use]
    pub fn with_classifier(mut self, classify: Classifier) -> Self {
        self.classify = Some(classify);
        self
    }
}

impl<S> fmt::Debug for TowerTransport<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TowerTransport")
            .field("service", &std::any::type_name::<S>())
            .field("classify", &self.classify.is_some())
            .finish()
    }
}

impl<S, B> HttpTransport for TowerTransport<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<B>> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<BoxError>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    fn send(&self, req: Request<Bytes>, limit: usize) -> TransportFuture<'_> {
        Box::pin(send(self.service.clone(), self.classify, req, limit))
    }
}

async fn send<S, B>(
    mut service: S,
    classify: Option<Classifier>,
    req: Request<Bytes>,
    limit: usize,
) -> Result<Response<Bytes>, TransportError>
where
    S: Service<Request<Full<Bytes>>, Response = Response<B>>,
    S::Error: Into<BoxError>,
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let req = req.map(Full::new);
    poll_fn(|cx| service.poll_ready(cx))
        .await
        .map_err(|e| classified(classify, e.into(), TransportErrorKind::Other))?;
    let resp = service
        .call(req)
        .await
        .map_err(|e| classified(classify, e.into(), TransportErrorKind::Other))?;
    let (parts, body) = resp.into_parts();
    if content_length(&parts.headers).is_some_and(|n| n > limit as u64)
        || body.size_hint().lower() > limit as u64
    {
        return Err(TransportError::new(TransportErrorKind::TooLarge));
    }
    let mut out = Vec::new();
    let mut body = pin!(body);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| classified(classify, e.into(), TransportErrorKind::Body))?;
        // Trailers are not data.
        if let Ok(data) = frame.into_data() {
            push_capped(&mut out, &data, limit)?;
        }
    }
    Ok(Response::from_parts(parts, Bytes::from(out)))
}

fn classified(
    classify: Option<Classifier>,
    e: BoxError,
    default: TransportErrorKind,
) -> TransportError {
    let kind = classify.and_then(|f| f(&e)).unwrap_or(default);
    TransportError::with_source(kind, e)
}

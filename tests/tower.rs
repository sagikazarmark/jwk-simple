//! `TowerTransport`, first over an in-process `tower::Service` with no network
//! (the store end to end, the body limit up front and while streaming, how
//! service and body errors are reported), then over a real HTTP stack,
//! `tower-reqwest` behind the `map_request` the README shows, against a mock
//! JWKS endpoint.

#![cfg(all(feature = "tower", not(target_arch = "wasm32")))]

use std::{
    collections::VecDeque,
    future::{Ready, ready},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use jwk_simple::Error;
use jwk_simple::jwks::{
    BoxError, HttpKeyStore, HttpTransport, KeyStore, TowerTransport, TransportErrorKind,
};
use tower_service::Service;

const JWKS: &str = r#"{"keys":[{"kty":"oct","kid":"k1","k":"AQAB"}]}"#;

/// A streaming body: one frame per chunk, then `fail` if set. Counts the
/// frames it yields, so a test can see where reading stopped.
struct Chunks {
    frames: VecDeque<Bytes>,
    fail: Option<&'static str>,
    hint: Option<u64>,
    yielded: Arc<AtomicUsize>,
}

impl Chunks {
    fn new(chunks: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            frames: chunks.into_iter().collect(),
            fail: None,
            hint: None,
            yielded: Arc::default(),
        }
    }

    fn one(body: impl Into<Bytes>) -> Self {
        Self::new([body.into()])
    }

    fn failing(mut self, message: &'static str) -> Self {
        self.fail = Some(message);
        self
    }

    fn hinting(mut self, lower: u64) -> Self {
        self.hint = Some(lower);
        self
    }

    fn counting(mut self, yielded: &Arc<AtomicUsize>) -> Self {
        self.yielded = yielded.clone();
        self
    }
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(match self.frames.pop_front() {
            Some(chunk) => {
                self.yielded.fetch_add(1, Ordering::SeqCst);
                Some(Ok(Frame::data(chunk)))
            }
            None => self.fail.take().map(|m| Err(m.into())),
        })
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty() && self.fail.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if let Some(lower) = self.hint {
            hint.set_lower(lower);
        }
        hint
    }
}

#[derive(Debug)]
enum ServiceError {
    Timeout,
    Refused,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Timeout => "the service timed out",
            Self::Refused => "the service was refused",
        })
    }
}

impl std::error::Error for ServiceError {}

type Answer = Arc<dyn Fn(&str) -> Result<Response<Chunks>, BoxError> + Send + Sync>;

/// A service answering by host, recording its requests.
#[derive(Clone)]
struct Mock {
    answer: Answer,
    requests: Arc<Mutex<Vec<Request<Full<Bytes>>>>>,
}

impl Mock {
    fn new(
        answer: impl Fn(&str) -> Result<Response<Chunks>, BoxError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            answer: Arc::new(answer),
            requests: Arc::default(),
        }
    }
}

impl Service<Request<Full<Bytes>>> for Mock {
    type Response = Response<Chunks>;
    type Error = BoxError;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Full<Bytes>>) -> Self::Future {
        let host = req.uri().host().unwrap_or_default().to_owned();
        let answer = (self.answer)(&host);
        self.requests.lock().unwrap().push(req);
        ready(answer)
    }
}

fn store(transport: TowerTransport<Mock>, host: &str) -> HttpKeyStore {
    HttpKeyStore::new_with_transport(format!("https://{host}/.well-known/jwks.json"), transport)
        .unwrap()
}

fn transport_error(err: Error) -> jwk_simple::jwks::TransportError {
    match err {
        Error::Transport(e) => e,
        other => panic!("expected a transport error, got: {other}"),
    }
}

#[tokio::test]
async fn a_tower_service_drives_the_store() {
    // Bodies arrive in two frames, to be reassembled.
    let mock = Mock::new(|_| {
        let (head, tail) = JWKS.split_at(JWKS.len() / 2);
        Ok(Response::new(Chunks::new([
            Bytes::copy_from_slice(head.as_bytes()),
            Bytes::copy_from_slice(tail.as_bytes()),
        ])))
    });
    let s = store(TowerTransport::new(mock.clone()), "memory");
    assert_eq!(s.get_keyset().await.unwrap().len(), 1);
    assert!(s.get_key("k1").await.unwrap().is_some());

    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for req in requests.iter() {
        assert_eq!(req.method(), Method::GET);
        assert_eq!(
            req.uri().to_string(),
            "https://memory/.well-known/jwks.json"
        );
        // A GET carries no body: the service can tell without reading it.
        assert!(req.body().is_end_stream());
    }
}

#[tokio::test]
async fn non_2xx_statuses_pass_through_to_the_store() {
    let mock = Mock::new(|_| {
        Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Chunks::one("try later"))
            .unwrap())
    });
    let s = store(TowerTransport::new(mock), "memory");
    let err = s.get_keyset().await.unwrap_err();
    assert!(matches!(err, Error::HttpStatus(503)), "{err}");
}

#[tokio::test]
async fn oversized_bodies_are_rejected_before_reading_when_announced() {
    const LIMIT: usize = 64;
    let yielded = Arc::new(AtomicUsize::new(0));
    let by_header = yielded.clone();
    let by_hint = yielded.clone();
    let mock = Mock::new(move |host| {
        let body = Chunks::one(JWKS);
        match host {
            "header" => Ok(Response::builder()
                .header(header::CONTENT_LENGTH, LIMIT + 1)
                .body(body.counting(&by_header))
                .unwrap()),
            _ => Ok(Response::new(
                body.hinting(LIMIT as u64 + 1).counting(&by_hint),
            )),
        }
    });
    for host in ["header", "hint"] {
        let s = store(TowerTransport::new(mock.clone()), host).with_max_body_size(LIMIT);
        let e = transport_error(s.get_keyset().await.unwrap_err());
        assert_eq!(e.kind(), TransportErrorKind::TooLarge, "{host}: {e}");
    }
    assert_eq!(yielded.load(Ordering::SeqCst), 0, "no frame was read");
}

#[tokio::test]
async fn oversized_bodies_stop_being_read_at_the_limit() {
    const CHUNK: usize = 1024;
    const LIMIT: usize = 16 * CHUNK;
    let total = LIMIT / CHUNK + 8;
    let yielded = Arc::new(AtomicUsize::new(0));
    let counter = yielded.clone();
    let mock = Mock::new(move |_| {
        Ok(Response::new(
            Chunks::new((0..total).map(|_| Bytes::from(vec![b'x'; CHUNK]))).counting(&counter),
        ))
    });
    let s = store(TowerTransport::new(mock), "stream").with_max_body_size(LIMIT);
    let e = transport_error(s.get_keyset().await.unwrap_err());
    assert_eq!(e.kind(), TransportErrorKind::TooLarge);
    // The frame that crosses the limit is the last one read.
    assert_eq!(yielded.load(Ordering::SeqCst), LIMIT / CHUNK + 1);
}

#[tokio::test]
async fn the_limit_applies_to_error_pages_too() {
    let mock = Mock::new(|_| {
        Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Chunks::one(vec![b' '; 128]))
            .unwrap())
    });
    let s = store(TowerTransport::new(mock), "memory").with_max_body_size(64);
    let e = transport_error(s.get_keyset().await.unwrap_err());
    assert_eq!(e.kind(), TransportErrorKind::TooLarge);
}

#[tokio::test]
async fn service_and_body_errors_are_reported_with_their_source() {
    let mock = Mock::new(|host| match host {
        "timeout" => Err(ServiceError::Timeout.into()),
        "refused" => Err(ServiceError::Refused.into()),
        _ => Ok(Response::new(Chunks::one(JWKS).failing("connection reset"))),
    });

    // By default: `Other` from the service, `Body` while reading, source kept.
    let mut kinds = Vec::new();
    for host in ["timeout", "refused", "body"] {
        let s = store(TowerTransport::new(mock.clone()), host);
        let e = transport_error(s.get_keyset().await.unwrap_err());
        kinds.push((e.kind(), e.to_string()));
        if host == "timeout" {
            let source = std::error::Error::source(&e).unwrap();
            assert!(matches!(
                source.downcast_ref::<ServiceError>(),
                Some(ServiceError::Timeout)
            ));
        }
    }
    assert_eq!(
        kinds,
        [
            (
                TransportErrorKind::Other,
                "transport error: the service timed out".to_owned()
            ),
            (
                TransportErrorKind::Other,
                "transport error: the service was refused".to_owned()
            ),
            (
                TransportErrorKind::Body,
                "reading the response body failed: connection reset".to_owned()
            ),
        ]
    );

    // A classifier refines the kind; `None` keeps the default.
    let classify = |e: &BoxError| {
        Some(match e.downcast_ref::<ServiceError>()? {
            ServiceError::Timeout => TransportErrorKind::Timeout,
            ServiceError::Refused => TransportErrorKind::Connect,
        })
    };
    let mut kinds = Vec::new();
    for host in ["timeout", "refused", "body"] {
        let transport = TowerTransport::new(mock.clone()).with_classifier(classify);
        let s = store(transport, host);
        kinds.push(transport_error(s.get_keyset().await.unwrap_err()).kind());
    }
    assert_eq!(
        kinds,
        [
            TransportErrorKind::Timeout,
            TransportErrorKind::Connect,
            TransportErrorKind::Body
        ]
    );
}

#[test]
fn debug_names_the_service_without_requiring_debug() {
    let transport = TowerTransport::new(Mock::new(|_| Err("unused".into())));
    let debug = format!("{transport:?}");
    assert!(debug.starts_with("TowerTransport {"), "{debug}");
    assert!(debug.contains("Mock"), "{debug}");
}

#[allow(dead_code)]
fn assert_send_sync(transport: &TowerTransport<Mock>) {
    fn send<T: Send>(_: T) {}
    fn send_sync<T: Send + Sync>(_: T) {}
    send_sync(transport.clone());
    send(transport.send(Request::new(Bytes::new()), 0));
}

// ---------------------------------------------------------------------------
// Over a real HTTP stack: tower-reqwest behind the README's `map_request`.

mod over_reqwest {
    use super::*;

    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tower::ServiceBuilder;
    use tower_reqwest::HttpClientService;

    /// The stack the README shows for `tower-reqwest`, with an optional classifier.
    fn transport(
        client: reqwest::Client,
        classify: Option<fn(&BoxError) -> Option<TransportErrorKind>>,
    ) -> impl HttpTransport {
        let service = ServiceBuilder::new()
            .map_request(|req: Request<Full<Bytes>>| req.map(reqwest::Body::wrap))
            .service(HttpClientService::new(client));
        let transport = TowerTransport::new(service);
        match classify {
            Some(classify) => transport.with_classifier(classify),
            None => transport,
        }
    }

    /// Serves `response` once, after `delay`. Returns the base URL.
    async fn endpoint(response: Vec<u8>, delay: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
        format!("http://{addr}/jwks")
    }

    fn announced(body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn streamed(body: &[u8]) -> Vec<u8> {
        let mut out = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn drives_the_store() {
        let url = endpoint(announced(JWKS.as_bytes()), Duration::ZERO).await;
        let s =
            HttpKeyStore::new_with_transport_insecure(url, transport(reqwest::Client::new(), None))
                .unwrap();
        assert_eq!(s.get_keyset().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn caps_bodies_with_and_without_content_length() {
        const LIMIT: usize = 4096;
        for response in [
            announced(&vec![b' '; LIMIT + 1]),
            streamed(&vec![b' '; LIMIT * 4]),
        ] {
            let url = endpoint(response, Duration::ZERO).await;
            let s = HttpKeyStore::new_with_transport_insecure(
                url,
                transport(reqwest::Client::new(), None),
            )
            .unwrap()
            .with_max_body_size(LIMIT);
            let e = transport_error(s.get_keyset().await.unwrap_err());
            assert_eq!(e.kind(), TransportErrorKind::TooLarge, "{e}");
        }
    }

    #[tokio::test]
    async fn errors_classify_by_downcast() {
        // A client timeout, surfaced through the service as a `reqwest::Error`.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();

        // By default the kind is `Other`, and the reqwest error is the source.
        let url = endpoint(announced(JWKS.as_bytes()), Duration::from_millis(300)).await;
        let s = HttpKeyStore::new_with_transport_insecure(url, transport(client.clone(), None))
            .unwrap();
        let e = transport_error(s.get_keyset().await.unwrap_err());
        assert_eq!(e.kind(), TransportErrorKind::Other);
        let source = std::error::Error::source(&e).unwrap();
        assert!(
            source
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout),
            "{source}"
        );

        // A classifier that downcasts to `reqwest::Error` tells `Timeout` apart.
        let classify = |e: &BoxError| {
            let e = e.downcast_ref::<reqwest::Error>()?;
            Some(if e.is_connect() {
                TransportErrorKind::Connect
            } else if e.is_timeout() {
                TransportErrorKind::Timeout
            } else {
                TransportErrorKind::Other
            })
        };
        let url = endpoint(announced(JWKS.as_bytes()), Duration::from_millis(300)).await;
        let s = HttpKeyStore::new_with_transport_insecure(url, transport(client, Some(classify)))
            .unwrap();
        let e = transport_error(s.get_keyset().await.unwrap_err());
        assert_eq!(e.kind(), TransportErrorKind::Timeout);
    }
}

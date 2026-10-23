//! Compile-time proof that the crate fits an axum router on Cloudflare Workers.
//!
//! axum requires `Handler::Future: Send` and `State<S>: Send + Sync`, and a
//! Worker has no tokio runtime, so this proves what the docs claim: a
//! `CachedKeyStore<KvKeyCache, HttpKeyStore>` over `TowerTransport<FetchService>`
//! is `Send + Sync`, its futures are `Send`, and an `Arc<dyn KeyStore>` can be
//! axum state awaited inside a handler without `#[worker::send]`. Nothing here
//! runs (there is no Worker environment under test); it only has to type-check,
//! which `cargo test` on `wasm32-unknown-unknown` does.
//!
//! The dependency on `tower-worker-fetch` is a wasm32 dev-dependency only: the
//! adapter is generic and needs nothing from it.

#![cfg(all(target_arch = "wasm32", feature = "cloudflare", feature = "tower"))]

use std::{sync::Arc, time::Duration};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use jwk_simple::jwks::{
    CachedKeyStore, HttpKeyStore, KeyStore, TowerTransport, cloudflare::KvKeyCache,
};
use tower::ServiceBuilder;
use tower_worker_fetch::{FetchService, Timeout};

type Store = CachedKeyStore<KvKeyCache, HttpKeyStore>;

/// The README's Workers store: KV-cached, fetched through `tower-worker-fetch`
/// with a per-request timeout in the request extensions (no tokio timer on
/// Workers, so no `tower::timeout`).
#[allow(dead_code)]
fn store(kv: worker::kv::KvStore) -> jwk_simple::Result<Store> {
    let service = ServiceBuilder::new()
        .map_request(|mut req: Request<Full<Bytes>>| {
            req.extensions_mut().insert(Timeout(Duration::from_secs(5)));
            req
        })
        .service(FetchService::new());
    let remote = HttpKeyStore::new_with_transport(
        "https://example.com/.well-known/jwks.json",
        TowerTransport::new(service),
    )?;
    Ok(CachedKeyStore::new(KvKeyCache::new(kv), remote))
}

/// An axum handler awaiting the store: its future must be `Send`.
#[allow(dead_code)]
async fn handler(State(store): State<Arc<dyn KeyStore>>) -> StatusCode {
    match store.get_key("kid").await {
        Ok(Some(_)) => StatusCode::OK,
        Ok(None) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::BAD_GATEWAY,
    }
}

/// `Router::with_state` requires `S: Clone + Send + Sync + 'static`.
#[allow(dead_code)]
fn router(kv: worker::kv::KvStore) -> jwk_simple::Result<Router> {
    let store: Arc<dyn KeyStore> = Arc::new(store(kv)?);
    Ok(Router::new().route("/", get(handler)).with_state(store))
}

/// Store-agnostic code (a tower layer, a verifier) takes `impl KeyStore`; the
/// shared `Arc<dyn KeyStore>` from axum's state satisfies it through the
/// blanket `KeyStore for Arc<T>` impl, and `assert_send_sync` below checks the
/// resulting future is `Send`.
#[allow(dead_code)]
async fn lookup<S: KeyStore>(store: &S, kid: &str) -> bool {
    matches!(store.get_key(kid).await, Ok(Some(_)))
}

#[allow(dead_code)]
fn assert_send_sync(store: &Store, shared: Arc<dyn KeyStore>) {
    fn is_send<T: Send>(_: &T) {}
    fn is_send_sync<T: Send + Sync>() {}

    is_send_sync::<Store>();
    is_send_sync::<Arc<dyn KeyStore>>();
    is_send_sync::<TowerTransport<FetchService>>();
    is_send(&store.get_keyset());
    is_send(&store.get_key("kid"));
    is_send(&lookup(&shared, "kid"));
}

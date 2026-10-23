//! `Send` futures on single-threaded wasm.

use std::future::Future;

/// `f` as a `Send` future.
///
/// On native targets `f` must already be `Send`: this is the identity. On
/// `wasm32-unknown-unknown` `f` may hold JS values (a `fetch` promise, a KV
/// read, a timer): the target is single-threaded, and the wrapper panics if
/// the future is ever polled or dropped on another thread.
///
/// Use it when implementing [`KeyStore`](super::KeyStore) or
/// [`KeyCache`](super::KeyCache) over a JS API, so the implementation
/// satisfies the traits' `Send` futures on wasm the same way the crate's own
/// implementations do:
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl KeyStore for MyStore {
///     async fn get_keyset(&self) -> jwk_simple::Result<KeySet> {
///         assume_send(async move { /* await JS futures here */ }).await
///     }
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn assume_send<F: Future + Send>(f: F) -> impl Future<Output = F::Output> + Send {
    f
}

/// `f` as a `Send` future.
///
/// On native targets `f` must already be `Send`: this is the identity. On
/// `wasm32-unknown-unknown` `f` may hold JS values (a `fetch` promise, a KV
/// read, a timer): the target is single-threaded, and the wrapper panics if
/// the future is ever polled or dropped on another thread.
///
/// Use it when implementing [`KeyStore`](super::KeyStore) or
/// [`KeyCache`](super::KeyCache) over a JS API, so the implementation
/// satisfies the traits' `Send` futures on wasm the same way the crate's own
/// implementations do:
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl KeyStore for MyStore {
///     async fn get_keyset(&self) -> jwk_simple::Result<KeySet> {
///         assume_send(async move { /* await JS futures here */ }).await
///     }
/// }
/// ```
#[cfg(target_arch = "wasm32")]
pub fn assume_send<F: Future>(f: F) -> impl Future<Output = F::Output> + Send {
    send_wrapper::SendWrapper::new(f)
}

#[cfg(feature = "http")]
mod http;

#[cfg(feature = "http")]
pub use http::HttpKeyStore;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use http::DEFAULT_TIMEOUT;

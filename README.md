# jwk-simple

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/jwk-simple/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/jwk-simple/actions/workflows/ci.yaml)
[![Crates.io](https://img.shields.io/crates/v/jwk-simple.svg?style=flat-square)](https://crates.io/crates/jwk-simple)
![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/jwk-simple/badge?style=flat-square)

A Rust library for working with JSON Web Keys (JWK) and JWK Sets (JWKS) as defined in RFC 7517, with WASM compatibility and optional [`jwt-simple`](https://github.com/jedisct1/rust-jwt-simple) integration.

## Features

- **RFC coverage (JOSE/JWK)**: Supports RFC 7517 (JWK), RFC 7518 (algorithms), RFC 8037 (OKP), RFC 9864 (Ed25519/Ed448 JOSE algorithms), and RFC 7638 (thumbprints)
- **Multiple key types**: RSA, EC (P-256, P-384, P-521, secp256k1), Symmetric (HMAC), and OKP (Ed25519, Ed448, X25519, X448)
- **WASM and WebCrypto compatible**: Core functionality works in WebAssembly environments, with optional WebCrypto integration on `wasm32`
- **Security-first**: Zeroize support for sensitive data, constant-time base64 encoding
- **jwt-simple integration**: Optional feature for converting JWKs to [`jwt-simple`](https://github.com/jedisct1/rust-jwt-simple) key types
- **Remote fetching**: Load JWKS from HTTP endpoints through a pluggable transport (reqwest, any `tower::Service`, or your own), with a hard cap on response size
- **Caching**: Optional TTL-based caching of fetched JWKS (`KeySet`) data
- **Runs on Cloudflare Workers**: `Send` futures on `wasm32`, KV caching, and `tower-worker-fetch` as the HTTP transport, so a store fits axum's `State`

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
jwk-simple = "0.6"
serde_json = "1"
```

Parse a JWKS and strictly select a verification key:

```rust
use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};

let json = r#"{
    "keys": [{
        "kty": "RSA",
        "kid": "my-key-id",
        "use": "sig",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB"
    }]
}"#;

let jwks: KeySet = serde_json::from_str(json)?;
let key = jwks
    .selector(&[Algorithm::Rs256])
    .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-key-id"))?;
assert!(key.is_public_key_only());
```

Note: JWKS parsing is permissive and may skip invalid keys.

## Feature Flags

Feature definitions live in `Cargo.toml` (`[features]`). This table documents
expected usage and platform constraints.

| Feature | Default | Description |
|---------|---------|-------------|
| `jwt-simple` | ❌ | Integration with the jwt-simple crate (all targets; requires a `jwt-simple` backend feature such as `jwt-simple/pure-rust`) |
| `http` | ❌ | Remote JWKS fetching through the `HttpTransport` trait: `HttpKeyStore` and the transport types (all targets). Bring your own transport, or enable one of the two below |
| `reqwest` | ❌ | The default transport, `ReqwestTransport` (implies `http`, all targets). On native targets it needs a TLS backend: `default-tls`, `rustls` or `native-tls` |
| `default-tls`, `rustls`, `native-tls` | ❌ | TLS backends for `reqwest` (no-ops without it, and on `wasm32` where the JS host does TLS) |
| `tower` | ❌ | `TowerTransport`, an `HttpTransport` over any `tower::Service` speaking `http` types (implies `http`, all targets): `tower-reqwest` natively, `tower-worker-fetch` on Cloudflare Workers |
| `web-crypto` | ❌ | WebCrypto API integration (`wasm32` only) |
| `cloudflare` | ❌ | Cloudflare Workers support: `KvKeyCache` over Workers KV (`wasm32` only) |
| `moka` | ❌ | In-memory TTL-based key caching (non-`wasm32` only) |

Invalid platform/feature combinations intentionally fail at compile time with
clear `compile_error!` messages.

## Usage Examples

Note: snippets below are focused examples and may omit surrounding async/runtime scaffolding and input setup.

### Basic JWKS Parsing

```rust
use jwk_simple::{KeyFilter, KeySet, KeyType, KeyUse};

// Parse from JSON string
let jwks: KeySet = serde_json::from_str(json)?;

// Find keys by various criteria
let key = jwks.get_by_kid("key-id");
let rsa_keys = jwks.find(KeyFilter::for_kty(KeyType::Rsa));
let signing_keys = jwks.find(KeyFilter::for_use(KeyUse::Signature));

// Get the first signing key (common pattern)
let first_signing = jwks.first_signing_key();

// Iterate over all keys
for key in &jwks {
    println!("Key: {:?}", key.kid());
}
```

### Converting to jwt-simple Keys

With the `jwt-simple` feature enabled:

Note: `jwt-simple` is not re-exported. Add it to your dependencies when using its key types directly, and enable a backend feature (for example `pure-rust`):

```toml
[dependencies]
jwk-simple = { version = "0.6", features = ["jwt-simple"] }
jwt-simple = { version = "0.15", default-features = false, features = ["pure-rust"] }
```

```rust
use jwk_simple::{Algorithm, KeyMatcher, KeyOperation, KeySet};
use jwt_simple::prelude::*;

let jwks: KeySet = serde_json::from_str(json)?;
let jwk = jwks
    .selector(&[Algorithm::Rs256])
    .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("my-key"))?;

// Convert to jwt-simple key type using TryFrom/TryInto
let key: RS256PublicKey = jwk.try_into()?;

// Verify a JWT
let claims = key.verify_token::<NoCustomClaims>(&token, None)?;
```

A conversion runs this crate's validation first (`Key::validate_for_use`: structure, declared
`alg`, `use`/`key_ops` intent, key strength), then hands jwt-simple only the key type, curve,
key material and `kid` through its `from_jwk` constructor, which applies jwt-simple's own
cryptographic checks (RSA 2048–4096 bits with `e = 65537`, EC points on the curve, a private
key's public part derived from `d`). The converted key carries the JWK's `kid`, so tokens signed
with a converted key pair include it. Ed25519 keys may declare either registered name, `EdDSA`
(RFC 8037) or `Ed25519` (RFC 9864). jwt-simple has no JWK import for symmetric keys; `HS*`
conversions use `from_bytes`.

### Publishing a JWKS from jwt-simple Keys

The other direction: `Key` implements `TryFrom` for every jwt-simple key type with a `to_jwk()`
(RS\*/PS\*/ES\*/Ed25519 public keys and key pairs), and for the `HS*` keys. The result is what
jwt-simple itself would publish — `alg`, `use: sig`, and the key id as `kid` — parsed into this
crate's model, so it can go into a `KeySet` and be served as `/.well-known/jwks.json`:

```rust
use jwk_simple::{Key, KeySet};
use jwt_simple::prelude::*;

let current = ES256KeyPair::generate().with_key_id("2026-10");
let previous = ES256KeyPair::generate().with_key_id("2026-04");

let mut jwks = KeySet::new();
jwks.add_key(Key::try_from(&current.public_key())?)?;
jwks.add_key(Key::try_from(&previous.public_key())?)?;
let body = serde_json::to_string(&jwks)?;
```

Converting a key pair or an `HS*` key exports private material; convert `public_key()` to
publish. A salted HMAC key (`generate_with_salt`) is refused with
`JwtSimpleKeyConversionError::Unrepresentable`, since a JWK has no member for the salt.

### Fetching from HTTP

With the `reqwest` feature (and, on native targets, a TLS feature):

```toml
[dependencies]
jwk-simple = { version = "0.6", features = ["reqwest", "default-tls"] }
```

```rust
use jwk_simple::jwks::{HttpKeyStore, KeyStore};

// Native targets use a default 30s timeout.
// On wasm32, reqwest uses the browser/Fetch backend where
// client-level timeout configuration is not available.
let remote = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;

// Fetch the JWKS
let jwks = remote.get_keyset().await?;
```

Responses are capped at 1 MiB by default (`HttpKeyStore::with_max_body_size` changes it): a
response announcing or streaming more than that fails with `Error::Transport` of kind
`TransportErrorKind::TooLarge`, and the transport stops reading at the limit.

### Bring your own HTTP client

The store sends requests through the `jwk_simple::jwks::HttpTransport` trait: one
`http::Request<Bytes>` in, one buffered `http::Response<Bytes>` out. HTTPS enforcement, status
handling, JSON parsing and caching all happen above it. The default transport, `ReqwestTransport`
(feature `reqwest`), is a `reqwest::Client` with a 30 s timeout and nothing else configured; wrap
your own `reqwest::Client` if you need custom TLS roots, a `User-Agent`, a different timeout or
proxy settings:

```rust
use std::time::Duration;
use jwk_simple::jwks::{HttpKeyStore, ReqwestTransport};

// reqwest is not re-exported; add it to your own Cargo.toml.
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(10))
    .user_agent("my-app/1.0")
    .build()?;
let remote = HttpKeyStore::new_with_transport(
    "https://example.com/.well-known/jwks.json",
    ReqwestTransport::new(client),
)?;
// `HttpKeyStore::new_with_client(url, client)` is shorthand for the same thing.
```

For another backend (a JS host's `fetch`, a `tower` service, an in-memory fake in tests), implement
`HttpTransport` yourself and enable `http` without `reqwest`: reqwest is then not compiled at all.
`ReqwestTransport::new` is the only place `reqwest` appears in this crate's API, so a `reqwest`
upgrade only affects you if you pass one in.

#### tower services

With the `tower` feature, `TowerTransport` adapts any `tower::Service` that takes an
`http::Request<Full<Bytes>>` and returns an `http::Response` with a streaming `http_body::Body`.
`tower-worker-fetch` on Cloudflare Workers accepts any `http_body::Body`, so it fits as is;
`tower-reqwest` takes `Request<reqwest::Body>`, so it needs a `map_request` in front (below); so does
any other service with its own request body type. `TowerTransport` clones the service per request,
caps the body at the store's limit while reading, and reports the service's errors as
`TransportErrorKind::Other` (body read errors as `Body`) with the original error as the source;
`with_classifier` lets you downcast and refine the kind.

```rust
use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use jwk_simple::jwks::{HttpKeyStore, TowerTransport};
use tower::ServiceBuilder;
use tower_reqwest::HttpClientService;

let service = ServiceBuilder::new()
    .map_request(|req: Request<Full<Bytes>>| req.map(reqwest::Body::wrap))
    .service(HttpClientService::new(reqwest::Client::new()));
let remote = HttpKeyStore::new_with_transport(
    "https://example.com/.well-known/jwks.json",
    TowerTransport::new(service),
)?;
```

#### Cloudflare Workers

Enable `cloudflare` (KV cache) and `tower`, and add
[`tower-worker-fetch`](https://crates.io/crates/tower-worker-fetch) to your own dependencies; nothing
Workers-specific beyond `KvKeyCache` is in this crate. There is no tokio timer in a Worker, so
`tower::timeout` would panic; put a `tower_worker_fetch::Timeout` in the request extensions instead:

```rust
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use jwk_simple::jwks::{CachedKeyStore, HttpKeyStore, KeyStore, TowerTransport, cloudflare::KvKeyCache};
use tower::ServiceBuilder;
use tower_worker_fetch::{FetchService, Timeout};

let transport = TowerTransport::new(
    ServiceBuilder::new()
        .map_request(|mut req: Request<Full<Bytes>>| {
            req.extensions_mut().insert(Timeout(Duration::from_secs(5)));
            req
        })
        .service(FetchService::new()),
);
let remote = HttpKeyStore::new_with_transport("https://example.com/.well-known/jwks.json", transport)?;
let store = CachedKeyStore::new(KvKeyCache::new(env.kv("JWKS_CACHE")?), remote);

let key = store.get_key("my-key-id").await?;
```

`KeyStore`, `KeyCache` and `HttpTransport` are `Send + Sync` with `Send` futures on `wasm32` too,
so the store above can be an `Arc<dyn KeyStore>` in axum's `State` and awaited in a handler without
`#[worker::send]` (`tests/workers.rs` type-checks exactly that in CI). The one exception is
WebCrypto: `web_sys::CryptoKey` is not `Send`, so a handler that verifies with the `web-crypto`
integration still needs `#[worker::send]`; verifying with `jwt-simple` (`pure-rust`) on `wasm32`
is `Send` end to end. If you implement `KeyStore` or `KeyCache` over a JS API yourself, wrap the
future with `jwk_simple::jwks::assume_send`.

### Caching Keys

With the `reqwest` and `moka` features enabled:

```rust
use jwk_simple::jwks::{CachedKeyStore, HttpKeyStore, KeyCache, KeyStore, MokaKeyCache};
use std::time::Duration;

// For production, wrap a remote store with caching (5 minute TTL)
let cache = MokaKeyCache::new(Duration::from_secs(300));
let cached = CachedKeyStore::new(
    cache,
    HttpKeyStore::new("https://example.com/.well-known/jwks.json")?,
);

// Keys are automatically cached on first access
let key = cached.get_key("key-id").await?;

// Invalidate the entire cache when needed
cached.cache().clear().await?;
```

### JWK Thumbprints (RFC 7638)

```rust
use jwk_simple::KeySet;

let jwks: KeySet = serde_json::from_str(json)?;
let key = jwks.first().unwrap();

// Calculate thumbprint (base64url-encoded SHA-256)
let thumbprint = key.thumbprint();

// Find key by thumbprint
let key = jwks.get_by_thumbprint(&thumbprint);
```

## Supported Key Types

### RSA (kty: "RSA")
- Public keys: n, e
- Private keys: n, e, d, p, q, dp, dq, qi
- Algorithms: RS256, RS384, RS512, PS256, PS384, PS512

### Elliptic Curve (kty: "EC")
- Curves: P-256, P-384, P-521, secp256k1
- Public keys: crv, x, y
- Private keys: crv, x, y, d
- Algorithms: ES256, ES384, ES512, ES256K

### Symmetric (kty: "oct")
- Keys: k
- Algorithms: HS256, HS384, HS512, A128KW, A192KW, A256KW

### Octet Key Pair (kty: "OKP")
- Curves: Ed25519, Ed448, X25519, X448
- Public keys: crv, x
- Private keys: crv, x, d
- Algorithms: Ed25519, Ed448 (preferred), EdDSA (legacy/deprecated)

## Comparison to Other Libraries

Status below is based on current crates.io releases as of 2026-03.

| Feature | jwk-simple | jwks-client | jsonwebkey | jwt-simple | jsonwebtoken |
|---------|-------------|-------------|------------|------------|--------------|
| Full JWKS spec | ✅ | ❌ | ❌ | ❌ | ❌ |
| RSA keys | ✅ | ✅ | ✅ | ✅ | ✅ |
| EC keys (P-256/384/521) | ✅ | ❌ | ⚠️ | ⚠️ | ⚠️ |
| EdDSA (Ed25519) | ✅ | ❌ | ❌ | ✅ | ✅ |
| Symmetric keys | ✅ | ❌ | ✅ | ✅ | ✅ |
| OKP keys (X25519) | ✅ | ❌ | ❌ | ❌ | ❌ |
| WASM support | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| jwt-simple integration | ✅ | ❌ | ❌ | N/A | ❌ |
| HTTP fetching | ✅ | ✅ | ❌ | ❌ | ❌ |
| Caching | ✅ | ✅ | ❌ | ❌ | ❌ |
| Zeroize support | ✅ | ❌ | ✅ | ✅ | ❌ |
| Panic-free APIs* | ✅ | ✅ | ❌ | ❌ | ❌ |
| JWK thumbprint (RFC 7638) | ✅ | ❌ | ⚠️ | ❌ | ✅ |
| TryFrom/TryInto traits | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Private key support | ✅ | ❌ | ✅ | ✅ | ✅ |

Legend for partial support (`⚠️`):
- `jsonwebkey` EC = P-256 only; thumbprints require the `thumbprint` feature
- `jwt-simple` EC = P-256/P-384/secp256k1 (not P-521)
- `jsonwebtoken` EC = P-256/P-384 (P-521 JWK exists but is not supported by the crypto backend)
- `jsonwebkey` WASM = core parsing works; behavior can depend on enabled optional features
- `jsonwebtoken` WASM = works on `wasm32` with `rust_crypto` (or a custom `CryptoProvider`)
- `jsonwebtoken` TryFrom/TryInto = `TryFrom<&Jwk>` is available for `DecodingKey`

*"Panic-free APIs" excludes standard panic-prone trait semantics such as out-of-bounds indexing via `Index`.

### When to use jwk-simple

- **You need jwt-simple integration** - Direct conversion to jwt-simple key types
- **You're building Cloudflare Workers** - `Send` futures for axum/tower on Workers, native KV cache, `tower-worker-fetch` transport
- **You need WASM support** - Core parsing works in browser
- **You want broad JOSE/JWK RFC coverage** - All key types including OKP
- **You want to control the HTTP stack** - Pluggable `HttpTransport` (reqwest, tower, or your own) with a bounded response size

### When to use alternatives

- **jwks-client** - If you only need RSA and want mature async HTTP
- **jsonwebkey** - If you need key generation and PEM/DER conversion
- **jwt-simple** - If you only need JWT operations, not JWKS
- **jsonwebtoken** - If you want the most widely-used JWT library

## Security Considerations

This crate prioritizes security:

- **Zeroize**: Private key parameters are zeroed from memory on drop via the `zeroize` crate
- **Constant-time base64**: Base64 encoding uses constant-time operations via `base64ct`
- **Debug redaction**: Debug output redacts sensitive key material
- **Panic-free APIs**: All fallible operations return `Result` types — standard trait implementations like `Index` follow normal Rust semantics and may panic on invalid input (e.g., out-of-bounds indexing)
- **Input validation**: Key parameters are validated for correct sizes
- **Trust boundary clarity**: `Key::validate` performs structural and metadata consistency checks only, while `Key::validate_for_use` adds algorithm suitability and operation intent checks; PKIX trust validation (chain path, trust anchors, validity, EKU/KU, revocation) must be provided by your application

When enabling the optional `jwt-simple` integration, note that some `jwt-simple`
dependency chains may pull in `rsa` versions affected by
[`RUSTSEC-2023-0071`](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
(Marvin timing side-channel). This primarily concerns RSA private-key
operations (for example, signing) in attacker-observable timing contexts. If
this matters for your deployment, prefer EdDSA/ECDSA or avoid RSA private-key
operations until an upstream patched chain is available.

## WASM Usage

Core JWKS parsing works in WebAssembly environments.

- `http`, `reqwest` and `tower` are available on `wasm32`: reqwest uses its Fetch backend, and
  `tower-worker-fetch` is the transport for Cloudflare Workers (see above)
- `web-crypto` and `cloudflare` are `wasm32`-only features
- `moka` is not available on `wasm32`
- Threaded wasm (the `atomics` target feature) is rejected at compile time: the crate's `Send`
  futures rest on `wasm32-unknown-unknown` being single-threaded

Example for WASM:

```rust
use jwk_simple::KeySet;

// In WASM, fetch JWKS via browser APIs, then parse
let jwks: KeySet = serde_json::from_str(&json_string)?;
let key = jwks.get_by_kid("key-id").expect("key not found");
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

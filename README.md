# jwk-simple

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/jwk-simple/ci.yaml?style=flat-square)
![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/jwk-simple/badge?style=flat-square)

> [!WARNING]
> This project is a work in progress. The API may change.

A Rust library for working with JSON Web Keys (JWK) and JWK Sets (JWKS) as defined in RFC 7517, with WASM compatibility and optional [`jwt-simple`](https://github.com/jedisct1/rust-jwt-simple) integration.

## Features

- **RFC coverage (JOSE/JWK)**: Supports RFC 7517 (JWK), RFC 7518 (algorithms), RFC 8037 (OKP), RFC 9864 (Ed25519/Ed448 JOSE algorithms), and RFC 7638 (thumbprints)
- **Multiple key types**: RSA, EC (P-256, P-384, P-521, secp256k1), Symmetric (HMAC), and OKP (Ed25519, Ed448, X25519, X448)
- **WASM compatible**: Core functionality works in WebAssembly environments
- **Security-first**: Zeroize support for sensitive data, constant-time base64 encoding
- **jwt-simple integration**: Optional feature for converting JWKs to [`jwt-simple`](https://github.com/jedisct1/rust-jwt-simple) key types
- **Remote fetching**: Load JWKS from HTTP endpoints with caching support
- **Caching**: Optional TTL-based caching of fetched JWKS (`KeySet`) data

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
jwk-simple = "0.1"
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
| `jwt-simple` | ❌ | Integration with the jwt-simple crate (all targets) |
| `http` | ❌ | Async HTTP fetching (reqwest, all targets) |
| `web-crypto` | ❌ | WebCrypto API integration (`wasm32` only) |
| `cloudflare` | ❌ | Cloudflare Workers support (KV cache + fetch, `wasm32` only) |
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

Note: `jwt-simple` is not re-exported. Add it to your dependencies when using its key types directly:

```toml
[dependencies]
jwk-simple = { version = "0.1", features = ["jwt-simple"] }
jwt-simple = "0.12"
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

### Fetching from HTTP

With the `http` feature enabled:

```rust
use jwk_simple::jwks::{HttpKeyStore, KeyStore};
use std::time::Duration;

// Create remote key store.
// Native targets use a default 30s timeout.
// On wasm32, reqwest uses the browser/Fetch backend where
// client-level timeout configuration is not available.
let remote = HttpKeyStore::new("https://example.com/.well-known/jwks.json")?;

// For custom timeout, use a custom client.
// Note: reqwest is not re-exported, so add it to your own Cargo.toml:
//   reqwest = "0.13"
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(10))
    .build()?;
let remote = HttpKeyStore::new_with_client(
    "https://example.com/.well-known/jwks.json",
    client,
)?;

// Fetch the JWKS
let jwks = remote.get_keyset().await?;
```

### Caching Keys

With the `http` and `moka` features enabled:

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
- **You're building Cloudflare Workers** - Native KV cache support
- **You need WASM support** - Core parsing works in browser
- **You want broad JOSE/JWK RFC coverage** - All key types including OKP

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

- `http` is available on `wasm32` via reqwest's Fetch backend
- `web-crypto` and `cloudflare` are `wasm32`-only features
- `moka` is not available on `wasm32`

Example for WASM:

```rust
use jwk_simple::KeySet;

// In WASM, fetch JWKS via browser APIs, then parse
let jwks: KeySet = serde_json::from_str(&json_string)?;
let key = jwks.get_by_kid("key-id").expect("key not found");
```

## License

The project is licensed under the [MIT License](LICENSE).

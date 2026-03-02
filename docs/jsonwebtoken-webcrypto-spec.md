# WebCrypto Backend for jsonwebtoken — Implementation Spec

## 1. Problem Statement

The [`jsonwebtoken`](https://github.com/Keats/jsonwebtoken) crate has two native crypto backends (`aws_lc_rs` and `rust_crypto`) that are synchronous. For WASM environments running in browsers, a WebCrypto backend would let JWT operations use the browser's native SubtleCrypto API instead — offering hardware-accelerated crypto without bundling a Rust crypto library into the WASM binary.

**Core challenge**: The existing `CryptoProvider` pattern uses sync `JwtSigner`/`JwtVerifier` traits (extending `signature::Signer<Vec<u8>>`/`signature::Verifier<Vec<u8>>`). WebCrypto is inherently async — all operations return JavaScript Promises. On `wasm32`, you cannot block on a future. Therefore, **WebCrypto cannot fit into the existing `CryptoProvider`** — it requires parallel async `encode`/`decode` functions.

## 2. Architecture

This is a **separate crate** (not a PR to jsonwebtoken). It wraps jsonwebtoken's non-crypto types with async WebCrypto-powered encode/decode functions.

```
┌──────────────────────────────────────┐
│  jsonwebtoken-web-crypto             │
│                                      │
│  pub async fn encode(...)            │
│  pub async fn decode(...)            │
│                                      │
│  ┌────────────────────────────────┐  │
│  │  jsonwebtoken (re-used types)  │  │
│  │  Header, Validation, TokenData │  │
│  │  Algorithm, EncodingKey,       │  │
│  │  DecodingKey                   │  │
│  │  b64_encode_part, b64_decode   │  │
│  │  validate(), etc.              │  │
│  └────────────────────────────────┘  │
│                                      │
│  ┌────────────────────────────────┐  │
│  │  web-sys / wasm-bindgen        │  │
│  │  SubtleCrypto.sign()           │  │
│  │  SubtleCrypto.verify()         │  │
│  │  SubtleCrypto.importKey()      │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

The crate lives inside the jsonwebtoken repo as an in-tree crate (e.g. `crates/web-crypto/` or `jsonwebtoken-web-crypto/`) that depends on the main `jsonwebtoken` crate. It uses `pub(crate)` internals from jsonwebtoken — specifically `b64_encode_part`, `b64_decode`, `DecodedJwtPartClaims`, and `validate()` — which means it needs to be inside the crate boundary (an internal module behind a feature flag, not a fully external crate).

**Revised architecture**: Add a `web_crypto` feature flag to jsonwebtoken with a new `src/crypto/web_crypto/` module that provides async equivalents of `encode()` and `decode()`, reusing all existing non-crypto types.

## 3. Public API

```rust
use jsonwebtoken::web_crypto;

// Async encode (signs using SubtleCrypto.sign())
let token = web_crypto::encode(&header, &claims, &encoding_key).await?;

// Async decode (verifies using SubtleCrypto.verify())
let data = web_crypto::decode::<Claims>(&token, &decoding_key, &validation).await?;
```

### Detailed Signatures

```rust
/// Async JWT encoding using WebCrypto.
///
/// Mirrors `jsonwebtoken::encode()` but uses SubtleCrypto.sign() instead
/// of the sync CryptoProvider.
pub async fn encode<T: Serialize>(
    header: &Header,
    claims: &T,
    key: &EncodingKey,
) -> Result<String>;

/// Async JWT decoding using WebCrypto.
///
/// Mirrors `jsonwebtoken::decode()` but uses SubtleCrypto.verify() instead
/// of the sync CryptoProvider.
pub async fn decode<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
) -> Result<TokenData<T>>;
```

Both functions return `jsonwebtoken::errors::Result<T>`, reusing the existing error types.

## 4. Supported Algorithms

| Algorithm | WebCrypto Name | Import Format (Sign) | Import Format (Verify) | Supported |
|-----------|---------------|---------------------|----------------------|-----------|
| HS256/384/512 | HMAC | `"raw"` (secret bytes) | `"raw"` (secret bytes) | Yes |
| RS256/384/512 | RSASSA-PKCS1-v1_5 | `"pkcs8"` (PKCS#8 wrapped) | `"spki"` (SPKI wrapped) or `"jwk"` | Yes |
| PS256/384/512 | RSA-PSS | `"pkcs8"` (PKCS#8 wrapped) | `"spki"` (SPKI wrapped) or `"jwk"` | Yes |
| ES256 | ECDSA (P-256) | `"pkcs8"` (already PKCS#8) | `"raw"` (SEC1 point) | Yes |
| ES384 | ECDSA (P-384) | `"pkcs8"` (already PKCS#8) | `"raw"` (SEC1 point) | Yes |
| EdDSA | Ed25519 | — | — | **No** (limited browser support) |

### Algorithm → WebCrypto Parameter Mapping

**For `importKey()`:**

| Algorithm | `name` | `hash` | `namedCurve` |
|-----------|--------|--------|-------------|
| RS256 | `RSASSA-PKCS1-v1_5` | `SHA-256` | — |
| RS384 | `RSASSA-PKCS1-v1_5` | `SHA-384` | — |
| RS512 | `RSASSA-PKCS1-v1_5` | `SHA-512` | — |
| PS256 | `RSA-PSS` | `SHA-256` | — |
| PS384 | `RSA-PSS` | `SHA-384` | — |
| PS512 | `RSA-PSS` | `SHA-512` | — |
| ES256 | `ECDSA` | — | `P-256` |
| ES384 | `ECDSA` | — | `P-384` |
| HS256 | `HMAC` | `SHA-256` | — |
| HS384 | `HMAC` | `SHA-384` | — |
| HS512 | `HMAC` | `SHA-512` | — |

**For `sign()`/`verify()`:**

| Algorithm | `name` | Extra params |
|-----------|--------|-------------|
| RS256/384/512 | `RSASSA-PKCS1-v1_5` | (none) |
| PS256 | `RSA-PSS` | `saltLength: 32` |
| PS384 | `RSA-PSS` | `saltLength: 48` |
| PS512 | `RSA-PSS` | `saltLength: 64` |
| ES256 | `ECDSA` | `hash: { name: "SHA-256" }` |
| ES384 | `ECDSA` | `hash: { name: "SHA-384" }` |
| HS256/384/512 | `HMAC` | (none) |

Note: RSA-PSS salt length equals the hash output size in bytes (SHA-256=32, SHA-384=48, SHA-512=64).

## 5. Key Format Conversion Details

jsonwebtoken's `EncodingKey` and `DecodingKey` store key material in specific internal formats. WebCrypto's `SubtleCrypto.importKey()` requires specific formats. This section details the conversions needed.

### 5.1 EncodingKey (Private Keys for Signing)

Determined by examining `EncodingKey`'s constructors:

| Constructor | Internal Format | WebCrypto Import Format | Conversion Needed |
|-------------|----------------|------------------------|-------------------|
| `from_secret(secret)` | Raw bytes | `"raw"` | None |
| `from_rsa_pem(pem)` | PKCS#1 DER (`RSAPrivateKey`) | `"pkcs8"` | **PKCS#1 → PKCS#8 wrapping** |
| `from_rsa_der(der)` | PKCS#1 DER | `"pkcs8"` | **PKCS#1 → PKCS#8 wrapping** |
| `from_ec_pem(pem)` | PKCS#8 DER (`PrivateKeyInfo`) | `"pkcs8"` | None |
| `from_ec_der(der)` | PKCS#8 DER | `"pkcs8"` | None |
| `from_ed_pem(pem)` | PKCS#8 DER | — | Not supported |
| `from_ed_der(der)` | PKCS#8 DER | — | Not supported |

### 5.2 DecodingKey (Public Keys for Verification)

| Constructor | Internal Format | WebCrypto Import Format | Conversion Needed |
|-------------|----------------|------------------------|-------------------|
| `from_secret(secret)` | Raw bytes | `"raw"` | None |
| `from_rsa_pem(pem)` | PKCS#1 DER (`RSAPublicKey`) | `"spki"` | **PKCS#1 → SPKI wrapping** |
| `from_rsa_der(der)` | PKCS#1 DER | `"spki"` | **PKCS#1 → SPKI wrapping** |
| `from_rsa_components(n, e)` | Raw n, e components | `"jwk"` | **Build JWK object** |
| `from_ec_pem(pem)` | SEC1 uncompressed point | `"raw"` | None |
| `from_ec_der(der)` | SEC1 uncompressed point | `"raw"` | None |
| `from_ed_pem(pem)` | DER | — | Not supported |
| `from_ed_der(der)` | DER | — | Not supported |

### 5.3 PKCS#1 → PKCS#8 Wrapping (RSA Private Key)

WebCrypto requires PKCS#8 (`PrivateKeyInfo`) format for private key imports. jsonwebtoken stores RSA private keys in PKCS#1 (`RSAPrivateKey`) format. The conversion wraps the PKCS#1 DER in a PKCS#8 envelope.

```
PKCS#8 structure (RFC 5958):
  SEQUENCE {
    INTEGER 0                              -- version
    SEQUENCE {                             -- algorithm identifier
      OID 1.2.840.113549.1.1.1            -- rsaEncryption
      NULL                                 -- parameters
    }
    OCTET STRING {                         -- privateKey (the PKCS#1 blob)
      <original PKCS#1 DER bytes>
    }
  }
```

Implementation (~30 lines):

```rust
/// Wraps a PKCS#1 RSAPrivateKey DER blob in a PKCS#8 PrivateKeyInfo envelope.
fn pkcs1_to_pkcs8_rsa(pkcs1_der: &[u8]) -> Vec<u8> {
    // RSA algorithm identifier: OID 1.2.840.113549.1.1.1 + NULL
    let algorithm_id: &[u8] = &[
        0x30, 0x0d,                                     // SEQUENCE (13 bytes)
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, // OID 1.2.840.113549.1.1.1
        0x01, 0x01, 0x01,
        0x05, 0x00,                                     // NULL
    ];

    // Version INTEGER 0
    let version: &[u8] = &[0x02, 0x01, 0x00];

    // OCTET STRING wrapping the PKCS#1 blob
    let octet_string = der_wrap(0x04, pkcs1_der);

    // Inner content: version + algorithmId + octetString
    let mut inner = Vec::new();
    inner.extend_from_slice(version);
    inner.extend_from_slice(algorithm_id);
    inner.extend_from_slice(&octet_string);

    // Outer SEQUENCE
    der_wrap(0x30, &inner)
}

/// Wraps data in a DER tag-length-value.
fn der_wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = data.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(data);
    out
}
```

### 5.4 PKCS#1 → SPKI Wrapping (RSA Public Key)

WebCrypto requires SPKI (`SubjectPublicKeyInfo`) format for public key imports. jsonwebtoken stores RSA public keys in PKCS#1 (`RSAPublicKey`) format.

```
SPKI structure (RFC 5280):
  SEQUENCE {
    SEQUENCE {                             -- algorithm identifier
      OID 1.2.840.113549.1.1.1            -- rsaEncryption
      NULL
    }
    BIT STRING {                           -- subjectPublicKey
      0x00                                 -- padding bits count
      <original PKCS#1 DER bytes>
    }
  }
```

```rust
/// Wraps a PKCS#1 RSAPublicKey DER blob in an SPKI SubjectPublicKeyInfo envelope.
fn pkcs1_to_spki_rsa(pkcs1_der: &[u8]) -> Vec<u8> {
    let algorithm_id: &[u8] = &[
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01,
        0x05, 0x00,
    ];

    // BIT STRING: 0x00 prefix byte + PKCS#1 DER
    let mut bit_string_content = vec![0x00];
    bit_string_content.extend_from_slice(pkcs1_der);
    let bit_string = der_wrap(0x03, &bit_string_content);

    let mut inner = Vec::new();
    inner.extend_from_slice(algorithm_id);
    inner.extend_from_slice(&bit_string);

    der_wrap(0x30, &inner)
}
```

### 5.5 JWK Construction (RSA from n, e Components)

When `DecodingKey::from_rsa_components(n, e)` is used, the key material is raw modulus/exponent bytes. Import via JWK format:

```rust
/// Builds a web_sys::JsonWebKey from raw RSA n and e components.
fn build_rsa_jwk(n: &[u8], e: &[u8], alg: Algorithm) -> Result<Object> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let obj = Object::new();
    Reflect::set(&obj, &"kty".into(), &"RSA".into())?;
    Reflect::set(&obj, &"n".into(), &URL_SAFE_NO_PAD.encode(n).into())?;
    Reflect::set(&obj, &"e".into(), &URL_SAFE_NO_PAD.encode(e).into())?;

    let alg_str = match alg {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        _ => return Err(/* invalid algorithm for RSA JWK */),
    };
    Reflect::set(&obj, &"alg".into(), &alg_str.into())?;

    Ok(obj)
}
```

## 6. Module / File Structure

All paths relative to the jsonwebtoken repo root:

```
src/crypto/web_crypto/
├── mod.rs              # Module root: get_subtle_crypto(), is_algorithm_supported(), re-exports
├── algorithm.rs        # Algorithm mapping for importKey() and sign()/verify()
├── key_import.rs       # Key format conversion + SubtleCrypto.importKey()
├── sign.rs             # SubtleCrypto.sign() wrapper
├── verify.rs           # SubtleCrypto.verify() wrapper
├── encode.rs           # Async JWT encoding (mirrors crate::encode)
└── decode.rs           # Async JWT decoding (mirrors crate::decode)

tests/
└── web_crypto.rs       # WASM integration tests (wasm_bindgen_test)
```

### Module Responsibilities

**`mod.rs`**
- `get_subtle_crypto() -> Result<SubtleCrypto>` — gets SubtleCrypto from Window or WorkerGlobalScope
- `is_algorithm_supported(alg: Algorithm) -> bool` — checks WebCrypto compatibility
- Re-exports `encode`, `decode`

**`algorithm.rs`**
- `build_import_algorithm(alg: Algorithm) -> Result<Object>` — creates algorithm object for `importKey()` (includes `hash` for RSA, `namedCurve` for EC)
- `build_sign_verify_algorithm(alg: Algorithm) -> Result<Object>` — creates algorithm object for `sign()`/`verify()` (includes `saltLength` for PSS, `hash` for ECDSA)
- Uses `js_sys::Object` + `Reflect::set()` for dynamic JS object construction

**`key_import.rs`**
- `import_signing_key(alg: Algorithm, key: &EncodingKey) -> Result<CryptoKey>` — async
- `import_verifying_key(alg: Algorithm, key: &DecodingKey) -> Result<CryptoKey>` — async
- `pkcs1_to_pkcs8_rsa(der: &[u8]) -> Vec<u8>` — ASN.1 envelope wrapping
- `pkcs1_to_spki_rsa(der: &[u8]) -> Vec<u8>` — ASN.1 envelope wrapping
- `build_rsa_jwk(n: &[u8], e: &[u8], alg: Algorithm) -> Result<Object>` — JWK construction
- `der_wrap(tag: u8, data: &[u8]) -> Vec<u8>` — DER helper

**`sign.rs`**
- `sign(alg: Algorithm, crypto_key: &CryptoKey, message: &[u8]) -> Result<Vec<u8>>` — calls `SubtleCrypto.sign()`, returns raw signature bytes

**`verify.rs`**
- `verify(alg: Algorithm, crypto_key: &CryptoKey, message: &[u8], signature: &[u8]) -> Result<()>` — calls `SubtleCrypto.verify()`, returns `InvalidSignature` on failure

**`encode.rs`**
- `encode<T: Serialize>(header: &Header, claims: &T, key: &EncodingKey) -> Result<String>`
- Steps: validate algorithm family → import key → base64url encode header+claims → sign → assemble `header.claims.signature`

**`decode.rs`**
- `decode<T: DeserializeOwned>(token: &str, key: &DecodingKey, validation: &Validation) -> Result<TokenData<T>>`
- Steps: decode header → validate algorithm → split token → import key → verify signature → deserialize claims → validate claims

## 7. Dependencies

Add to `Cargo.toml`:

```toml
[features]
web_crypto = ["dep:web-sys", "dep:wasm-bindgen", "dep:wasm-bindgen-futures", "dep:js-sys"]

[dependencies]
web-sys = { version = "0.3", optional = true, features = [
    "Crypto",
    "CryptoKey",
    "SubtleCrypto",
    "Window",
    "WorkerGlobalScope",
] }
wasm-bindgen = { version = "0.2", optional = true }
wasm-bindgen-futures = { version = "0.4", optional = true }
js-sys = { version = "0.3", optional = true }

[dev-dependencies]
wasm-bindgen-test = "0.3"
```

Conditional module declaration in `src/crypto/mod.rs`:

```rust
#[cfg(feature = "web_crypto")]
pub mod web_crypto;
```

Public re-export in `src/lib.rs`:

```rust
#[cfg(feature = "web_crypto")]
pub use crypto::web_crypto;
```

## 8. Error Handling

Map all errors to existing `jsonwebtoken::errors::ErrorKind` variants — **no new error variants needed**:

| Error Scenario | ErrorKind Variant |
|---------------|-------------------|
| Unsupported algorithm (EdDSA) | `InvalidAlgorithm` |
| SubtleCrypto unavailable | `Crypto(String)` (via the `Provider(String)` or equivalent) |
| `importKey()` failure | `Crypto(String)` |
| `sign()` failure | `Crypto(String)` |
| `verify()` returns `false` | `InvalidSignature` |
| `verify()` throws | `Crypto(String)` |
| Malformed token | `InvalidToken` |
| Claims validation failure | `ExpiredSignature`, `InvalidIssuer`, etc. (reuse existing validation) |

JS errors from `wasm-bindgen` are converted to strings:

```rust
let result = JsFuture::from(promise)
    .await
    .map_err(|e| Error::from(ErrorKind::Crypto(format!("{:?}", e))))?;
```

## 9. Testing Strategy

### 9.1 Unit Tests (any platform)

These run with `cargo test` on any target and don't require a browser:

- ASN.1 envelope construction correctness (`pkcs1_to_pkcs8_rsa`, `pkcs1_to_spki_rsa`)
- `der_wrap` edge cases (short/long length forms)
- Algorithm support checks (`is_algorithm_supported`)
- Algorithm object construction (verify field names and values)

### 9.2 WASM Integration Tests (browser)

Run with `wasm-pack test --headless --chrome`:

```rust
#![cfg(all(target_arch = "wasm32", feature = "web_crypto"))]

use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);
```

Test cases:
- **Round-trip encode/decode** for each algorithm family (HMAC, RSA PKCS1, RSA PSS, ECDSA)
- **Cross-backend validation**: encode with `rust_crypto` backend → decode with `web_crypto` (and vice versa) to confirm interoperability
- **Error cases**: unsupported algorithm, wrong key type, invalid signature, expired token
- **Key import**: verify CryptoKey properties (`.type_()`, `.extractable()`, `.usages()`)

### 9.3 Test Data

Use the same test keys that jsonwebtoken already has in its test suite. Additionally, use RFC 7517 Appendix A test vectors for known-good JWK values.

## 10. Implementation Order

1. **Feature flag + dependencies** in `Cargo.toml`
2. **Module scaffold** (`mod.rs` with `get_subtle_crypto`, `is_algorithm_supported`)
3. **Algorithm mapping** (`algorithm.rs`) — build import and sign/verify algorithm objects
4. **Key import + ASN.1 helpers** (`key_import.rs`) — most complex piece; test ASN.1 wrapping separately with unit tests
5. **Sign + verify** (`sign.rs`, `verify.rs`) — thin wrappers around SubtleCrypto
6. **Encode + decode** (`encode.rs`, `decode.rs`) — orchestrate the above
7. **Public re-export** in `lib.rs`, integration tests

## 11. Design Decisions

- **Import on every call** (not pre-cached): Simpler initial implementation. A `WebCryptoSigningKey`/`WebCryptoVerifyingKey` wrapper holding a pre-imported `CryptoKey` can be added later as an optimization.
- **ECDSA signatures**: Both JWS (RFC 7518) and WebCrypto use IEEE P1363 format (r||s concatenation), so **no signature format conversion is needed**.
- **No EdDSA**: Ed25519 support in WebCrypto is still non-universal across browsers. Can be added later behind a sub-feature flag.
- **Hand-rolled ASN.1 envelopes**: The `pkcs8` crate could be used instead but adds a dependency; hand-rolled is ~30 lines and well-tested for the specific fixed structures needed.
- **`pub(crate)` access**: Functions like `b64_encode_part`, `b64_decode`, `DecodedJwtPartClaims`, and `validate()` are `pub(crate)` which works since `web_crypto` is a module inside the crate.

## 12. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| RSA format conversion correctness | Test with RFC 7517 vectors; compare output against `openssl` conversions |
| `EncodingKey`/`DecodingKey` internal format assumptions | Verified by reading source: RSA uses PKCS#1, EC uses PKCS#8/SEC1 |
| Browser compatibility of Ed25519 in WebCrypto | Excluded from initial scope; add later with feature detection |
| `EncodingKey`/`DecodingKey` fields are private | The module lives inside the crate so it can access `pub(crate)` internals |

## 13. Reference: jwk-simple's WebCrypto Integration

The `jwk-simple` crate (this repository) has a working WebCrypto integration at `src/integrations/web_crypto.rs` that serves as a reference for:

- **Getting SubtleCrypto**: Works in both Window and WorkerGlobalScope contexts (lines 82-101)
- **Algorithm object construction**: Uses `js_sys::Object` + `Reflect::set()` for building JavaScript objects (lines 260-370, 406-469)
- **Key import via JWK format**: Converts keys to `web_sys::JsonWebKey` then calls `importKey("jwk", ...)` (lines 582-607)
- **Promise handling**: Uses `wasm_bindgen_futures::JsFuture` for async (lines 602-604)
- **Error handling**: `WebCrypto(String)` variant for JS errors, `UnsupportedForWebCrypto` for unsupported key types (see `src/error.rs` lines 67-78)
- **Test patterns**: `wasm_bindgen_test` with `run_in_browser`, testing CryptoKey properties (see `tests/web_crypto.rs`)

The key difference from jwk-simple is that jsonwebtoken imports keys via DER/raw formats (`"pkcs8"`, `"spki"`, `"raw"`) rather than JWK format, since `EncodingKey`/`DecodingKey` store binary key material rather than parsed JWK parameters.

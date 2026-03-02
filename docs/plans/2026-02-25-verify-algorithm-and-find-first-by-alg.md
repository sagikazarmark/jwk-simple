# Verify Algorithm Builder & find_first_by_alg Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a public `build_verify_algorithm` function for building WebCrypto `SubtleCrypto.verify()` algorithm objects, and a `find_first_by_alg` convenience method on `KeySet`.

**Architecture:** Two independent additions to the existing web-crypto integration and KeySet API. The verify algorithm builder takes an `Algorithm` enum value and returns a `js_sys::Object` suitable for `SubtleCrypto.verify()`. The `find_first_by_alg` wraps the existing `find_by_alg` to return a single key.

**Tech Stack:** Rust, web-sys, js-sys, wasm-bindgen

---

### Task 1: Add `find_first_by_alg` to KeySet — write failing test

**Files:**
- Modify: `src/jwks.rs` (tests section, ~line 477)

**Step 1: Write the failing test**

Add this test to the existing `mod tests` block in `src/jwks.rs`, after the `test_first_signing_key` test (around line 568):

```rust
#[test]
fn test_find_first_by_alg() {
    let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

    let key = jwks.find_first_by_alg(&Algorithm::Rs256);
    assert!(key.is_some());
    assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-key-1"));

    let key = jwks.find_first_by_alg(&Algorithm::Es256);
    assert!(key.is_some());
    assert_eq!(key.unwrap().kid.as_deref(), Some("ec-key-1"));

    let missing = jwks.find_first_by_alg(&Algorithm::Ps512);
    assert!(missing.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_find_first_by_alg`
Expected: FAIL — `no method named find_first_by_alg found`

---

### Task 2: Implement `find_first_by_alg` on KeySet

**Files:**
- Modify: `src/jwks.rs` (impl KeySet block, after `first_signing_key` at ~line 393)

**Step 1: Write minimal implementation**

Add this method to `impl KeySet`, right after `first_signing_key()`:

```rust
/// Returns the first key matching the specified algorithm, if any.
///
/// This is a convenience method that returns a single key instead of the
/// vector returned by [`find_by_alg`].
///
/// # Arguments
///
/// * `alg` - The algorithm to search for.
///
/// # Examples
///
/// ```
/// use jwk_simple::{KeySet, Algorithm};
///
/// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
/// let jwks: KeySet = serde_json::from_str(json).unwrap();
///
/// let key = jwks.find_first_by_alg(&Algorithm::Rs256);
/// assert!(key.is_some());
/// ```
pub fn find_first_by_alg(&self, alg: &Algorithm) -> Option<&Key> {
    self.keys.iter().find(|k| k.alg.as_ref() == Some(alg))
}
```

**Step 2: Run test to verify it passes**

Run: `cargo test test_find_first_by_alg`
Expected: PASS

**Step 3: Run full test suite**

Run: `cargo test`
Expected: All existing tests still pass

**Step 4: Run clippy and fmt**

Run: `cargo fmt && cargo clippy`
Expected: No warnings

**Step 5: Commit**

```bash
git add src/jwks.rs
git commit -m "feat: add find_first_by_alg to KeySet"
```

---

### Task 3: Add `build_verify_algorithm` — write failing test

**Files:**
- Modify: `src/integrations/web_crypto.rs` (validation_tests section, ~line 604)

The verify algorithm for `SubtleCrypto.verify()` differs from the import algorithm:
- RSASSA-PKCS1-v1_5: just `{ name }` (no hash needed)
- RSA-PSS: `{ name, saltLength }` (salt length = hash output size in bytes)
- ECDSA: `{ name, hash: { name } }` (needs hash, NOT namedCurve)
- HMAC: just `{ name }` (no hash needed)

**Step 1: Write the failing tests**

Add these tests to the `validation_tests` module in `src/integrations/web_crypto.rs` (after the `test_is_web_crypto_compatible_secp256k1` test, ~line 688). These tests only check that the function exists and returns the right structure — they do NOT need wasm32 since they only test `Result<Object>` return type via the function signature existing. However, `js_sys::Object` is only available on wasm32, so these tests go in the wasm32-only `mod tests` block instead (after `test_build_hmac_algorithm`, ~line 843):

```rust
#[test]
fn test_build_verify_algorithm_rs256() {
    let alg = Algorithm::Rs256;
    let obj = build_verify_algorithm(&alg).unwrap();

    let name = Reflect::get(&obj, &"name".into()).unwrap();
    assert_eq!(name.as_string().unwrap(), "RSASSA-PKCS1-v1_5");

    // RSASSA-PKCS1-v1_5 verify does NOT need hash
    let hash = Reflect::get(&obj, &"hash".into()).unwrap();
    assert!(hash.is_undefined());
}

#[test]
fn test_build_verify_algorithm_ps256() {
    let alg = Algorithm::Ps256;
    let obj = build_verify_algorithm(&alg).unwrap();

    let name = Reflect::get(&obj, &"name".into()).unwrap();
    assert_eq!(name.as_string().unwrap(), "RSA-PSS");

    let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
    assert_eq!(salt_length.as_f64().unwrap() as u32, 32);
}

#[test]
fn test_build_verify_algorithm_ps384() {
    let alg = Algorithm::Ps384;
    let obj = build_verify_algorithm(&alg).unwrap();

    let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
    assert_eq!(salt_length.as_f64().unwrap() as u32, 48);
}

#[test]
fn test_build_verify_algorithm_ps512() {
    let alg = Algorithm::Ps512;
    let obj = build_verify_algorithm(&alg).unwrap();

    let salt_length = Reflect::get(&obj, &"saltLength".into()).unwrap();
    assert_eq!(salt_length.as_f64().unwrap() as u32, 64);
}

#[test]
fn test_build_verify_algorithm_es256() {
    let alg = Algorithm::Es256;
    let obj = build_verify_algorithm(&alg).unwrap();

    let name = Reflect::get(&obj, &"name".into()).unwrap();
    assert_eq!(name.as_string().unwrap(), "ECDSA");

    let hash = Reflect::get(&obj, &"hash".into()).unwrap();
    let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
    assert_eq!(hash_name.as_string().unwrap(), "SHA-256");
}

#[test]
fn test_build_verify_algorithm_es384() {
    let alg = Algorithm::Es384;
    let obj = build_verify_algorithm(&alg).unwrap();

    let hash = Reflect::get(&obj, &"hash".into()).unwrap();
    let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
    assert_eq!(hash_name.as_string().unwrap(), "SHA-384");
}

#[test]
fn test_build_verify_algorithm_es512() {
    let alg = Algorithm::Es512;
    let obj = build_verify_algorithm(&alg).unwrap();

    let hash = Reflect::get(&obj, &"hash".into()).unwrap();
    let hash_name = Reflect::get(&hash, &"name".into()).unwrap();
    assert_eq!(hash_name.as_string().unwrap(), "SHA-512");
}

#[test]
fn test_build_verify_algorithm_hs256() {
    let alg = Algorithm::Hs256;
    let obj = build_verify_algorithm(&alg).unwrap();

    let name = Reflect::get(&obj, &"name".into()).unwrap();
    assert_eq!(name.as_string().unwrap(), "HMAC");
}

#[test]
fn test_build_verify_algorithm_unsupported() {
    let alg = Algorithm::EdDsa;
    let result = build_verify_algorithm(&alg);
    assert!(result.is_err());
}
```

**Step 2: Verify tests fail**

These tests are wasm32-only and use `build_verify_algorithm` which doesn't exist yet. Verify compilation fails:

Run: `cargo check --features web-crypto --target wasm32-unknown-unknown`
Expected: FAIL — `cannot find function build_verify_algorithm`

---

### Task 4: Implement `build_verify_algorithm`

**Files:**
- Modify: `src/integrations/web_crypto.rs` (after the existing algorithm builder section, ~line 370)

**Step 1: Write the implementation**

Add this public function after `build_symmetric_algorithm` and before the "Key Import Functions" section (~line 370):

```rust
/// Builds a WebCrypto algorithm object for use with `SubtleCrypto.verify()`.
///
/// This is different from the import algorithm: `verify()` requires algorithm-specific
/// parameters like `saltLength` (RSA-PSS) or `hash` (ECDSA), while not needing
/// parameters like `namedCurve` that are only needed during import.
///
/// # Supported Algorithms
///
/// | Algorithm | Verify Object |
/// |-----------|---------------|
/// | RS256/384/512 | `{ name: "RSASSA-PKCS1-v1_5" }` |
/// | PS256/384/512 | `{ name: "RSA-PSS", saltLength }` |
/// | ES256/384/512 | `{ name: "ECDSA", hash }` |
/// | HS256/384/512 | `{ name: "HMAC" }` |
///
/// # Errors
///
/// Returns [`Error::UnsupportedForWebCrypto`] if the algorithm is not supported
/// by WebCrypto (e.g., EdDSA, ES256K).
///
/// # Examples
///
/// ```ignore
/// use jwk_simple::{Algorithm, integrations::web_crypto};
///
/// let alg = Algorithm::Rs256;
/// let verify_algo = web_crypto::build_verify_algorithm(&alg)?;
///
/// // Use with SubtleCrypto.verify()
/// let subtle = web_crypto::get_subtle_crypto()?;
/// let result = subtle.verify_with_object_and_buffer_source_and_buffer_source(
///     &verify_algo, &crypto_key, &signature, &data,
/// )?;
/// ```
pub fn build_verify_algorithm(alg: &Algorithm) -> Result<Object> {
    let obj = Object::new();

    match alg {
        // RSASSA-PKCS1-v1_5: only needs the algorithm name
        Algorithm::Rs256 | Algorithm::Rs384 | Algorithm::Rs512 => {
            Reflect::set(&obj, &"name".into(), &"RSASSA-PKCS1-v1_5".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
        }

        // RSA-PSS: needs algorithm name and salt length (= hash output size in bytes)
        Algorithm::Ps256 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &32.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }
        Algorithm::Ps384 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &48.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }
        Algorithm::Ps512 => {
            Reflect::set(&obj, &"name".into(), &"RSA-PSS".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
            Reflect::set(&obj, &"saltLength".into(), &64.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set saltLength: {:?}", e)))?;
        }

        // ECDSA: needs algorithm name and hash
        Algorithm::Es256 | Algorithm::Es384 | Algorithm::Es512 => {
            Reflect::set(&obj, &"name".into(), &"ECDSA".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;

            let hash = match alg {
                Algorithm::Es256 => "SHA-256",
                Algorithm::Es384 => "SHA-384",
                Algorithm::Es512 => "SHA-512",
                _ => unreachable!(),
            };

            let hash_obj = Object::new();
            Reflect::set(&hash_obj, &"name".into(), &hash.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash name: {:?}", e)))?;
            Reflect::set(&obj, &"hash".into(), &hash_obj.into())
                .map_err(|e| Error::WebCrypto(format!("failed to set hash: {:?}", e)))?;
        }

        // HMAC: only needs the algorithm name
        Algorithm::Hs256 | Algorithm::Hs384 | Algorithm::Hs512 => {
            Reflect::set(&obj, &"name".into(), &"HMAC".into())
                .map_err(|e| Error::WebCrypto(format!("failed to set algorithm name: {:?}", e)))?;
        }

        _ => {
            return Err(Error::UnsupportedForWebCrypto {
                reason: "algorithm not supported for WebCrypto verify",
            });
        }
    }

    Ok(obj)
}
```

**Step 2: Verify it compiles**

Run: `cargo check --features web-crypto --target wasm32-unknown-unknown`
Expected: Compiles successfully

**Step 3: Run the non-wasm tests**

Run: `cargo test`
Expected: All tests pass (wasm32-only tests are skipped on native)

**Step 4: Run clippy and fmt**

Run: `cargo fmt && cargo clippy --features web-crypto --target wasm32-unknown-unknown`
Expected: No warnings

**Step 5: Commit**

```bash
git add src/integrations/web_crypto.rs
git commit -m "feat: add build_verify_algorithm for WebCrypto SubtleCrypto.verify()"
```

---

### Task 5: Update example to use the new `build_verify_algorithm`

**Files:**
- Modify: `examples/webcrypto_jwt_verify.rs`

**Step 1: Replace the hand-rolled `build_verify_algorithm` in the example**

In `examples/webcrypto_jwt_verify.rs`, replace the local `build_verify_algorithm` function (~lines 210-265) with a call to the library function. The `verify_signature` function (~line 268) should use `web_crypto::build_verify_algorithm` instead.

Replace the `build_verify_algorithm` function definition with this import usage:

In the imports at the top (~line 50), change:
```rust
use jwk_simple::{web_crypto, Algorithm, Key, KeySet};
```

Remove the entire `build_verify_algorithm` function definition (lines 210-265).

In the `verify_signature` function, replace:
```rust
let algorithm = build_verify_algorithm(&jwt.header.alg)?;
```
with:
```rust
let alg: Algorithm = jwt.header.alg.parse().unwrap_or(Algorithm::Unknown(jwt.header.alg.clone()));
let algorithm = web_crypto::build_verify_algorithm(&alg)
    .map_err(|e| JwtError::CryptoError(e.to_string()))?;
```

**Step 2: Verify it compiles**

Run: `cargo check --features web-crypto --target wasm32-unknown-unknown --example webcrypto_jwt_verify`
Expected: Compiles successfully

**Step 3: Run clippy and fmt**

Run: `cargo fmt && cargo clippy --features web-crypto --target wasm32-unknown-unknown`
Expected: No warnings

**Step 4: Commit**

```bash
git add examples/webcrypto_jwt_verify.rs
git commit -m "refactor: use library build_verify_algorithm in example"
```

---

### Task 6: Re-export `find_first_by_alg` is already accessible & final verification

**Files:** None (just verification)

**Step 1: Verify `find_first_by_alg` is accessible from the public API**

`KeySet` is already re-exported at `src/lib.rs:120`. The new method is `pub` on `KeySet`, so it's automatically available to consumers. No additional re-exports needed.

**Step 2: Verify `build_verify_algorithm` is accessible from the public API**

`web_crypto` module is already re-exported at `src/lib.rs:136`. The new function is `pub`, so it's accessible via `jwk_simple::web_crypto::build_verify_algorithm`. No additional re-exports needed.

**Step 3: Run full test suite**

Run: `cargo test`
Expected: All tests pass

**Step 4: Run clippy on all feature combos**

Run: `cargo clippy && cargo clippy --features jwt-simple && cargo clippy --features web-crypto --target wasm32-unknown-unknown`
Expected: No warnings

//! WASM integration tests for WebCrypto functionality.
//!
//! These tests run in a headless browser using wasm-pack test.
//! Run with: `wasm-pack test --headless --chrome`

#![cfg(all(target_arch = "wasm32", feature = "web-crypto"))]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use js_sys::Uint8Array;
use jwk_simple::Key;
use jwk_simple::web_crypto;

// Test RSA public key from RFC 7517 Appendix A.1
const RFC_RSA_PUBLIC_KEY: &str = r#"{
    "kty": "RSA",
    "kid": "rsa-test-key",
    "use": "sig",
    "alg": "RS256",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB"
}"#;

// Test EC P-256 public key
const EC_P256_PUBLIC_KEY: &str = r#"{
    "kty": "EC",
    "kid": "ec-test-key",
    "use": "sig",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
}"#;

// Test EC P-384 public key
const EC_P384_PUBLIC_KEY: &str = r#"{
    "kty": "EC",
    "kid": "ec-p384-key",
    "crv": "P-384",
    "x": "iGnmKXM6H_pF-xhNa8os8JYvJpe4jn7wBbCBmtNuC9H9xb8M2Z1vJJf-iFMt-3g4",
    "y": "20M1ZBIKQpWeJzpBhWxxCiZCY6CHwJrIvYk5S6Qmzp15hG-nV7nY2oJRZUFfGpjX"
}"#;

// Test HMAC key
const HMAC_KEY: &str = r#"{
    "kty": "oct",
    "kid": "hmac-test-key",
    "alg": "HS256",
    "k": "AyM32w-8O0TGsGDYX0MlWy-9XQP-xrryrP7gkXKfY5WhoLxmT3fzfVr7LXqgDDFSfowWBY-u6bSH5f9kBZ_n7Q"
}"#;

fn to_uint8_array(data: &[u8]) -> Uint8Array {
    let array = Uint8Array::new_with_length(data.len() as u32);
    array.copy_from(data);
    array
}

#[wasm_bindgen_test]
async fn test_import_rsa_verify_key() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let crypto_key = web_crypto::import_verify_key(&key).await.unwrap();

    // Verify the key was imported correctly
    assert_eq!(crypto_key.type_(), "public");
    assert!(!crypto_key.extractable());

    let usages = crypto_key.usages();
    assert!(usages.includes(&wasm_bindgen::JsValue::from_str("verify"), 0));
}

#[wasm_bindgen_test]
async fn test_import_ec_p256_verify_key() {
    let key: Key = serde_json::from_str(EC_P256_PUBLIC_KEY).unwrap();
    let crypto_key = web_crypto::import_verify_key(&key).await.unwrap();

    assert_eq!(crypto_key.type_(), "public");
    assert!(!crypto_key.extractable());
}

#[wasm_bindgen_test]
async fn test_import_ec_p384_verify_key() {
    let key: Key = serde_json::from_str(EC_P384_PUBLIC_KEY).unwrap();
    let crypto_key = web_crypto::import_verify_key(&key).await.unwrap();

    assert_eq!(crypto_key.type_(), "public");
}

#[wasm_bindgen_test]
async fn test_import_hmac_sign_key() {
    let key: Key = serde_json::from_str(HMAC_KEY).unwrap();
    let crypto_key = web_crypto::import_sign_key(&key).await.unwrap();

    // HMAC keys are "secret" type
    assert_eq!(crypto_key.type_(), "secret");
}

#[wasm_bindgen_test]
async fn test_import_hmac_verify_key() {
    let key: Key = serde_json::from_str(HMAC_KEY).unwrap();
    let crypto_key = web_crypto::import_verify_key(&key).await.unwrap();

    assert_eq!(crypto_key.type_(), "secret");
}

#[wasm_bindgen_test]
async fn test_hmac_sign_and_verify_behavior() {
    let key: Key = serde_json::from_str(HMAC_KEY).unwrap();
    let sign_key = web_crypto::import_sign_key(&key).await.unwrap();
    let verify_key = web_crypto::import_verify_key(&key).await.unwrap();

    let subtle = web_crypto::get_subtle_crypto().unwrap();
    let data = b"hello-webcrypto";
    let data_array = to_uint8_array(data);

    let sign_alg = js_sys::Object::new();
    js_sys::Reflect::set(&sign_alg, &"name".into(), &"HMAC".into()).unwrap();
    let sign_promise = subtle
        .sign_with_object_and_buffer_source(&sign_alg, &sign_key, &data_array)
        .unwrap();
    let signature = wasm_bindgen_futures::JsFuture::from(sign_promise)
        .await
        .unwrap();

    let verify_alg = web_crypto::build_verify_algorithm(&jwk_simple::Algorithm::Hs256).unwrap();
    let verify_promise = subtle
        .verify_with_object_and_buffer_source_and_buffer_source(
            &verify_alg,
            &verify_key,
            &signature,
            &data_array,
        )
        .unwrap();
    let ok = wasm_bindgen_futures::JsFuture::from(verify_promise)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(ok);

    let tampered = to_uint8_array(b"hello-webcrypto!");
    let verify_tampered = subtle
        .verify_with_object_and_buffer_source_and_buffer_source(
            &verify_alg,
            &verify_key,
            &signature,
            &tampered,
        )
        .unwrap();
    let tampered_ok = wasm_bindgen_futures::JsFuture::from(verify_tampered)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(!tampered_ok);
}

#[wasm_bindgen_test]
fn test_get_subtle_crypto() {
    // This should succeed in a browser environment
    let subtle = web_crypto::get_subtle_crypto();
    assert!(subtle.is_ok());
}

#[wasm_bindgen_test]
fn test_to_json_web_key_rsa() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let jwk = web_crypto::to_json_web_key(&key).unwrap();

    assert_eq!(jwk.kty(), "RSA");
    // Note: `kid` is not part of the WebCrypto JsonWebKey dictionary,
    // so it is not set on the web_sys::JsonWebKey object.
    assert_eq!(jwk.alg(), Some("RS256".to_string()));
    assert!(jwk.n().is_some());
    assert!(jwk.e().is_some());
}

#[wasm_bindgen_test]
fn test_to_json_web_key_ec() {
    let key: Key = serde_json::from_str(EC_P256_PUBLIC_KEY).unwrap();
    let jwk = web_crypto::to_json_web_key(&key).unwrap();

    assert_eq!(jwk.kty(), "EC");
    assert_eq!(jwk.crv(), Some("P-256".to_string()));
    assert!(jwk.x().is_some());
    assert!(jwk.y().is_some());
}

#[wasm_bindgen_test]
fn test_convenience_method_to_web_crypto_jwk() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let jwk = key.to_web_crypto_jwk().unwrap();

    assert_eq!(jwk.kty(), "RSA");
}

#[wasm_bindgen_test]
async fn test_convenience_method_import_as_verify_key() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let crypto_key = key.import_as_verify_key().await.unwrap();

    assert_eq!(crypto_key.type_(), "public");
}

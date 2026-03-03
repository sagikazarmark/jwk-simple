//! WASM integration tests for WebCrypto functionality.
//!
//! These tests run in a headless browser using wasm-pack test.
//! Run with: `wasm-pack test --headless --chrome`

#![cfg(all(target_arch = "wasm32", feature = "web-crypto"))]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use js_sys::{Object, Reflect, Uint8Array};
use jwk_simple::Key;
use jwk_simple::error::ValidationError;
use jwk_simple::web_crypto;
use std::convert::TryFrom;

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

// Test EC P-256 private key from RFC 7517 Appendix A.2
const EC_P256_PRIVATE_KEY: &str = r#"{
    "kty": "EC",
    "kid": "ec-test-key",
    "use": "sig",
    "alg": "ES256",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
}"#;

// Test EC P-384 private key
const EC_P384_PRIVATE_KEY: &str = r#"{
    "kty": "EC",
    "kid": "ec-p384-key",
    "use": "sig",
    "alg": "ES384",
    "crv": "P-384",
    "x": "NzMtUzQovdr-Z_jkY-WC4oqyqutKc2UV29koQG_aJ7H059vEfCkI1Rooi978DAjC",
    "y": "YT8tnNm05Tfm8K5aSvXHupxCPTiJ-WWD83M6_pOsSgENgPAZ9xbUm0CMcCTu0RNM",
    "d": "Az36XG8hJd_AxN2TcIN0-6R0kxB1IUxCNkzCrSgpS2rCdvtCpDbf4Fz6doX6zdO4"
}"#;

// Matching EC P-384 public key for EC_P384_PRIVATE_KEY
const EC_P384_PUBLIC_KEY_MATCHING_PRIVATE: &str = r#"{
    "kty": "EC",
    "kid": "ec-p384-key",
    "crv": "P-384",
    "x": "NzMtUzQovdr-Z_jkY-WC4oqyqutKc2UV29koQG_aJ7H059vEfCkI1Rooi978DAjC",
    "y": "YT8tnNm05Tfm8K5aSvXHupxCPTiJ-WWD83M6_pOsSgENgPAZ9xbUm0CMcCTu0RNM"
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

fn rsassa_verify_alg() -> Object {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &"RSASSA-PKCS1-v1_5".into()).unwrap();
    obj
}

fn ecdsa_verify_alg(hash_name: &str) -> Object {
    let obj = Object::new();
    Reflect::set(&obj, &"name".into(), &"ECDSA".into()).unwrap();
    let hash = Object::new();
    Reflect::set(&hash, &"name".into(), &hash_name.into()).unwrap();
    Reflect::set(&obj, &"hash".into(), &hash.into()).unwrap();
    obj
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
    // Use the public key that matches the private ES384 fixture.
    let key: Key = serde_json::from_str(EC_P384_PUBLIC_KEY_MATCHING_PRIVATE).unwrap();
    let crypto_key = web_crypto::import_verify_key_for_alg(&key, &jwk_simple::Algorithm::Es384)
        .await
        .unwrap();

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
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &verify_alg,
            &verify_key,
            &Uint8Array::new(&signature),
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
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &verify_alg,
            &verify_key,
            &Uint8Array::new(&signature),
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
    let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();

    assert_eq!(jwk.get_kty(), "RSA");
    // Note: `kid` is not part of the WebCrypto JsonWebKey dictionary,
    // so it is not set on the web_sys::JsonWebKey object.
    assert_eq!(jwk.get_alg(), Some("RS256".to_string()));
    assert!(jwk.get_n().is_some());
    assert!(jwk.get_e().is_some());
}

#[wasm_bindgen_test]
fn test_to_json_web_key_ec() {
    let key: Key = serde_json::from_str(EC_P256_PUBLIC_KEY).unwrap();
    let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();

    assert_eq!(jwk.get_kty(), "EC");
    assert_eq!(jwk.get_crv(), Some("P-256".to_string()));
    assert!(jwk.get_x().is_some());
    assert!(jwk.get_y().is_some());
}

#[wasm_bindgen_test]
fn test_try_from_to_json_web_key() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let jwk = web_sys::JsonWebKey::try_from(&key).unwrap();

    assert_eq!(jwk.get_kty(), "RSA");
}

#[wasm_bindgen_test]
async fn test_convenience_method_import_as_verify_key() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let crypto_key = key.import_as_verify_key().await.unwrap();

    assert_eq!(crypto_key.type_(), "public");
}

#[wasm_bindgen_test]
async fn test_import_verify_key_rejects_usage_algorithm_mismatch() {
    let key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let err = web_crypto::import_encrypt_key(&key).await.unwrap_err();
    assert!(matches!(
        err,
        jwk_simple::Error::UnsupportedForWebCrypto { .. }
    ));
}

#[wasm_bindgen_test]
async fn test_import_verify_key_for_alg_rejects_weak_hs256_key_without_alg() {
    // 31 bytes (248 bits): structurally valid oct key, but too weak for HS256.
    let weak_hmac_key = r#"{
        "kty": "oct",
        "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }"#;

    let key: Key = serde_json::from_str(weak_hmac_key).unwrap();
    let err = web_crypto::import_verify_key_for_alg(&key, &jwk_simple::Algorithm::Hs256)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        jwk_simple::Error::Validation(ValidationError::InvalidKeySize { .. })
    ));
}

#[wasm_bindgen_test]
async fn test_rsa_verify_behavior_rejects_invalid_signatures() {
    let subtle = web_crypto::get_subtle_crypto().unwrap();
    let public_key: Key = serde_json::from_str(RFC_RSA_PUBLIC_KEY).unwrap();
    let verify_key =
        web_crypto::import_verify_key_for_alg(&public_key, &jwk_simple::Algorithm::Rs256)
            .await
            .unwrap();

    let data = to_uint8_array(b"web-crypto-rsa-check");
    let verify_alg = rsassa_verify_alg();
    let invalid_sig = Uint8Array::new_with_length(256);

    let verify_invalid = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &verify_alg,
            &verify_key,
            &invalid_sig,
            &data,
        )
        .unwrap();
    let invalid_ok = wasm_bindgen_futures::JsFuture::from(verify_invalid)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(!invalid_ok);

    // Tampered payload with invalid signature also fails.
    let tampered = to_uint8_array(b"web-crypto-rsa-check!");
    let verify_tampered = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &verify_alg,
            &verify_key,
            &invalid_sig,
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
async fn test_ec_verify_behavior_rejects_invalid_signature() {
    let subtle = web_crypto::get_subtle_crypto().unwrap();

    let p256: Key = serde_json::from_str(EC_P256_PUBLIC_KEY).unwrap();
    let p256_private: Key = serde_json::from_str(EC_P256_PRIVATE_KEY).unwrap();
    let p256_sign_key =
        web_crypto::import_sign_key_for_alg(&p256_private, &jwk_simple::Algorithm::Es256)
            .await
            .unwrap();
    let p256_key = web_crypto::import_verify_key_for_alg(&p256, &jwk_simple::Algorithm::Es256)
        .await
        .unwrap();
    let p256_alg = ecdsa_verify_alg("SHA-256");
    let data = to_uint8_array(b"ec-p256-verify");

    let p256_sign = subtle
        .sign_with_object_and_buffer_source(&p256_alg, &p256_sign_key, &data)
        .unwrap();
    let p256_sig = wasm_bindgen_futures::JsFuture::from(p256_sign)
        .await
        .unwrap();
    let p256_verify_ok = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &p256_alg,
            &p256_key,
            &Uint8Array::new(&p256_sig),
            &data,
        )
        .unwrap();
    let p256_ok = wasm_bindgen_futures::JsFuture::from(p256_verify_ok)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(p256_ok);

    let p256_tampered_data = to_uint8_array(b"ec-p256-verify!");
    let p256_tampered = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &p256_alg,
            &p256_key,
            &Uint8Array::new(&p256_sig),
            &p256_tampered_data,
        )
        .unwrap();
    let p256_tampered_ok = wasm_bindgen_futures::JsFuture::from(p256_tampered)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(!p256_tampered_ok);

    let bad_sig = to_uint8_array(&[0u8; 64]);
    let p256_verify = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(&p256_alg, &p256_key, &bad_sig, &data)
        .unwrap();
    let p256_bad_ok = wasm_bindgen_futures::JsFuture::from(p256_verify)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(true);
    assert!(!p256_bad_ok);

    let p384: Key = serde_json::from_str(EC_P384_PUBLIC_KEY_MATCHING_PRIVATE).unwrap();
    let p384_private: Key = serde_json::from_str(EC_P384_PRIVATE_KEY).unwrap();
    let p384_sign_key =
        web_crypto::import_sign_key_for_alg(&p384_private, &jwk_simple::Algorithm::Es384)
            .await
            .unwrap();
    let p384_key = web_crypto::import_verify_key_for_alg(&p384, &jwk_simple::Algorithm::Es384)
        .await
        .unwrap();
    let p384_alg = ecdsa_verify_alg("SHA-384");
    let p384_data = to_uint8_array(b"ec-p384-verify");

    let p384_sign = subtle
        .sign_with_object_and_buffer_source(&p384_alg, &p384_sign_key, &p384_data)
        .unwrap();
    let p384_sig = wasm_bindgen_futures::JsFuture::from(p384_sign)
        .await
        .unwrap();
    let p384_verify_ok = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &p384_alg,
            &p384_key,
            &Uint8Array::new(&p384_sig),
            &p384_data,
        )
        .unwrap();
    let p384_valid_ok = wasm_bindgen_futures::JsFuture::from(p384_verify_ok)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(p384_valid_ok);

    let p384_tampered_data = to_uint8_array(b"ec-p384-verify!");
    let p384_verify_tampered = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &p384_alg,
            &p384_key,
            &Uint8Array::new(&p384_sig),
            &p384_tampered_data,
        )
        .unwrap();
    let p384_tampered_ok = wasm_bindgen_futures::JsFuture::from(p384_verify_tampered)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(false);
    assert!(!p384_tampered_ok);

    let p384_bad_sig = to_uint8_array(&[0u8; 96]);
    let p384_verify = subtle
        .verify_with_object_and_js_u8_array_and_buffer_source(
            &p384_alg,
            &p384_key,
            &p384_bad_sig,
            &p384_data,
        )
        .unwrap();
    let p384_ok = wasm_bindgen_futures::JsFuture::from(p384_verify)
        .await
        .unwrap()
        .as_bool()
        .unwrap_or(true);
    assert!(!p384_ok);
}

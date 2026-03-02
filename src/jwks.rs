//! JSON Web Key Set (JWKS) as defined in RFC 7517 Section 5.
//!
//! A JWKS is a collection of JWK objects, typically used for key distribution
//! and discovery. This module also defines the [`KeySource`] trait, which abstracts
//! over different sources of JWK keys.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::Result;
use crate::jwk::{Algorithm, Key, KeyType, KeyUse};

mod cache;
#[cfg(all(feature = "cloudflare", target_arch = "wasm32"))]
pub mod cloudflare;
#[cfg(feature = "cache-inmemory")]
mod inmemory_cache;
#[cfg(feature = "http")]
mod remote;

pub use cache::{CachedKeySet, KeyCache};
#[cfg(feature = "cache-inmemory")]
pub use inmemory_cache::{DEFAULT_CACHE_TTL, InMemoryCachedKeySet, InMemoryKeyCache};
#[cfg(feature = "http")]
pub use remote::{DEFAULT_TIMEOUT, RemoteKeySet};

/// A trait for types that can provide JWK keys.
///
/// This trait abstracts over different sources of keys, whether from
/// a static set, a remote HTTP endpoint, or a cached source.
///
/// # Naming
///
/// This trait is called `KeySource` (not `Jwks`) to distinguish it from:
/// - [`KeySet`] - The data structure holding keys
/// - A potential `Jwks` type for serving keys via HTTP endpoints
///
/// # Async and Send Bounds
///
/// On native targets, the trait requires `Send + Sync` and futures are `Send`.
/// On WASM targets, these bounds are relaxed since everything is single-threaded.
///
/// # Examples
///
/// Using a static key set:
///
/// ```
/// use jwk_simple::{KeySource, KeySet};
///
/// # async fn example() -> jwk_simple::Result<()> {
/// let source: KeySet = serde_json::from_str(r#"{"keys": []}"#)?;
/// let key = source.get_key("some-kid").await?;
/// # Ok(())
/// # }
/// ```
///
/// Generic code that works with any source:
///
/// ```ignore
/// async fn verify_token<S: KeySource>(source: &S, kid: &str) -> Result<()> {
///     let key = source.get_key(kid).await?.ok_or(Error::KeyNotFound)?;
///     // ... verify with key
///     Ok(())
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeySource {
    /// Gets a key by its key ID (`kid`).
    ///
    /// Returns `Ok(None)` if no key with the given ID exists.
    /// Returns `Err` if the lookup failed (e.g., network error for remote sources).
    ///
    /// # Arguments
    ///
    /// * `kid` - The key ID to look up.
    async fn get_key(&self, kid: &str) -> Result<Option<Key>>;

    /// Gets all available keys as a [`KeySet`].
    ///
    /// For remote sources, this may trigger a fetch if the cache is empty or expired.
    async fn get_keyset(&self) -> Result<KeySet>;
}

// Implement KeySource for KeySet (static, immediate)
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeySource for KeySet {
    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        Ok(self.find_by_kid(kid).cloned())
    }

    async fn get_keyset(&self) -> Result<KeySet> {
        Ok(self.clone())
    }
}

/// A JSON Web Key Set (RFC 7517 Section 5).
///
/// A KeySet contains a collection of keys that can be looked up by various
/// criteria such as key ID (`kid`), algorithm, or key use.
///
/// # RFC Compliance
///
/// Per RFC 7517 Section 5:
/// > "Implementations SHOULD ignore JWKs within a JWK Set that use 'kty'
/// > (key type) values that are not understood by them"
///
/// This implementation follows this guidance by silently skipping keys with
/// unknown `kty` values during deserialization rather than failing.
///
/// # Examples
///
/// Parse a JWKS from JSON:
///
/// ```
/// use jwk_simple::KeySet;
///
/// let json = r#"{
///     "keys": [
///         {
///             "kty": "RSA",
///             "kid": "key-1",
///             "use": "sig",
///             "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
///             "e": "AQAB"
///         }
///     ]
/// }"#;
///
/// let jwks: KeySet = serde_json::from_str(json).unwrap();
/// assert_eq!(jwks.len(), 1);
/// ```
///
/// Keys with unknown `kty` values are silently skipped:
///
/// ```
/// use jwk_simple::KeySet;
///
/// let json = r#"{
///     "keys": [
///         {"kty": "UNKNOWN", "data": "ignored"},
///         {"kty": "oct", "k": "AQAB"}
///     ]
/// }"#;
///
/// let jwks: KeySet = serde_json::from_str(json).unwrap();
/// assert_eq!(jwks.len(), 1); // Only the "oct" key is included
/// ```
#[derive(Debug, Clone, Serialize, Default)]
pub struct KeySet {
    /// The collection of keys.
    pub keys: Vec<Key>,
}

impl<'de> Deserialize<'de> for KeySet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Helper struct for raw deserialization
        #[derive(Deserialize)]
        struct RawJwkSet {
            keys: Vec<serde_json::Value>,
        }

        let raw = RawJwkSet::deserialize(deserializer)?;

        // Try to parse each key, silently skipping those with unknown kty values
        // per RFC 7517 Section 5
        let keys: Vec<Key> = raw
            .keys
            .into_iter()
            .filter_map(|value| {
                // Try to deserialize as a Key
                serde_json::from_value::<Key>(value).ok()
            })
            .collect();

        Ok(KeySet { keys })
    }
}

impl KeySet {
    /// Creates a new empty KeySet.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::KeySet;
    ///
    /// let jwks = KeySet::new();
    /// assert!(jwks.is_empty());
    /// ```
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Creates a KeySet from a vector of keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Key};
    ///
    /// let keys = vec![]; // Would contain Key instances
    /// let jwks = KeySet::from_keys(keys);
    /// ```
    pub fn from_keys(keys: Vec<Key>) -> Self {
        Self { keys }
    }
    /// Returns the number of keys in the set.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the set contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Adds a key to the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Key};
    ///
    /// let mut jwks = KeySet::new();
    /// // jwks.add_key(some_jwk);
    /// ```
    pub fn add_key(&mut self, key: Key) {
        self.keys.push(key);
    }

    /// Removes and returns a key by its ID.
    ///
    /// # Arguments
    ///
    /// * `kid` - The key ID to look for.
    ///
    /// # Returns
    ///
    /// The removed key, or `None` if not found.
    pub fn remove_by_kid(&mut self, kid: &str) -> Option<Key> {
        if let Some(pos) = self.keys.iter().position(|k| k.kid.as_deref() == Some(kid)) {
            Some(self.keys.remove(pos))
        } else {
            None
        }
    }

    /// Finds a key by its ID (`kid`).
    ///
    /// # Arguments
    ///
    /// * `kid` - The key ID to look for.
    ///
    /// # Returns
    ///
    /// A reference to the key, or `None` if not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::KeySet;
    ///
    /// let json = r#"{"keys": [{"kty": "oct", "kid": "my-key", "k": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let key = jwks.find_by_kid("my-key");
    /// assert!(key.is_some());
    ///
    /// let missing = jwks.find_by_kid("unknown");
    /// assert!(missing.is_none());
    /// ```
    pub fn find_by_kid(&self, kid: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Finds all keys with the specified algorithm.
    ///
    /// # Arguments
    ///
    /// * `alg` - The algorithm to filter by.
    ///
    /// # Returns
    ///
    /// A vector of references to matching keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Algorithm};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let rs256_keys = jwks.find_by_alg(&Algorithm::Rs256);
    /// assert_eq!(rs256_keys.len(), 1);
    /// ```
    pub fn find_by_alg(&self, alg: &Algorithm) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|k| k.alg.as_ref() == Some(alg))
            .collect()
    }

    /// Finds all keys with the specified key type.
    ///
    /// # Arguments
    ///
    /// * `kty` - The key type to filter by.
    ///
    /// # Returns
    ///
    /// A vector of references to matching keys.
    pub fn find_by_kty(&self, kty: KeyType) -> Vec<&Key> {
        self.keys.iter().filter(|k| k.kty == kty).collect()
    }

    /// Finds all keys with the specified use.
    ///
    /// # Arguments
    ///
    /// * `key_use` - The key use to filter by.
    ///
    /// # Returns
    ///
    /// A vector of references to matching keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, KeyUse};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let signing_keys = jwks.find_by_use(KeyUse::Signature);
    /// assert_eq!(signing_keys.len(), 1);
    /// ```
    pub fn find_by_use(&self, key_use: KeyUse) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|k| k.key_use.as_ref() == Some(&key_use))
            .collect()
    }

    /// Finds all signing keys.
    ///
    /// A key is considered a signing key if:
    /// - It has `use: "sig"`, OR
    /// - It has no `use` specified (default behavior for signature keys)
    ///
    /// # Returns
    ///
    /// A vector of references to signing keys.
    pub fn signing_keys(&self) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|k| k.key_use.is_none() || k.key_use.as_ref() == Some(&KeyUse::Signature))
            .collect()
    }

    /// Finds all encryption keys.
    ///
    /// # Returns
    ///
    /// A vector of references to encryption keys.
    pub fn encryption_keys(&self) -> Vec<&Key> {
        self.keys
            .iter()
            .filter(|k| k.key_use.as_ref() == Some(&KeyUse::Encryption))
            .collect()
    }

    /// Returns the first signing key, if any.
    ///
    /// This is a convenience method for cases where only one signing key is expected.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::KeySet;
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let key = jwks.first_signing_key().expect("expected a signing key");
    /// ```
    pub fn first_signing_key(&self) -> Option<&Key> {
        self.signing_keys().into_iter().next()
    }

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

    /// Returns the first signing key matching the specified algorithm, if any.
    ///
    /// This combines algorithm matching with a signing-key filter: a key matches
    /// if its `alg` field equals the given algorithm AND it is a signing key
    /// (i.e., `use` is `"sig"` or unspecified).
    ///
    /// This is the most common lookup pattern for JWKS consumers that need to
    /// verify JWT signatures.
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
    /// let json = r#"{"keys": [
    ///     {"kty": "RSA", "alg": "RS256", "use": "enc", "n": "AQAB", "e": "AQAB"},
    ///     {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "signing-key", "n": "AQAB", "e": "AQAB"}
    /// ]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let key = jwks.find_signing_key_by_alg(&Algorithm::Rs256);
    /// assert_eq!(key.unwrap().kid.as_deref(), Some("signing-key"));
    /// ```
    pub fn find_signing_key_by_alg(&self, alg: &Algorithm) -> Option<&Key> {
        self.keys.iter().find(|k| {
            k.alg.as_ref() == Some(alg)
                && (k.key_use.is_none() || k.key_use.as_ref() == Some(&KeyUse::Signature))
        })
    }

    /// Returns the first key, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::KeySet;
    ///
    /// let jwks = KeySet::new();
    /// assert!(jwks.first().is_none());
    /// ```
    pub fn first(&self) -> Option<&Key> {
        self.keys.first()
    }

    /// Returns an iterator over the keys.
    pub fn iter(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter()
    }

    /// Validates all keys in the set.
    ///
    /// # Errors
    ///
    /// Returns the first validation error encountered, if any.
    pub fn validate(&self) -> Result<()> {
        for key in &self.keys {
            key.validate()?;
        }
        Ok(())
    }

    /// Finds a key by its JWK thumbprint.
    ///
    /// # Arguments
    ///
    /// * `thumbprint` - The base64url-encoded SHA-256 thumbprint.
    ///
    /// # Returns
    ///
    /// A reference to the key, or `None` if not found.
    pub fn find_by_thumbprint(&self, thumbprint: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.thumbprint() == thumbprint)
    }
}

impl IntoIterator for KeySet {
    type Item = Key;
    type IntoIter = std::vec::IntoIter<Key>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.into_iter()
    }
}

impl<'a> IntoIterator for &'a KeySet {
    type Item = &'a Key;
    type IntoIter = std::slice::Iter<'a, Key>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

impl FromIterator<Key> for KeySet {
    fn from_iter<I: IntoIterator<Item = Key>>(iter: I) -> Self {
        Self {
            keys: iter.into_iter().collect(),
        }
    }
}

impl std::ops::Index<usize> for KeySet {
    type Output = Key;

    fn index(&self, index: usize) -> &Self::Output {
        &self.keys[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JWKS: &str = r#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "rsa-key-1",
                "use": "sig",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            },
            {
                "kty": "EC",
                "kid": "ec-key-1",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            },
            {
                "kty": "RSA",
                "kid": "rsa-enc-1",
                "use": "enc",
                "n": "sXchDaQebSXKcvL0vwlG",
                "e": "AQAB"
            }
        ]
    }"#;

    #[test]
    fn test_parse_jwks() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        assert_eq!(jwks.len(), 3);
    }

    #[test]
    fn test_find_by_kid() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert!(jwks.find_by_kid("rsa-key-1").is_some());
        assert!(jwks.find_by_kid("ec-key-1").is_some());
        assert!(jwks.find_by_kid("unknown").is_none());
    }

    #[test]
    fn test_find_by_alg() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let rs256_keys = jwks.find_by_alg(&Algorithm::Rs256);
        assert_eq!(rs256_keys.len(), 1);

        let es256_keys = jwks.find_by_alg(&Algorithm::Es256);
        assert_eq!(es256_keys.len(), 1);
    }

    #[test]
    fn test_find_by_use() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let sig_keys = jwks.find_by_use(KeyUse::Signature);
        assert_eq!(sig_keys.len(), 2);

        let enc_keys = jwks.find_by_use(KeyUse::Encryption);
        assert_eq!(enc_keys.len(), 1);
    }

    #[test]
    fn test_signing_keys() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let signing = jwks.signing_keys();
        assert_eq!(signing.len(), 2);
    }

    #[test]
    fn test_encryption_keys() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let encryption = jwks.encryption_keys();
        assert_eq!(encryption.len(), 1);
    }

    #[test]
    fn test_first_signing_key() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let first = jwks.first_signing_key().unwrap();
        assert!(first.key_use == Some(KeyUse::Signature) || first.key_use.is_none());
    }

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

    #[test]
    fn test_find_signing_key_by_alg() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-enc", "alg": "RS256", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "rsa-sig", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "ec-sig", "alg": "ES256", "use": "sig", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Should find the signing key, not the encryption key
        let key = jwks.find_signing_key_by_alg(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-sig"));

        // Should find ES256 signing key
        let key = jwks.find_signing_key_by_alg(&Algorithm::Es256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("ec-sig"));

        // No PS512 key exists
        assert!(jwks.find_signing_key_by_alg(&Algorithm::Ps512).is_none());
    }

    #[test]
    fn test_find_signing_key_by_alg_no_use() {
        // Keys without "use" should be treated as signing keys
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-no-use", "alg": "RS256", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let key = jwks.find_signing_key_by_alg(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-no-use"));
    }

    #[test]
    fn test_find_signing_key_by_alg_only_enc() {
        // Only encryption keys — should return None
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-enc", "alg": "RS256", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        assert!(jwks.find_signing_key_by_alg(&Algorithm::Rs256).is_none());
    }

    #[test]
    fn test_empty_jwks() {
        let jwks = KeySet::new();
        assert!(jwks.is_empty());
        assert_eq!(jwks.len(), 0);
        assert!(jwks.first().is_none());
        assert!(jwks.first_signing_key().is_none());
    }

    #[test]
    fn test_serde_roundtrip() {
        let original: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: KeySet = serde_json::from_str(&json).unwrap();
        assert_eq!(original.len(), parsed.len());
    }

    #[test]
    fn test_iterator() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let count = jwks.iter().count();
        assert_eq!(count, 3);

        let kids: Vec<_> = jwks.iter().filter_map(|k| k.kid.as_deref()).collect();
        assert!(kids.contains(&"rsa-key-1"));
    }

    #[test]
    fn test_from_iterator() {
        let keys = vec![];
        let jwks: KeySet = keys.into_iter().collect();
        assert!(jwks.is_empty());
    }

    #[test]
    fn test_index() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let first = &jwks[0];
        assert_eq!(first.kid, Some("rsa-key-1".to_string()));
    }

    #[tokio::test]
    async fn test_jwkset_implements_source() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let source: KeySet = serde_json::from_str(json).unwrap();

        // Test get_key
        let key = source.get_key("test-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, Some("test-key".to_string()));

        // Test missing key
        let missing = source.get_key("nonexistent").await.unwrap();
        assert!(missing.is_none());

        // Test get_keyset
        let keyset = source.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 1);
    }
}

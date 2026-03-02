//! JSON Web Key Set (JWKS) as defined in RFC 7517 Section 5.
//!
//! A JWKS is a collection of JWK objects, typically used for key distribution
//! and discovery. This module also defines the [`KeyStore`] trait, which abstracts
//! over different sources of JWK keys.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::Result;
use crate::jwk::{Algorithm, Key, KeyOperation, KeyType, KeyUse};

mod cache;
#[cfg(all(feature = "cloudflare", target_arch = "wasm32"))]
pub mod cloudflare;
#[cfg(feature = "cache-inmemory")]
mod inmemory_cache;
#[cfg(feature = "http")]
mod remote;

pub use cache::{CachedKeyStore, KeyCache};
#[cfg(feature = "cache-inmemory")]
pub use inmemory_cache::{DEFAULT_CACHE_TTL, InMemoryCachedKeyStore, InMemoryKeyCache};
#[cfg(feature = "http")]
pub use remote::{DEFAULT_TIMEOUT, RemoteKeyStore};

/// A trait for types that can provide JWK keys.
///
/// This trait abstracts over different sources of keys, whether from
/// a static set, a remote HTTP endpoint, or a cached source.
///
/// The only required method is [`get_keyset`](KeyStore::get_keyset), which returns
/// the full key set. A default implementation of [`get_key`](KeyStore::get_key) is
/// provided that fetches the full set and looks up by key ID.
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
/// use jwk_simple::{KeyStore, KeySet};
///
/// # async fn example() -> jwk_simple::Result<()> {
/// let store: KeySet = serde_json::from_str(r#"{"keys": []}"#)?;
/// let key = store.get_key("some-kid").await?;
/// # Ok(())
/// # }
/// ```
///
/// Generic code that works with any store:
///
/// ```ignore
/// async fn verify_token<S: KeyStore>(store: &S, kid: &str) -> Result<()> {
///     let key = store.get_key(kid).await?
///         .ok_or_else(|| Error::Other("key not found".into()))?;
///     // ... verify with key
///     Ok(())
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeyStore {
    /// Gets all available keys as a [`KeySet`].
    ///
    /// For remote sources, this may trigger a fetch if the cache is empty or expired.
    async fn get_keyset(&self) -> Result<KeySet>;

    /// Gets a key by its key ID (`kid`).
    ///
    /// Returns `Ok(None)` if no key with the given ID exists.
    /// Returns `Err` if the lookup failed (e.g., network error for remote sources).
    ///
    /// The default implementation fetches the full key set and looks up by key ID.
    /// Implementations may override this for more efficient lookups (e.g., caching).
    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        Ok(self.get_keyset().await?.find_by_kid(kid).cloned())
    }
}

// Implement KeyStore for KeySet (static, immediate)
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyStore for KeySet {
    async fn get_keyset(&self) -> Result<KeySet> {
        Ok(self.clone())
    }

    async fn get_key(&self, kid: &str) -> Result<Option<Key>> {
        Ok(self.find_by_kid(kid).cloned())
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
/// > (key type) values that are not understood by them, that are missing
/// > required members, or for which values are out of the supported ranges."
///
/// This implementation follows this guidance by silently skipping keys with
/// unknown `kty` values, missing required members, or invalid parameter
/// values during deserialization rather than failing.
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
/// Keys that cannot be parsed are silently skipped:
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
    keys: Vec<Key>,
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

        // Parse each key, silently skipping those that cannot be understood
        // per RFC 7517 Section 5: "Implementations SHOULD ignore JWKs within
        // a JWK Set that use 'kty' (key type) values that are not understood
        // by them, that are missing required members, or for which values are
        // out of the supported ranges."
        let mut keys = Vec::with_capacity(raw.keys.len());
        for value in raw.keys {
            // Attempt to parse each key; skip any that fail.
            // This covers unknown/missing kty values, missing required fields,
            // invalid base64url, and other parse errors per RFC 7517 Section 5.
            if let Ok(key) = serde_json::from_value::<Key>(value) {
                keys.push(key);
            }
        }

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

    /// Returns a slice of all keys in the set.
    pub fn keys(&self) -> &[Key] {
        &self.keys
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
    pub fn remove_by_kid(&mut self, kid: &str) -> Option<Key> {
        if let Some(pos) = self.keys.iter().position(|k| k.kid.as_deref() == Some(kid)) {
            Some(self.keys.remove(pos))
        } else {
            None
        }
    }

    /// Finds a key by its ID (`kid`).
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
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Algorithm};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let rs256_keys: Vec<_> = jwks.find_by_alg(&Algorithm::Rs256).collect();
    /// assert_eq!(rs256_keys.len(), 1);
    /// ```
    pub fn find_by_alg<'a>(&'a self, alg: &'a Algorithm) -> impl Iterator<Item = &'a Key> {
        self.keys
            .iter()
            .filter(move |k| k.alg.as_ref() == Some(alg))
    }

    /// Finds all keys with the specified key type.
    pub fn find_by_kty(&self, kty: KeyType) -> impl Iterator<Item = &Key> {
        self.keys.iter().filter(move |k| k.kty() == kty)
    }

    /// Finds all keys with the specified use.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, KeyUse};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "use": "sig", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let signing_keys: Vec<_> = jwks.find_by_use(KeyUse::Signature).collect();
    /// assert_eq!(signing_keys.len(), 1);
    /// ```
    pub fn find_by_use(&self, key_use: KeyUse) -> impl Iterator<Item = &Key> {
        self.keys
            .iter()
            .filter(move |k| k.key_use.as_ref() == Some(&key_use))
    }

    /// Finds all signing keys.
    ///
    /// A key is considered a signing key if:
    /// - It has `key_ops` containing `sign` or `verify`, OR (when `key_ops` is absent)
    /// - It has `use: "sig"`, OR
    /// - It has neither `use` nor `key_ops` specified
    pub fn signing_keys(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter().filter(|k| is_signing_key(k))
    }

    /// Finds all encryption keys.
    ///
    /// A key is considered an encryption key if:
    /// - It has `key_ops` containing `encrypt`, `decrypt`, `wrapKey`, or `unwrapKey`,
    ///   OR (when `key_ops` is absent)
    /// - It has `use: "enc"`
    pub fn encryption_keys(&self) -> impl Iterator<Item = &Key> {
        self.keys.iter().filter(|k| is_encryption_key(k))
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
        self.signing_keys().next()
    }

    /// Returns the first key matching the specified algorithm, if any.
    ///
    /// This is a convenience method that returns a single key instead of the
    /// vector returned by [`find_by_alg`].
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

    /// Finds all keys compatible with the specified algorithm.
    ///
    /// Unlike [`find_by_alg`](KeySet::find_by_alg), which only matches keys whose `alg`
    /// field is explicitly set to the given algorithm, this method uses
    /// [`Key::is_algorithm_compatible`] to check whether the key's type (and curve,
    /// where applicable) is compatible with the algorithm. This catches keys that
    /// don't have an `alg` field set, which is common in real-world JWKS endpoints.
    ///
    /// A key is considered compatible if:
    /// - Its `alg` field matches the given algorithm, OR
    /// - Its `alg` field is not set and its key type/curve is compatible
    ///
    /// Keys whose `alg` field is set to a *different* algorithm are excluded,
    /// even if the key type would otherwise be compatible.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Algorithm};
    ///
    /// // This RSA key has no "alg" field, so find_by_alg would miss it
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// assert_eq!(jwks.find_by_alg(&Algorithm::Rs256).count(), 0);
    /// assert_eq!(jwks.find_compatible(&Algorithm::Rs256).count(), 1);
    /// ```
    pub fn find_compatible<'a>(&'a self, alg: &'a Algorithm) -> impl Iterator<Item = &'a Key> {
        self.keys.iter().filter(move |k| match &k.alg {
            Some(key_alg) => key_alg == alg,
            None => k.is_algorithm_compatible(alg),
        })
    }

    /// Returns the first key compatible with the specified algorithm, if any.
    ///
    /// This is a convenience method that returns a single key from
    /// [`find_compatible`](KeySet::find_compatible).
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Algorithm};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// // find_first_by_alg misses keys without an explicit "alg" field
    /// assert!(jwks.find_first_by_alg(&Algorithm::Rs256).is_none());
    /// // find_first_compatible finds them
    /// assert!(jwks.find_first_compatible(&Algorithm::Rs256).is_some());
    /// ```
    pub fn find_first_compatible<'a>(&'a self, alg: &'a Algorithm) -> Option<&'a Key> {
        self.find_compatible(alg).next()
    }

    /// Returns the first signing key compatible with the specified algorithm, if any.
    ///
    /// This combines compatibility matching with a signing-key filter: a key matches
    /// if it is compatible with the given algorithm (by key type/curve, not just the
    /// `alg` field) AND it is a signing key (i.e., `use` is `"sig"` or unspecified).
    ///
    /// This is the recommended lookup method for JWKS consumers that need to
    /// verify JWT signatures, as it handles keys both with and without an explicit
    /// `alg` field.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{KeySet, Algorithm};
    ///
    /// let json = r#"{"keys": [
    ///     {"kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB"},
    ///     {"kty": "RSA", "use": "sig", "kid": "signing-key", "n": "AQAB", "e": "AQAB"}
    /// ]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let key = jwks.find_compatible_signing_key(&Algorithm::Rs256);
    /// assert_eq!(key.unwrap().kid.as_deref(), Some("signing-key"));
    /// ```
    pub fn find_compatible_signing_key<'a>(&'a self, alg: &'a Algorithm) -> Option<&'a Key> {
        self.find_compatible(alg).find(|k| is_signing_key(k))
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
        self.keys
            .iter()
            .find(|k| k.alg.as_ref() == Some(alg) && is_signing_key(k))
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

    /// Finds a key by its JWK thumbprint (RFC 7638).
    ///
    /// # Performance
    ///
    /// This method computes the SHA-256 thumbprint of each key in the set on
    /// every call, making it O(n) hash computations per lookup. For hot paths
    /// (e.g., verifying JWTs in a web server), consider caching thumbprints
    /// externally or using [`find_by_kid`](KeySet::find_by_kid) instead.
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

impl Extend<Key> for KeySet {
    fn extend<I: IntoIterator<Item = Key>>(&mut self, iter: I) {
        self.keys.extend(iter);
    }
}

impl std::ops::Index<usize> for KeySet {
    type Output = Key;

    fn index(&self, index: usize) -> &Self::Output {
        &self.keys[index]
    }
}

/// Checks whether a key is suitable for signing/verification operations.
///
/// When `key_ops` is present it is treated as authoritative: the key must
/// include [`KeyOperation::Sign`] or [`KeyOperation::Verify`].
/// When `key_ops` is absent, `key_use` is consulted: the key is a signing
/// key if `use` is `"sig"` or unset.
fn is_signing_key(key: &Key) -> bool {
    if let Some(ref ops) = key.key_ops {
        ops.contains(&KeyOperation::Sign) || ops.contains(&KeyOperation::Verify)
    } else {
        key.key_use.is_none() || key.key_use.as_ref() == Some(&KeyUse::Signature)
    }
}

/// Checks whether a key is suitable for encryption operations.
///
/// When `key_ops` is present it is treated as authoritative: the key must
/// include [`KeyOperation::Encrypt`], [`KeyOperation::Decrypt`],
/// [`KeyOperation::WrapKey`], or [`KeyOperation::UnwrapKey`].
/// When `key_ops` is absent, `key_use` is consulted: the key is an
/// encryption key if `use` is `"enc"`.
fn is_encryption_key(key: &Key) -> bool {
    if let Some(ref ops) = key.key_ops {
        ops.contains(&KeyOperation::Encrypt)
            || ops.contains(&KeyOperation::Decrypt)
            || ops.contains(&KeyOperation::WrapKey)
            || ops.contains(&KeyOperation::UnwrapKey)
    } else {
        key.key_use.as_ref() == Some(&KeyUse::Encryption)
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

        assert_eq!(jwks.find_by_alg(&Algorithm::Rs256).count(), 1);
        assert_eq!(jwks.find_by_alg(&Algorithm::Es256).count(), 1);
    }

    #[test]
    fn test_find_by_use() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert_eq!(jwks.find_by_use(KeyUse::Signature).count(), 2);
        assert_eq!(jwks.find_by_use(KeyUse::Encryption).count(), 1);
    }

    #[test]
    fn test_signing_keys() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert_eq!(jwks.signing_keys().count(), 2);
    }

    #[test]
    fn test_encryption_keys() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert_eq!(jwks.encryption_keys().count(), 1);
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
    fn test_find_compatible_with_alg_set() {
        let json = r#"{"keys": [
            {"kty": "RSA", "alg": "RS256", "kid": "with-alg", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "alg": "ES256", "kid": "ec-key", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Keys with matching alg are found
        assert_eq!(jwks.find_compatible(&Algorithm::Rs256).count(), 1);
        assert_eq!(jwks.find_compatible(&Algorithm::Es256).count(), 1);

        // RSA key with alg=RS256 should NOT match RS384 (alg mismatch)
        assert_eq!(jwks.find_compatible(&Algorithm::Rs384).count(), 0);
    }

    #[test]
    fn test_find_compatible_without_alg() {
        // Keys without "alg" field — should match by key type/curve
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-no-alg", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "kid": "ec-no-alg", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // find_by_alg misses keys without alg
        assert_eq!(jwks.find_by_alg(&Algorithm::Rs256).count(), 0);
        // find_compatible finds them by type
        assert_eq!(jwks.find_compatible(&Algorithm::Rs256).count(), 1);
        assert_eq!(jwks.find_compatible(&Algorithm::Ps256).count(), 1); // RSA is also PS-compatible
        assert_eq!(jwks.find_compatible(&Algorithm::Es256).count(), 1);

        // EC P-256 key should NOT match ES384 (wrong curve)
        assert_eq!(jwks.find_compatible(&Algorithm::Es384).count(), 0);
    }

    #[test]
    fn test_find_first_compatible() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-no-alg", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // find_first_by_alg misses keys without alg
        assert!(jwks.find_first_by_alg(&Algorithm::Rs256).is_none());
        // find_first_compatible finds them
        let key = jwks.find_first_compatible(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-no-alg"));
    }

    #[test]
    fn test_find_compatible_signing_key() {
        let json = r#"{"keys": [
            {"kty": "RSA", "use": "enc", "kid": "rsa-enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "rsa-no-use", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Should find the first signing-compatible RSA key (skipping enc)
        let key = jwks.find_compatible_signing_key(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-sig"));

        // No ES256-compatible keys at all
        assert!(
            jwks.find_compatible_signing_key(&Algorithm::Es256)
                .is_none()
        );
    }

    #[test]
    fn test_find_compatible_signing_key_no_use() {
        // Key without "use" should be treated as signing key
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa-no-use", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let key = jwks.find_compatible_signing_key(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("rsa-no-use"));
    }

    #[test]
    fn test_signing_keys_respects_key_ops_verify() {
        // A key with key_ops=["verify"] should be considered a signing key
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "verify-key", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        assert_eq!(jwks.signing_keys().count(), 1);
    }

    #[test]
    fn test_signing_keys_respects_key_ops_sign() {
        // A key with key_ops=["sign"] should be considered a signing key
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "sign-key", "key_ops": ["sign"], "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        assert_eq!(jwks.signing_keys().count(), 1);
    }

    #[test]
    fn test_signing_keys_excludes_encrypt_key_ops() {
        // A key with key_ops=["encrypt"] should NOT be considered a signing key
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "enc-key", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        assert_eq!(jwks.signing_keys().count(), 0);
    }

    #[test]
    fn test_find_signing_key_by_alg_respects_key_ops() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "enc-key", "alg": "RS256", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "verify-key", "alg": "RS256", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Should skip the encrypt-only key and find the verify key
        let key = jwks.find_signing_key_by_alg(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("verify-key"));
    }

    #[test]
    fn test_find_compatible_signing_key_respects_key_ops() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "enc-key", "key_ops": ["encrypt"], "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "verify-key", "key_ops": ["verify"], "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Should skip the encrypt-only key and find the verify key
        let key = jwks.find_compatible_signing_key(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("verify-key"));
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
    fn test_index() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let first = &jwks[0];
        assert_eq!(first.kid, Some("rsa-key-1".to_string()));
    }

    #[test]
    fn test_add_key() {
        let mut jwks = KeySet::new();
        assert!(jwks.is_empty());

        let key: Key = serde_json::from_str(r#"{"kty":"oct","kid":"k1","k":"AQAB"}"#).unwrap();
        jwks.add_key(key);
        assert_eq!(jwks.len(), 1);
        assert!(jwks.find_by_kid("k1").is_some());
    }

    #[test]
    fn test_remove_by_kid() {
        let mut jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        assert_eq!(jwks.len(), 3);

        let removed = jwks.remove_by_kid("ec-key-1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().kid.as_deref(), Some("ec-key-1"));
        assert_eq!(jwks.len(), 2);
        assert!(jwks.find_by_kid("ec-key-1").is_none());

        // Removing non-existent kid returns None
        assert!(jwks.remove_by_kid("nonexistent").is_none());
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn test_find_by_kty() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert_eq!(jwks.find_by_kty(KeyType::Rsa).count(), 2);
        assert_eq!(jwks.find_by_kty(KeyType::Ec).count(), 1);
        assert_eq!(jwks.find_by_kty(KeyType::Okp).count(), 0);
        assert_eq!(jwks.find_by_kty(KeyType::Symmetric).count(), 0);
    }

    #[tokio::test]
    async fn test_jwkset_implements_store() {
        let json = r#"{"keys": [{"kty": "oct", "kid": "test-key", "k": "AQAB"}]}"#;
        let store: KeySet = serde_json::from_str(json).unwrap();

        // Test get_key
        let key = store.get_key("test-key").await.unwrap();
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, Some("test-key".to_string()));

        // Test missing key
        let missing = store.get_key("nonexistent").await.unwrap();
        assert!(missing.is_none());

        // Test get_keyset
        let keyset = store.get_keyset().await.unwrap();
        assert_eq!(keyset.len(), 1);
    }
}

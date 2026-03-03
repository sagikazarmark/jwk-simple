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
mod store;

#[cfg(all(feature = "moka", not(target_arch = "wasm32")))]
pub use cache::moka::{DEFAULT_MOKA_CACHE_TTL, MokaKeyCache};
pub use cache::{CachedKeyStore, KeyCache};

#[cfg(feature = "http")]
pub use store::http::HttpKeyStore;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use store::http::DEFAULT_TIMEOUT;

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
/// use jwk_simple::KeySet;
/// use jwk_simple::jwks::KeyStore;
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
/// unknown `kty` values, missing required members, or invalid key parameter
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

/// Diagnostics for permissive JWKS parsing.
///
/// When parsing via [`KeySet::from_json_with_diagnostics`], keys that fail to
/// parse or key-parameter validation are skipped (per RFC 7517 guidance) and summarized here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySetParseDiagnostics {
    /// Number of keys skipped due to parse errors.
    pub skipped_keys: usize,
    /// Human-readable parse errors for skipped keys.
    pub skipped_errors: Vec<String>,
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
            // Attempt to parse each key, then validate key parameters.
            // Skip any key that fails either phase.
            if let Ok(key) = serde_json::from_value::<Key>(value)
                && key.params.validate().is_ok()
            {
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

    /// Parses a JWKS JSON document and returns parse diagnostics for skipped keys.
    ///
    /// This behaves like normal [`serde_json`] parsing for top-level structure
    /// errors (e.g. invalid JSON or missing `keys` member), but preserves the
    /// RFC 7517 Section 5 behavior of ignoring malformed individual JWK entries.
    pub fn from_json_with_diagnostics(json: &str) -> Result<(Self, KeySetParseDiagnostics)> {
        #[derive(Deserialize)]
        struct RawJwkSet {
            keys: Vec<serde_json::Value>,
        }

        let raw: RawJwkSet = serde_json::from_str(json)?;

        let mut keys = Vec::with_capacity(raw.keys.len());
        let mut diagnostics = KeySetParseDiagnostics::default();

        for value in raw.keys {
            match serde_json::from_value::<Key>(value) {
                Ok(key) => {
                    if let Err(err) = key.params.validate() {
                        diagnostics.skipped_keys += 1;
                        diagnostics.skipped_errors.push(err.to_string());
                    } else {
                        keys.push(key);
                    }
                }
                Err(err) => {
                    diagnostics.skipped_keys += 1;
                    diagnostics.skipped_errors.push(err.to_string());
                }
            }
        }

        Ok((Self { keys }, diagnostics))
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
    /// use jwk_simple::KeySet;
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
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let rs256_keys: Vec<_> = jwks.find_by_alg(&Algorithm::Rs256).collect();
    /// assert_eq!(rs256_keys.len(), 1);
    /// ```
    pub fn find_by_alg<'a>(&'a self, alg: &Algorithm) -> impl Iterator<Item = &'a Key> + 'a {
        let alg = alg.clone();
        self.keys
            .iter()
            .filter(move |k| k.alg.as_ref() == Some(&alg))
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
    /// use jwk_simple::{KeyUse, KeySet};
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
    /// iterator returned by [`KeySet::find_by_alg`].
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Algorithm, KeySet};
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
    /// - For known algorithms: its `alg` field matches and its key type/curve is compatible, OR
    ///   its `alg` field is not set and its key type/curve is compatible
    /// - For unknown/private algorithms: its `alg` field exactly matches the given algorithm
    ///   (keys without `alg` are not included)
    ///
    /// Keys whose `alg` field is set to a *different* algorithm are excluded,
    /// even if the key type would otherwise be compatible.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// // This RSA key has no "alg" field, so find_by_alg would miss it
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// assert_eq!(jwks.find_by_alg(&Algorithm::Rs256).count(), 0);
    /// assert_eq!(jwks.find_compatible(&Algorithm::Rs256).count(), 1);
    /// ```
    pub fn find_compatible<'a>(&'a self, alg: &Algorithm) -> impl Iterator<Item = &'a Key> + 'a {
        let alg = alg.clone();
        let is_unknown_alg = alg.is_unknown();
        self.keys.iter().filter(move |k| match &k.alg {
            Some(key_alg) => key_alg == &alg && (is_unknown_alg || k.is_algorithm_compatible(&alg)),
            None => !is_unknown_alg && k.is_algorithm_compatible(&alg),
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
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// // find_first_by_alg misses keys without an explicit "alg" field
    /// assert!(jwks.find_first_by_alg(&Algorithm::Rs256).is_none());
    /// // find_first_compatible finds them
    /// assert!(jwks.find_first_compatible(&Algorithm::Rs256).is_some());
    /// ```
    pub fn find_first_compatible<'a>(&'a self, alg: &Algorithm) -> Option<&'a Key> {
        self.find_compatible(alg).next()
    }

    /// Returns the first signing key compatible with the specified algorithm, if any.
    ///
    /// This combines compatibility matching with a signing-key filter: a key matches
    /// if it is compatible with the given algorithm (by key type/curve, not just the
    /// `alg` field) AND it is a signing key.
    ///
    /// Signing-key determination is:
    /// - if `key_ops` is present, it must contain `sign` or `verify`
    /// - otherwise, `use` must be `"sig"` or unspecified
    ///
    /// This is the recommended lookup method for JWKS consumers that need to
    /// verify JWT signatures, as it handles keys both with and without an explicit
    /// `alg` field.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Algorithm, KeySet};
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
    pub fn find_compatible_signing_key<'a>(&'a self, alg: &Algorithm) -> Option<&'a Key> {
        self.find_compatible(alg).find(|k| is_signing_key(k))
    }

    /// Returns the first signing key matching the specified algorithm, if any.
    ///
    /// This combines algorithm matching with a signing-key filter: a key matches
    /// if its `alg` field equals the given algorithm, and it is a signing key.
    /// For known algorithms, key type/curve compatibility is also required;
    /// for unknown/private algorithms, exact `alg` equality is treated as compatible.
    /// Signing-key determination follows the same rules as
    /// [`signing_keys`](KeySet::signing_keys):
    /// - if `key_ops` is present, it must contain `sign` or `verify`
    /// - otherwise, `use` must be `"sig"` or unspecified
    ///
    /// Use this when you require strict `alg` equality on keys.
    /// For JWT verification against real-world JWKS (where `alg` may be absent),
    /// prefer [`find_compatible_signing_key`](KeySet::find_compatible_signing_key).
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Algorithm, KeySet};
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
        let is_unknown_alg = alg.is_unknown();
        self.keys.iter().find(|k| {
            k.alg.as_ref() == Some(alg)
                && (is_unknown_alg || k.is_algorithm_compatible(alg))
                && is_signing_key(k)
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

impl From<Vec<Key>> for KeySet {
    fn from(keys: Vec<Key>) -> Self {
        Self { keys }
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
    fn test_parse_with_diagnostics_reports_skipped_keys() {
        let json = r#"{
            "keys": [
                {"kty": "UNKNOWN", "data": "ignored"},
                {"kty": "oct", "k": "AQAB"}
            ]
        }"#;

        let (jwks, diagnostics) = KeySet::from_json_with_diagnostics(json).unwrap();
        assert_eq!(jwks.len(), 1);
        assert_eq!(diagnostics.skipped_keys, 1);
        assert_eq!(diagnostics.skipped_errors.len(), 1);
    }

    #[test]
    fn test_parse_skips_semantically_invalid_key() {
        let json = r#"{
            "keys": [
                {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ", "kid": "bad"},
                {"kty": "oct", "k": "AQAB", "kid": "good"}
            ]
        }"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.len(), 1);
        assert!(jwks.find_by_kid("bad").is_none());
        assert!(jwks.find_by_kid("good").is_some());
    }

    #[test]
    fn test_parse_with_diagnostics_reports_validation_failures() {
        let json = r#"{
            "keys": [
                {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ", "kid": "bad"},
                {"kty": "oct", "k": "AQAB", "kid": "good"}
            ]
        }"#;

        let (jwks, diagnostics) = KeySet::from_json_with_diagnostics(json).unwrap();
        assert_eq!(jwks.len(), 1);
        assert_eq!(diagnostics.skipped_keys, 1);
        assert_eq!(diagnostics.skipped_errors.len(), 1);
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
        assert_eq!(first.kid.as_deref(), Some("rsa-key-1"));
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
    fn test_find_compatible_with_alg_set_rejects_incompatible_key_type() {
        let json = r#"{"keys": [
            {"kty": "oct", "alg": "RS256", "kid": "bad-oct", "k": "AQAB"},
            {"kty": "RSA", "alg": "RS256", "kid": "good-rsa", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let matching: Vec<&Key> = jwks.find_compatible(&Algorithm::Rs256).collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].kid.as_deref(), Some("good-rsa"));
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
    fn test_find_signing_key_by_alg_rejects_incompatible_key_type() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "bad-oct", "alg": "RS256", "use": "sig", "k": "AQAB"},
            {"kty": "RSA", "kid": "good-rsa", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let key = jwks.find_signing_key_by_alg(&Algorithm::Rs256);
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("good-rsa"));
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
    fn test_rfc9864_alg_lookup_behavior() {
        let json = r#"{"keys": [
            {"kty": "OKP", "kid": "ed25519-key", "use": "sig", "alg": "Ed25519", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
            {"kty": "OKP", "kid": "legacy-eddsa", "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        // Strict alg matching only finds exact matches.
        assert_eq!(jwks.find_by_alg(&Algorithm::Ed25519).count(), 1);
        assert_eq!(jwks.find_by_alg(&Algorithm::EdDsa).count(), 1);

        // Compatibility matching also requires exact alg when `alg` is set.
        assert_eq!(jwks.find_compatible(&Algorithm::Ed25519).count(), 1);
        assert_eq!(jwks.find_compatible(&Algorithm::EdDsa).count(), 1);

        assert_eq!(
            jwks.find_signing_key_by_alg(&Algorithm::Ed25519)
                .unwrap()
                .kid
                .as_deref(),
            Some("ed25519-key")
        );
        assert_eq!(
            jwks.find_signing_key_by_alg(&Algorithm::EdDsa)
                .unwrap()
                .kid
                .as_deref(),
            Some("legacy-eddsa")
        );
    }

    #[test]
    fn test_find_compatible_unknown_alg_matches_only_exact_alg() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "custom-1", "alg": "CUSTOM", "k": "AQAB"},
            {"kty": "RSA", "kid": "custom-2", "alg": "CUSTOM", "n": "AQAB", "e": "AQAB"},
            {"kty": "oct", "kid": "other", "alg": "OTHER", "k": "AQAB"},
            {"kty": "oct", "kid": "no-alg", "k": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let custom = Algorithm::Unknown("CUSTOM".to_string());
        let matching: Vec<_> = jwks.find_compatible(&custom).collect();

        assert_eq!(matching.len(), 2);
        assert_eq!(matching[0].kid.as_deref(), Some("custom-1"));
        assert_eq!(matching[1].kid.as_deref(), Some("custom-2"));
    }

    #[test]
    fn test_find_signing_key_by_alg_unknown_alg_preserves_exact_match() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "custom-enc", "alg": "CUSTOM", "use": "enc", "k": "AQAB"},
            {"kty": "oct", "kid": "custom-sig", "alg": "CUSTOM", "use": "sig", "k": "AQAB"},
            {"kty": "RSA", "kid": "other-sig", "alg": "OTHER", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let custom = Algorithm::Unknown("CUSTOM".to_string());
        let key = jwks.find_signing_key_by_alg(&custom);

        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_deref(), Some("custom-sig"));
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
        assert_eq!(original.keys(), parsed.keys());
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

    #[cfg(not(target_arch = "wasm32"))]
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

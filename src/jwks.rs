//! JSON Web Key Set (JWKS) as defined in RFC 7517 Section 5.
//!
//! A JWKS is a collection of JWK objects, typically used for key distribution
//! and discovery. This module also defines the [`KeyStore`] trait, which abstracts
//! over different sources of JWK keys.

use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result, ValidationError};
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

/// Errors returned by strict key selection.
#[derive(Debug)]
#[non_exhaustive]
pub enum SelectionError {
    /// Verification selection was requested without a configured allowlist.
    EmptyVerifyAllowlist,
    /// The requested algorithm is unknown/private and strict selection rejects it.
    UnknownAlgorithm,
    /// The requested verification algorithm is not permitted by the allowlist.
    AlgorithmNotAllowed,
    /// The requested algorithm conflicts with a key's declared `alg` value.
    AlgorithmMismatch {
        /// Algorithm requested by the caller.
        requested: Algorithm,
        /// Algorithm declared on the matching key.
        declared: Algorithm,
    },
    /// Key metadata (`use` / `key_ops`) does not permit the requested operation.
    IntentMismatch,
    /// Key material type/curve is incompatible with the requested algorithm.
    IncompatibleKeyType,
    /// Key failed algorithm-specific validation (strength/parameter constraints).
    KeyValidationFailed(ValidationError),
    /// More than one key satisfies strict selection criteria.
    AmbiguousSelection {
        /// Number of matched keys.
        count: usize,
    },
    /// No key satisfies strict selection criteria.
    NoMatchingKey,
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionError::EmptyVerifyAllowlist => {
                write!(f, "verification allowlist is empty")
            }
            SelectionError::UnknownAlgorithm => write!(f, "unknown or unsupported algorithm"),
            SelectionError::AlgorithmNotAllowed => {
                write!(f, "algorithm is not allowed for verification")
            }
            SelectionError::AlgorithmMismatch {
                requested,
                declared,
            } => write!(
                f,
                "algorithm mismatch: requested {}, key declares {}",
                requested, declared
            ),
            SelectionError::IntentMismatch => {
                write!(f, "key metadata does not permit requested operation")
            }
            SelectionError::IncompatibleKeyType => {
                write!(f, "key type/curve is incompatible with requested algorithm")
            }
            SelectionError::KeyValidationFailed(e) => {
                write!(f, "key validation failed: {}", e)
            }
            SelectionError::AmbiguousSelection { count } => {
                write!(f, "selection is ambiguous: {} matching keys", count)
            }
            SelectionError::NoMatchingKey => write!(f, "no matching key found"),
        }
    }
}

impl std::error::Error for SelectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SelectionError::KeyValidationFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Strict selection request criteria.
#[derive(Debug, Clone)]
pub struct KeyMatcher<'a> {
    /// Requested cryptographic operation.
    op: KeyOperation,
    /// Requested JOSE algorithm.
    alg: Algorithm,
    /// Optional key identifier (`kid`) constraint.
    kid: Option<&'a str>,
}

impl<'a> KeyMatcher<'a> {
    /// Creates strict selection criteria for an operation and algorithm.
    pub fn new(op: KeyOperation, alg: Algorithm) -> Self {
        Self { op, alg, kid: None }
    }

    /// Adds a key identifier (`kid`) constraint.
    pub fn with_kid(mut self, kid: &'a str) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Adds an optional key identifier (`kid`) constraint.
    pub fn with_optional_kid(mut self, kid: Option<&'a str>) -> Self {
        self.kid = kid;
        self
    }
}

/// Discovery filter criteria.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KeyFilter<'a> {
    /// Optional operation-intent filter.
    pub op: Option<KeyOperation>,
    /// Optional algorithm filter (exact `alg` match only).
    pub alg: Option<Algorithm>,
    /// Optional key identifier filter.
    pub kid: Option<&'a str>,
    /// Optional key-type filter.
    pub kty: Option<KeyType>,
    /// Optional key-use filter.
    pub key_use: Option<KeyUse>,
}

impl<'a> KeyFilter<'a> {
    /// Creates an empty discovery filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an operation filter.
    pub fn with_op(mut self, op: KeyOperation) -> Self {
        self.op = Some(op);
        self
    }

    /// Adds an exact algorithm filter.
    pub fn with_alg(mut self, alg: Algorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Adds a key identifier (`kid`) filter.
    pub fn with_kid(mut self, kid: &'a str) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Adds an optional key identifier (`kid`) filter.
    pub fn with_optional_kid(mut self, kid: Option<&'a str>) -> Self {
        self.kid = kid;
        self
    }

    /// Adds a key type filter.
    pub fn with_kty(mut self, kty: KeyType) -> Self {
        self.kty = Some(kty);
        self
    }

    /// Adds a key use filter.
    pub fn with_key_use(mut self, key_use: KeyUse) -> Self {
        self.key_use = Some(key_use);
        self
    }
}

/// Policy-bound strict selector for a [`KeySet`].
#[derive(Debug, Clone)]
pub struct KeySelector<'a> {
    /// Backing key set used for selection.
    keyset: &'a KeySet,
    /// Allowed algorithms for verification operations.
    allowed_verify_algs: Vec<Algorithm>,
}

impl<'a> KeySelector<'a> {
    /// Selects exactly one key using strict cryptographic suitability checks.
    ///
    /// When `kid` is present in the matcher, candidate-level validation failures are
    /// surfaced with specific diagnostics (`AlgorithmMismatch`, `IntentMismatch`,
    /// `KeyValidationFailed`, `IncompatibleKeyType`) using deterministic precedence.
    ///
    /// When `kid` is not present, candidates that fail per-key checks are skipped and
    /// selection resolves by surviving cardinality (`AmbiguousSelection` / `NoMatchingKey`).
    ///
    /// Error precedence is deterministic:
    /// 1. `UnknownAlgorithm`
    /// 2. `EmptyVerifyAllowlist` / `AlgorithmNotAllowed` (verify only)
    /// 3. Candidate evaluation
    /// 4. If no candidate survives: `AlgorithmMismatch` -> `IntentMismatch`
    ///    -> `KeyValidationFailed` -> `IncompatibleKeyType` -> `NoMatchingKey`
    /// 5. If multiple candidates survive: `AmbiguousSelection`
    ///
    /// If `kid` is omitted and selection returns `NoMatchingKey`, use
    /// [`KeySet::find`] for discovery diagnostics to inspect broad candidates.
    pub fn select(&self, matcher: KeyMatcher<'_>) -> std::result::Result<&'a Key, SelectionError> {
        if matcher.alg.is_unknown() {
            return Err(SelectionError::UnknownAlgorithm);
        }

        if matcher.op == KeyOperation::Verify {
            if self.allowed_verify_algs.is_empty() {
                return Err(SelectionError::EmptyVerifyAllowlist);
            }

            if !self.allowed_verify_algs.contains(&matcher.alg) {
                return Err(SelectionError::AlgorithmNotAllowed);
            }
        }

        let mut candidates = Vec::new();
        let mut incompatible_for_known_kid = false;
        let mut saw_alg_mismatch: Option<(Algorithm, Algorithm)> = None;
        let mut saw_intent_mismatch = false;
        let mut saw_validation_error: Option<ValidationError> = None;

        for key in self.keyset.keys.iter() {
            if let Some(kid) = matcher.kid
                && key.kid.as_deref() != Some(kid)
            {
                continue;
            }

            if let Some(declared_alg) = &key.alg {
                if declared_alg != &matcher.alg {
                    if matcher.kid.is_some() {
                        if saw_alg_mismatch.is_none() {
                            saw_alg_mismatch = Some((matcher.alg.clone(), declared_alg.clone()));
                        }
                    }
                    continue;
                }
            }

            if !key.is_algorithm_compatible(&matcher.alg) {
                if matcher.kid.is_some() {
                    incompatible_for_known_kid = true;
                }
                continue;
            }

            if key.validate_operation_metadata(matcher.op.clone()).is_err() {
                if matcher.kid.is_some() {
                    saw_intent_mismatch = true;
                }
                continue;
            }

            if let Err(e) = key.validate_for_algorithm(&matcher.alg) {
                if matcher.kid.is_some() {
                    match e {
                        Error::Validation(validation) => {
                            if saw_validation_error.is_none() {
                                saw_validation_error = Some(validation);
                            }
                        }
                        // `validate_for_algorithm` should primarily return
                        // `Error::Validation`. Non-validation failures are treated
                        // conservatively as incompatibility in strict selection.
                        _ => incompatible_for_known_kid = true,
                    }
                }
                continue;
            }

            candidates.push(key);
        }

        if candidates.is_empty() {
            if let Some((requested, declared)) = saw_alg_mismatch {
                return Err(SelectionError::AlgorithmMismatch {
                    requested,
                    declared,
                });
            }
            if saw_intent_mismatch {
                return Err(SelectionError::IntentMismatch);
            }
            if let Some(validation) = saw_validation_error {
                return Err(SelectionError::KeyValidationFailed(validation));
            }
            if incompatible_for_known_kid {
                return Err(SelectionError::IncompatibleKeyType);
            }
            return Err(SelectionError::NoMatchingKey);
        }

        if candidates.len() > 1 {
            return Err(SelectionError::AmbiguousSelection {
                count: candidates.len(),
            });
        }

        Ok(candidates[0])
    }
}

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
        Ok(self.get_keyset().await?.get_by_kid(kid).cloned())
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
        Ok(self.get_by_kid(kid).cloned())
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
    /// let key = jwks.get_by_kid("my-key");
    /// assert!(key.is_some());
    ///
    /// let missing = jwks.get_by_kid("unknown");
    /// assert!(missing.is_none());
    /// ```
    pub fn get_by_kid(&self, kid: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Finds a key by its ID (`kid`).
    #[deprecated(note = "use get_by_kid instead")]
    pub fn find_by_kid(&self, kid: &str) -> Option<&Key> {
        self.get_by_kid(kid)
    }

    /// Finds all keys with the specified algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[allow(deprecated)]
    /// # fn main() {
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let rs256_keys: Vec<_> = jwks.find_by_alg(&Algorithm::Rs256).collect();
    /// assert_eq!(rs256_keys.len(), 1);
    /// # }
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
    /// let signing_keys: Vec<_> = jwks.find_by_use(&KeyUse::Signature).collect();
    /// assert_eq!(signing_keys.len(), 1);
    /// ```
    pub fn find_by_use<'a>(&'a self, key_use: &KeyUse) -> impl Iterator<Item = &'a Key> + 'a {
        let key_use = key_use.clone();
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
    /// # #[allow(deprecated)]
    /// # fn main() {
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "alg": "RS256", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let key = jwks.find_first_by_alg(&Algorithm::Rs256);
    /// assert!(key.is_some());
    /// # }
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
    /// # #[allow(deprecated)]
    /// # fn main() {
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// // This RSA key has no "alg" field, so find_by_alg would miss it
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// assert_eq!(jwks.find_by_alg(&Algorithm::Rs256).count(), 0);
    /// assert_eq!(jwks.find_compatible(&Algorithm::Rs256).count(), 1);
    /// # }
    /// ```
    #[deprecated(
        note = "use find(&KeyFilter) for discovery or selector(...).select(...) for strict selection"
    )]
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
    /// # #[allow(deprecated)]
    /// # fn main() {
    /// use jwk_simple::{Algorithm, KeySet};
    ///
    /// let json = r#"{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// // find_first_by_alg misses keys without an explicit "alg" field
    /// assert!(jwks.find_first_by_alg(&Algorithm::Rs256).is_none());
    /// // find_first_compatible finds them
    /// assert!(jwks.find_first_compatible(&Algorithm::Rs256).is_some());
    /// # }
    /// ```
    #[deprecated(note = "use selector(...).select(KeyMatcher::new(...)) for strict selection")]
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
    /// # #[allow(deprecated)]
    /// # fn main() {
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
    /// # }
    /// ```
    #[deprecated(
        note = "use selector(...).select(KeyMatcher::new(KeyOperation::Sign, ...)) for signing-key selection"
    )]
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
    #[deprecated(
        note = "use selector(...).select(KeyMatcher::new(KeyOperation::Sign, ...)) for signing-key selection"
    )]
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
            key.validate_structure()?;
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
    /// externally or using [`get_by_kid`](KeySet::get_by_kid) instead.
    ///
    /// Note: each candidate comparison is constant-time, but the iterator scan
    /// still short-circuits once a match is found.
    pub fn get_by_thumbprint(&self, thumbprint: &str) -> Option<&Key> {
        self.keys
            .iter()
            .find(|k| bool::from(k.thumbprint().as_bytes().ct_eq(thumbprint.as_bytes())))
    }

    /// Finds a key by its JWK thumbprint (RFC 7638).
    #[deprecated(note = "use get_by_thumbprint instead")]
    pub fn find_by_thumbprint(&self, thumbprint: &str) -> Option<&Key> {
        self.get_by_thumbprint(thumbprint)
    }

    /// Finds keys by optional discovery criteria.
    ///
    /// This method is for discovery/filtering only and does not provide
    /// cryptographic suitability guarantees.
    ///
    /// When `filter.op` is set:
    /// - keys with explicit `key_ops` must contain that operation,
    /// - otherwise, keys with `use` must be compatible with the operation,
    /// - keys with neither `key_ops` nor `use` are treated as discovery
    ///   candidates and pass through.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwk_simple::{Algorithm, KeyFilter, KeySet, KeyType};
    ///
    /// let json = r#"{"keys": [
    ///     {"kty": "RSA", "kid": "r1", "alg": "RS256", "n": "AQAB", "e": "AQAB"},
    ///     {"kty": "EC", "kid": "e1", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
    /// ]}"#;
    /// let jwks: KeySet = serde_json::from_str(json).unwrap();
    ///
    /// let rsa_rs256 = KeyFilter::new()
    ///     .with_kty(KeyType::Rsa)
    ///     .with_alg(Algorithm::Rs256);
    ///
    /// assert_eq!(jwks.find(&rsa_rs256).count(), 1);
    /// ```
    pub fn find<'a>(&'a self, filter: &'a KeyFilter<'a>) -> impl Iterator<Item = &'a Key> + 'a {
        self.keys.iter().filter(move |k| {
            if let Some(kid) = filter.kid
                && k.kid.as_deref() != Some(kid)
            {
                return false;
            }

            if let Some(kty) = filter.kty
                && k.kty() != kty
            {
                return false;
            }

            if let Some(alg) = &filter.alg
                && k.alg.as_ref() != Some(alg)
            {
                return false;
            }

            if let Some(key_use) = &filter.key_use
                && k.key_use.as_ref() != Some(key_use)
            {
                return false;
            }

            if let Some(op) = &filter.op {
                if let Some(key_ops) = &k.key_ops {
                    if !key_ops.contains(op) {
                        return false;
                    }
                } else if let Some(key_use) = &k.key_use {
                    let allowed_by_use = match op {
                        KeyOperation::Sign | KeyOperation::Verify => key_use == &KeyUse::Signature,
                        KeyOperation::Encrypt
                        | KeyOperation::Decrypt
                        | KeyOperation::WrapKey
                        | KeyOperation::UnwrapKey
                        | KeyOperation::DeriveKey
                        | KeyOperation::DeriveBits => key_use == &KeyUse::Encryption,
                        KeyOperation::Unknown(_) => true,
                    };

                    if !allowed_by_use {
                        return false;
                    }
                }
            }

            true
        })
    }

    /// Creates a strict selector bound to this key set.
    ///
    /// Verification algorithm allowlists are enforced only when selecting for
    /// [`KeyOperation::Verify`].
    /// For non-verify operations (for example [`KeyOperation::Sign`]),
    /// `allowed_verify_algs` is not consulted.
    ///
    /// # Errors
    ///
    /// This constructor is infallible; strict selection failures are returned
    /// by [`KeySelector::select`].
    pub fn selector(&self, allowed_verify_algs: &[Algorithm]) -> KeySelector<'_> {
        KeySelector {
            keyset: self,
            allowed_verify_algs: allowed_verify_algs.to_vec(),
        }
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
    fn test_parse_skips_semantically_invalid_key() {
        let json = r#"{
            "keys": [
                {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ", "kid": "bad"},
                {"kty": "oct", "k": "AQAB", "kid": "good"}
            ]
        }"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.len(), 1);
        assert!(jwks.get_by_kid("bad").is_none());
        assert!(jwks.get_by_kid("good").is_some());
    }

    #[test]
    fn test_parse_skips_unknown_kty() {
        let json = r#"{
            "keys": [
                {"kty": "UNKNOWN", "kid": "unknown"},
                {"kty": "oct", "k": "AQAB", "kid": "good"}
            ]
        }"#;

        let jwks: KeySet = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.len(), 1);
        assert!(jwks.get_by_kid("unknown").is_none());
        assert!(jwks.get_by_kid("good").is_some());
    }

    #[test]
    fn test_find_by_kid() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        assert!(jwks.get_by_kid("rsa-key-1").is_some());
        assert!(jwks.get_by_kid("rsa-enc-1").is_some());
        assert!(jwks.get_by_kid("ec-key-1").is_some());
        assert!(jwks.get_by_kid("unknown").is_none());
    }

    #[test]
    fn test_find_with_filter() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let by_alg = KeyFilter {
            alg: Some(Algorithm::Rs256),
            ..Default::default()
        };
        assert_eq!(jwks.find(&by_alg).count(), 1);

        let by_kty = KeyFilter {
            kty: Some(KeyType::Rsa),
            ..Default::default()
        };
        assert_eq!(jwks.find(&by_kty).count(), 2);

        let by_use = KeyFilter {
            key_use: Some(KeyUse::Encryption),
            ..Default::default()
        };
        assert_eq!(jwks.find(&by_use).count(), 1);

        let by_op_use = KeyFilter {
            op: Some(KeyOperation::Sign),
            ..Default::default()
        };
        assert_eq!(jwks.find(&by_op_use).count(), 2);

        let by_unknown_op = KeyFilter {
            op: Some(KeyOperation::Unknown("custom".to_string())),
            ..Default::default()
        };
        assert_eq!(jwks.find(&by_unknown_op).count(), 3);

        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "sign", "n": "AQAB", "e": "AQAB", "key_ops": ["sign"]},
            {"kty": "RSA", "kid": "enc", "n": "AQAB", "e": "AQAB", "key_ops": ["encrypt"]}
        ]}"#;
        let with_key_ops: KeySet = serde_json::from_str(json).unwrap();
        let by_op_key_ops = KeyFilter {
            op: Some(KeyOperation::Sign),
            ..Default::default()
        };
        assert_eq!(with_key_ops.find(&by_op_key_ops).count(), 1);
    }

    #[test]
    fn test_selector_verify_empty_allowlist() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256))
            .unwrap_err();

        assert!(matches!(err, SelectionError::EmptyVerifyAllowlist));
    }

    #[test]
    fn test_selector_verify_algorithm_not_allowed() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[Algorithm::Es256]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256))
            .unwrap_err();

        assert!(matches!(err, SelectionError::AlgorithmNotAllowed));
    }

    #[test]
    fn test_selector_verify_selects_single_key() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[Algorithm::Rs256]);

        let key = selector
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Rs256).with_kid("rsa-key-1"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("rsa-key-1"));
    }

    #[test]
    fn test_selector_ambiguous_selection() {
        let json = r#"{"keys": [
            {"kty": "EC", "kid": "ec-1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},
            {"kty": "EC", "kid": "ec-2", "use": "sig", "alg": "ES256", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[Algorithm::Es256]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Es256))
            .unwrap_err();

        assert!(matches!(
            err,
            SelectionError::AmbiguousSelection { count: 2 }
        ));
    }

    #[test]
    fn test_selector_algorithm_mismatch_for_known_kid() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "rsa", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[Algorithm::Es256]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("rsa"))
            .unwrap_err();

        assert!(matches!(
            err,
            SelectionError::AlgorithmMismatch {
                requested: Algorithm::Es256,
                declared: Algorithm::Rs256
            }
        ));
    }

    #[test]
    fn test_selector_unknown_algorithm_rejected() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(
                KeyOperation::Sign,
                Algorithm::Unknown("CUSTOM".to_string()),
            ))
            .unwrap_err();

        assert!(matches!(err, SelectionError::UnknownAlgorithm));
    }

    #[test]
    fn test_selector_incompatible_key_type_for_known_kid() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "oct-1", "k": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("oct-1"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::IncompatibleKeyType));
    }

    #[test]
    fn test_selector_key_validation_failed_for_known_kid() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "weak-rsa", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("weak-rsa"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::KeyValidationFailed(_)));
    }

    #[test]
    fn test_selector_intent_mismatch_for_known_kid() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "enc-rsa", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("enc-rsa"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::IntentMismatch));
    }

    #[test]
    fn test_selector_no_kid_all_candidates_invalid_returns_no_match() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "weak-1", "use": "sig", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "weak-2", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256))
            .unwrap_err();

        assert!(matches!(err, SelectionError::NoMatchingKey));
    }

    #[test]
    fn test_selector_error_precedence_alg_mismatch_over_intent() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "dup", "alg": "ES256", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("dup"))
            .unwrap_err();

        assert!(matches!(
            err,
            SelectionError::AlgorithmMismatch {
                requested: Algorithm::Rs256,
                declared: Algorithm::Es256
            }
        ));
    }

    #[test]
    fn test_selector_error_precedence_intent_over_validation() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "dup", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "dup", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("dup"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::IntentMismatch));
    }

    #[test]
    fn test_selector_error_precedence_intent_over_incompatible() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "dup", "k": "AQAB"},
            {"kty": "RSA", "kid": "dup", "use": "enc", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("dup"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::IntentMismatch));
    }

    #[test]
    fn test_selector_error_precedence_validation_over_incompatible() {
        let json = r#"{"keys": [
            {"kty": "oct", "kid": "dup", "k": "AQAB"},
            {"kty": "RSA", "kid": "dup", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("dup"))
            .unwrap_err();

        assert!(matches!(err, SelectionError::KeyValidationFailed(_)));
    }

    #[test]
    fn test_selector_verify_selects_single_key_without_kid() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[Algorithm::Es256]);

        let key = selector
            .select(KeyMatcher::new(KeyOperation::Verify, Algorithm::Es256))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("ec-key-1"));
    }

    #[test]
    fn test_selector_sign_selects_single_key() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[]);

        let key = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256).with_kid("rsa-key-1"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("rsa-key-1"));
    }

    #[test]
    fn test_selector_empty_verify_allowlist_does_not_block_signing() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        let selector = jwks.selector(&[]);

        let key = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("ec-key-1"))
            .unwrap();

        assert_eq!(key.kid.as_deref(), Some("ec-key-1"));
    }

    #[test]
    fn test_find_with_filter_op_and_use_combination() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let compatible = KeyFilter {
            op: Some(KeyOperation::Sign),
            key_use: Some(KeyUse::Signature),
            ..Default::default()
        };
        assert_eq!(jwks.find(&compatible).count(), 2);

        let conflicting = KeyFilter {
            op: Some(KeyOperation::Sign),
            key_use: Some(KeyUse::Encryption),
            ..Default::default()
        };
        assert_eq!(jwks.find(&conflicting).count(), 0);
    }

    #[test]
    fn test_find_with_filter_op_passthrough_without_metadata() {
        let json = r#"{"keys": [
            {"kty": "RSA", "kid": "meta-less", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "sig-use", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]}"#;
        let jwks: KeySet = serde_json::from_str(json).unwrap();

        let by_sign = KeyFilter {
            op: Some(KeyOperation::Sign),
            ..Default::default()
        };

        // Keys without key_ops/use pass through in discovery mode by design.
        assert_eq!(jwks.find(&by_sign).count(), 2);
    }

    #[test]
    fn test_find_with_filter_builder_api() {
        let jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();

        let filter = KeyFilter::new()
            .with_kty(KeyType::Rsa)
            .with_alg(Algorithm::Rs256)
            .with_kid("rsa-key-1");

        let keys: Vec<_> = jwks.find(&filter).collect();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid.as_deref(), Some("rsa-key-1"));
    }

    #[test]
    fn test_selector_no_matching_key_for_empty_keyset() {
        let jwks = KeySet::new();
        let selector = jwks.selector(&[]);

        let err = selector
            .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Rs256))
            .unwrap_err();

        assert!(matches!(err, SelectionError::NoMatchingKey));
    }

    #[test]
    fn test_selection_error_display_messages() {
        assert_eq!(
            SelectionError::EmptyVerifyAllowlist.to_string(),
            "verification allowlist is empty"
        );
        assert_eq!(
            SelectionError::UnknownAlgorithm.to_string(),
            "unknown or unsupported algorithm"
        );
        assert_eq!(
            SelectionError::AlgorithmNotAllowed.to_string(),
            "algorithm is not allowed for verification"
        );
        assert_eq!(
            SelectionError::IntentMismatch.to_string(),
            "key metadata does not permit requested operation"
        );
        assert_eq!(
            SelectionError::IncompatibleKeyType.to_string(),
            "key type/curve is incompatible with requested algorithm"
        );

        let mismatch = SelectionError::AlgorithmMismatch {
            requested: Algorithm::Rs256,
            declared: Algorithm::Es256,
        };
        assert_eq!(
            mismatch.to_string(),
            "algorithm mismatch: requested RS256, key declares ES256"
        );

        let ambiguous = SelectionError::AmbiguousSelection { count: 2 };
        assert_eq!(
            ambiguous.to_string(),
            "selection is ambiguous: 2 matching keys"
        );

        let validation = SelectionError::KeyValidationFailed(ValidationError::InvalidKeySize {
            expected: 32,
            actual: 16,
            context: "HS256",
        });
        assert_eq!(
            validation.to_string(),
            "key validation failed: invalid key size for HS256: expected 32 bytes, got 16"
        );

        assert_eq!(
            SelectionError::NoMatchingKey.to_string(),
            "no matching key found"
        );
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

        assert_eq!(jwks.find_by_use(&KeyUse::Signature).count(), 2);
        assert_eq!(jwks.find_by_use(&KeyUse::Encryption).count(), 1);
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
        assert!(jwks.get_by_kid("k1").is_some());
    }

    #[test]
    fn test_remove_by_kid() {
        let mut jwks: KeySet = serde_json::from_str(SAMPLE_JWKS).unwrap();
        assert_eq!(jwks.len(), 3);

        let removed = jwks.remove_by_kid("ec-key-1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().kid.as_deref(), Some("ec-key-1"));
        assert_eq!(jwks.len(), 2);
        assert!(jwks.get_by_kid("ec-key-1").is_none());

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

# Strict Key Selection API (Consolidated)

This document compacts the proposal, acceptance criteria, implementation plan, and review notes into one source of truth. It explains how the API evolved and defines the final v1 solution.

## Status

- Design direction accepted.
- v1 scope is security-boundary fix first, minimal API surface, controlled migration.
- Breaking changes are allowed across release `R` and cleanup release `R+1`.

## Why this change exists

The recurring finding is API boundary ambiguity: discovery helpers were used as security gates.

Observed failure pattern:

1. A structurally compatible key is found.
2. Strict operation/algorithm suitability is not enforced at selection time.
3. Caller treats key as trust-approved for crypto.

Examples include weak RSA for `RS256`, weak HMAC for `HS512`, and signing candidates selected without full strict checks.

## Final v1 model

Keep one `KeySet` type, but split semantics by API contract:

- Discovery-only: `get_*`, `find(...)`.
- Security selection: `selector(allowed_verify_algs).select(matcher)`.

This preserves ingestion compatibility while forcing strict, fail-closed cryptographic key selection.

## Final v1 API (canonical)

```rust
pub enum SelectionError {
    EmptyVerifyAllowlist,
    UnknownAlgorithm,
    AlgorithmNotAllowed,
    AlgorithmMismatch {
        requested: Algorithm,
        declared: Algorithm,
    },
    IntentMismatch,
    IncompatibleKeyType,
    KeyValidationFailed(ValidationError),
    AmbiguousSelection { count: usize },
    NoMatchingKey,
}

pub struct KeyMatcher<'a> {
    op: KeyOperation,
    alg: Algorithm,
    kid: Option<&'a str>,
}

impl<'a> KeyMatcher<'a> {
    pub fn new(op: KeyOperation, alg: Algorithm) -> Self;
    pub fn with_kid(mut self, kid: Option<&'a str>) -> Self;
}

pub struct KeyFilter<'a> {
    pub op: Option<KeyOperation>,
    pub alg: Option<Algorithm>,
    pub kid: Option<&'a str>,
    pub kty: Option<KeyType>,
    pub key_use: Option<KeyUse>,
}

pub struct KeySelector<'a> {
    keyset: &'a KeySet,
    allowed_verify_algs: Vec<Algorithm>,
}

impl KeySet {
    // discovery-only
    pub fn get_by_kid(&self, kid: &str) -> Option<&Key>;
    pub fn get_by_thumbprint(&self, thumbprint: &str) -> Option<&Key>;
    pub fn find<'a, 'f>(&'a self, filter: KeyFilter<'f>) -> impl Iterator<Item = &'a Key> + 'a;

    // strict selection entrypoint
    pub fn selector(&self, allowed_verify_algs: &[Algorithm]) -> KeySelector<'_>;
}

impl<'a> KeySelector<'a> {
    pub fn select(&self, matcher: KeyMatcher<'_>) -> Result<&'a Key, SelectionError>;
}
```

Constructor behavior:

- `KeySet::selector(...)` does not fail on empty allowlist.
- `EmptyVerifyAllowlist` is enforced only when `select(...)` is called with `op == KeyOperation::Verify`.

## Strict selection contract (must enforce)

`KeySelector::select(...)` enforces:

1. Operation intent checks (`use` / `key_ops` semantics).
2. Algorithm suitability via `validate_for_algorithm` (surfaced as `KeyValidationFailed`).
3. Algorithm consistency (`jwk.alg` must match requested `alg` when declared).
4. Verify allowlist (`Verify` only):
   - empty allowlist -> `EmptyVerifyAllowlist`
   - requested alg outside allowlist -> `AlgorithmNotAllowed`
5. Unknown/unsupported algorithms rejected (`UnknownAlgorithm`).
6. Key-type incompatibility reported (`IncompatibleKeyType`) when relevant candidates exist.
7. Ambiguity fail-closed (`AmbiguousSelection { count }`) when multiple valid keys remain.
8. Terminal outcomes: one match succeeds, zero matches fail.

Structural validation scope:

- `select(...)` does not run full set-wide `validate_structure()`.
- Full structural validation remains explicit ingestion-time choice (`keyset.validate()` and related flows).

## Deterministic error precedence

Check order is fixed to keep behavior and telemetry stable:

1. `UnknownAlgorithm`
2. Verify-only allowlist checks: `EmptyVerifyAllowlist`, `AlgorithmNotAllowed`
3. Candidate evaluation and validation
4. If no candidate survives, terminal precedence is:
   - `AlgorithmMismatch`
   - `IntentMismatch`
   - `KeyValidationFailed`
   - `IncompatibleKeyType`
   - `NoMatchingKey`

## Discovery contract

- `get_*` and `find(...)` are non-security discovery APIs.
- They can return zero/one/many keys.
- Multiplicity handling is caller responsibility.
- Discovery results must not be treated as trust approval.

## Integration requirements

Security-sensitive integrations must use strict selection only.

- `jwt-simple`: verify/sign paths must pass header/requested algorithm and optional `kid` into matcher.
- `web_crypto`: verify/sign/encrypt/decrypt paths must select strictly before key use/import.
- No fallback to discovery for trust decisions.

Allowlist source:

- `allowed_verify_algs` comes from application verifier configuration, not from the `KeySet`.

Examples:

```rust
// verify
let key = keyset
    .selector(&allowed_verify_algs)
    .select(KeyMatcher::new(KeyOperation::Verify, header_alg).with_kid(header_kid))?;

// sign
let key = keyset
    .selector(&[])
    .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("my-kid"))?;
```

## Naming, deprecations, and migration

Discovery renames:

- `find_by_kid` -> `get_by_kid`
- `find_by_thumbprint` -> `get_by_thumbprint`
- `find_by_alg` / `find_by_kty` / `find_by_use` -> `find(KeyFilter { ... })`

Deprecated ambiguous selectors (v1 keeps temporarily, then removes):

- `find_compatible`
- `find_first_compatible`
- `find_compatible_signing_key`
- `find_signing_key_by_alg`

Kept in v1 to reduce churn:

- `signing_keys()`
- `encryption_keys()`
- `first_signing_key()`

Release schedule:

1. `R`: ship strict selector + integration migration + deprecations.
2. `R+1`: remove deprecated ambiguous selectors/aliases.

## Tests required for v1

Strict selector tests:

1. Weak RSA + `RS256` verify -> `KeyValidationFailed(...)`
2. Weak HMAC + `HS512` verify -> `KeyValidationFailed(...)`
3. Empty verify allowlist -> `EmptyVerifyAllowlist`
4. Disallowed verify alg -> `AlgorithmNotAllowed`
5. `jwk.alg` mismatch -> `AlgorithmMismatch`
6. Candidate present but wrong key type/curve -> `IncompatibleKeyType`
7. Multiple valid matches -> `AmbiguousSelection`
8. One strong valid match -> success

Integration tests:

1. `jwt-simple` verify/sign route through strict selection.
2. `web_crypto` verify/sign/encrypt/decrypt route through strict selection.
3. Missing `kid` + multiple compatible keys fails with ambiguity.

## Evolution (how we got here)

- **v0**: considered split types (`Loose/Strict`, `Parsed/Validated`).
- **v1**: considered `*_strict` transitional methods.
- **v2**: considered hardening legacy selectors in place.
- **v3**: converged on one `KeySet` with semantic split (`get/find/select`).
- **v4**: unknown algorithms made fail-closed.
- **v5**: typed errors and strict ambiguity behavior added.
- **v6**: verify allowlist requirement and migration schedule tightened.
- **v7**: complexity reduced; wrappers/policy features deferred.
- **v8**: simplified to allowlist-bound selector construction.
- **v9**: minimal strict API settled on canonical `select(KeyMatcher)`.
- **v10**: constructor semantics refined; broader operation coverage clarified; diagnostics improved.
- **v11**: terminology aligned on `KeyOperation`; error payload/context clarified.

Net result: minimal but strict API boundary that is explicit, testable, and migration-friendly.

## What remains intentionally open (post-v1)

1. Optional deterministic tie-break mode (separate explicit API).
2. Optional convenience wrappers over `select(...)`.
3. Optional pluggable policy trait.
4. Additional cosmetic renames beyond security-critical items.
5. Possible strict helper for kid-less JWT verification without discovery bypass.

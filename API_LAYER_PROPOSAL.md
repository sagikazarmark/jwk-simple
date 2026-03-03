# Proposal: Strict Key Selection API for `KeySet`

## Status

- Stage: Design accepted in principle; refinements incorporated from latest review.
- Scope: Breaking changes are allowed.
- Current direction:
  - Keep a single `KeySet` type.
  - Discovery and security boundaries are split by API semantics.
  - Discovery: `get_*` and `find(...)`.
  - Security: `selector(allowed_verify_algs).select(matcher)`.
  - No `*_strict` stopgap methods.

## Executive summary

The recurring security finding class is caused by API boundary ambiguity: compatibility/discovery helpers are used as security gates.

This proposal makes the boundary explicit:

- `get_*` and `find(...)` are discovery-only.
- `select(...)` is the only strict key selection entrypoint intended for cryptographic operations.

This preserves ingestion compatibility while making security selection fail-closed and testable.

---

## Problem statement

Current behavior exposes structural compatibility checks close to selection helpers. In practice, many callers treat helper output as trust-approved for verification/signing.

Observed issue pattern:

- structurally compatible key selected,
- algorithm-strength/operation suitability not enforced at selection point,
- caller treats selected key as safe.

Examples:

- Weak RSA selected as compatible with `RS256`.
- Weak HMAC selected as compatible with `HS512`.
- Signing candidate selected without full suitability checks.

---

## RFC posture (practical)

- Ingestion/discovery can remain permissive.
- Cryptographic use must be strict and operation-scoped.
- Verification must be constrained by explicit acceptable algorithms (allowlist).
- Unknown/unsupported algorithms are rejected in strict v1 behavior.

---

## Selected architecture

## One type, two semantics

- `KeySet`: data/discovery model.
- `KeySelector`: strict selection engine bound to a `KeySet` and verification allowlist.

This keeps API simple while enforcing a clear trust boundary.

## Complexity stance

- Keep v1 public surface minimal.
- Do not introduce request-wrapper proliferation.
- Do not introduce a custom policy trait in v1.
- Prefer one canonical strict method (`select`) and one canonical discovery method (`find`).

---

## Complete v1 API (proposed)

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
    // Discovery-only APIs
    pub fn get_by_kid(&self, kid: &str) -> Option<&Key>;
    pub fn get_by_thumbprint(&self, thumbprint: &str) -> Option<&Key>;
    pub fn find<'a>(&'a self, filter: &'a KeyFilter<'a>) -> impl Iterator<Item = &'a Key>;

    // Strict selector entrypoint
    pub fn selector(
        &self,
        allowed_verify_algs: &[Algorithm],
    ) -> KeySelector<'_>;
}

impl<'a> KeySelector<'a> {
    pub fn select(&self, matcher: KeyMatcher<'_>) -> Result<&'a Key, SelectionError>;
}
```

### Constructor behavior note

`KeySet::selector(...)` does not fail for empty allowlist in v1. This avoids forcing signing/encryption callers to provide irrelevant verify settings.

Verification allowlist requirements are enforced at `select(...)` time when `matcher.op == KeyOperation::Verify`.

---

## Strict selection contract (normative)

`KeySelector::select` MUST enforce:

1. **Operation intent constraints**
   - Enforce key intent compatibility for operation (`KeyOperation`) when metadata (`use`/`key_ops`) is present.

2. **Algorithm suitability constraints**
   - Require `key.validate_for_algorithm(&alg)` (or equivalent operation-aware validation).
   - Validation failures are surfaced as `SelectionError::KeyValidationFailed(ValidationError)`.

3. **Algorithm consistency constraints**
   - If JWK declares `alg`, it must match requested algorithm.
   - Integration code must pass JWT/JWS header algorithm into matcher and reject mismatch in integration flow.

4. **Verification allowlist constraints**
   - For `KeyOperation::Verify`, requested algorithm must be in `allowed_verify_algs`.
   - If verify allowlist is empty and operation is verify -> `SelectionError::EmptyVerifyAllowlist`.
   - If algorithm not in allowlist -> `SelectionError::AlgorithmNotAllowed`.

5. **Unknown algorithm handling**
   - Unknown/unsupported algorithms are rejected in v1 strict behavior.
   - `SelectionError::UnknownAlgorithm` is returned when parsing/representation yields an unknown algorithm identifier (for example, an unknown enum variant or parse-time unknown value).

6. **Type compatibility diagnostics**
   - If a key candidate is identified (for example by `kid`) but key type/curve is incompatible with requested algorithm family, return `SelectionError::IncompatibleKeyType` rather than collapsing to `NoMatchingKey`.

7. **Ambiguity handling**
   - Multiple valid matches -> `SelectionError::AmbiguousSelection`.
   - No first-match behavior in strict path.

8. **Terminal outcomes**
   - 0 matches -> `SelectionError::NoMatchingKey`.
   - 1 match -> success.

### Structural validation scope (explicit)

- `select(...)` does not run full structural `validate_structure()` on all keys as a prerequisite.
- Strict selection relies on operation/algorithm checks (`validate_for_operation`, `validate_for_algorithm`) for selected candidates.
- Full set-level structural validation remains an explicit call-site choice (e.g., `keyset.validate()`) and an ingestion concern.

---

## Discovery contract (normative)

- `get_*` and `find(...)` are discovery APIs and MUST NOT be treated as security approval.
- `find(...)` supports optional criteria via `KeyFilter` and can return zero, one, or many keys.
- Multiplicity in discovery is caller-managed by design.

---

## Rename and deprecation table

### Current -> Proposed

- `find_by_kid` -> `get_by_kid`
- `find_by_thumbprint` -> `get_by_thumbprint`
- `find_by_alg` -> `find(KeyFilter { alg: Some(...), .. })` (or keep helper alias)
- `find_by_kty` -> `find(KeyFilter { kty: Some(...), .. })` (or keep helper alias)
- `find_by_use` -> `find(KeyFilter { key_use: Some(...), .. })` (or keep helper alias)
- `find_compatible` -> deprecated; use discovery `find(...)`
- `find_first_compatible` -> deprecated; use strict `select(...)` for security selection
- `find_compatible_signing_key` -> deprecated; use strict `select(...)`
- `find_signing_key_by_alg` -> deprecated; use strict `select(...)`

### Candidate wording cleanup

- Keep `signing_keys()` and `encryption_keys()` as-is in v1 to reduce churn.
- Keep `first_signing_key()` as-is in v1 to reduce churn.
- Discovery/security disambiguation is primarily by `get/find` vs `select` contracts.

### Type naming alignment (cosmetic, explicit)

- Keep `KeyOperation` as the operation type in v1 selector APIs to avoid semantic drift with JWK `key_ops` handling.
- `KeyAlgorithms` -> `Algorithm` remains optional and can be phased separately.

Compatibility plan:

- Release R: provide compatibility aliases where feasible.
- Release R+1: remove deprecated aliases and keep canonical names.

---

## Integration guidance (`jwt-simple`, `web_crypto`)

Security-sensitive integrations MUST use strict selection only.

Allowlist source:

- `allowed_verify_algs` is caller/application configuration, not derived from `KeySet`.
- Typical source is verifier configuration near token validation settings.

Examples:

### Verification

```rust
let header_alg = parsed_header.alg;
let kid = parsed_header.kid.as_deref();

let key = keyset
    .selector(&allowed_verify_algs)
    .select(KeyMatcher::new(KeyOperation::Verify, header_alg).with_kid(kid))?;
```

### Signing

```rust
let key = keyset
    .selector(&[])
    .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid(Some("my-key")))?;
```

---

## Determinism and ambiguity

- Strict path: ambiguity always errors.
- Optional deterministic tie-break mode is out-of-scope for initial release and, if added later, must be separate explicit API behavior.

---

## Migration strategy (hard schedule)

1. **Release R (breaking release)**
   - Introduce strict selector API (`selector(...).select(...)`).
   - Introduce `KeyMatcher` and discovery `KeyFilter`.
   - Introduce renamed discovery APIs (`get_*`, `find(...)`).
   - Migrate `jwt-simple` and `web_crypto` to strict selection.
   - Deprecate ambiguous legacy selector names with migration notes.

2. **Release R+1**
   - Remove deprecated ambiguous selector names.
   - Remove deprecated compatibility type aliases.
   - Keep canonical discovery and strict selection surfaces.

3. **Documentation gate**
   - All security-sensitive examples use strict `select(...)`.
   - Discovery examples explicitly marked non-security.

---

## Test plan

### Strict selection tests

1. Weak RSA key present; verify selection for `RS256` rejects with `KeyValidationFailed(...)`.
2. Weak HMAC key present; verify selection for `HS512` rejects with `KeyValidationFailed(...)`.
3. Strong key selected successfully for known algorithm.
4. Verify selection with empty allowlist yields `EmptyVerifyAllowlist`.
5. Verify selection with algorithm outside allowlist yields `AlgorithmNotAllowed`.
6. Unknown/unsupported algorithm rejected.
7. `jwk.alg` mismatch yields `AlgorithmMismatch`.
8. Incompatible key type for requested algorithm yields `IncompatibleKeyType`.
9. Ambiguous matches yield `AmbiguousSelection`.

### Discovery regression tests

1. `get_by_kid` and `get_by_thumbprint` remain functional.
2. `find(KeyFilter)` supports optional criteria including `kty` and `key_use`.

### Integration tests

1. `jwt-simple` verify/sign flows route through strict `select(...)`.
2. `web_crypto` verify/sign/encrypt/decrypt flows route through strict `select(...)`.

---

## Open decisions

1. Whether optional deterministic tie-break API is needed later.
2. Whether to add operation-specific convenience wrappers later while keeping `select(...)` canonical.
3. Whether to add a custom policy trait in a future version.
4. Whether to fully rename `KeyOperation`/`KeyAlgorithms` in the same release or phase that change separately.
5. Whether to provide a blessed strict helper for kid-less JWT verification that tries strict-compatible candidates internally and avoids discovery-path bypass.

---

## Proposal history and discarded options

### v0

- Initial split-type framing (`Loose/Strict`, `Parsed/Validated`).

### v1

- Considered `*_strict` transitional APIs.

Outcome: discarded due to API sprawl risk.

### v2

- Considered hardening existing selectors in place.

Outcome: viable but did not fully solve naming/trust boundary clarity.

### v3

- Converged on single `KeySet` with semantic split (`get/find/select`).

### v4

- Tightened unknown algorithm handling to fail-closed strict behavior.

### v5

- Added typed error model and ambiguity fail-closed requirement.

### v6

- Enforced allowlist requirement and hard migration schedule.

### v7

- Reduced complexity; deferred request-wrapper structs and optional features.

### v8

- Simplified from policy-object-first approach to allowlist-bound selector construction.

### v9

- Minimized strict surface to canonical `select(KeyMatcher)` and added `KeyFilter` for discovery.

### v10

- Refined constructor semantics: verify allowlist checked at verify-selection time, not selector construction.
- Extended operation coverage to include wrap/unwrap/derive operations.
- Added compatibility diagnostics and nested validation error propagation.
- Reduced naming churn by keeping `signing_keys`/`encryption_keys`/`first_signing_key` in v1.

### v11

- Reconciled selector and acceptance docs on operation naming by using `KeyOperation` in v1 API sketches.
- Added contextual payloads for `AlgorithmMismatch` and `AmbiguousSelection` in proposal API sketch.
- Clarified where `UnknownAlgorithm` originates in v1.

---

## Summary

This proposal fixes the root cause (API boundary ambiguity) without sacrificing discovery interoperability:

- discovery remains flexible (`get/find`),
- strict selection is explicit and fail-closed (`selector(...).select(...)`),
- integrations use strict selection by default,
- migration is explicit and time-bound.

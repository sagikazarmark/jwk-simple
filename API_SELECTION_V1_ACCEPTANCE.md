# Strict Selection v1 Acceptance Criteria

This document defines the non-negotiable scope for v1 so the security boundary fix lands quickly, with controlled migration risk.

## Must-haves (ship blockers)

1. **Explicit trust boundary**
   - `get_*` / `find(...)` remain discovery-only.
   - `selector(...).select(...)` is the only strict selection path for cryptographic use.

2. **Verify allowlist enforcement without constructor coupling**
   - Selector construction must not require verify-only config for non-verify operations.
   - Verify allowlist is enforced when `select(op=Verify, ...)` is called.
   - Empty allowlist on verify selection is a typed error.

3. **Strict selection contract is enforced in code**
   - `select(...)` must enforce:
     - operation intent (`use` / `key_ops`) checks,
     - algorithm consistency (`requested alg` vs `jwk.alg`),
     - `validate_for_algorithm` suitability checks,
     - ambiguity fail-closed behavior.

4. **Typed, contextual errors**
   - `select(...) -> Result<_, SelectionError>` only.
   - Keep diagnostic fidelity by surfacing nested validation details (e.g. `KeyValidationFailed(ValidationError)`).
   - Ambiguity and mismatch errors include enough context for operators.

5. **Deterministic error precedence**
   - Define and document check order (and corresponding error precedence):
     - `UnknownAlgorithm`
     - `EmptyVerifyAllowlist` / `AlgorithmNotAllowed` (verify only)
     - per-candidate matching and validation
     - terminal result resolution in this order when no candidate survives:
       - `AlgorithmMismatch`
       - `IntentMismatch`
       - `KeyValidationFailed`
       - `IncompatibleKeyType`
       - `NoMatchingKey`
   - Add tests to lock precedence and prevent telemetry drift.

6. **Operation scope clarity for v1**
   - Either limit v1 strict API to `Verify` + `Sign`, or explicitly define `alg` semantics for each operation included.
   - No ambiguous operation semantics in v1.

7. **Integration migration completed for strict path**
   - `jwt-simple` and `web_crypto` security-sensitive flows must use `select(...)`.
   - No fallback to discovery APIs for trust decisions.

8. **Ambiguity behavior documented and tested**
   - Multiple matching keys in strict path must fail with `AmbiguousSelection`.
   - Add integration test for missing `kid` + multiple compatible keys.
   - Document expected migration impact for rollover setups.

9. **Review notes and proposal synchronized**
   - `API_LAYER_PROPOSAL_REVIEW_NOTES.md` must reference current section names and current error/type names.
   - No stale references to removed terms.

## Should-haves (not required for v1 ship)

1. Operation-specific convenience wrappers over `select(...)`.
2. Optional deterministic tie-break API as a separate explicit mode.
3. Custom policy trait/pluggable policy engine.
4. Large naming cleanup beyond security-critical ambiguity removals.

## Explicit de-scopes for v1

1. Do not introduce `*_strict` transitional API family.
2. Do not require global type-system split (`Loose/Strict` keyset types).
3. Do not block v1 on broad cosmetic renames.

## Exit criteria checklist

- [x] Strict selector API implemented and documented
- [x] Verify allowlist enforced at verify selection time
- [x] Typed contextual errors implemented and tested
- [x] Error precedence documented and tested
- [x] `jwt-simple` integration migrated to strict path
- [x] `web_crypto` integration migrated to strict path
- [x] Ambiguity and no-`kid` integration tests added
- [x] Proposal and review-notes docs synchronized

## Reference code sketch (v1)

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
    pub fn new(op: KeyOperation, alg: Algorithm) -> Self {
        Self { op, alg, kid: None }
    }

    pub fn with_kid(mut self, kid: &'a str) -> Self {
        self.kid = Some(kid);
        self
    }

    pub fn with_optional_kid(mut self, kid: Option<&'a str>) -> Self {
        self.kid = kid;
        self
    }
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
    pub fn find<'a>(&'a self, filter: &'a KeyFilter<'a>) -> impl Iterator<Item = &'a Key>;

    // strict path
    pub fn selector(&self, allowed_verify_algs: &[Algorithm]) -> KeySelector<'_>;
}

impl<'a> KeySelector<'a> {
    pub fn select(&self, matcher: KeyMatcher<'_>) -> Result<&'a Key, SelectionError> {
        // Implemented in src/jwks.rs.
        // Deterministic precedence and strict semantics are enforced there.
        # unimplemented!()
    }
}
```

### Integration usage (verification)

```rust
let key = keyset
    .selector(&allowed_verify_algs)
    .select(KeyMatcher::new(KeyOperation::Verify, header_alg).with_optional_kid(header_kid))?;
```

### Integration usage (signing)

```rust
let key = keyset
    .selector(&[])
    .select(KeyMatcher::new(KeyOperation::Sign, Algorithm::Es256).with_kid("my-kid"))?;
```

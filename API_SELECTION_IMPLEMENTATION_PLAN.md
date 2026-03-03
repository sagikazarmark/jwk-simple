# API Selection Implementation Plan

This plan maps the accepted v1 API design to concrete implementation steps in the codebase.

## Scope

- Introduce strict selection via `KeySet::selector(...).select(...)`.
- Keep discovery APIs (`get/find`) available.
- Migrate integrations to strict selection path.
- Add tests for security guarantees and migration behavior.

## Phase 1: Core types and API surface (src/jwks.rs)

1. Add new public types:
   - `SelectionError`
   - `KeyMatcher<'a>`
   - `KeyFilter<'a>`
   - `KeySelector<'a>`

2. Add strict selector entrypoint:
   - `KeySet::selector(&self, allowed_verify_algs: &[Algorithm]) -> KeySelector<'_>`

3. Add strict selection method:
   - `KeySelector::select(&self, matcher: KeyMatcher<'_>) -> Result<&Key, SelectionError>`

4. Add or rename discovery methods:
   - `find_by_kid` -> `get_by_kid` (keep alias/deprecation as needed)
   - `find_by_thumbprint` -> `get_by_thumbprint` (keep alias/deprecation as needed)
   - Add `find(&KeyFilter)` iterator-based discovery

5. Deprecate ambiguous legacy selectors (do not remove yet):
   - `find_compatible`
   - `find_first_compatible`
   - `find_compatible_signing_key`
   - `find_signing_key_by_alg`

## Phase 2: Strict selection engine behavior (src/jwks.rs + src/jwk.rs)

Implement deterministic validation/check order in `KeySelector::select`:

1. Unknown/unsupported algorithm handling.
2. Verify allowlist handling when `matcher.op == KeyOperation::Verify`:
   - empty allowlist -> `SelectionError::EmptyVerifyAllowlist`
   - algorithm not in allowlist -> `SelectionError::AlgorithmNotAllowed`
3. Candidate filtering (`kid`, optional `kty`/`use` from matcher context if any).
4. JWK algorithm consistency (`jwk.alg` mismatch -> `AlgorithmMismatch { requested, declared }`).
5. Operation intent validation via existing `Key::validate_for_operation`.
6. Algorithm suitability validation via existing `Key::validate_for_algorithm`.
7. Cardinality resolution:
   - 0 candidates -> `NoMatchingKey`
   - >1 candidates -> `AmbiguousSelection { count }`
   - exactly 1 -> return key

Reuse existing validation logic in `src/jwk.rs`:

- `validate_for_operation` (`src/jwk.rs:1058`)
- `validate_for_algorithm` (`src/jwk.rs:1419`)
- Keep `is_algorithm_compatible` as discovery helper only (`src/jwk.rs:1151`)

## Phase 3: Integration migration

### jwt-simple integration (src/integrations/jwt_simple.rs)

1. Replace direct/legacy compatibility-based selection with strict selector flow.
2. Ensure verify paths pass header `alg` and optional `kid` into matcher.
3. Keep existing cryptographic verification logic unchanged; selection changes only.
4. Preserve current use of `validate_for_operation` semantics through selector.

### web-crypto integration (src/integrations/web_crypto.rs)

1. Ensure all key usage paths (verify/sign/encrypt/decrypt) use strict selector before key import/use.
2. Avoid discovery helper usage for trust decisions.

## Phase 4: Tests

### Unit tests (primarily src/jwks.rs test module)

Add tests for:

1. Weak RSA key in set + verify RS256 -> `KeyValidationFailed(...)`
2. Weak HMAC key in set + verify HS512 -> `KeyValidationFailed(...)`
3. Verify with empty allowlist -> `EmptyVerifyAllowlist`
4. Verify with disallowed algorithm -> `AlgorithmNotAllowed`
5. `jwk.alg` mismatch -> `AlgorithmMismatch { ... }`
6. Incompatible key type when candidate exists -> `IncompatibleKeyType` (or selected equivalent)
7. Multiple strict matches -> `AmbiguousSelection { count }`
8. Single strong key -> success

### Integration tests

1. jwt-simple verification path enforces header alg + allowlist intersection.
2. web-crypto path uses strict selector and rejects weak/incompatible keys.
3. Missing `kid` + multiple compatible keys returns ambiguity in strict path.

## Phase 5: Docs and migration messaging

1. Update rustdoc examples in `src/jwks.rs`:
   - show `selector(...).select(...)` as security path
   - mark `get/find` as discovery only

2. Update proposal/supporting docs for consistency:
   - `API_LAYER_PROPOSAL.md`
   - `API_LAYER_PROPOSAL_REVIEW_NOTES.md`
   - `API_SELECTION_V1_ACCEPTANCE.md`

3. Add deprecation notes to legacy selector docs with migration snippet.

## Phase 6: Release sequencing

### Release R

- Ship strict selector API + integration migration + deprecations.
- Keep legacy methods with warnings.

### Release R+1

- Remove deprecated ambiguous selector APIs.
- Keep canonical discovery + strict selection model.

## Acceptance checklist

- [ ] Strict selector implemented and publicly documented
- [ ] Verify allowlist enforced at verify selection time
- [ ] Legacy ambiguous selectors deprecated
- [ ] Integrations migrated to strict selector path
- [ ] Security test matrix added and passing
- [ ] Documentation/examples updated to strict-by-default guidance

# Review Backlog

This document tracks findings that were intentionally **deferred** or **ignored** during review.
It is structured so new findings can be added consistently over time.

## Entry Template

Copy this block for new items:

```md
## [Title]
- Date added: YYYY-MM-DD
- Source: [review round, PR, audit, etc.]
- Validity: CONFIRMED | PLAUSIBLE | DISPUTED | DUPLICATE
- Trigger likelihood: COMMON | UNCOMMON | RARE | THEORETICAL
- Severity: [original] -> [adjusted]
- Decision: DEFER | IGNORE
- Rationale: [why not fixing now]
- Preconditions/Trigger: [when it manifests]
- Risk if not fixed: [impact of leaving as-is]
- Revisit signal: [what should trigger re-evaluation]
- Suggested future action: [concrete next step]
```

## Deferred Findings

## ECDH-ES compatibility accepts secp256k1 EC keys
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: RISK -> LOW/MEDIUM RISK
- Decision: DEFER
- Rationale: Interoperability hardening rather than a direct correctness break; may affect users relying on extension behavior.
- Preconditions/Trigger: EC JWK with `crv=secp256k1` is used with `alg=ECDH-ES` (or ECDH-ES key-wrap variants) against stricter JOSE stacks.
- Risk if not fixed: Cross-implementation import/negotiation failures for non-RFC curve usage.
- Revisit signal: Interop bugs involving ECDH-ES with secp256k1.
- Suggested future action: Restrict ECDH-ES EC curves to P-256/P-384/P-521 or gate secp256k1 behind explicit extension mode.

## OKP private-key validation accepts extended lengths
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: RISK -> LOW/MEDIUM RISK
- Decision: DEFER
- Rationale: Current permissive behavior is intentional compatibility, but strict RFC-profile consumers may want tighter checks.
- Preconditions/Trigger: OKP JWK `d` uses extended seed+public representation and peer/tooling expects canonical private length only.
- Risk if not fixed: Interop mismatches on import/export with strict toolchains.
- Revisit signal: Requests for strict RFC profile or reported OKP import incompatibilities.
- Suggested future action: Add strict validation mode (or `validate_strict`) enforcing exact per-curve private key lengths.

## Duplicate DER helper logic across modules
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Maintainability cleanup only; no immediate functional risk.
- Preconditions/Trigger: Future DER behavior changes are applied in one module but not the other.
- Risk if not fixed: Drift between implementations and extra maintenance overhead.
- Revisit signal: Any DER-related bugfix touching both `src/jwk.rs` and `src/integrations/jwt_simple.rs`.
- Suggested future action: Extract shared crate-private DER helpers and remove duplicate implementations.

## WebCrypto pass-through wrappers add unnecessary indirection
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Pure simplification with minimal impact; defer until nearby edits.
- Preconditions/Trigger: Ongoing maintenance in WebCrypto algorithm builder path.
- Risk if not fixed: Small readability/maintenance tax.
- Revisit signal: Next refactor touching `build_algorithm_object*` path.
- Suggested future action: Call `build_algorithm_object_with_alg` directly at call sites and remove thin wrappers.

## RFC compliance tests rely on broad is_ok/is_err checks
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Better diagnostics are useful but broad conversion to variant-level assertions may be noisy and costly.
- Preconditions/Trigger: A test continues passing/failing for an unintended reason because only boolean result is asserted.
- Risk if not fixed: Reduced precision in regression signals for rule-targeted tests.
- Revisit signal: Confusing compliance test failures or refactors in validation error taxonomy.
- Suggested future action: Add specific error-variant assertions to highest-value rule-focused tests first.

## Weak conversion tests rely on non-empty output checks
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: HIGH -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Broader behavioral conversion tests are now present; remaining non-empty checks are narrow and mostly diagnostic.
- Preconditions/Trigger: A conversion-specific regression escapes behavioral token sign/verify checks while still producing non-empty output.
- Risk if not fixed: Residual blind spots in conversion-path diagnostics rather than broad semantic coverage gaps.
- Revisit signal: Conversion-related bug where behavioral tests pass but format/output assumptions are wrong.
- Suggested future action: Replace non-empty assertions with token verify/reject behavioral checks.

## parse_jwt format test does not assert parsed fields
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: HIGH -> LOW
- Decision: DEFER
- Rationale: Test robustness issue only; no immediate production behavior change required.
- Preconditions/Trigger: `parse_jwt` returns incorrect header/claims/signing input while test still passes.
- Risk if not fixed: False confidence in parsing correctness.
- Revisit signal: Parser changes or bug reports around JWT segment handling.
- Suggested future action: Assert ParsedJwt fields and specific error variants for malformed inputs.

## Moka expiration test has tight timing margins
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Timing margin is currently reasonable for the test shape; keep deferred unless CI variability proves otherwise.
- Preconditions/Trigger: Slow or contended CI causes sleep/TTL race variance.
- Risk if not fixed: Intermittent test flakiness.
- Revisit signal: Repeated flakes in `moka_cache_expiration`.
- Suggested future action: Increase timing margin or use deterministic time control where compatible.

## Missing direct coverage for KeySet::get_by_thumbprint
- Date added: 2026-03-05
- Source: PR #38 review thread
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Functionality is exercised indirectly; dedicated direct tests are low-risk follow-up.
- Preconditions/Trigger: Regression in thumbprint lookup behavior.
- Risk if not fixed: Direct lookup regressions may be slower to detect.
- Revisit signal: Changes to thumbprint comparison or lookup iteration behavior.
- Suggested future action: Add direct positive/negative/multi-key lookup tests for `get_by_thumbprint`.

## Convenience conversion test uses broad is_ok checks
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Primarily diagnostics/readability; current test still catches gross failures.
- Preconditions/Trigger: Semantic regressions still return `Ok`.
- Risk if not fixed: Coarse failure localization and weaker semantic guarantees.
- Revisit signal: Conversion refactors or recurring ambiguous test failures.
- Suggested future action: Split into focused per-method tests with behavioral post-conditions.

## EC parameter validation is structural only
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Stronger cryptographic validation is valuable but non-trivial and potentially backend-dependent.
- Preconditions/Trigger: Structurally valid but non-curve points or inconsistent EC material are accepted pre-crypto.
- Risk if not fixed: Invalid EC keys fail later at crypto import/use rather than early validation.
- Revisit signal: Requests for stricter validation profile or interop/security requirements.
- Suggested future action: Add optional strict EC validation mode (curve membership and consistency checks).

## EC jwt-simple key-pair conversion ignores x/y consistency with d
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Policy-sensitive tightening; strict checks may reject currently accepted inputs.
- Preconditions/Trigger: JWK provides mismatched public/private EC components.
- Risk if not fixed: Malformed EC inputs may appear acceptable until later use.
- Revisit signal: Input-quality incidents or demand for strict key consistency guarantees.
- Suggested future action: Add optional consistency check before EC key-pair conversion.

## JWKS-level kid uniqueness is not enforced in KeySet::validate
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: DEVIATION -> LOW/MEDIUM
- Decision: DEFER
- Rationale: RFC guidance is SHOULD; strict rejection may reduce compatibility.
- Preconditions/Trigger: JWKS contains duplicate `kid` values and callers rely on unambiguous `kid` selection.
- Risk if not fixed: Ambiguous key selection behavior in duplicate-kid sets.
- Revisit signal: Consumer incidents involving duplicate `kid` rollovers.
- Suggested future action: Add optional strict JWKS validation mode enforcing distinct `kid` values.

## Thumbprint API can operate on unvalidated non-canonical RSA input
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: RISK -> LOW/MEDIUM RISK
- Decision: DEFER
- Rationale: Important edge-case hardening, but API changes require design care.
- Preconditions/Trigger: Caller computes thumbprint on unvalidated RSA JWK representation.
- Risk if not fixed: Possible thumbprint mismatch across implementations for equivalent RSA keys.
- Revisit signal: Interop issues around thumbprint-derived identifiers.
- Suggested future action: Add validated/fallible thumbprint path and document raw method semantics.

## Cloudflare remote fetch timeout is not explicitly configured
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Primarily resilience hardening; platform-level worker timeout already bounds worst-case behavior.
- Preconditions/Trigger: Upstream stalls or responds very slowly, and callers need tighter app-level fail-fast semantics.
- Risk if not fixed: Longer-than-desired latency and less precise timeout classification for retry/backoff behavior.
- Revisit signal: SLO pressure, latency incidents, or need for distinct timeout error handling.
- Suggested future action: Add optional configurable timeout/abort in Cloudflare `FetchKeyStore` with typed timeout error.

## Public-only OKP enforcement is not explicit
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: HIGH -> MEDIUM
- Decision: DEFER
- Rationale: Generic key model supports both public and private OKP keys; strict RFC 8037 public-only enforcement requires context-aware validation.
- Preconditions/Trigger: A workflow treats parsed keys as public-only material but accepts keys carrying `d` without additional policy checks.
- Risk if not fixed: Potential policy/compliance mismatch in public-key-only pipelines.
- Revisit signal: Requests for strict public-key validation profile or compliance certification needs.
- Suggested future action: Add `validate_public()` or context-specific parser that rejects `d` for public-only use.

## Cache behavior policy (strict vs fail-open) for cache backend errors
- Date added: 2026-03-03
- Source: implementation planning follow-up
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> MEDIUM
- Decision: DEFER
- Rationale: Requires product-level behavior decision; immediate `Result` propagation is implemented, but policy toggles can be introduced later.
- Preconditions/Trigger: Cache backend read/write/delete errors occur under load or outage.
- Risk if not fixed: Current behavior follows direct error propagation; no configurable fail-open fallback in `CachedKeyStore` yet.
- Revisit signal: Need for high-availability fail-open operation or strict consistency mode split.
- Suggested future action: Add explicit cache error policy configuration on `CachedKeyStore`.

## Malformed key drops are silent at parse time
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: UNCOMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Mostly observability/diagnostics; core behavior is intentional permissive parsing.
- Preconditions/Trigger: Provider emits malformed entries that fail key deserialization.
- Risk if not fixed: Slower diagnosis of upstream key quality problems.
- Revisit signal: Operational incidents with unexplained key lookup misses.
- Suggested future action: Add default counters/logging for skipped keys in remote/cache flows.

## Error classification collapses into Error::Other(String)
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: MEDIUM -> MEDIUM
- Decision: DEFER
- Rationale: Valuable but cross-cutting API design change with moderate churn risk.
- Preconditions/Trigger: Consumers need typed handling (retry/alert policy) across integrations.
- Risk if not fixed: Weaker observability and less precise caller policy handling.
- Revisit signal: Requests for programmatic error matching or repeated support/debug pain.
- Suggested future action: Introduce typed error variants incrementally, keep `Other` for unknowns only.

## Timeout test may be timing-flaky
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Test uses explicit timeout with a wider server-delay margin; still timing-based but lower practical flake risk.
- Preconditions/Trigger: Slow/variable CI hosts cause timeout race around small margins.
- Risk if not fixed: Intermittent CI flakes.
- Revisit signal: Any recurring flaky failures in `test_http_keystore_timeout`.
- Suggested future action: Increase margin or migrate to deterministic timeout harness.

## x5c RSA SPKI OID excludes RSASSA-PSS OID
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Likely edge-case interoperability issue; needs policy confirmation and test vectors.
- Preconditions/Trigger: Certificate SPKI uses `id-RSASSA-PSS` OID with key material matching JWK RSA params.
- Risk if not fixed: False-negative validation for uncommon cert profiles.
- Revisit signal: User reports/certs exhibiting this OID.
- Suggested future action: Accept both `rsaEncryption` and `id-RSASSA-PSS` OIDs in RSA x5c matching path.

## x5u checks are syntactic only
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: RISK -> LOW/MEDIUM RISK
- Decision: DEFER
- Rationale: Full semantic validation requires network/certificate resolver design beyond current scope.
- Preconditions/Trigger: Consumers assume `validate()` implies full cert/key binding via x5u retrieval.
- Risk if not fixed: Trust-model misunderstanding by integrators.
- Revisit signal: Feature request for resolver-backed x5u validation.
- Suggested future action: Document current scope clearly; add optional resolver API in a future release.

## x5t/x5t#S256 binding only checked when x5c present
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: RARE
- Severity: RISK -> LOW RISK
- Decision: DEFER
- Rationale: Full binding check is not possible without certificate material.
- Preconditions/Trigger: JWK provides thumbprints without local cert chain/material.
- Risk if not fixed: Consumers may over-assume local validation guarantees.
- Revisit signal: Repeated confusion about thumbprint-only trust semantics.
- Suggested future action: Clarify docs and optionally add external-cert lookup hooks.

## `validate_for_use` collects `IntoIterator` into Vec unconditionally
- Date added: 2026-03-05
- Source: PR #43 review
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: The allocation is negligible for typical 1-2 operation inputs. Changing the signature to `&[KeyOperation]` reduces ergonomics for callers passing arrays or iterators.
- Preconditions/Trigger: Hot-path validation with many operations per call.
- Risk if not fixed: Minor unnecessary allocation on every `validate_for_use` call.
- Revisit signal: Performance profiling showing validation as a bottleneck.
- Suggested future action: Consider accepting `&[KeyOperation]` with a convenience wrapper, or use `SmallVec` to avoid heap allocation for small counts.

## `InconsistentParameters(String)` and `OperationNotPermitted.reason: String` use unstructured payloads
- Date added: 2026-03-05
- Source: PR #43 review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: All current values are static strings with no user-supplied data. Changing to `&'static str` for `reason` is low-risk but `InconsistentParameters` uses `format!()` in some call sites, requiring more design work. Related to the existing `Error::Other(String)` deferred finding.
- Preconditions/Trigger: Future contributors accidentally embed sensitive key material in error message strings.
- Risk if not fixed: Brittle programmatic matching on message text; potential future information leak.
- Revisit signal: Error taxonomy refactor or security audit of error message contents.
- Suggested future action: Change `OperationNotPermitted.reason` to `&'static str`; evaluate structured variants for `InconsistentParameters`.

## `OperationNotPermitted` may embed unsanitized `KeyOperation::Unknown` values
- Date added: 2026-03-05
- Source: PR #43 review (second round)
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: `KeyOperation::Unknown(String)` can carry arbitrary strings from untrusted JWK `key_ops`. These are joined unsanitized into `OperationNotPermitted.operations` and rendered in error `Display`. Risk is theoretical — real JWKS sources use short RFC-defined strings — but log injection is possible in adversarial inputs.
- Preconditions/Trigger: Untrusted JWKS contains `key_ops` with control characters or very long values, and errors are logged/displayed.
- Risk if not fixed: Potential log injection or noisy error output from adversarial inputs.
- Revisit signal: Security audit of error output paths or adoption in environments processing untrusted JWKS.
- Suggested future action: Truncate/escape operation strings in `Display` impl, or sanitize before storing in the error.

## `SelectionError::IncompatibleKeyType` used for structurally invalid keys
- Date added: 2026-03-05
- Source: PR #43 review (second round)
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: When `check_algorithm_suitability` returns `Error::InvalidKey` (from `params.validate()` on programmatically added keys), the `KeySelector` maps it to `SelectionError::IncompatibleKeyType` via the catch-all arm. This makes structurally invalid keys indistinguishable from type/curve incompatibility. The behavior is safe but not maximally informative.
- Preconditions/Trigger: Programmatically constructed keys with malformed params added via `add_key()` and selected via `KeySelector`.
- Risk if not fixed: Callers cannot distinguish structural invalidity from type incompatibility in selector errors.
- Revisit signal: Need for finer-grained selector error handling or addition of `SelectionError::InvalidKey` variant.
- Suggested future action: Add `SelectionError::InvalidKey(InvalidKeyError)` variant and handle `Error::InvalidKey` explicitly in the selector loop.

## Ignored Findings

(No active ignored findings.)

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

## Conversion tests still include coarse assertions in a few paths
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: HIGH -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Broader behavioral conversion tests are now present; remaining coarse checks (for example non-empty output and broad `is_ok`) are narrow and mostly diagnostic.
- Preconditions/Trigger: A conversion-specific regression escapes behavioral token sign/verify checks while still satisfying coarse assertions.
- Risk if not fixed: Residual blind spots and weaker failure localization in conversion-path diagnostics rather than broad semantic coverage gaps.
- Revisit signal: Conversion-related bug where behavioral tests pass but format/output assumptions are wrong.
- Suggested future action: Replace remaining non-empty and broad `is_ok` conversion assertions with focused behavioral checks (verify/reject, type/shape expectations).

## Example parse_jwt format test does not assert parsed fields
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: HIGH -> LOW
- Decision: DEFER
- Rationale: Applies to an example-scoped test (`examples/webcrypto_jwt_verify.rs`) rather than core library tests; still worth tightening if the example remains a reference path.
- Preconditions/Trigger: Example `parse_jwt` returns incorrect header/claims/signing input while the format test still passes.
- Risk if not fixed: False confidence in example parser correctness (not core crate behavior).
- Revisit signal: Example parser changes or user reports based on the example workflow.
- Suggested future action: Assert parsed fields and specific malformed-input errors in the example test, or remove the test if the example parser is not intended for robustness guarantees.

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

## `IncompatibleAlgorithm` fields use `String` instead of `&'static str` or `Cow`
- Date added: 2026-03-05
- Source: PR #43 review (second round)
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: `algorithm` and `key_type` are allocated via `as_str().to_string()` on every `IncompatibleAlgorithm` error. In practice, only known enum variants reach this path (unknown algorithms are rejected earlier), so the values are always `&'static str` at the source. Using `Cow<'static, str>` would avoid heap allocation without restricting future unknown-variant support. Pre-1.0 so low change cost, but also low impact since this is an error path.
- Preconditions/Trigger: Every `IncompatibleAlgorithm` error construction.
- Risk if not fixed: Unnecessary heap allocation on error paths; minor ergonomic friction in tests.
- Revisit signal: Error type ergonomics pass or performance audit of error paths.
- Suggested future action: Change both fields to `Cow<'static, str>`, or `&'static str` if unknown algorithms are guaranteed not to reach this path.

## `OperationNotPermitted` Display renders unsanitized `KeyOperation::Unknown` values
- Date added: 2026-03-05
- Source: PR #43 review (second round)
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: The `operations` field now stores `Vec<KeyOperation>` (preserving type info), but the `Display` impl still renders `KeyOperation::Unknown` values via `as_str()` without sanitization. Callers who inspect the error programmatically can distinguish known from unknown operations, but log output from `Display` may still embed control characters or long strings from adversarial inputs. Risk is theoretical — real JWKS sources use short RFC-defined strings.
- Preconditions/Trigger: Untrusted JWKS contains `key_ops` with control characters or very long values, and errors are logged via `Display`.
- Risk if not fixed: Potential log injection or noisy error output from adversarial inputs when using `Display`.
- Revisit signal: Security audit of error output paths or adoption in environments processing untrusted JWKS.
- Suggested future action: Truncate/escape `KeyOperation::Unknown` values in `Display` impl.

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

## `oth` prime validation `map_err` erases typed error variants
- Date added: 2026-03-05
- Source: PR #43 review (third round)
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: `prime.validate()` returns typed `InvalidKeyError` variants (`MissingParameter`, `InvalidParameter`), but the call site wraps them via `map_err(|e| InvalidKeyError::InconsistentParameters(format!("Invalid oth[{}]: {}", i, e)))`, collapsing the original variant into a formatted string. This is the same pattern as before the error type refactor (no regression). Fixing it requires either a dedicated `InvalidKeyError::InvalidOtherPrime { index, source }` variant or adding `source: Option<Box<dyn Error>>` to `InconsistentParameters`, both adding complexity for a narrow case.
- Preconditions/Trigger: Caller matches on specific `InvalidKeyError` variants from RSA `oth` validation (e.g., `MissingParameter("oth.r")`) and gets `InconsistentParameters` instead.
- Risk if not fixed: Less precise programmatic error handling for multi-prime RSA validation failures.
- Revisit signal: Error taxonomy refactor or need for structured `oth` validation errors.
- Suggested future action: Add `InvalidKeyError::InvalidOtherPrime { index: usize, source: Box<InvalidKeyError> }` variant, or preserve the source chain via `InconsistentParameters` with a `source` field.

## PartialEq on Key performs non-constant-time comparison of secret key material
- Date added: 2026-03-06
- Source: security review
- Validity: CONFIRMED
- Trigger likelihood: RARE
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: The library itself does not use `Key` equality in any security-sensitive path. `PartialEq` is useful for legitimate non-secret comparisons (e.g., public key deduplication in sets/maps). Constant-time helpers already exist on the lower-level types (`SymmetricParams::ct_eq`, `Base64UrlBytes::ct_eq`). A doc comment warning has been added to the `PartialEq` impl.
- Preconditions/Trigger: Application code uses `==` to compare `Key` values where one side is attacker-controlled input, enabling a timing oracle over private key bytes.
- Risk if not fixed: Downstream users may unknowingly perform timing-vulnerable comparisons of secret key material.
- Revisit signal: Requests for a `Key`-level constant-time comparison API, or evidence of downstream misuse.
- Suggested future action: Consider adding `Key::ct_eq` that delegates to the underlying params' constant-time comparison methods.

## Selector suitability bucket conflates capability and strength failures
- Date added: 2026-03-06
- Source: post-merge feedback review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: LOW/MEDIUM -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Current behavior is safe and still programmatically distinguishable through inner `IncompatibleKeyError` variants (`OperationNotPermitted` vs `InsufficientKeyStrength`). Splitting top-level `SelectionError` variants now would expand public taxonomy with limited immediate benefit.
- Preconditions/Trigger: Caller branches only on top-level `SelectionError::KeySuitabilityFailed` and does not inspect its inner `IncompatibleKeyError`.
- Risk if not fixed: Coarser selector error handling and less direct diagnostics at the top-level error enum.
- Revisit signal: Requests for finer-grained selector telemetry/routing or broader selector error taxonomy redesign.
- Suggested future action: Consider adding dedicated selector variants for capability vs strength failures (or an explicit sub-classification wrapper) while keeping backward compatibility strategy in mind.

## Ignored Findings

(No active ignored findings.)

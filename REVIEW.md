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

## Weak conversion tests rely on non-empty output checks
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: HIGH -> LOW/MEDIUM
- Decision: DEFER
- Rationale: Test-quality improvement with low immediate product risk; stronger behavioral assertions can be added incrementally.
- Preconditions/Trigger: Conversion returns structurally non-empty bytes while semantic correctness regresses.
- Risk if not fixed: Reduced regression signal in jwt-simple conversion coverage.
- Revisit signal: Any conversion-related bug escaping current tests.
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
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Low product risk; adjust only if CI noise appears.
- Preconditions/Trigger: Slow or contended CI causes sleep/TTL race variance.
- Risk if not fixed: Intermittent test flakiness.
- Revisit signal: Repeated flakes in `moka_cache_expiration`.
- Suggested future action: Increase timing margin or use deterministic time control where compatible.

## Missing direct coverage for KeySet::find_by_thumbprint
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Useful completeness improvement but not urgent.
- Preconditions/Trigger: Regression in thumbprint lookup behavior.
- Risk if not fixed: Lookup regressions may go undetected.
- Revisit signal: Changes to thumbprint or key lookup internals.
- Suggested future action: Add positive/negative/multi-key lookup tests for `find_by_thumbprint`.

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
- Suggested future action: Add optional configurable timeout/abort in Cloudflare `RemoteKeyStore` with typed timeout error.

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
- Validity: CONFIRMED
- Trigger likelihood: UNCOMMON
- Severity: MEDIUM -> LOW
- Decision: DEFER
- Rationale: Low product risk; test currently acceptable unless CI instability appears.
- Preconditions/Trigger: Slow/variable CI hosts cause timeout race around small margins.
- Risk if not fixed: Intermittent CI flakes.
- Revisit signal: Any recurring flaky failures in `test_remote_keystore_timeout`.
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

## Ignored Findings

## JWKS ingestion should always run full `Key::validate()`
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: DISPUTED
- Trigger likelihood: THEORETICAL
- Severity: HIGH -> LOW
- Decision: IGNORE
- Rationale: Current behavior is intentional permissive JWKS ingestion aligned with RFC 7517 Section 5 SHOULD-ignore semantics.
- Preconditions/Trigger: Assumes project policy should be strict-at-ingest for all metadata consistency checks.
- Risk if not fixed: None for intended permissive mode; strict-mode users should call explicit validation.
- Revisit signal: Product decision to switch to strict parsing by default.
- Suggested future action: If needed, add an opt-in strict ingestion mode rather than changing default behavior.

## `test_get_subtle_crypto` is environment-oriented noise
- Date added: 2026-03-03
- Source: second-opinion review
- Validity: PLAUSIBLE
- Trigger likelihood: UNCOMMON
- Severity: LOW -> LOW
- Decision: IGNORE
- Rationale: Test is cheap and can serve as a minimal environment smoke check.
- Preconditions/Trigger: Browser test runner lacks crypto APIs or has environmental quirks.
- Risk if not fixed: Minor CI noise only.
- Revisit signal: If this test starts flaking frequently or blocks useful signal.
- Suggested future action: Keep as-is unless flakiness trends upward.

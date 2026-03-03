# Review Backlog

This document tracks findings that were intentionally **deferred** or **ignored** during review.
It is structured so new findings can be added consistently over time.

## Entry Template

Copy this block for new items:

```md
## Finding #[N]: [Title]
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

## Finding #26: Cache behavior policy (strict vs fail-open) for cache backend errors
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

## Finding #5: Malformed key drops are silent at parse time
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

## Finding #7: Error classification collapses into Error::Other(String)
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

## Finding #11: Timeout test may be timing-flaky
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

## Finding #22: x5c RSA SPKI OID excludes RSASSA-PSS OID
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

## Finding #24: x5u checks are syntactic only
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

## Finding #25: x5t/x5t#S256 binding only checked when x5c present
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

## Finding #12: `test_get_subtle_crypto` is environment-oriented noise
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

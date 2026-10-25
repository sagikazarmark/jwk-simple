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

## Core treats `EdDSA` and `Ed25519`/`Ed448` as distinct algorithms
- Date added: 2026-10-24
- Source: jwt-simple `from_jwk` refactor (round-trip testing)
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: MEDIUM -> MEDIUM
- Decision: DEFER
- Rationale: `Key::validate_declared_algorithm_match` and the selector compare `alg` with `!=`, so a key declaring `alg: EdDSA` (the RFC 8037 name, still what jwt-simple, jose, Nimbus and most IdPs emit) does not match a request for `Algorithm::Ed25519`, and vice versa. RFC 9864 deprecates `EdDSA` in favour of the curve-specific names but expects both to be understood during the transition. The `jwt-simple` integration was the only in-crate caller affected and now requests the name the key declares (`ed25519_requested_alg`); whether the core should treat the names as equivalent (for the matching curve) is a policy decision that also affects `KeySelector` and the `web-crypto` integration, so it is deferred rather than changed in a conversion-focused PR.
- Preconditions/Trigger: `KeySet::selector(&[Algorithm::Ed25519]).select(KeyMatcher::new(Verify, Algorithm::Ed25519))` against a JWKS whose Ed25519 key declares `alg: "EdDSA"` (or a token header saying `EdDSA` against a key declaring `Ed25519`).
- Risk if not fixed: `NoMatchingKey` / `AlgorithmMismatch` for interoperable Ed25519 keys; callers must know to try both names.
- Revisit signal: Interop reports involving EdDSA keys and the selector; a decision on RFC 9864 transition policy.
- Suggested future action: In `validate_declared_algorithm_match` and the selector's declared-`alg` check, treat `EdDsa` as matching `Ed25519`/`Ed448` when the key's curve agrees (and the reverse), possibly behind an explicit strict mode. Add RFC 9864 vectors for both spellings.

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

## jwt-simple conversion impls repeat the same shape per key type
- Date added: 2026-10-25
- Source: PR #104 review (standards axis)
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: `src/integrations/jwt_simple.rs` has four forward macros (RSA/EC × public/key-pair) that differ only in the operation set and the builder called, two hand-written Ed25519 impls that mirror the macro bodies, `ec_params`/`okp_params` of identical shape, and `private: bool` flag arguments on `ec_jwk`/`okp_jwk`. A single macro parameterised on `$ops` and `$builder`, or a trait over the jwt-simple key types, would halve the module; it would also make each impl harder to read on its own, and the per-type `# Errors` lists would have to be generated or shared. Not worth the churn while the surface is still settling.
- Preconditions/Trigger: A fix applied to one macro (ordering of checks, a new error case) and missed in another.
- Risk if not fixed: Drift between the conversion paths; the kind of inconsistency that `require_private_key` just fixed.
- Revisit signal: The next change that touches more than two of the macros, or support for another key family (ML-DSA/AKP) that would add a fifth.
- Suggested future action: Consolidate into one macro (or a small trait) when the next structural change lands; keep the `# Errors` docs per impl.

## Publishing direction has no `examples/` entry
- Date added: 2026-10-25
- Source: PR #104 review (standards axis, CLAUDE.md §3 "integration test or example")
- Validity: CONFIRMED
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: `Key: TryFrom<&jwt-simple key>` is covered by a compiled (not `no_run`) doctest in `src/lib.rs`, a README snippet, and the in-module `publish_and_consume_a_key_set` test that goes generate → `KeySet` → JSON → select → convert → verify. An `examples/` program would show the same lines again; `examples/jwt_verify.rs` is the natural home if one is wanted.
- Preconditions/Trigger: A reader looks only at `examples/` to learn the publishing API.
- Risk if not fixed: Discoverability only; behaviour is tested.
- Revisit signal: A user question that the README and crate docs did not answer, or an `examples/` reorganisation.
- Suggested future action: Add the publishing direction to `examples/jwt_verify.rs` (generate a key pair, publish the public key, verify against the published set).

## jwt-simple's RSA `to_jwk()` leaves BigNum copies behind
- Date added: 2026-10-25
- Source: PR #104 review (security axis)
- Validity: PLAUSIBLE
- Trigger likelihood: COMMON
- Severity: LOW -> LOW
- Decision: DEFER
- Rationale: Upstream. `Key: TryFrom<&RS*KeyPair>` parses jwt-simple's `to_jwk()`; with the `pure-rust` backend that export goes through `superboring`'s `BigNum` clones (`superboring/src/implementation.rs`, `to_vec` on `d`, `p`, `q`, `dp`, `dq`, `qi`), which are not zeroized. Everything this crate allocates on that path is `Zeroizing`, and the forward direction (`from_jwk`) borrows and wipes inside jwt-simple. Nothing to fix here without bypassing jwt-simple's export, which is the point of the integration.
- Preconditions/Trigger: RSA key pair converted to `Key` on the `pure-rust` backend; an attacker who can read freed heap of the process.
- Risk if not fixed: RSA private components may linger in freed memory after a publishing conversion. Same exposure as any jwt-simple RSA signing operation on that backend.
- Revisit signal: An upstream fix in superboring/jwt-simple, or a request to document the integration's memory-hygiene boundary more prominently.
- Suggested future action: Report upstream; if accepted, bump the minimum jwt-simple version and note it in the module docs.

## Ignored Findings

(No active ignored findings.)

## Resolved Findings

Previously deferred findings that a later change closed, kept for traceability.

## Duplicate DER helper logic across modules
- Date added: 2026-03-03
- Resolved: 2026-10-24
- Resolution: The `jwt-simple` integration no longer encodes DER at all. Conversions build a reduced JWK (`kty`, `crv`, key material, `kid`) and go through jwt-simple 0.15's `from_jwk` constructors, so the PKCS#1 encoders in `src/integrations/jwt_simple.rs` and the `pkcs1` dependency are gone. The only DER code left is the x5c SPKI matcher in `src/jwk.rs`; there is nothing to drift from.

## EC jwt-simple key-pair conversion ignores x/y consistency with d
- Date added: 2026-03-03
- Resolved: 2026-10-24
- Resolution: `ES256KeyPair`/`ES384KeyPair`/`ES256kKeyPair::from_jwk` derive the public point from `d` and require it to match `x`/`y`, so a mismatched key pair is now rejected with `JwtSimpleKeyConversionError::Import` (test `ec_key_pair_conversion_rejects_public_point_not_derived_from_d`). The same import path checks Ed25519 `d` against `x`. Core `EcParams::validate` is unchanged (see "EC parameter validation is structural only"); the consistency check lives in the backend, which is where the curve arithmetic is.

## Cloudflare remote fetch timeout is not explicitly configured
- Date added: 2026-03-03
- Resolved: 2026-10-23
- Resolution: `cloudflare::FetchKeyStore` was removed with the `HttpTransport` refactor. The Workers path is now `HttpKeyStore` over `TowerTransport<tower_worker_fetch::FetchService>`, where a per-request timeout is a `tower_worker_fetch::Timeout` request extension (`AbortSignal.timeout()` under the hood) and surfaces as a transport error whose source downcasts to `tower_worker_fetch::Error` (`is_timeout()`); `TowerTransport::with_classifier` maps it to `TransportErrorKind::Timeout`. The README Workers example and `tests/workers.rs` show the pattern.

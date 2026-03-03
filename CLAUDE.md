# Claude Review Guidelines

This file provides structured review criteria for Claude Code when reviewing pull requests in this repository.

## About This Repository

`jwk-simple` is a security-sensitive Rust library for JWK/JWKS handling targeting RFC 7517, 7518, 7638, 8037, and 9864. It also supports WebCrypto and integrates with `jwt-simple` for JWT workflows. The library runs on both native (x86/arm) and WASM (via `wasm-bindgen`) targets.

## Review Process

See `AGENTS.md` for general review conventions. In particular:
- Ignore findings that are already listed in `REVIEW.md`.
- If a finding is deferred or ignored during review, add it to `REVIEW.md` using the template defined there.

---

## 1. Compliance Verification

Cross-check changes against the RFCs this library targets:

- **RFC 7517** — JSON Web Key (JWK): key structure, `kty`, `use`, `key_ops`, `alg`, `kid`, `x5*` parameters
- **RFC 7518** — JSON Web Algorithms (JWA): algorithm identifiers, key requirements per algorithm, curve names
- **RFC 7638** — JWK Thumbprint: canonical member ordering, required members per `kty`, SHA-256 hashing
- **RFC 8037** — OKP Keys (Ed25519/Ed448/X25519/X448): `crv`, `x`, `d` parameters and constraints
- **RFC 9864** — Ed25519/Ed448 JOSE algorithms and EdDSA deprecation guidance

Specific things to verify:
- New algorithm identifiers or curve names match IANA-registered values exactly (case-sensitive).
- Required JWK members are validated before use; missing members return structured errors.
- Changes to validation logic do not silently relax RFC MUST/MUST NOT requirements.
- Deferred or ignored findings in `REVIEW.md` are not being quietly re-introduced or worked around without a corresponding `REVIEW.md` update.
- Flag any breaking changes to public API surfaces, even pre-1.0, so they can be noted in the changelog.

---

## 2. Security Checks

### Key Material Handling

- `zeroize` / `Zeroize` / `ZeroizeOnDrop` must be applied to all types holding private key bytes (`d`, `k`, raw byte buffers).
- `Debug` implementations for types with key material must redact sensitive fields (use `[redacted]` or omit).
- Private key bytes must never appear in log output, error messages, or `Display` implementations.

### Algorithm Validation

- Algorithm validation must remain centralized in the canonical algorithm-aware validation gate (see `Key::validate_for_alg` and related checks). Verify that new algorithm paths do not bypass the central validation gate.
- New algorithms added to the `alg` field must be registered in the centralized validation map, not handled with ad-hoc string matching.

### Base64 Operations

- All base64 encode/decode for key material must use `base64ct` (constant-time). The regular `base64` crate must not be introduced for key-material paths.
- Verify that new base64 operations import from `base64ct`, not from any other base64 crate.

### Error Messages

- Error messages and `Display` output must not leak key bytes, raw private key material, or internal implementation paths that could aid an attacker.
- Error variants should carry structured data (key type, algorithm ID, curve name) rather than formatted strings containing raw input.

### Timing Considerations

- Flag any early-exit conditions in code that compares sensitive values (e.g., thumbprints, key IDs used for security decisions). These should use constant-time comparison.
- `sha2` / digest operations used for thumbprints are fine; highlight if new comparison logic is introduced on digest outputs.

### Dependency Hygiene

- If the PR adds or upgrades dependencies, note whether `cargo audit` advisories are relevant to the changed code paths.
- Prefer `default-features = false` for new optional dependencies.

---

## 3. UX / API Sanity Check

### API Consistency

- New public types, methods, and trait implementations should follow the naming and ergonomics patterns of existing APIs (e.g., `Key`, `KeySet`, `jwks::KeyStore`, `HttpKeyStore`, `CachedKeyStore`).
- Builder patterns should be consistent with existing builders.
- Method names should follow Rust idioms: `From`/`Into` (and commonly `from_*`/`into_*`) are for infallible conversions; use `TryFrom`/`TryInto`, `try_*`, or `parse_*` for conversions that can fail.

### Error Types

- New error conditions should introduce typed variants rather than collapsing into `Error::Other(String)`. The `Error::Other` variant is a known deferred issue; new code should not make it worse.
- Public error enums (and structs) should be `#[non_exhaustive]` to allow future additions without breaking callers.

### Documentation

- All new or changed public items (structs, enums, traits, methods, type aliases) must have `///` doc comments.
- Doc comments should include a one-line summary, and for non-trivial methods, a description of panics, errors, and usage examples.
- If a method has a non-obvious invariant or RFC citation, include it in the doc comment.

### Feature Flag Correctness

- Code that uses WASM-only APIs (`web-sys`, `wasm-bindgen`, `js-sys`) must be guarded with `#[cfg(target_arch = "wasm32")]` or the appropriate feature gate.
- Code gated on optional features (`moka`, `cloudflare`, `http`, `jwt-simple`, `web-crypto`) must not compile or link when the feature is disabled.
- New platform-specific code paths should have a corresponding test that compiles under the correct target/feature combination.

### Examples and Tests

- Significant new public features should have either an integration test demonstrating the intended usage pattern or a new entry in `examples/`.
- Tests should assert specific error variants (not just `is_err()`) and specific output values (not just `is_ok()`) where feasible.
- RFC compliance tests should use test vectors from the relevant RFC appendix where available.

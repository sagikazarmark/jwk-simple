# API Layer Proposal Review Notes

This companion document maps reviewer concerns to the current `API_LAYER_PROPOSAL.md` structure.

## Purpose

- Provide fast concern-to-resolution traceability.
- Show what is resolved vs intentionally deferred.
- Keep terminology synchronized with the current proposal revision.

---

## Concern-to-resolution mapping

### 1) Discovery helpers are used as trust gates

- Addressed in:
  - `Executive summary`
  - `Selected architecture`
  - `Discovery contract (normative)`

Resolution:

- Trust boundary is explicit: discovery (`get/find`) vs strict selection (`selector(...).select(...)`).

Status: **Resolved in proposal text**.

---

### 2) Strict contract must be concrete and testable

- Addressed in:
  - `Strict selection contract (normative)`
  - `Test plan`

Resolution:

- Contract specifies intent checks, algorithm checks, allowlist checks for verify, ambiguity fail-closed, and terminal outcomes.

Status: **Resolved in proposal text**.

---

### 3) Verify allowlist coupling should not block non-verify operations

- Addressed in:
  - `Complete v1 API (proposed)`
  - `Constructor behavior note`
  - `Strict selection contract (normative)`

Resolution:

- Selector construction does not fail on empty allowlist.
- Empty verify allowlist is enforced only when `select(..., op=KeyOperation::Verify, ...)` is used.

Status: **Resolved in proposal text**.

---

### 4) Typed errors should preserve diagnostic detail

- Addressed in:
  - `Complete v1 API (proposed)`
  - `Strict selection contract (normative)`

Resolution:

- `SelectionError` includes `KeyValidationFailed(ValidationError)`.
- `AlgorithmMismatch` and `AmbiguousSelection` include context payloads.

Status: **Resolved in proposal text**.

---

### 5) Operation naming/type drift (`Operation` vs `KeyOperation`)

- Addressed in:
  - `Complete v1 API (proposed)`
  - `Type naming alignment (cosmetic, explicit)`

Resolution:

- Proposal now uses `KeyOperation` for v1 selector APIs.
- Cosmetic type renames are explicitly phased/deferred.

Status: **Resolved in proposal text**.

---

### 6) Ambiguity behavior must be strict and explicit

- Addressed in:
  - `Strict selection contract (normative)`
  - `Determinism and ambiguity`
  - `Test plan`

Resolution:

- Strict path always errors on multiple matches.
- Optional tie-break remains deferred and explicitly non-default.

Status: **Resolved in proposal text**.

---

### 7) Structural validation scope should be explicit

- Addressed in:
  - `Structural validation scope (explicit)`

Resolution:

- `select(...)` does not perform full set-wide `validate_structure()`.
- Strict selection depends on operation/algorithm checks; full structure validation remains explicit ingestion choice.

Status: **Resolved in proposal text**.

---

### 8) Integration guidance needs allowlist source and signing example

- Addressed in:
  - `Integration guidance (jwt-simple, web_crypto)`

Resolution:

- Proposal states allowlist source is caller/app configuration.
- Includes verification and signing examples.

Status: **Resolved in proposal text**.

---

### 9) KeyFilter should cover legacy find dimensions

- Addressed in:
  - `Complete v1 API (proposed)`
  - `Rename and deprecation table`

Resolution:

- `KeyFilter` includes `kty` and `key_use` fields.

Status: **Resolved in proposal text**.

---

### 10) Review notes staleness

- Addressed by this document rewrite.

Resolution:

- Removed stale references (`select_*`, `PolicyError`, old section names).
- Mapping now uses current proposal section titles.

Status: **Resolved**.

---

### 11) Bypass risk via raw discovery access remains possible

- Addressed in:
  - `Discovery contract (normative)`
  - `Integration guidance`

Resolution:

- Contract/docs state discovery is non-security.
- Integration migration mandates strict selector path.

Status: **Partially resolved** (API cannot prevent all misuse; enforcement relies on integration discipline, examples, and tests).

---

## Decisions captured

- Keep a single `KeySet`.
- Keep one canonical strict selection method: `select(KeyMatcher)`.
- Keep one discovery filter entrypoint: `find(KeyFilter)`.
- Enforce verify allowlist at verify selection time.
- Keep strict ambiguity behavior fail-closed.
- Keep v1 scope minimal; defer tie-break mode and custom policy trait.

---

## Remaining open items

1. Whether to add a blessed strict helper for kid-less JWT verification that iterates strict-compatible candidates internally.
2. Whether to add operation-specific convenience wrappers while keeping `select(...)` canonical.
3. Whether and when to introduce a custom policy trait in a future version.
4. Whether to phase additional cosmetic renames in a later release.

---

## Suggested reviewer checklist

- Do all security-sensitive integration paths use strict `select(...)`?
- Is verify allowlist enforcement applied when `op == KeyOperation::Verify`?
- Are selection errors typed and context-rich?
- Is ambiguity handled as an error in strict path?
- Are weak-key and mismatch paths covered by tests?
- Are proposal and examples aligned with current API names?

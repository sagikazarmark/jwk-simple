# AGENTS

## Code style

- In doc examples and test code, always import re-exported types from the crate root (`jwk_simple::Key`) rather than the full module path (`jwk_simple::jwk::Key`). All public types from `jwk_simple::jwk` are re-exported at the crate root.

## Review process

- Reviewers should ignore findings that are already listed in `REVIEW.md`.
- If a finding is marked as ignored or deferred during a review round, add it to `REVIEW.md`.

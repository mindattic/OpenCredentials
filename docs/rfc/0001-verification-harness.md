---
codex: 1
project: OpenCredentials
code: OC
layer: rfc
status: in-progress
updated: 2026-10-03
---

# RFC 0001 — A verification harness for the non-retention and disclosure invariants

## Problem

OpenCredentials's most important properties — **non-retention of secrets** ([OC-LAW-1](../BIBLE.md#OC-LAW-1)), **review-before-disclosure** ([OC-LAW-2](../BIBLE.md#OC-LAW-2)), and **race-safe concurrency** ([OC-LAW-5](../BIBLE.md#OC-LAW-5)) — were guaranteed only by code structure and reviewer discipline. `OpenCredentials.Tests` now proves the disclosure stories (auto-inform gate, idempotency, advisory-first routing); non-retention, pattern matching, remediation and concurrency are still unproven, so a refactor could silently regress those guarantees.

## Options compared

1. **No tests, rely on review.** Status quo. Cheap, but the prime directive is unprotected and "done" can never be honestly claimed.
2. **Full end-to-end tests hitting GitHub.** Highest fidelity, but slow, rate-limited, non-deterministic, and would require a live PAT in CI — at odds with the project's own ethics.
3. **Unit/integration tests against a faked `GitHubClient` + in-memory or LocalDB EF context.** Deterministic, fast, no network, isolates each invariant. Requires making `GitHubClient` substitutable (interface or virtual seam) — a source change, so out of scope for the docs migration but the recommended next step.

## Decision

Pursue **Option 3**. Add a `OpenCredentials.Tests` project that fakes the GitHub boundary and exercises the `Shared` engine + `Scraper` directly. Prioritize, in order: non-retention, pattern matching, auto-inform gate, notice idempotency, remediation transitions, concurrency claim.

## What NOT to do

- Do **not** put a real credential (even an expired one) in a fixture. Use synthetic strings shaped to match the regexes.
- Do **not** call any provider API or open real GitHub issues from tests.
- Do **not** weaken `Scraper.Fingerprint`'s drop-after-hash structure to make it more testable; test the observable output (only fingerprints are emitted), not internals that would invite retention.

## Phased plan (with risk)

1. **Seam — done:** `GitHubClient` has an internal constructor taking an `HttpMessageHandler`; tests inject a fake GitHub API.
2. **Harness — done:** [`v2/Tests/OpenCredentials.Tests.csproj`](../../v2/Tests/OpenCredentials.Tests.csproj) (xUnit + bUnit, in-memory EF).
3. **Invariant tests (medium):** auto-inform gate done; non-retention next.
4. **Coverage (medium):** idempotency done; patterns, remediation, concurrency remain.

## Graduates into

- [BIBLE §6 — Verified state](../BIBLE.md#OC-§6) (flip evidence from "build only" to test-cited).
- [USER_STORIES.md](../USER_STORIES.md) — promotes OC-US-A1/A2, B1/B3, C1, E3 from 🟡 to ✅ as each test lands.

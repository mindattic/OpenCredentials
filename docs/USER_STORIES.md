---
codex: 1
project: OpenCredentials
code: OC
layer: stories
status: living
updated: 2026-10-03
---

# OpenCredentials — User Stories

> ✅ done (shipped & tested) · 🟡 partial (shipped, not test-proven) · ⬜ planned.
> Every ✅ cites the test that proves it. Tests live in
> [`v2/Tests/OpenCredentials.Tests.csproj`](../v2/Tests/OpenCredentials.Tests.csproj) (fake GitHub API +
> in-memory EF; `dotnet test OpenCredentials.sln`). They cover disclosure so far; other shipped behavior
> is 🟡 with the strongest available evidence ([RFC 0001](rfc/0001-verification-harness.md), [OC-§7](BIBLE.md#OC-§7)).

## Epic A — Detection

- **OC-US-A1 🟡** As an operator, I can scan public GitHub for leaked credentials across many providers (LLM, cloud, VCS, payments, comms, DB URIs, private keys), so I find real exposures. *Given a GitHub PAT, When I run `opencreds --headless`, Then it searches each provider needle, fetches matches, and records `Finding` rows.* *(Shipped: `Scraper.RunAsync` + `Patterns.All` in [`v2/Cli/Scraper.cs`](../v2/Cli/Scraper.cs), [`v2/Shared/Patterns.cs`](../v2/Shared/Patterns.cs). No verifying test.)*
- **OC-US-A2 🟡** As a researcher, the scanner records metadata only and never retains the raw secret, so the project is IRB-defensible ([OC-LAW-1](BIBLE.md#OC-LAW-1)). *Given a match, When it is recorded, Then only SHA-256 + 16-char prefix + length persist.* *(Shipped: `Scraper.Fingerprint`, `rawKey = null!` after hashing. NO automated test asserts non-retention — this invariant is the #1 thing to test.)*
- **OC-US-A3 🟡** As an operator, I can opt into high-false-positive PlainTextPassword patterns separately, so they never pollute the default scan. *Given `--include-passwords`, When I scan, Then `Patterns.WithPasswords()` is used; otherwise it is not.* *(Shipped: `Patterns.WithPasswords`, gated by the `--include-passwords` flag in [`v2/Cli/Program.cs`](../v2/Cli/Program.cs).)*

## Epic B — Disclosure

- **OC-US-B1 ✅** As an operator, the scanner never auto-discloses until I flip a category on, so innocent repos aren't harmed ([OC-LAW-2](BIBLE.md#OC-LAW-2)). *Given all exposure types default `auto_inform=false`, When the notify pass runs, Then it sends nothing.* *(Shipped: `Scraper.SendPendingNoticesAsync` auto-inform gate; seed defaults `AutoInform=false` in [`v2/Shared/Db.cs`](../v2/Shared/Db.cs). verified by `Notify_pass_sends_nothing_while_every_type_is_auto_inform_off`.)*
- **OC-US-B2 ✅** As an operator, I can file a courtesy issue on a leaker's repo with the fingerprint (never the secret) when it has no private vulnerability reporting, so they can rotate. *Given a finding on a repo without private reporting, When I send a notice, Then a GitHub issue is opened and a `github_issue` Notice recorded.* *(Shipped: `NoticeService.SendAsync` → `GitHubClient.OpenIssueAsync`. verified by `Repo_without_private_reporting_falls_back_to_public_issue`; also `Notify_pass_falls_back_to_public_issue_when_private_reporting_is_off`.)*
- **OC-US-B3 ✅** As an operator, sending a notice twice for the same finding is a no-op on either channel, so I never spam a repo. *Given an existing `sent` notice, When I send again, Then it returns `Skipped=true` without calling GitHub.* *(Shipped: idempotency checks in `NoticeService.SendAsync` and `SendVulnerabilityReportAsync`. verified by `Sending_an_issue_twice_is_a_no_op`; also `Finding_already_disclosed_by_issue_is_skipped_without_any_GitHub_call`, `Finding_already_disclosed_by_advisory_is_skipped_without_any_GitHub_call`.)*
- **OC-US-B4 ✅** As an operator, disclosure goes through GitHub's private vulnerability reporting when the repo has it enabled and falls back to a public issue otherwise, so security findings use the private channel first. *Given a repo with private vulnerability reporting, When a notice is sent from the CLI notify pass or the Findings page, Then a `github_advisory` Notice is recorded instead of a public issue; a transient advisory failure is recorded as failed and never goes public.* *(Shipped: `NoticeService.SendVulnerabilityReportAsync` in [`v2/Shared/NoticeService.cs`](../v2/Shared/NoticeService.cs), called by `Scraper.SendPendingNoticesAsync` and the Findings page Send/Retry button. verified by `Repo_with_private_reporting_gets_a_private_advisory_and_no_public_issue`; also `Transient_advisory_failure_never_goes_public`, `Rate_limited_403_is_a_transient_failure_not_unavailable`, `Notify_pass_discloses_through_private_advisory_first`, `Send_button_files_a_private_advisory_not_a_public_issue`.)*

## Epic C — Remediation tracking

- **OC-US-C1 🟡** As a researcher, each run re-checks existing findings to see if the leak was removed, so I can measure time-to-remediate. *Given prior findings, When the recheck pass runs, Then it re-fetches + re-hashes and writes a `RemediationCheck` (`present`/`removed`/`repo_gone`/`file_gone`).* *(Shipped: `Scraper.RecheckRemediationsAsync`.)*
- **OC-US-C2 🟡** As an operator, remediation rechecks are capped per run, so a large DB doesn't burn the whole API budget. *Given `--max-rechecks N`, When the pass runs, Then at most N findings are re-checked, stalest first.* *(Shipped: `_maxRechecks` ordering by `CheckedAtUtc`.)*

## Epic D — Review UI (Blazor)

- **OC-US-D1 🟡** As a reviewer, I see a live, paginated table of every finding with notice + remediation status, so I can triage. *(Shipped: [`v2/Blazor/Components/Pages/Findings.razor`](../v2/Blazor/Components/Pages/Findings.razor), 3s live polling.)*
- **OC-US-D2 🟡** As a researcher, I see KPIs and charts (cumulative findings/notices/remediations, time-to-remediate, by-provider, status donut), so I can report aggregates. *(Shipped: [`v2/Blazor/Components/Pages/Visualizations.razor`](../v2/Blazor/Components/Pages/Visualizations.razor) + [`v2/Blazor/VizData.cs`](../v2/Blazor/VizData.cs).)*
- **OC-US-D3 🟡** As an operator, I can pause/resume the scanner and toggle per-type auto-inform from the UI, so I control disclosure without restarting the CLI. *(Shipped: [`v2/Blazor/Components/Pages/Settings.razor`](../v2/Blazor/Components/Pages/Settings.razor) writing `ScannerControl` + `SetAutoInform`.)*

## Epic E — Operations

- **OC-US-E1 🟡** As an operator, the scanner loops forever and never crashes on a 403, so it can run unattended ([OC-LAW-3](BIBLE.md#OC-LAW-3)). *(Shipped: `RunLoopAsync` + `GitHubClient.HandleRateLimitAsync`.)*
- **OC-US-E2 🟡** As a CI user, `--headless` with no `--loop` runs a single pass and exits non-zero on failure, so it is automatable. *(Shipped: one-shot branch in [`v2/Cli/Program.cs`](../v2/Cli/Program.cs).)*
- **OC-US-E3 🟡** As an operator, multiple scanners can run concurrently against one DB without double-scanning a file ([OC-LAW-5](BIBLE.md#OC-LAW-5)). *(Shipped: atomic `Db.ClaimScan`/`ReleaseScan` via PK uniqueness. Concurrency is asserted by structure, not by a test.)*

## Priority backlog

Dependency-ordered toward a test-proven, IRB-defensible pipeline:

1. ⬜ **Non-retention test** proving `Scraper.Fingerprint`/`ScanContent` emit only fingerprints (OC-US-A2 → ✅).
2. ⬜ **Pattern-matching tests** with synthetic-key fixtures per provider (OC-US-A1 → ✅).
3. ⬜ **Remediation status-transition test** over a fake `GitHubClient` (OC-US-C1 → ✅).
4. ⬜ **Concurrency test** for `ClaimScan` race (OC-US-E3 → ✅).

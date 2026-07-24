---
codex: 1
project: OpenCredentials
code: OC
layer: amendments
status: living
updated: 2026-07-23
---

# OpenCredentials — Amendments (append-only; amendment wins over the bible)

> Append-only change log. Never rewrite an amendment; supersede it with a new one. Beyond ~25,
> fold into [BIBLE.md](BIBLE.md) and start a new epoch (note the git tag). History stays in git.

## OC-A1 — Adopt the Codex documentation standard (supersedes —)

**What changed.** Installed the MindAttic Codex canonical-documentation layout: [`docs/BIBLE.md`](BIBLE.md) (L0), this amendments log (L1), [`docs/USER_STORIES.md`](USER_STORIES.md) (L2), [`docs/rfc/`](rfc/) design notes, [`docs/data/`](data/) canon-as-data (L5), a generated [`docs/BIBLE.digest.md`](BIBLE.digest.md), the [`tools/codex.ps1`](../tools/codex.ps1) doctor/digest CLI, and the `.claude/hooks/inject-digest.ps1` SessionStart hook.

**Why.** Prior to this, the only canon was prose in `README.md` plus the retired-v1 pointer in `v1/DEPRECATED.md` — facts (architecture, laws, status) were not addressable by stable ID and "done" was asserted, not verified.

**Migration.**
- `README.md` is unchanged and remains the build/run reference; [BIBLE.md](BIBLE.md) now owns "how to think about the system."
- The org-wide laws are inherited by reference from [`MindAttic.HouseRules.md`](../../MindAttic.HouseRules.md); only OpenCredentials-specific laws live in [BIBLE §5](BIBLE.md#OC-§5).
- The `ExposureTypes` catalog (previously duplicated between `README.md` and [`v2/Shared/Patterns.cs`](../v2/Shared/Patterns.cs)) is now canon-as-data at [`docs/data/exposure_types.json`](data/exposure_types.json) with a schema; prose cites entities by `id`.
- Status was set honestly: with no automated test project present, all shipped stories are `🟡`, not `✅` ([HOUSE-LAW-8](../../MindAttic.HouseRules.md#HOUSE-LAW-8)).

**Documentation correction (not a code change).** The `README.md` non-retention section cites `v2/Cli/Scraper.cs` method `ScanItemAsync`; the actual method is `ScanContent` (called from `RunAsync`). [BIBLE §4.3](BIBLE.md#OC-§4) cites the real symbol. The README wording is left untouched per the no-source-edit constraint of this migration; a future RFC may correct it.

## OC-A2 — Project renamed from FractionsOfACent to OpenCredentials; advisory-first disclosure added (supersedes —)

**What changed.**

1. **Complete rename**: every internal identifier was updated from `FractionsOfACent` / `FOAC` to `OpenCredentials` / `OC` — namespaces, assembly names, DB name (`OpenCredentials`), CLI binary (`opencreds`), settings path (`%APPDATA%\MindAttic\OpenCredentials\`), env var (`OPENCREDS_DB`), connection-string key (`ConnectionStrings:OpenCredentials`), config section (`OpenCredentials`), and the GitHub repo. The solution file, all csproj files, and all context class names (`OpenCredentialsContext`) are updated. All stable codex IDs are migrated (`OC-LAW-*`, `OC-US-*`, `OC-A*`, `OC-§*`).

2. **Advisory-first disclosure** (`NoticeService.SendVulnerabilityReportAsync`): the responsible-disclosure path now attempts GitHub's private vulnerability reporting API (`POST /repos/{owner}/{repo}/security-advisories`) before falling back to a public GitHub issue. If the target repo has private vulnerability reporting enabled, the disclosure is private (preferred — less public noise, correct disclosure channel for security findings). A 404 / 403 / 422 response signals the feature is unavailable and the method transparently falls back to `SendAsync` (public issue). The channel field in the `Notices` table records which path was taken (`github_advisory` vs `github_issue`). New types added to `GitHubClient`: `AdvisoryResult`, `AdvisoryCreateRequest`, `AdvisoryCreateResponse`.

**Why.** The old name `FractionsOfACent` was an early working title. `OpenCredentials` better communicates the project's mission — finding and disclosing open/exposed credentials — to external observers (repo owners receiving notices, potential contributors). The advisory-first path is the correct responsible-disclosure channel per [GitHub's private vulnerability reporting docs](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability); it should be preferred wherever available.

**Migration note.** The SQL Server LocalDB database must be recreated under the new name (`OpenCredentials`). Run `dotnet ef database drop` against the old `OpenCredentials.Shared` project (now renamed) or manually drop the `FractionsOfACent` LocalDB database, then `dotnet run --project v2/Cli` to auto-apply migrations against the new `OpenCredentials` database.

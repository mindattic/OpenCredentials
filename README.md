# OpenCredentials

Public-service credential-leak detection for GitHub: find exposed API keys and connection strings, file a courtesy notice with the repo owner, and measure whether the leak gets fixed, without ever storing the secret.

[![.NET 9](https://img.shields.io/badge/.NET-9-512BD4)](https://dotnet.microsoft.com/) [![Blazor Server](https://img.shields.io/badge/UI-Blazor%20Server-5C2D91)](#web-ui) [![SQL Server LocalDB](https://img.shields.io/badge/storage-SQL%20Server%20LocalDB-CC2927)](#how-it-works) [![Status active](https://img.shields.io/badge/status-active-2ea44f)](docs/BIBLE.md) [![License none](https://img.shields.io/badge/license-none-lightgrey)](#license)

```text
                ┌──────────────────────────────────────────────────┐
                │                                                  │
   GitHub  ─►   1. Scan  ─►  2. Notify (gated)  ─►  3. Recheck  ───┘
   Code Search                                       (every run)
   + Contents      └─ writes findings           └─ writes
                                                   remediation_checks
   leaker repo  ◄─── advisory or issue (only when auto-inform is on)

   raw match ─► SHA-256 + scheme prefix ─► discarded inside one function
```

OpenCredentials runs on your own machine against public GitHub; there is no hosted instance. Build it and open the review UI with `.\run.bat`.

## Why

- Close the gap between provider secret scanning and nobody at all: a third party that sees the leak, tells the owner politely, and checks back.
- Tell owners without making things worse: the notice carries only a SHA-256 fingerprint and scheme prefix, never the secret.
- Stay out of trouble with false positives: no notice goes out for a category until a human turns auto-inform on.
- Get research numbers for free: leak rate per provider, time to remediate and notice-to-fix conversion fall out of normal runs.
- Run it unattended: a headless loop rides out GitHub rate limits and can be paused from the web UI.

## Features

### Scan

- Searches GitHub Code Search for regex-matched credential patterns across four exposure types: API keys, connection strings, private keys and (opt-in) plaintext passwords.
- Covers LLM and cloud API keys, GitHub PATs, payment, messaging and package-registry tokens, database URIs with inline credentials, and PEM private keys (`v2/Shared/Patterns.cs`).
- Hashes each raw match with SHA-256 and drops it in the same function; nothing is validated against a provider API.

### Notify

- `NoticeService` tries GitHub's private security-advisory channel first and falls back to a public courtesy issue on the leaker's own repo.
- Fires automatically only for exposure types switched to auto-inform; any finding can also be sent by hand from the web UI.

### Recheck

- Every pass re-fetches previously found files to see whether the hash is still there, recording each check so time-to-remediate and check-backs-until-fixed can be measured.

### Review UI

- Findings: a paginated, live-updating table of every finding with notice and remediation status and a per-row Send button.
- Visualizations: KPIs plus cumulative, time-to-remediate, check-back, per-provider and remediation-status charts.
- Settings: scanner pause and resume, scanner heartbeat age, and per-type auto-inform toggles.

## Quick start

Prerequisites: the .NET 9 SDK, SQL Server LocalDB, and a fine-grained GitHub PAT with public-repo read (plus `Issues: write` if you want notices filed).

```powershell
git clone https://github.com/mindattic/OpenCredentials.git
cd OpenCredentials
dotnet build OpenCredentials.sln -c Release

$env:GITHUB_TOKEN = "github_pat_..."

# One scan / notify / recheck pass, then exit
dotnet run --project v2/Cli -- --headless

# Review what it found
.\run.bat
```

The CLI writes findings to the LocalDB `OpenCredentials` database and regenerates `findings.htm`. `run.bat` starts the web UI and opens `http://localhost:50677/` in your browser once it is listening. Nothing is sent to anyone until you turn on auto-inform for a category or press Send on a finding.

## How it works

Each invocation runs three phases in order and stores everything in the SQL Server LocalDB `OpenCredentials` database (override with `--connection` or the `OPENCREDS_DB` env var):

1. Scan. Query GitHub Code Search for each pattern's needle, fetch matching files, run the regexes, and store metadata plus the SHA-256 of each match.
2. Notify. For exposure types with auto-inform on, file an advisory or issue for unnotified findings, up to `--max-notices` per run.
3. Recheck. Re-fetch earlier findings and record whether the hash is still present, up to `--max-rechecks` per run.

The default mode loops every 60 seconds with an interactive menu; `--headless` drops the menu and pairs with `--loop` for daemon or sidecar use.

```text
   ┌─────────────┐        ┌──────────────────────────────┐        ┌──────────────┐
   │ Cli         │        │ Shared (library)             │        │ Blazor       │
   │ `opencreds` │──uses──│ Db · Scraper-DTOs · Patterns │──uses──│ Server UI    │
   │ scan/notify │        │ NoticeService · GitHubClient │        │ Findings/Viz │
   │ /recheck    │        │ OpenCredentialsContext (EF)  │        │ /Settings    │
   └──────┬──────┘        └───────────────┬──────────────┘        └──────┬───────┘
          │                               │                              │
          └──────────────► SQL Server LocalDB `OpenCredentials` ◄────────┘
                               (ScannerControl row coordinates pause/resume)
```

Three projects, one solution (`OpenCredentials.sln`):

- `OpenCredentials.Shared` (`v2/Shared/`): EF Core entities, `OpenCredentialsContext`, the `Db` persistence facade, detection patterns (`Patterns.cs`), `NoticeService`, `GitHubClient`, `GitHubTokenProvider`, settings. Used by both front doors.
- `OpenCredentials.Cli` (`v2/Cli/`): the `opencreds` executable. Argument parsing, interactive and headless modes, the three-phase pipeline (`Scraper.cs`), the interactive menu (`Menu.cs`), the heartbeat writer, and the HTML report renderer (`Report.cs`).
- `OpenCredentials.Blazor` (`v2/Blazor/`): the Blazor Server review UI with Findings, Visualizations and Settings tabs.

The CLI and the web app read and write the same database. EF Core and SQL Server's MVCC make concurrent access from several CLI instances (for example an interactive session plus a `--headless --loop` sidecar) race-safe. Pause and resume coordinate through the single `ScannerControl` row.

The full domain model and the project Laws are canon in [docs/BIBLE.md](docs/BIBLE.md) section 4.

## Exposure types

Findings fall into four types via the `ExposureTypes` lookup table, joined to `Findings.ExposureType`. The catalog itself is canon-as-data at [`docs/data/exposure_types.json`](docs/data/exposure_types.json), validated against `docs/data/_schema/exposure_type.schema.json`. Summary:

| Type | What it covers | Auto-inform default |
| --- | --- | --- |
| `ApiKey` | Provider tokens: Anthropic, OpenAI (including legacy), Google Gemini, AWS access keys, GitHub PATs (classic, fine-grained, OAuth and app variants), Stripe live secret and restricted, Slack bot, user and webhook, Discord webhooks, Twilio, SendGrid, Mailgun, npm, PyPI, DigitalOcean PAT and OAuth, Shopify private and access, Square access and secret, JWT | `false` |
| `ConnectionString` | Postgres, MySQL, MongoDB and Redis URIs containing inline `user:pass@host` | `false` |
| `PrivateKey` | PEM-encoded private key blocks: RSA, OpenSSH, EC, PGP | `false` |
| `PlainTextPassword` | Contextual `password = "..."` literals plus opt-in shape patterns. Enabled only with `--include-passwords` because of the false-positive rate | `false` |

Every type defaults to auto-inform off, so the CLI's auto-notify pass does nothing until you switch a category on in the web UI. This is deliberate: a false positive that auto-files a public issue against an innocent repo does real reputational harm. You review, then approve. The web UI can switch a whole category to auto-inform, send notices per finding, or both.

## Research ethics and non-retention

- Scope. Public repositories indexed by GitHub Code Search only. No private data, no auth-walled endpoints, no cloning, no execution of repo code.
- Non-retention is enforced in code. The raw regex match is bound to a local variable, used to compute SHA-256 and a short scheme prefix, then dropped. It is never written to disk, logged, serialized or returned from a function. See `ScanContent` in [v2/Cli/Scraper.cs](v2/Cli/Scraper.cs).
- No validation. The tool never calls provider APIs with detected credentials. Liveness is inferred from the recheck pass (does the hash still appear in the file?), not from authenticated probes.
- Disclosure. The Notify pass first tries GitHub's private security-advisory API and falls back to a public issue on the leaker's own repo. Either way the body is Markdown, links to the offending file, and includes only the SHA-256 fingerprint and scheme prefix. Public issues mention the repo owner so GitHub emails them.
- IRB note. Opening an issue or advisory on someone's repo is a third-party disclosure act; for a thesis committee, document it in your IRB submission. The `Notices` and `RemediationChecks` tables keep the audit trail of what was sent, when, to whom, and what happened next.

The project began as a Masters-thesis dataset on LLM API key prevalence and now covers the broader credential surface.

### Methodology precedent

The hash-and-discard method follows Meli, M., McNiece, M. R., and Reaves, B. (2019), How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories, NDSS: [ndss-symposium.org](https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/).

## Usage

### Scanner CLI

```powershell
dotnet build v2/Cli
# Token resolution is automatic (see GitHub PAT below). GITHUB_TOKEN is the simplest override:
$env:GITHUB_TOKEN = "github_pat_..."

# Interactive (default): scans every 60s in the background; the menu accepts
# [p]ause, [r]esume, [s]tatus, [q]uit. Pause/resume use the same ScannerControl
# row the Blazor Settings tab uses.
dotnet run --project v2/Cli

# Headless sidecar: no menu, loops indefinitely, obeys ScannerControl
dotnet run --project v2/Cli -- --headless --loop 5m

# Headless one-shot: single pass and exit (CI-friendly)
dotnet run --project v2/Cli -- --headless

# Override the database (defaults to SQL Server LocalDB)
dotnet run --project v2/Cli -- --connection "Server=...;Database=..."

# Opt into PlainTextPassword patterns (high false-positive rate)
dotnet run --project v2/Cli -- --include-passwords --loop 1h
```

The project's `/scan` agent skill ([.claude/skills/scan/SKILL.md](.claude/skills/scan/SKILL.md)) launches `--headless --loop 60` in the background and tails `scan-run.log`.

| Flag | Meaning |
| --- | --- |
| `--headless` | No interactive menu. Loops with `--loop`, otherwise runs one pass and exits. Obeys `ScannerControl.RequestedState`, so the web UI can still pause it. |
| `--loop INTERVAL` | Sleep `INTERVAL` between passes: `60`, `30s`, `5m`, `1h`, `1d`. Rate limits are absorbed internally (Retry-After, then primary reset, then a 60s secondary back-off); the loop never crashes on a 403. Defaults to 60s in long-lived modes. |
| `--connection "conn-string"` | Override the SQL Server connection. The `OPENCREDS_DB` env var works too. |
| `--report PATH` | Output `.htm` report path (default `findings.htm`, regenerated each pass from the full database). |
| `--max-per-provider N` | Cap per-needle file fetches per pass (default 50). |
| `--max-rechecks N` | Cap remediation rechecks per run (default 100). |
| `--no-recheck` | Skip the recheck phase. |
| `--max-notices N` | Cap auto-notices per run (default 25). Only fires for types with auto-inform on. |
| `--no-notify` | Skip the notify phase. |
| `--include-passwords` | Opt into the contextual and shape-based PlainTextPassword patterns. |
| `--provider X` | Narrow to one or more providers (repeatable). |
| `-v`, `--verbose` | Extra configuration logging. |

### Web UI

```powershell
dotnet run --project v2/Blazor
```

Default URLs are `https://localhost:50676` and `http://localhost:50677` (see `v2/Blazor/Properties/launchSettings.json`).

- Findings. Paginated table of every finding: exposure type, provider, repo, file, first-seen date, notice status, remediation status and check-back count. The per-row Send button files a notice by hand. Live-updates every 3 seconds while open.
- Visualizations. KPI strip (exposed LLM credentials, filed issues, remediated, percent remediated, average time to remediate, average check-backs until remediated) plus charts: cumulative findings vs notices vs remediations, time-to-remediate distribution, check-backs histogram, by-provider breakdown and remediation-status donut. Same live polling.
- Settings. Scanner pause and resume (the same `ScannerControl` row the CLI menu uses) plus auto-inform toggles per exposure type. The scanner heartbeat age shows whether the sidecar is alive.

The web app reads `ConnectionStrings:OpenCredentials` from `appsettings.json` (defaults to the LocalDB `OpenCredentials` database). Override the notice template with `OpenCredentials:NoticeChannel`, `NoticeTitle` and `NoticeBody`; otherwise the in-code default in [v2/Shared/NoticeService.cs](v2/Shared/NoticeService.cs) is used.

### run.bat

A double-click launcher at the repo root. It starts the web UI (`dotnet run --project v2\Blazor`) and, in parallel, a background PowerShell one-liner that polls `localhost:50677` every 500 ms for up to 60 seconds and opens the default browser the moment the server is listening. It does not start the CLI scanner.

```powershell
.\run.bat
```

## Configuration

### GitHub PAT

Token resolution is centralised in `GitHubTokenProvider`. The CLI and the web app try these sources in order:

1. `IConfiguration["MindAttic:Vault:Tokens:github"]`: App Service Application Settings or Azure Key Vault.
2. The `MindAttic.Vault` token store, `%APPDATA%\MindAttic\Tokens\tokens.json` (`{ "github": "github_pat_..." }`), the canonical local source.
3. The `GITHUB_TOKEN` env var.
4. Legacy `%APPDATA%\MindAttic\OpenCredentials\settings.json` with a `github_token` key. Deprecated; migrate to one of the above.

A fine-grained PAT with public-repo read and `Issues: write` covers the full pipeline. `Issues: write` is needed only because the Notify pass opens issues; scanning alone needs just public-repo read.

### Rate limits

GitHub authenticated rate limits:

- Primary REST: 5,000 requests per hour per token.
- Code Search: 30 requests per minute per token, the binding constraint.
- Issue creation: a stricter content-creation secondary limit.

The rate-limit handler respects `Retry-After`, `X-RateLimit-Remaining` and `X-RateLimit-Reset`, and falls back to a 60-second back-off for secondary limits with no hint. `--loop` mode rides this out indefinitely. Do not rotate several PATs to multiply the budget: that violates GitHub's Acceptable Use Policy. For more legitimate throughput, apply for GitHub Research Access.

## Version history

| Aspect | v1 (`v1/`) | v2 (`v2/`) |
| --- | --- | --- |
| Language | Python | C# on .NET 9 |
| Status | Retired 2026-04-25; reference only, do not run | Current |
| Storage | SQLite | SQL Server LocalDB |
| Coverage | LLM keys only | LLM and cloud API keys, GitHub PATs, payment tokens, DB connection strings, PEM private keys, contextual passwords |
| Disclosure | `disclosure.py` | `NoticeService`: private security advisory first, public issue as fallback |
| Reporting | `report.py` (static HTML) | Live Blazor Server UI plus `Report.cs` HTML export |
| Front doors | One scraper process | CLI (`opencreds`) and Blazor UI sharing one engine (`OpenCredentials.Shared`) |

The project's early working title was FractionsOfACent (FOAC). Every identifier (namespaces, database name, CLI binary, settings paths, env vars) was renamed to `OpenCredentials` or `OC`; see [docs/AMENDMENTS.md](docs/AMENDMENTS.md) (`OC-A2`) for the rename record and the advisory-first disclosure change.

`v1/` dates from when the project ran two parallel scrapers (Python and an early C# version) against one SQLite database. It never gained the exposure-type coverage, and notify, recheck and the Blazor UI were C# only from the start. Do not run `v1/` code; it predates the current schema. [v1/DEPRECATED.md](v1/DEPRECATED.md) maps every old file to its replacement.

### findings.db and findings.htm

Two artifacts at the repo root are not part of the current v2 persistence path:

- `findings.db`, `findings.db-shm`, `findings.db-wal`: a legacy, essentially empty SQLite database from the SQLite era. Current persistence is SQL Server LocalDB only, configured in [v2/Shared/Settings.cs](v2/Shared/Settings.cs). These files are tracked in git because they predate the `.gitignore` rule. Do not treat them as live data.
- `findings.htm`: a committed historical snapshot of the report that [v2/Cli/Report.cs](v2/Cli/Report.cs) regenerates on every pass (path set by `--report`). Regenerate it locally by running the CLI; `.gitignore` keeps future regenerations out of git.

## Project layout

```text
OpenCredentials/
├── v2/                           Current implementation (C# / .NET 9)
│   ├── Shared/                   OpenCredentials.Shared (library)
│   │   ├── Entities.cs           EF Core entity types
│   │   ├── OpenCredentialsContext.cs  DbContext + model config
│   │   ├── Db.cs                 Query/command facade used by both apps
│   │   ├── Finding.cs
│   │   ├── Notice.cs             Notice + RemediationCheck records
│   │   ├── NoticeService.cs      Advisory/issue opening + notice persistence
│   │   ├── GitHubClient.cs       Search, fetch, refetch, open issue/advisory
│   │   ├── GitHubTokenProvider.cs  MindAttic.Vault + env + legacy resolver
│   │   ├── Patterns.cs           ProviderPattern[] + ExposureTypes
│   │   ├── Settings.cs           LocalDB default + config paths
│   │   └── Migrations/           EF Core migrations
│   ├── Cli/                      OpenCredentials.Cli (exe: opencreds)
│   │   ├── Program.cs            Arg parsing, interactive + headless modes
│   │   ├── Scraper.cs            3-phase pipeline (scan/notify/recheck)
│   │   ├── Menu.cs               Interactive menu: p/r/s/q keys
│   │   ├── Heartbeat.cs          Writes the ScannerControl heartbeat each pass
│   │   └── Report.cs             Renders findings.htm
│   └── Blazor/                   OpenCredentials.Blazor (Blazor Server)
│       ├── Program.cs            DI + render pipeline
│       ├── VizData.cs            Visualizations data plumbing
│       ├── Components/
│       │   ├── Pages/            Findings.razor, Visualizations.razor, Settings.razor
│       │   └── CumulativeChart, HistogramChart, ProviderBarChart, DonutChart (.razor)
│       ├── wwwroot/app.css
│       └── appsettings.json
├── v1/                           Retired Python reference; do not extend or run
├── docs/                         Codex canonical documentation (BIBLE, AMENDMENTS,
│                                 USER_STORIES, digest, data/, rfc/)
├── tools/                        codex.ps1 (digest + doctor), build-readme.ps1
├── screenshots/                  internal UI reference captures (not published here)
├── findings.db / .db-shm / .db-wal   legacy SQLite artifact
├── findings.htm                  last committed HTML report snapshot
├── run.bat                       double-click launcher for the web UI
└── OpenCredentials.sln           Shared + Cli + Blazor
```

## Building

```powershell
dotnet build OpenCredentials.sln -c Release
```

## Testing

There is no automated test project yet (no `*.Tests` project in the repo), so `dotnet test` has nothing to run. Every behaviour in the user stories is marked shipped-but-not-test-proven for that reason. Closing the gap is the top item on the project's active frontier: see [docs/BIBLE.md](docs/BIBLE.md) section 7 and [docs/rfc/0001-verification-harness.md](docs/rfc/0001-verification-harness.md).

## Limitations

- It does not retrieve, retain or transmit any credential.
- It does not validate credentials against provider APIs.
- It does not scan private repos, commits behind auth, or GitHub Enterprise.
- It does not rotate or cycle PATs to evade rate limits.
- It is not a pentest or offensive-security tool: it does detection, disclosure and measurement only.
- It has no automated tests yet (see [Testing](#testing)).

## Documentation

This repo follows the MindAttic Codex documentation standard: each fact lives in exactly one place.

| Layer | File | Purpose |
| --- | --- | --- |
| L0 | [docs/BIBLE.md](docs/BIBLE.md) | What OpenCredentials is and is not, architecture canon, project Laws (`OC-LAW-*`), verified build and test state, glossary |
| L1 | [docs/AMENDMENTS.md](docs/AMENDMENTS.md) | Append-only change log (`OC-A<n>`); an amendment wins over the bible |
| L2 | [`docs/USER_STORIES.md`](docs/USER_STORIES.md) | Test-cited stories (`OC-US-*`) |
| rfc | [docs/rfc](docs/rfc) | Design notes, for example [0001-verification-harness.md](docs/rfc/0001-verification-harness.md) |
| L5 | [`docs/data/exposure_types.json`](docs/data/exposure_types.json) | Canon-as-data for the `ExposureTypes` catalog |
| generated | [docs/BIBLE.digest.md](docs/BIBLE.digest.md) | Produced by `tools/codex.ps1 digest`; never hand-edit |

Org-wide laws live in `MindAttic.HouseRules.md` in the workspace root and are inherited by reference from BIBLE section 5. Agents and contributors: start with [AGENTS.md](AGENTS.md). Run `powershell -NoProfile -File tools/codex.ps1 doctor` after editing anything under `docs/`.

## License

This repository has no LICENSE file; all rights are reserved.

Part of [MindAttic](https://mindattic.com) — see more projects at [github.com/mindattic](https://github.com/mindattic). Related: [MindAttic.Vault](https://github.com/mindattic/MindAttic.Vault) (token resolution).

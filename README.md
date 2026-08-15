# OpenCredentials

**Version 1.0.0** | .NET 9 | SQL Server LocalDB

**Public-service credential-leak detection. Find leaks, file courtesy issues, measure remediation — never store the secret.**

A pipeline that watches public GitHub for exposed credentials — API keys, connection strings, private keys, plaintext passwords — opens a courtesy issue (or, where supported, a private security advisory) on the leaker's own repo asking them to rotate, then tracks whether the leak actually gets fixed. Originated as a Masters-thesis dataset on LLM API key prevalence; now covers the broader credential surface (see [Exposure types](#exposure-types)).

The system records **metadata only**. Raw matches are SHA-256 hashed and discarded inside one function. No credential is persisted, logged, transmitted, returned from a function, or validated against any provider API. Detection, disclosure, and measurement — not exploitation.

For the full architecture canon (Laws, domain model, verified state, glossary), see **[docs/BIBLE.md](docs/BIBLE.md)**. This README says how to build and run; the bible says how to think about the system.

---

## Table of Contents

- [What this is](#what-this-is)
- [Pipeline at a glance](#pipeline-at-a-glance)
- [Why this exists](#why-this-exists)
- [Version history: v1 → v2](#version-history-v1--v2)
- [Current architecture](#current-architecture)
- [Exposure types](#exposure-types)
- [Research ethics & non-retention](#research-ethics--non-retention)
- [Methodology precedent](#methodology-precedent)
- [Repository layout](#repository-layout)
- [Build & test](#build--test)
- [Running](#running)
  - [Scanner CLI](#scanner-cli)
  - [Web UI](#web-ui)
  - [run.bat](#runbat)
- [findings.db & findings.htm](#findingsdb--findingshtm)
- [Screenshots](#screenshots)
- [GitHub PAT](#github-pat)
- [Rate limits](#rate-limits)
- [Documentation canon](#documentation-canon)
- [What this tool does NOT do](#what-this-tool-does-not-do)

---

## What this is

OpenCredentials is a public-service credential-leak pipeline. It:

1. **Scans** public GitHub Code Search for regex-matched credential patterns (LLM/cloud API keys, DB connection strings, PEM private keys, contextual passwords).
2. **Discloses** a leak to the repo owner — preferring GitHub's private security-advisory channel, falling back to a public courtesy issue — but only for exposure types a human has explicitly opted into.
3. **Rechecks** every previously found leak on each pass to measure whether it was remediated, and how long that took.

It ships as one solution, two runnable front doors, and one shared engine — a CLI scanner (`opencreds`) and a Blazor Server review UI — both reading and writing the same SQL Server LocalDB database. There are no offensive capabilities: nothing is validated against a live provider API, nothing is exploited, and the raw secret is never retained anywhere.

## Pipeline at a glance

```
                ┌──────────────────────────────────────────────────┐
                │                                                  │
   GitHub  ─►   1. Scan  ─►  2. Notify (gated)  ─►  3. Recheck  ───┘
   Code Search                                       (every run)
   + Contents      └─ writes findings           └─ writes
                                                   remediation_checks
   leaker repo  ◄─── auto-issue (only when auto_inform=true)
```

Each invocation runs all three phases in order and persists everything
to the SQL Server LocalDB `OpenCredentials` database (override with
`--connection` or the `OPENCREDS_DB` env var). The default mode loops
forever every 60s with an interactive menu; `--headless` drops the
menu and pairs with `--loop` for daemon/sidecar use.

## Why this exists

Leaked LLM keys, cloud credentials, payment-provider tokens, and DB
connection strings are an active abuse vector on public GitHub.
Providers run secret-scanning partner programs, and GitHub's Push
Protection blocks many of them at push time. **What's missing is the
public-service tier**: a third-party that observes the leaks, files a
courteous notice on the leaker's own repo, then watches whether the
leak gets remediated. That's what this project does.

The research artifact and the public-service operator are the same
binary. Aggregate measurements (leak rate per provider, time-to-
remediate, notice-to-remediation conversion) fall out for free as the
pipeline runs.

## Version history: v1 → v2

| | v1 (`v1/`) | v2 (`v2/`) |
|---|---|---|
| Language | Python | C# / .NET 9 |
| Status | **Retired 2026-04-25** — reference only, do not run | Current, actively developed |
| Storage | SQLite | SQL Server LocalDB |
| Coverage | Original LLM-key-only scope | Broader surface: LLM/cloud API keys, GitHub PATs, payment tokens, DB connection strings, PEM private keys, contextual passwords |
| Disclosure | `disclosure.py` | `NoticeService` — advisory-first (private security advisory), falls back to a public issue |
| Reporting | `report.py` (static HTML) | Blazor Server live UI (Findings / Visualizations / Settings tabs) + `Report.cs` HTML export |
| Front doors | One scraper process | CLI (`opencreds`) + Blazor UI sharing one engine (`OpenCredentials.Shared`) |

The project also carried an early working title, `FractionsOfACent` (FOAC); every identifier — namespaces, DB name, CLI binary, settings paths, env vars — was renamed to `OpenCredentials` / `OC`. See [`docs/AMENDMENTS.md`](docs/AMENDMENTS.md) (`OC-A2`) for the full rename record and the advisory-first disclosure change.

`v1/` mirrors an earlier era when the project ran two parallel scrapers (Python + an early C# version) against the same SQLite DB. It never grew the exposure-type coverage the C# side now has, and the notify/recheck/Blazor pipeline was C#-only from the start. **Do not run `v1/` code** — it predates the current schema and will drift further from the scanner every release. See [`v1/DEPRECATED.md`](v1/DEPRECATED.md) for the full old-file → new-file mapping.

## Current architecture

```
   ┌─────────────┐        ┌──────────────────────────────┐        ┌──────────────┐
   │ Cli         │        │ Shared (library)             │        │ Blazor       │
   │ `opencreds` │──uses──│ Db · Scraper-DTOs · Patterns │──uses──│ Server UI    │
   │ scan/notify │        │ NoticeService · GitHubClient │        │ Findings/Viz │
   │ /recheck    │        │ OpenCredentialsContext (EF Core)  │    │ /Settings    │
   └──────┬──────┘        └───────────────┬──────────────┘        └──────┬───────┘
          │                               │                              │
          └──────────────► SQL Server LocalDB `OpenCredentials` ◄────────┘
                               (ScannerControl row coordinates pause/resume)
```

Three projects, one solution (`OpenCredentials.sln`):

- **`OpenCredentials.Shared`** (`v2/Shared/`) — library: EF Core entities, `OpenCredentialsContext`, the `Db` persistence facade, detection patterns (`Patterns.cs`), `NoticeService`, `GitHubClient`, `GitHubTokenProvider`, settings. Consumed by both front doors.
- **`OpenCredentials.Cli`** (`v2/Cli/`) — the `opencreds` executable: argument parsing, interactive + headless modes, the 3-phase pipeline (`Scraper.cs`), the interactive TUI menu (`Menu.cs`), heartbeat writer, HTML report renderer (`Report.cs`).
- **`OpenCredentials.Blazor`** (`v2/Blazor/`) — Blazor Server review UI: Findings table, Visualizations (KPIs + charts), Settings (pause/resume + per-type auto-inform toggles).

The CLI and the Web app both read/write the same SQL Server LocalDB
`OpenCredentials` database. EF Core + SQL Server's MVCC make concurrent
access from multiple CLI instances (e.g. an interactive session + a
`--headless --loop` sidecar) race-safe. Pause/resume coordinates through
the single `ScannerControl` row.

The full domain model (entities, services, the project Laws) is canon in [docs/BIBLE.md §4](docs/BIBLE.md#OC-§4) — not restated here to avoid two sources of truth.

## Exposure types

Findings are categorized into four broad types via the
`ExposureTypes` lookup table, joined to `Findings.ExposureType`. The catalog itself is canon-as-data at [`docs/data/exposure_types.json`](docs/data/exposure_types.json) (validated against [`docs/data/_schema/exposure_type.schema.json`](docs/data/_schema/exposure_type.schema.json)); the table below is a human-readable summary:

| Type | What it covers | Auto-inform default |
|---|---|---|
| `ApiKey` | Provider tokens — Anthropic, OpenAI (incl. legacy), Google Gemini, AWS access keys, GitHub PATs (classic + fine + OAuth + app variants), Stripe live secret/restricted, Slack bot/user/webhook, Discord webhooks, Twilio (SK\*), SendGrid, Mailgun, npm, PyPI, DigitalOcean PAT/OAuth, Shopify (private + access), Square access/secret, JWT | `false` |
| `ConnectionString` | Postgres / MySQL / MongoDB / Redis URIs containing inline `user:pass@host` | `false` |
| `PrivateKey` | PEM-encoded private key blocks: RSA, OpenSSH, EC, PGP | `false` |
| `PlainTextPassword` | Contextual `password = "..."` literals + opt-in shape patterns. Opt-in only via `--include-passwords` because of the false-positive rate | `false` |

**Every type defaults to `auto_inform = false`** — the CLI's auto-notify
pass does nothing until you flip a category on in the Web UI. This is
deliberate: false positives that auto-file public issues against
innocent repos = real reputational harm. You review, then approve.

The Web UI can either flip a whole category to auto-inform, or send
notices manually per finding, or do both.

## Research ethics & non-retention

- **Scope**: public repositories indexed by GitHub Code Search. No
  private data, no auth-walled endpoints, no cloning, no execution of
  repo code.
- **Non-retention** is enforced at the code level. The raw regex match
  is bound to a local variable, used to compute SHA-256 + a short scheme
  prefix, then dropped. It is never written to disk, emitted to logs,
  serialized, or returned from a function. See
  [`v2/Cli/Scraper.cs`](v2/Cli/Scraper.cs) `ScanContent`.
- **No validation**: the tool does not call provider APIs with detected
  credentials. Liveness is inferred from the recheck pass (does the
  hash still appear in the file?), not authenticated probes.
- **Public disclosure via issues (or advisories)**: the `Notify` pass
  first attempts GitHub's private security-advisory API, and falls
  back to opening a public GitHub issue on the leaker's own repo when
  advisories aren't available. Either way, the disclosure body is
  markdown, links to the offending file, and includes only the SHA-256
  fingerprint and scheme prefix — never the secret itself. Public
  issues `@`-mention the repo owner so GitHub's notification system
  emails them automatically.
- **IRB note**: opening a public issue (or private advisory) on
  someone's repo is a third-party disclosure act. For a
  thesis-committee record, document this as part of your IRB
  submission. The project keeps the audit trail (`Notices` table +
  `RemediationChecks` table) so you can report exactly what was sent,
  when, to whom, and what happened next.

## Methodology precedent

Hash-and-discard methodology follows:

> Meli, M., McNiece, M. R., & Reaves, B. (2019).
> *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub
> Repositories.* NDSS.
> <https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/>

## Repository layout

```
OpenCredentials/
├── v2/                          # Current implementation (C# / .NET 9)
│   ├── Shared/                  # OpenCredentials.Shared (library)
│   │   ├── Entities.cs          # EF Core entity types
│   │   ├── OpenCredentialsContext.cs # DbContext + model config
│   │   ├── Db.cs                # Query/command facade used by both apps
│   │   ├── Finding.cs
│   │   ├── Notice.cs            # Notice + RemediationCheck records
│   │   ├── NoticeService.cs     # Advisory/issue-opening + notice persistence
│   │   ├── GitHubClient.cs      # Search, fetch, refetch, open-issue/advisory
│   │   ├── GitHubTokenProvider.cs  # MindAttic.Vault + env + legacy resolver
│   │   ├── Patterns.cs          # ProviderPattern[] + ExposureTypes
│   │   └── Settings.cs          # LocalDB default + config paths
│   ├── Cli/                     # OpenCredentials.Cli (exe — `opencreds`)
│   │   ├── Program.cs           # arg parsing, interactive + headless modes
│   │   ├── Scraper.cs           # 3-phase pipeline (scan/notify/recheck)
│   │   ├── Menu.cs              # interactive TUI: p/r/s/q keys
│   │   ├── Heartbeat.cs         # writes ScannerControl heartbeat each pass
│   │   └── Report.cs            # renders findings.htm
│   └── Blazor/                  # OpenCredentials.Blazor (Blazor Server)
│       ├── Program.cs           # DI + render pipeline
│       ├── VizData.cs           # Visualizations data plumbing
│       ├── Components/
│       │   ├── Pages/
│       │   │   ├── Findings.razor          # Tab 1: paginated table
│       │   │   ├── Visualizations.razor    # Tab 2: charts + KPIs
│       │   │   └── Settings.razor          # Tab 3: pause/resume + auto-inform
│       │   ├── CumulativeChart.razor
│       │   ├── HistogramChart.razor
│       │   ├── ProviderBarChart.razor
│       │   └── DonutChart.razor
│       ├── wwwroot/app.css
│       └── appsettings.json
├── v1/                           # Retired Python reference; do not extend or run
│   ├── DEPRECATED.md             # Why it's retired + old→new file mapping
│   ├── scraper.py, db.py, patterns.py, disclosure.py, report.py
│   └── requirements.txt
├── docs/                         # Codex canonical documentation
│   ├── BIBLE.md                  # Architecture canon + project Laws (L0)
│   ├── AMENDMENTS.md             # Append-only change log (L1)
│   ├── USER_STORIES.md           # Test-cited stories (L2)
│   ├── BIBLE.digest.md           # GENERATED — never hand-edit
│   ├── data/
│   │   ├── exposure_types.json   # ExposureTypes catalog (canon-as-data, L5)
│   │   └── _schema/exposure_type.schema.json
│   └── rfc/
│       └── 0001-verification-harness.md
├── tools/
│   ├── codex.ps1                 # digest + doctor CLI for docs/
│   └── build-readme.ps1          # thin wrapper → shared README→HTML engine
├── screenshots/                  # UI reference screenshots (Blazor Findings tab, etc.)
├── findings.db / .db-shm / .db-wal   # legacy SQLite artifact — see below
├── findings.htm                  # last-generated HTML report snapshot
├── run.bat                       # double-click launcher for the Blazor UI
├── OpenCredentials.sln            # Shared + Cli + Blazor
└── .slnLaunch.json                # multi-project VS launch profiles
```

## Build & test

```powershell
# Build everything (Shared, Cli, Blazor)
dotnet build OpenCredentials.sln -c Release
```

**There is currently no automated test project** in this repo (no `*.Tests` project; confirmed via `git ls-files`). Every behavior described in [docs/USER_STORIES.md](docs/USER_STORIES.md) is marked `🟡` (shipped, not test-proven) rather than `✅` for exactly this reason — closing that gap is the top item on the project's active frontier ([docs/BIBLE.md §7](docs/BIBLE.md#OC-§7), [docs/rfc/0001-verification-harness.md](docs/rfc/0001-verification-harness.md)). Until a test project exists, `dotnet test` has nothing to run.

## Running

### Scanner CLI

```powershell
dotnet build v2/Cli
# Token resolution is automatic (see GitHub PAT section below).
# Set GITHUB_TOKEN env var as the simplest override:
$env:GITHUB_TOKEN = "github_pat_..."

# Interactive (default) — scans every 60s in the background; in-terminal
# menu accepts [p]ause, [r]esume, [s]tatus, [q]uit. Pause/resume route
# through the same ScannerControl row the Blazor Settings tab uses.
dotnet run --project v2/Cli

# Headless sidecar — no menu, loops indefinitely, obeys ScannerControl:
dotnet run --project v2/Cli -- --headless --loop 5m

# Headless one-shot — single pass and exit (CI-friendly):
dotnet run --project v2/Cli -- --headless

# Override the database (defaults to SQL Server LocalDB):
dotnet run --project v2/Cli -- --connection "Server=...;Database=..."

# Opt into PlainTextPassword patterns (high FP rate):
dotnet run --project v2/Cli -- --include-passwords --loop 1h
```

Or via the project's `/scan` skill ([`.claude/skills/scan/SKILL.md`](.claude/skills/scan/SKILL.md)), which launches `--headless --loop 60`
in the background and tails to `scan-run.log`.

Useful flags:

- `--headless` — no interactive menu. Loops indefinitely with `--loop`,
  otherwise runs a single pass and exits. Pair with `--loop` for sidecar
  use; obeys `ScannerControl.RequestedState` so the Blazor UI can still
  pause it.
- `--loop INTERVAL` — sleeps `INTERVAL` between passes. Accepts `60`,
  `30s`, `5m`, `1h`, `1d`. Rate limits are absorbed internally
  (Retry-After → primary reset → secondary 60s back-off); the loop never
  crashes on a 403. Default cadence is 60s when omitted in a long-lived
  mode (interactive or `--headless` without one-shot).
- `--connection "<conn-string>"` — override the SQL Server connection.
  Also accepts the `OPENCREDS_DB` env var.
- `--report PATH` — output `.htm` report path (default `findings.htm`,
  regenerated each pass from the full DB).
- `--max-per-provider N` (default 50) — caps per-needle file fetches per pass.
- `--max-rechecks N` (default 100) / `--no-recheck` — caps the per-run
  remediation-recheck work.
- `--max-notices N` (default 25) / `--no-notify` — caps the per-run
  auto-notify volume. Only fires for types with `auto_inform=true`.
- `--include-passwords` — opt into the contextual + shape-based
  PlainTextPassword patterns.
- `--provider X` — narrow to one or more providers (repeatable).
- `-v` / `--verbose` — extra config logging.

### Web UI

```powershell
dotnet run --project v2/Blazor
```

Default URLs are `https://localhost:50676` / `http://localhost:50677`
(see `v2/Blazor/Properties/launchSettings.json`).

Three tabs:

- **Findings** — paginated table of every finding, with columns for
  exposure type, provider, repo, file, first-seen date, notice
  status, remediation status, and check-back count. Per-row `Send`
  button manually files an issue. Live-updates every 3s while the page
  is open.
- **Visualizations** — KPI strip (Exposed LLM Credentials, Filed
  Issues, Remediated, % Remediated, Avg Time-to-Remediate, Avg
  Check-Backs Until Remediated) plus charts: cumulative findings vs.
  notices vs. remediations, time-to-remediate distribution,
  check-backs-until-remediated histogram, by-provider breakdown,
  remediation-status donut. Same live polling.
- **Settings** — scanner pause/resume (writes to the same
  `ScannerControl` row the CLI menu uses) plus auto-inform toggles
  per exposure type. Heartbeat age from the scanner side is shown so
  you can confirm the sidecar is alive.

The Web app reads `appsettings.json` for `ConnectionStrings:OpenCredentials`
(defaults to SQL Server LocalDB `OpenCredentials`). Override the
notice template by setting `OpenCredentials:NoticeChannel` /
`NoticeTitle` / `NoticeBody`; otherwise the in-code default in
[`NoticeService.cs`](v2/Shared/NoticeService.cs) is used.

### run.bat

A double-click convenience launcher at the repo root:

```bat
@echo off
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "..."
dotnet run --project v2\Blazor
```

It starts the Blazor app (`dotnet run --project v2\Blazor`) and, in parallel, a background PowerShell one-liner that polls `localhost:50677` every 500ms for up to 60 seconds and auto-opens the default browser to `http://localhost:50677/` the moment the server is listening. This does **not** start the CLI scanner — it only launches the Web UI. Run it from the repo root:

```powershell
.\run.bat
```

## findings.db & findings.htm

Two report/data artifacts live at the repo root and are worth understanding separately, since neither is part of the current v2 persistence path:

- **`findings.db` / `findings.db-shm` / `findings.db-wal`** — a **legacy SQLite database** (confirmed: SQLite 3.x format, essentially empty). It is a holdover from an earlier era when the project persisted to SQLite (see [Version history](#version-history-v1--v2)); current v2 persistence is exclusively SQL Server LocalDB, configured in [`v2/Shared/Settings.cs`](v2/Shared/Settings.cs). These files are tracked in git despite `findings.htm`/`findings.json` being listed in `.gitignore` — they predate that rule. Do not treat `findings.db` as live data.
- **`findings.htm`** — a static HTML snapshot of the findings report, generated by [`Report.cs`](v2/Cli/Report.cs) and regenerated on every scanner pass (path overridable via `--report`). The copy at the repo root is a **committed historical snapshot** from a prior run, not live data — regenerate it locally by running the CLI. `.gitignore` marks future regenerations as ignored (`findings.htm`, `findings.json`, `findings.html`), so a fresh run's output won't get accidentally re-committed.

Neither file is touched by the current SQL Server LocalDB pipeline at runtime except as the CLI's rendered HTML export target (`findings.htm`).

## Screenshots

Reference screenshots of the Blazor review UI live under [`screenshots/`](screenshots/):

- `01.png`
- `blazor-findings.png`
- `blazor-findings-fixed.png`

## GitHub PAT

Token resolution is centralized in `GitHubTokenProvider`. The CLI and
the Web app try sources in this order:

1. `IConfiguration["MindAttic:Vault:Tokens:github"]` — App Service
   Application Settings or Azure Key Vault (cloud-native).
2. `MindAttic.Vault` token store — `%APPDATA%\MindAttic\Tokens\tokens.json`
   (`{ "github": "github_pat_..." }`) — canonical local source.
3. `GITHUB_TOKEN` env var.
4. Legacy `%APPDATA%\MindAttic\OpenCredentials\settings.json`
   `{ "github_token": "github_pat_..." }` — deprecated; migrate to one
   of the above.

A fine-grained PAT with public-repo read **and `Issues: write`** is
sufficient for the full pipeline. (Issues:write is needed because the
Notify pass opens issues; if you only ever scan, public-repo read is
enough.)

## Rate limits

GitHub authenticated rate limits:

- Primary REST: 5,000 req/hour per token
- Code Search: 30 req/min per token (the binding constraint)
- Issue creation: subject to a stricter content-creation secondary limit

The pipeline's rate-limit handler respects `Retry-After`,
`X-RateLimit-Remaining=0`/`X-RateLimit-Reset`, and falls back to a 60s
back-off for secondary limits without an explicit hint. The `--loop`
mode is designed to ride this out indefinitely. **Do not rotate
multiple PATs to multiply the budget — that violates GitHub's
Acceptable Use Policy.** For higher legitimate throughput, apply for
GitHub Research Access (academic study).

## Documentation canon

This repo follows the MindAttic **Codex** documentation standard — a layered set of docs where each fact lives in exactly one place:

| Layer | File | Purpose |
|---|---|---|
| L0 | [docs/BIBLE.md](docs/BIBLE.md) | What OpenCredentials IS/is NOT, architecture canon, the project Laws (`OC-LAW-*`), verified build/test state, glossary |
| L1 | [docs/AMENDMENTS.md](docs/AMENDMENTS.md) | Append-only change log (`OC-A<n>`); an amendment **wins** over the bible |
| L2 | [docs/USER_STORIES.md](docs/USER_STORIES.md) | Test-cited stories (`OC-US-*`); `✅` only when a test or build proves it |
| rfc | [docs/rfc/](docs/rfc/) | Design notes, e.g. [0001-verification-harness.md](docs/rfc/0001-verification-harness.md) |
| L5 | [docs/data/exposure_types.json](docs/data/exposure_types.json) | Canon-as-data for the `ExposureTypes` catalog |
| generated | [docs/BIBLE.digest.md](docs/BIBLE.digest.md) | Produced by `tools/codex.ps1 digest`; never hand-edit |

Org-wide laws live in `../MindAttic.HouseRules.md` and are inherited by reference from [docs/BIBLE.md §5](docs/BIBLE.md#OC-§5) — not restated here.

Run `powershell -NoProfile -File tools/codex.ps1 doctor` after editing anything under `docs/` to validate cross-references, cited paths, and digest freshness.

## What this tool does NOT do

- It does not retrieve, retain, or transmit any credential.
- It does not validate credentials against provider APIs.
- It does not scrape private repos, commits behind auth, or GitHub
  Enterprise.
- It does not rotate or cycle PATs to evade rate limits.
- It is not a pentest or offensive-security tool. It is detection +
  disclosure + measurement.

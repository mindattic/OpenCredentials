---
layer: release
status: living
---
# OpenCredentials — Release charter

> The one finish line this repo is working toward. Every open ticket in this repo sits under one of the epics
> below, and every epic is part of the milestone. Work that does not fit is out of scope until this milestone is
> reached (owner, 2026-11-27, MAT-T319).

## 1. What this is
A local, public-service credential-leak pipeline: the `opencreds` CLI scans public GitHub for exposed credentials,
keeps only a SHA-256 fingerprint, optionally discloses to the leaker (private advisory first, courtesy issue as
fallback) and rechecks remediation; a Blazor Server review UI shares the same database. For the owner, run locally.

## 2. The milestone: OpenCredentials 1.0 — verified local scanner {#milestone}
- **Milestone:** MS-24, "OpenCredentials 1.0 verified local scanner"
- **Published means:** internal tool on `R:\MindAttic\Apps\OpenCredentials\Release` (CLI + review UI on
  `http://localhost:50677/`), started from `run.bat`. Not hosted anywhere.
- **The natural stopping point:** the deployed app runs against the local SQL Server `OpenCredentials` database
  (Azure is gone), and the laws that make it safe to run — non-retention (OC-LAW-1), review before disclosure
  (OC-LAW-2), race-safe claims (OC-LAW-5) and correct remediation states — are proven by NUnit tests rather than
  by code structure alone. That closes RFC 0001 and leaves a tool the owner can leave scanning without worrying
  about it leaking or mis-disclosing.

## 3. Done when (acceptance checks)
1. build — `OpenCredentials.sln` builds clean on main.
2. exists — `R:\MindAttic\Apps\OpenCredentials\Release` holds the deployed CLI and review UI.
3. (tracked by epic OC-T56, not a milestone check) — the NUnit suite in `v2/Tests` covers fingerprinting, the scan pass, Db claims, notify/recheck,
   NoticeService rendering and GitHubClient status mapping, and passes.
4. signoff — the owner runs a scan pass and opens the review UI against the local SQL database end to end.

## 4. Epics, in priority order
| Priority | Epic (ticket) | What it delivers | Features |
|---|---|---|---|
| 900 | OC-T55 Local SQL database | The app runs on local SQL Server, docs say so, deployed build verified | OC-T57 Local database default (990), OC-T58 Deployed end-to-end run (980) |
| 800 | OC-T56 Invariant test coverage | RFC 0001 finished: every law proven by tests | OC-T59 Non-retention and scan pass (890), OC-T60 Persistence and concurrency (880), OC-T61 Disclosure and remediation (870) |

## 5. Out of scope (not before this milestone)
- Hosting on Hetzner or any server (OC-T47/48/49) — it is a local tool; Azure is decommissioned and the data
  stays on local SQL.
- MindAttic.Log adoption (OC-T22/42/43/44) — a portfolio-wide initiative, not part of this finish line; console
  output and the HTML report are enough for a local tool.
- Tests for presentation and plumbing that no law depends on: chart math (VizData), the static HTML report, token
  resolution order, CLI duration parsing, bUnit page coverage beyond disclosure.
- Generic sweeps: "run the whole suite", "/simplify cleanup", exhaustive bughunts (two already landed: OC-T31,
  OC-T32).
- New providers/patterns, GitHub Research Access, private-repo or non-GitHub sources, credential validation
  (forbidden by OC-LAW-4), the `v1/` Python scraper.

## 6. Current verified state
- Run menu over the shared deploy-lib; Debug and Release deployed to `R:\MindAttic\Apps\OpenCredentials`
  (7f4253f, 2026-11-26).
- NUnit suite exists (OC-T16): disclosure routing, notify pass, auto-inform gate, LAMP settings, and every
  detection pattern (OC-T2, `PatternsTests.cs`).
- Two bughunts landed (65b779c, 7bda6f2): KeyPrefix keeps only the public prefix, claims released on failures,
  403 handling, loop limit guard. Live-refresh loops survive DB exceptions (OC-T51); invariant report CSS (OC-T50).
- Known gap: `Settings.DefaultConnectionString` still points at the decommissioned Azure SQL server; README and
  BIBLE still say Azure SQL (E1 fixes this).

## 7. Decision record
- 2026-11-27 — charter drafted from README/BIBLE/RFC 0001/tickets; Legion vote: Approve, 9/9 voters, plurality quorum reached, consensus 1.0; no dissent.
- Triage: 24 open → done 1 (OC-T53), duplicate 0, wont-do 15, kept 8 (OC-T52 and OC-T20 reworded), +1 new task (OC-T62).

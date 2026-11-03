using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenCredentials;

public sealed class Scraper
{
    private const int ContextRadius = 200;

    private readonly GitHubClient _client;
    private readonly Db _db;
    private readonly FileInfo _reportFile;
    private readonly int _maxPerProvider;
    private readonly int _maxRechecks;
    private readonly int _maxNotices;
    private readonly ProviderPattern[] _patterns;
    private readonly NoticeConfig _noticeConfig;
    private Heartbeat? _hb;

    /// <summary>Delay between disclosures in the notify pass (tests set it to zero).</summary>
    internal TimeSpan NoticePacing { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Test entry point: runs only the notify pass.</summary>
    internal async Task RunNotifyPassAsync(CancellationToken ct)
    {
        using var hb = new Heartbeat("notifying");
        _hb = hb;
        try { await SendPendingNoticesAsync(_db, ct); }
        finally { _hb = null; }
    }

    public Scraper(
        GitHubClient client,
        Db db,
        FileInfo reportFile,
        int maxPerProvider,
        int maxRechecks,
        int maxNotices,
        bool includePasswords,
        NoticeConfig? noticeConfig = null)
    {
        // The notice template the CLI sends: the same Vault-edited template the
        // dashboard uses (OC-T28); the built-in default only when none is given.
        _noticeConfig = noticeConfig ?? NoticeConfig.Default;
        _client = client;
        _db = db;
        _reportFile = reportFile;
        _maxPerProvider = maxPerProvider;
        _maxRechecks = maxRechecks;
        _maxNotices = maxNotices;
        _patterns = includePasswords ? Patterns.WithPasswords() : Patterns.All;
    }

    public async Task<int> RunAsync(string[]? providerFilter, CancellationToken ct)
    {
        var db = _db;
        using var hb = new Heartbeat("starting");
        _hb = hb;
        try
        {
        await WaitWhilePausedAsync(hb, "starting", ct);
        var (startFindings, startScanned) = db.Stats();
        hb.WriteLine(
            $"[db] start findings={startFindings} scanned_files={startScanned}");

        var totalNew = 0;
        // Patterns share a SearchNeedle — e.g. all the password-shape
        // patterns use "\"password\":". Group so we search each needle
        // once, fetch each file once, then run every pattern in the group
        // (and every other pattern, in case the file happens to contain
        // an unrelated leak too) over the content.
        var activePatterns = _patterns
            .Where(p => providerFilter is null
                || providerFilter.Length == 0
                || providerFilter.Contains(p.Provider))
            .ToArray();
        var needleGroups = activePatterns
            .GroupBy(p => p.SearchNeedle)
            .ToList();

        foreach (var group in needleGroups)
        {
            var primary = group.First();
            var needleLabel = $"scanning {primary.SearchNeedle}";
            await WaitWhilePausedAsync(hb, needleLabel, ct);
            SetLabel(hb, needleLabel);
            hb.WriteLine(
                $"[scan] needle={primary.SearchNeedle} " +
                $"providers=[{string.Join(",", group.Select(p => p.Provider))}]");

            var fetched = 0;
            var skipped = 0;

            await foreach (var item in _client.SearchCodeAsync(primary.SearchNeedle, ct: ct))
            {
                if (fetched >= _maxPerProvider) break;

                var repo = item.Repository?.FullName ?? "";
                var path = item.Path ?? "";
                if (string.IsNullOrEmpty(repo) || string.IsNullOrEmpty(path)) continue;
                // Atomic claim: if a concurrent scraper already grabbed
                // this file, skip without fetching.
                if (!db.ClaimScan(repo, path))
                {
                    skipped++;
                    continue;
                }

                fetched++;
                try
                {
                    var result = await _client.FetchFileAsync(item, ct);
                    if (result.Unavailable)
                    {
                        // Blocked / gone (a 403 that is not a rate limit, 404,
                        // 451): keep the claim so the file is not re-fetched
                        // every pass. Nothing was read, so nothing is recorded.
                        hb.WriteLine($"[skip] unavailable: {repo}#{path}");
                        continue;
                    }
                    if (!result.Ok)
                    {
                        // Transient fetch failure (rate-limited / error).
                        // Release the claim so the file is retried next pass
                        // instead of being permanently marked scanned.
                        db.ReleaseScan(repo, path);
                        fetched--;
                        continue;
                    }

                    var fileFindings = ScanContent(result, item, activePatterns);
                    db.RecordCommitForScan(repo, path, result.CommitSha);
                    foreach (var finding in fileFindings)
                    {
                        if (db.UpsertFinding(finding))
                        {
                            totalNew++;
                            hb.WriteLine(
                                $"  {finding.Provider} ({finding.ExposureType}) " +
                                $"{finding.RepoFullName}#{finding.FilePath}");
                        }
                    }
                }
                catch (Exception e) when (!ct.IsCancellationRequested
                    && e is HttpRequestException or TaskCanceledException
                        or System.Text.Json.JsonException)
                {
                    // HttpClient's 30s timeout surfaces as TaskCanceledException
                    // and a malformed body as JsonException; both are transient
                    // fetch failures and must not leave the claim in place.
                    db.ReleaseScan(repo, path);
                    fetched--;
                    hb.WriteLine($"[warn] fetch failed: {e.Message}");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    // Shutdown mid-fetch: the file was never scanned.
                    db.ReleaseScan(repo, path);
                    throw;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
                await WaitWhilePausedAsync(hb, needleLabel, ct);
            }

            hb.WriteLine(
                $"[scan] needle={primary.SearchNeedle} fetched={fetched} " +
                $"skipped(already-scanned)={skipped} total_new={totalNew}");
        }

        if (_maxNotices > 0)
        {
            await SendPendingNoticesAsync(db, ct);
        }

        if (_maxRechecks > 0)
        {
            await RecheckRemediationsAsync(db, ct);
        }

        hb.Label = "writing report";
        var all = db.AllFindings();
        var htmlFile = await Report.WriteAsync(all, _reportFile, ct);
        var (endFindings, endScanned) = db.Stats();
        hb.WriteLine(
            $"[done] new findings: {totalNew}, total in db: {endFindings}, " +
            $"scanned_files: {endScanned}");
        hb.WriteLine($"[report] {htmlFile.FullName}");
        return totalNew;
        }
        finally
        {
            _hb = null;
        }
    }

    /// <summary>
    /// Auto-disclose every finding we haven't already notified, capped at
    /// _maxNotices per run: a private vulnerability report when the repo has
    /// private reporting enabled, else a public courtesy issue. Skips findings that are
    /// already in a terminal remediation state — no point pinging a repo
    /// where the leak has already been removed.
    ///
    /// This is the public-service notification step. Notices document the
    /// leak in the leaker's own issue tracker; subsequent recheck passes
    /// then track whether the leak is removed.
    /// </summary>
    private async Task SendPendingNoticesAsync(Db db, CancellationToken ct)
    {
        var hb = _hb!;
        await WaitWhilePausedAsync(hb, "notifying", ct);
        SetLabel(hb, "notifying");
        var noticeSvc = new NoticeService(db, _client, _noticeConfig);
        var findings = db.AllFindings();
        var latest = db.LatestRemediationChecks();
        var sentKeys = db.AllNotices()
            .Where(n => n.Status == "sent")
            .Select(n => (n.KeySha256, n.RepoFullName, n.FilePath))
            .ToHashSet();

        // Per-type auto_inform gate. Defaults to false for every type, so
        // unless the user has flipped a type to auto-inform via the Web
        // UI, this pass does nothing — review-then-act is the safe path.
        var autoInformByType = db.AllExposureTypes()
            .ToDictionary(t => t.Name, t => t.AutoInform);

        var queue = findings
            .Where(f =>
            {
                if (!autoInformByType.TryGetValue(f.ExposureType, out var auto) || !auto)
                    return false;
                var key = (f.KeySha256, f.RepoFullName, f.FilePath);
                if (sentKeys.Contains(key)) return false;
                if (latest.TryGetValue(key, out var rc)
                    && rc.Status is "removed" or "repo_gone" or "file_gone")
                    return false;
                return true;
            })
            .Take(_maxNotices)
            .ToList();

        if (queue.Count == 0)
        {
            var allOff = autoInformByType.Values.All(v => !v);
            hb.WriteLine(allOff
                ? "[notify] no pending notices (all exposure types are auto_inform=false; review and approve in the Web UI)"
                : "[notify] no pending notices");
            return;
        }

        hb.WriteLine($"[notify] {queue.Count} pending notice(s)");
        var ok = 0;
        var failed = 0;
        foreach (var f in queue)
        {
            if (ct.IsCancellationRequested) break;
            // Advisory-first: private vulnerability report when the repo
            // supports it, public courtesy issue only as the fallback.
            var result = await noticeSvc.SendVulnerabilityReportAsync(f, ct);
            if (result.Ok)
            {
                ok++;
                hb.WriteLine(result.IssueNumber is { } n
                    ? $"  notified {f.RepoFullName} via issue #{n}"
                    : $"  notified {f.RepoFullName} via private advisory {result.IssueHtmlUrl}");
            }
            else
            {
                failed++;
                hb.WriteLine(
                    $"  FAILED {f.RepoFullName}: {result.Error}");
            }
            // Pace issue creation; GitHub's content-creation secondary
            // limit is stricter than read.
            await Task.Delay(NoticePacing, ct);
        }
        hb.WriteLine($"[notify] sent={ok} failed={failed}");
    }

    /// <summary>
    /// For each finding not already in a terminal remediation state
    /// (removed | repo_gone | blocked), re-fetch the file and check whether the
    /// original key_sha256 still hashes out of the current content.
    /// Caps the per-run work at _maxRechecks so a 10k-finding DB doesn't
    /// burn the whole API budget on one run.
    /// </summary>
    private async Task RecheckRemediationsAsync(Db db, CancellationToken ct)
    {
        var hb = _hb!;
        await WaitWhilePausedAsync(hb, "rechecking", ct);
        SetLabel(hb, "rechecking");
        var patternByProvider = _patterns.ToDictionary(p => p.Provider);
        var latest = db.LatestRemediationChecks();
        var findings = db.AllFindings();

        // Sort by latest-checked-asc so stale findings are checked first.
        var queue = findings
            .Where(f =>
            {
                if (!latest.TryGetValue((f.KeySha256, f.RepoFullName, f.FilePath), out var prev))
                    return true;
                // "blocked": GitHub refuses the file (non-rate-limit 403);
                // re-asking every pass only burns API budget.
                return prev.Status is not ("removed" or "repo_gone" or "blocked");
            })
            .OrderBy(f =>
                latest.TryGetValue((f.KeySha256, f.RepoFullName, f.FilePath), out var prev)
                    ? prev.CheckedAtUtc : "")
            .Take(_maxRechecks)
            .ToList();

        if (queue.Count == 0)
        {
            hb.WriteLine("[recheck] nothing to recheck");
            return;
        }

        hb.WriteLine($"[recheck] {queue.Count} finding(s)");
        var n = 0;
        foreach (var f in queue)
        {
            if (ct.IsCancellationRequested) break;
            if (!patternByProvider.TryGetValue(f.Provider, out var pat)) continue;

            RefetchResult refetch;
            try
            {
                refetch = await _client.RefetchAsync(f.RepoFullName, f.FilePath, ct);
            }
            catch (Exception e) when (!ct.IsCancellationRequested
                && e is HttpRequestException or TaskCanceledException
                    or System.Text.Json.JsonException)
            {
                // Record it rather than abort the pass: an unchecked finding
                // sorts first, so one bad file would otherwise kill every
                // later recheck pass at the same spot.
                hb.WriteLine($"[warn] recheck fetch failed: {e.Message}");
                refetch = new RefetchResult(RefetchStatus.FetchFailed, "", null);
            }
            string status;
            string? commitSha = refetch.CommitSha;

            switch (refetch.Status)
            {
                case RefetchStatus.RepoGone:
                    status = "repo_gone";
                    break;
                case RefetchStatus.FileGone:
                    status = "file_gone";
                    break;
                case RefetchStatus.FetchFailed:
                    status = "fetch_failed";
                    break;
                case RefetchStatus.Blocked:
                    status = "blocked";
                    break;
                default:
                    // Re-hash matches, look for our key_sha256.
                    status = "removed";
                    foreach (Match m in pat.Regex.Matches(refetch.Content))
                    {
                        var rawKey = m.Value;
                        var (sha256, _, _) = Fingerprint(rawKey, pat);
                        rawKey = null!;
                        if (sha256 == f.KeySha256) { status = "present"; break; }
                    }
                    break;
            }

            db.InsertRemediationCheck(new RemediationCheck(
                KeySha256: f.KeySha256,
                RepoFullName: f.RepoFullName,
                FilePath: f.FilePath,
                CheckedAtUtc: DateTime.UtcNow.ToString("O"),
                Status: status,
                CommitSha: commitSha));

            n++;
            if (n % 25 == 0)
            {
                hb.WriteLine($"[recheck] {n}/{queue.Count}");
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
        }
        hb.WriteLine($"[recheck] done ({n} checks)");
    }

    private static List<Finding> ScanContent(
        FileContentResult result,
        CodeSearchItem item,
        ProviderPattern[] patterns)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrEmpty(result.Content)) return findings;

        // Per-file dedup so the same key isn't recorded twice if two
        // patterns happen to overlap on the same literal.
        var localSeen = new HashSet<string>();
        foreach (var pat in patterns)
        {
            foreach (Match m in pat.Regex.Matches(result.Content))
            {
                // rawKey leaves scope at the end of the loop body. Used
                // only to compute the SHA-256 hash and prefix; never
                // logged, never persisted, never returned.
                var rawKey = m.Value;
                var (sha256, prefix, length) = Fingerprint(rawKey, pat);
                rawKey = null!;

                if (!localSeen.Add(sha256)) continue;

                var start = m.Index;
                var end = start + m.Length;
                var ctxStart = Math.Max(0, start - ContextRadius);
                var ctxEnd = Math.Min(result.Content.Length, end + ContextRadius);
                var context = result.Content.Substring(ctxStart, ctxEnd - ctxStart);
                var model = Patterns.InferModel(context, pat.ModelHints);

                var repo = item.Repository;
                findings.Add(new Finding(
                    Provider: pat.Provider,
                    ExposureType: pat.ExposureType,
                    ModelHint: model,
                    RepoFullName: repo?.FullName ?? "",
                    RepoUrl: repo?.Url ?? "",
                    RepoHtmlUrl: repo?.HtmlUrl ?? "",
                    AuthorLogin: repo?.Owner?.Login,
                    FilePath: item.Path,
                    FileHtmlUrl: item.HtmlUrl,
                    CommitSha: result.CommitSha,
                    DefaultBranch: repo?.DefaultBranch,
                    KeySha256: sha256,
                    KeyPrefix: prefix,
                    KeyLength: length));
            }
        }
        return findings;
    }

    /// <summary>
    /// Cross-process pause check. Polls ScannerControl.RequestedState; when
    /// it flips to "paused" we idle in 1s ticks emitting heartbeats with a
    /// "paused" label so the UI shows liveness. Returns when state flips
    /// back to "running" or the cancellation token fires.
    /// </summary>
    private async Task WaitWhilePausedAsync(Heartbeat hb, string resumeLabel, CancellationToken ct)
    {
        var ctrl = _db.GetScannerControl();
        if (ctrl.RequestedState != "paused")
        {
            _db.WriteScannerHeartbeat(resumeLabel);
            return;
        }

        var pausedLabel = $"paused (was: {resumeLabel})";
        SetLabel(hb, pausedLabel);
        hb.WriteLine("[control] paused — waiting for resume");
        while (!ct.IsCancellationRequested)
        {
            _db.WriteScannerHeartbeat(pausedLabel);
            try { await Task.Delay(TimeSpan.FromSeconds(1), ct); }
            catch (OperationCanceledException) { break; }
            ctrl = _db.GetScannerControl();
            if (ctrl.RequestedState != "paused") break;
        }
        if (!ct.IsCancellationRequested)
        {
            hb.WriteLine("[control] resumed");
            SetLabel(hb, resumeLabel);
            _db.WriteScannerHeartbeat(resumeLabel);
        }
    }

    private void SetLabel(Heartbeat hb, string label)
    {
        hb.Label = label;
        _db.WriteScannerHeartbeat(label);
    }

    /// <summary>
    /// Reduces a raw match to what may be persisted (OC-LAW-1): SHA-256,
    /// the provider's fixed public prefix only (<see cref="Patterns.PublicPrefix"/>
    /// — nothing from the secret part, "" for passwords, the scheme for
    /// connection strings), and the length.
    /// </summary>
    private static (string sha256, string prefix, int length) Fingerprint(
        string key, ProviderPattern pattern)
    {
        var bytes = Encoding.UTF8.GetBytes(key);
        var hash = SHA256.HashData(bytes);
        var sha = Convert.ToHexString(hash).ToLowerInvariant();
        return (sha, Patterns.PublicPrefix(pattern.Provider, pattern.ExposureType, key), key.Length);
    }
}

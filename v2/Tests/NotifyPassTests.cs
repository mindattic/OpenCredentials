using Xunit;

namespace OpenCredentials.Tests;

/// <summary>
/// The CLI notify pass (Scraper.SendPendingNoticesAsync): the auto-inform
/// gate (OC-US-B1) and advisory-first routing (OC-US-B4).
/// </summary>
public class NotifyPassTests
{
    private static Scraper NewScraper(FakeGitHub gh, Db db) =>
        new(gh.Client(), db, new FileInfo(Path.GetTempFileName()),
            maxPerProvider: 0, maxRechecks: 0, maxNotices: 10, includePasswords: false)
        {
            NoticePacing = TimeSpan.Zero,
        };

    [Fact]
    public async Task Notify_pass_sends_nothing_while_every_type_is_auto_inform_off()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        db.UpsertFinding(TestData.Finding());

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.Empty(gh.Calls);
        Assert.Empty(db.AllNotices());
    }

    [Fact]
    public async Task Notify_pass_discloses_through_private_advisory_first()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb(autoInformOn: ExposureTypes.ApiKey);
        var f = TestData.Finding();
        db.UpsertFinding(f);

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.Single(gh.AdvisoryCalls);
        Assert.Empty(gh.IssueCalls);
        var notice = Assert.Single(db.AllNotices());
        Assert.Equal(NoticeService.AdvisoryChannel, notice.Channel);
        Assert.Equal("sent", notice.Status);
    }

    [Fact]
    public async Task Notify_pass_falls_back_to_public_issue_when_private_reporting_is_off()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(System.Net.HttpStatusCode.NotFound) };
        var db = TestData.NewDb(autoInformOn: ExposureTypes.ApiKey);
        db.UpsertFinding(TestData.Finding());

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.Single(gh.IssueCalls);
        var notice = Assert.Single(db.AllNotices());
        Assert.Equal("github_issue", notice.Channel);
    }
}

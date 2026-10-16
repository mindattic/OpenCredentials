using NUnit.Framework;

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

    [Test]
    public async Task Notify_pass_sends_nothing_while_every_type_is_auto_inform_off()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        db.UpsertFinding(TestData.Finding());

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.That(gh.Calls, Is.Empty);
        Assert.That(db.AllNotices(), Is.Empty);
    }

    [Test]
    public async Task Notify_pass_discloses_through_private_advisory_first()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb(autoInformOn: ExposureTypes.ApiKey);
        var f = TestData.Finding();
        db.UpsertFinding(f);

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.That(gh.AdvisoryCalls, Has.Exactly(1).Items);
        Assert.That(gh.IssueCalls, Is.Empty);
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
        var notice = db.AllNotices().Single();
        Assert.That(notice.Channel, Is.EqualTo(NoticeService.AdvisoryChannel));
        Assert.That(notice.Status, Is.EqualTo("sent"));
    }

    [Test]
    public async Task Notify_pass_falls_back_to_public_issue_when_private_reporting_is_off()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(System.Net.HttpStatusCode.NotFound) };
        var db = TestData.NewDb(autoInformOn: ExposureTypes.ApiKey);
        db.UpsertFinding(TestData.Finding());

        await NewScraper(gh, db).RunNotifyPassAsync(CancellationToken.None);

        Assert.That(gh.IssueCalls, Has.Exactly(1).Items);
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
        var notice = db.AllNotices().Single();
        Assert.That(notice.Channel, Is.EqualTo("github_issue"));
    }
}

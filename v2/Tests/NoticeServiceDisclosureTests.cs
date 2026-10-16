using System.Net;
using NUnit.Framework;

namespace OpenCredentials.Tests;

/// <summary>
/// Advisory-first disclosure (OC-US-B4) and notice idempotency (OC-US-B3),
/// against a fake GitHub API and an in-memory database.
/// </summary>
public class NoticeServiceDisclosureTests
{
    private static Notice? Notice(Db db, Finding f, string channel) =>
        db.GetNotice(f.KeySha256, f.RepoFullName, f.FilePath, channel);

    [Test]
    public async Task Repo_with_private_reporting_gets_a_private_advisory_and_no_public_issue()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(result.Ok, Is.True);
        Assert.That(result.Skipped, Is.False);
        Assert.That(gh.AdvisoryCalls, Has.Exactly(1).Items);
        Assert.That(gh.AdvisoryCalls.Single().Path, Is.EqualTo("/repos/octo/leaky/security-advisories/reports"));
        Assert.That(gh.IssueCalls, Is.Empty);
        var advisory = Notice(db, f, NoticeService.AdvisoryChannel);
        Assert.That(advisory, Is.Not.Null);
        Assert.That(advisory!.Status, Is.EqualTo("sent"));
        Assert.That(advisory.IssueHtmlUrl, Is.EqualTo("https://github.com/o/r/security/advisories/GHSA-test-0000-0001"));
        Assert.That(Notice(db, f, "github_issue"), Is.Null);
    }

    [TestCase(HttpStatusCode.NotFound)]
    [TestCase(HttpStatusCode.Forbidden)]
    [TestCase(HttpStatusCode.UnprocessableEntity)]
    public async Task Repo_without_private_reporting_falls_back_to_public_issue(HttpStatusCode unavailable)
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(unavailable) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(result.Ok, Is.True);
        Assert.That(result.IssueNumber, Is.EqualTo(7));
        Assert.That(gh.AdvisoryCalls, Has.Exactly(1).Items);
        Assert.That(gh.IssueCalls, Has.Exactly(1).Items);
        Assert.That(Notice(db, f, "github_issue")!.Status, Is.EqualTo("sent"));
        Assert.That(Notice(db, f, NoticeService.AdvisoryChannel), Is.Null);
    }

    [Test]
    public async Task Transient_advisory_failure_never_goes_public()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.BadGateway) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(result.Ok, Is.False);
        Assert.That(gh.IssueCalls, Is.Empty);
        Assert.That(Notice(db, f, NoticeService.AdvisoryChannel)!.Status, Is.EqualTo("failed"));
        Assert.That(Notice(db, f, "github_issue"), Is.Null);
    }

    [Test]
    public async Task Rate_limited_403_is_a_transient_failure_not_unavailable()
    {
        var gh = new FakeGitHub
        {
            Advisory = () =>
            {
                var r = FakeGitHub.Status(HttpStatusCode.Forbidden);
                r.Headers.Add("X-RateLimit-Remaining", "0");
                return r;
            },
        };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(result.Ok, Is.False);
        Assert.That(gh.IssueCalls, Is.Empty);
    }

    [Test]
    public async Task Retry_after_failed_advisory_replaces_the_failed_row()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.InternalServerError) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f);

        gh.Advisory = new FakeGitHub().Advisory;
        var retry = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(retry.Ok, Is.True);
        Assert.That(Notice(db, f, NoticeService.AdvisoryChannel)!.Status, Is.EqualTo("sent"));
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
        Assert.That(gh.IssueCalls, Is.Empty);
    }

    [Test]
    public async Task Finding_already_disclosed_by_issue_is_skipped_without_any_GitHub_call()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.NotFound) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f); // falls back to issue
        gh.Calls.Clear();

        var again = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(again.Skipped, Is.True);
        Assert.That(gh.Calls, Is.Empty);
    }

    [Test]
    public async Task Finding_already_disclosed_by_advisory_is_skipped_without_any_GitHub_call()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f);
        gh.Calls.Clear();

        var again = await svc.SendVulnerabilityReportAsync(f);

        Assert.That(again.Skipped, Is.True);
        Assert.That(gh.Calls, Is.Empty);
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
    }

    [Test]
    public async Task Sending_an_issue_twice_is_a_no_op()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var first = await svc.SendAsync(f);
        var second = await svc.SendAsync(f);

        Assert.That(first.Skipped, Is.False);
        Assert.That(second.Skipped, Is.True);
        Assert.That(gh.IssueCalls, Has.Exactly(1).Items);
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
    }
}

using System.Net;
using Xunit;

namespace OpenCredentials.Tests;

/// <summary>
/// Advisory-first disclosure (OC-US-B4) and notice idempotency (OC-US-B3),
/// against a fake GitHub API and an in-memory database.
/// </summary>
public class NoticeServiceDisclosureTests
{
    private static Notice? Notice(Db db, Finding f, string channel) =>
        db.GetNotice(f.KeySha256, f.RepoFullName, f.FilePath, channel);

    [Fact]
    public async Task Repo_with_private_reporting_gets_a_private_advisory_and_no_public_issue()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.True(result.Ok);
        Assert.False(result.Skipped);
        Assert.Single(gh.AdvisoryCalls);
        Assert.Equal("/repos/octo/leaky/security-advisories/reports", gh.AdvisoryCalls.Single().Path);
        Assert.Empty(gh.IssueCalls);
        var advisory = Notice(db, f, NoticeService.AdvisoryChannel);
        Assert.NotNull(advisory);
        Assert.Equal("sent", advisory!.Status);
        Assert.Equal("https://github.com/o/r/security/advisories/GHSA-test-0000-0001", advisory.IssueHtmlUrl);
        Assert.Null(Notice(db, f, "github_issue"));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.UnprocessableEntity)]
    public async Task Repo_without_private_reporting_falls_back_to_public_issue(HttpStatusCode unavailable)
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(unavailable) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.True(result.Ok);
        Assert.Equal(7, result.IssueNumber);
        Assert.Single(gh.AdvisoryCalls);
        Assert.Single(gh.IssueCalls);
        Assert.Equal("sent", Notice(db, f, "github_issue")!.Status);
        Assert.Null(Notice(db, f, NoticeService.AdvisoryChannel));
    }

    [Fact]
    public async Task Transient_advisory_failure_never_goes_public()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.BadGateway) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var result = await svc.SendVulnerabilityReportAsync(f);

        Assert.False(result.Ok);
        Assert.Empty(gh.IssueCalls);
        Assert.Equal("failed", Notice(db, f, NoticeService.AdvisoryChannel)!.Status);
        Assert.Null(Notice(db, f, "github_issue"));
    }

    [Fact]
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

        Assert.False(result.Ok);
        Assert.Empty(gh.IssueCalls);
    }

    [Fact]
    public async Task Retry_after_failed_advisory_replaces_the_failed_row()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.InternalServerError) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f);

        gh.Advisory = new FakeGitHub().Advisory;
        var retry = await svc.SendVulnerabilityReportAsync(f);

        Assert.True(retry.Ok);
        Assert.Equal("sent", Notice(db, f, NoticeService.AdvisoryChannel)!.Status);
        Assert.Single(db.AllNotices());
        Assert.Empty(gh.IssueCalls);
    }

    [Fact]
    public async Task Finding_already_disclosed_by_issue_is_skipped_without_any_GitHub_call()
    {
        var gh = new FakeGitHub { Advisory = () => FakeGitHub.Status(HttpStatusCode.NotFound) };
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f); // falls back to issue
        gh.Calls.Clear();

        var again = await svc.SendVulnerabilityReportAsync(f);

        Assert.True(again.Skipped);
        Assert.Empty(gh.Calls);
    }

    [Fact]
    public async Task Finding_already_disclosed_by_advisory_is_skipped_without_any_GitHub_call()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());
        await svc.SendVulnerabilityReportAsync(f);
        gh.Calls.Clear();

        var again = await svc.SendVulnerabilityReportAsync(f);

        Assert.True(again.Skipped);
        Assert.Empty(gh.Calls);
        Assert.Single(db.AllNotices());
    }

    [Fact]
    public async Task Sending_an_issue_twice_is_a_no_op()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        var svc = new NoticeService(db, gh.Client());

        var first = await svc.SendAsync(f);
        var second = await svc.SendAsync(f);

        Assert.False(first.Skipped);
        Assert.True(second.Skipped);
        Assert.Single(gh.IssueCalls);
        Assert.Single(db.AllNotices());
    }
}

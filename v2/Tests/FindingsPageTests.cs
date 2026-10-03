using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using FindingsPage = OpenCredentials.Blazor.Components.Pages.Findings;

namespace OpenCredentials.Tests;

/// <summary>The Findings page Send button routes through advisory-first disclosure (OC-US-B4).</summary>
public class FindingsPageTests : TestContext
{
    [Fact]
    public void Send_button_files_a_private_advisory_not_a_public_issue()
    {
        var gh = new FakeGitHub();
        var db = TestData.NewDb();
        var f = TestData.Finding();
        db.UpsertFinding(f);
        Services.AddSingleton(db);
        Services.AddSingleton(new NoticeService(db, gh.Client()));

        var page = RenderComponent<FindingsPage>();
        var send = page.FindAll("button.btn").Single(b => b.TextContent.Trim() == "Send");
        send.Click();

        page.WaitForAssertion(() => Assert.Contains("advisory", page.Markup));
        Assert.Single(gh.AdvisoryCalls);
        Assert.Empty(gh.IssueCalls);
        var notice = Assert.Single(db.AllNotices());
        Assert.Equal(NoticeService.AdvisoryChannel, notice.Channel);
    }
}

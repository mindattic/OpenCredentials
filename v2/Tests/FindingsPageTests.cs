using Bunit;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using FindingsPage = OpenCredentials.Blazor.Components.Pages.Findings;

namespace OpenCredentials.Tests;

/// <summary>The Findings page Send button routes through advisory-first disclosure (OC-US-B4).</summary>
public class FindingsPageTests : Bunit.TestContext
{
    [Test]
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

        page.WaitForAssertion(() => Assert.That(page.Markup, Does.Contain("advisory")));
        Assert.That(gh.AdvisoryCalls, Has.Exactly(1).Items);
        Assert.That(gh.IssueCalls, Is.Empty);
        Assert.That(db.AllNotices(), Has.Exactly(1).Items);
        var notice = db.AllNotices().Single();
        Assert.That(notice.Channel, Is.EqualTo(NoticeService.AdvisoryChannel));
    }
}

using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace OpenCredentials.Tests;

/// <summary>
/// Fake GitHub API: an HttpMessageHandler that records every request and
/// answers from canned responses. Nothing ever leaves the process.
/// </summary>
public sealed class FakeGitHub : HttpMessageHandler
{
    public sealed record Call(HttpMethod Method, string Path, string Body);

    public List<Call> Calls { get; } = [];

    /// <summary>Response for POST .../security-advisories/reports.</summary>
    public Func<HttpResponseMessage> Advisory { get; set; } =
        () => Json(HttpStatusCode.Created,
            """{"ghsa_id":"GHSA-test-0000-0001","html_url":"https://github.com/o/r/security/advisories/GHSA-test-0000-0001"}""");

    /// <summary>Response for POST .../issues.</summary>
    public Func<HttpResponseMessage> Issue { get; set; } =
        () => Json(HttpStatusCode.Created,
            """{"number":7,"html_url":"https://github.com/o/r/issues/7"}""");

    public IEnumerable<Call> AdvisoryCalls =>
        Calls.Where(c => c.Path.EndsWith("/security-advisories/reports"));
    public IEnumerable<Call> IssueCalls =>
        Calls.Where(c => c.Path.EndsWith("/issues"));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        var path = request.RequestUri!.AbsolutePath;
        Calls.Add(new Call(request.Method, path, body));

        if (request.Method == HttpMethod.Post && path.EndsWith("/security-advisories/reports"))
            return Advisory();
        if (request.Method == HttpMethod.Post && path.EndsWith("/issues"))
            return Issue();
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    public static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Status(HttpStatusCode code) =>
        Json(code, """{"message":"fake"}""");

    public GitHubClient Client() => new("fake-token", this);
}

/// <summary>In-memory EF factory: each instance is an isolated database.</summary>
public sealed class InMemoryFactory : IDbContextFactory<OpenCredentialsContext>
{
    private readonly DbContextOptions<OpenCredentialsContext> _opts =
        new DbContextOptionsBuilder<OpenCredentialsContext>()
            .UseInMemoryDatabase("oc-" + Guid.NewGuid())
            .Options;

    public OpenCredentialsContext CreateDbContext() => new(_opts);
}

public static class TestData
{
    /// <summary>
    /// A Db over a fresh in-memory store, seeded like the real one
    /// (every exposure type, auto_inform off; one ScannerControl row).
    /// </summary>
    public static Db NewDb(params string[] autoInformOn)
    {
        var factory = new InMemoryFactory();
        using (var ctx = factory.CreateDbContext())
        {
            foreach (var (name, description) in ExposureTypes.All)
            {
                ctx.ExposureTypes.Add(new ExposureTypeEntity
                {
                    Name = name,
                    Description = description,
                    AutoInform = autoInformOn.Contains(name),
                });
            }
            ctx.ScannerControls.Add(new ScannerControlEntity
            {
                Id = 1,
                RequestedState = "running",
                RequestedAtUtc = DateTime.UtcNow,
            });
            ctx.SaveChanges();
        }
        return new Db(factory);
    }

    /// <summary>Synthetic finding — fingerprint only, no real credential anywhere.</summary>
    public static Finding Finding(string repo = "octo/leaky", string path = "src/config.js") => new(
        Provider: "openai",
        ExposureType: "ApiKey",
        ModelHint: null,
        RepoFullName: repo,
        RepoUrl: $"https://api.github.com/repos/{repo}",
        RepoHtmlUrl: $"https://github.com/{repo}",
        AuthorLogin: "octocat",
        FilePath: path,
        FileHtmlUrl: $"https://github.com/{repo}/blob/main/{path}",
        CommitSha: "abc123",
        DefaultBranch: "main",
        KeySha256: new string('a', 64),
        KeyPrefix: "sk-proj-",
        KeyLength: 51);
}

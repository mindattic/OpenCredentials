using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenCredentials;

public static class Settings
{
    /// <summary>
    /// LocalDB connection used by both the CLI scraper and the Blazor app.
    /// Override in Web's appsettings.json (ConnectionStrings:OpenCredentials) or
    /// via the OPENCREDS_DB env var for the CLI.
    /// </summary>
    public const string DefaultConnectionString =
        "Server=(localdb)\\MSSQLLocalDB;Database=OpenCredentials;" +
        "Trusted_Connection=True;TrustServerCertificate=True;Encrypt=False";

    public static string ResolveConnectionString() =>
        Environment.GetEnvironmentVariable("OPENCREDS_DB")
            ?? DefaultConnectionString;

    public static string ConfigPath
    {
        get
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, "MindAttic", "OpenCredentials", "settings.json");
        }
    }

    [Obsolete("Use GitHubTokenProvider; this fallback will be removed once developer machines have migrated to %APPDATA%\\MindAttic\\Tokens\\tokens.json or the GITHUB_TOKEN env var.")]
    public static string? LoadGitHubToken()
    {
        var path = ConfigPath;
        if (!File.Exists(path)) return null;
        try
        {
            using var stream = File.OpenRead(path);
            var doc = JsonSerializer.Deserialize<SettingsFile>(stream);
            return string.IsNullOrWhiteSpace(doc?.GitHubToken) ? null : doc.GitHubToken;
        }
        catch
        {
            return null;
        }
    }

    private sealed class SettingsFile
    {
        [JsonPropertyName("github_token")] public string? GitHubToken { get; set; }
    }
}

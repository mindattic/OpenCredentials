using Microsoft.Extensions.Configuration;
using MindAttic.Vault.Settings;
using MindAttic.Vault.Settings.Manifest;

namespace OpenCredentials;

/// <summary>
/// OpenCredentials' settings, shared by the CLI scraper and the Blazor app, edited in MindAttic.Vault.Desktop
/// (<c>%APPDATA%\MindAttic\OpenCredentials\settings.json</c>; deployed: <c>MindAttic:Settings:OpenCredentials:*</c>).
/// The GitHub token is a Vault credential (Tokens: github), never a setting.
/// </summary>
[SettingsApp(AppId, "OpenCredentials", Icon = "shield",
    Description = "Leaked-credential prevalence scanner and disclosure notices (metadata only).")]
public sealed class OpenCredentialsSettings
{
    public const string AppId = "OpenCredentials";

    /// <summary>The CLI's explicit override, kept for scripts and scheduled runs.</summary>
    public const string ConnectionEnvVar = "OPENCREDS_DB";

    [Setting("Database", Group = "Storage", Order = 1, NotSecret = true,
        Help = "SQL Server connection string the CLI scraper writes and the dashboard reads. OPENCREDS_DB or the CLI's --connection still override it.")]
    public string DatabaseConnection { get; set; } = Settings.DefaultConnectionString;

    [Setting("Notice channel", Group = "Disclosure notices", Order = 1,
        Help = "How a leak is disclosed to the repo owner: github_issue opens an issue, github_advisory records an advisory notice.")]
    [SettingChoices("github_issue", "github_advisory")]
    public string NoticeChannel { get; set; } = NoticeConfig.Default.Channel;

    [Setting("Notice title", Group = "Disclosure notices", Order = 2,
        Help = "Tokens: {provider} {exposure_type} {repo} {file_path} {file_html_url} {key_sha_short} {key_prefix} {detected_at} {author_at}.")]
    public string NoticeTitle { get; set; } = NoticeConfig.Default.Title;

    [Setting("Notice body", Group = "Disclosure notices", Order = 3, Help = "Markdown; same tokens as the title.")]
    [Multiline]
    public string NoticeBody { get; set; } = NoticeConfig.Default.Body;

    /// <summary>The notice template the dashboard sends.</summary>
    public NoticeConfig ToNotice() => new(NoticeChannel, NoticeTitle, NoticeBody);

    /// <summary>
    /// The settings: deployed App Configuration values when present; otherwise the Vault file, importing today's
    /// <c>ConnectionStrings:OpenCredentials</c>, <c>OPENCREDS_DB</c> and <c>OpenCredentials:Notice*</c> once.
    /// </summary>
    public static OpenCredentialsSettings Load(IConfiguration? configuration = null, ISettingsStore<OpenCredentialsSettings>? store = null,
        Func<string, string?>? getEnv = null)
    {
        var deployed = configuration?.GetSection(SettingsManifest.PrefixFor(AppId));
        if (deployed is not null && deployed.Exists())
            return deployed.Get<OpenCredentialsSettings>() ?? new OpenCredentialsSettings();

        store ??= JsonSettingsStore<OpenCredentialsSettings>.ForSettingsApp();
        if (!store.Exists())
        {
            getEnv ??= Environment.GetEnvironmentVariable;
            var imported = new OpenCredentialsSettings();
            if (configuration?.GetConnectionString(AppId) is { Length: > 0 } cs) imported.DatabaseConnection = cs;
            else if (getEnv(ConnectionEnvVar) is { Length: > 0 } env) imported.DatabaseConnection = env;
            var legacy = configuration?.GetSection(AppId);
            if (legacy?["NoticeChannel"] is { Length: > 0 } channel) imported.NoticeChannel = channel;
            if (legacy?["NoticeTitle"] is { Length: > 0 } title) imported.NoticeTitle = title;
            if (legacy?["NoticeBody"] is { Length: > 0 } body) imported.NoticeBody = body;
            store.Save(imported);
        }
        return store.LoadOrSeed();
    }

    /// <summary>The connection the CLI uses: <c>OPENCREDS_DB</c> when set, else this setting.</summary>
    public static string ResolveConnection(OpenCredentialsSettings settings, Func<string, string?>? getEnv = null) =>
        (getEnv ?? Environment.GetEnvironmentVariable)(ConnectionEnvVar) is { Length: > 0 } env ? env : settings.DatabaseConnection;
}

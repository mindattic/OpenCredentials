using Microsoft.Extensions.Configuration;
using MindAttic.Vault.Paths;
using MindAttic.Vault.Settings;
using MindAttic.Vault.Settings.Manifest;
using NUnit.Framework;

namespace OpenCredentials.Tests;

/// <summary>Every test in this assembly sees temp Vault roots, so nothing can write the real AppData.</summary>
[SetUpFixture]
public sealed class TestVaultRoots
{
    private string root = "";

    [OneTimeSetUp]
    public void SetUp()
    {
        root = Path.Combine(Path.GetTempPath(), "OpenCredsVault-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable(VaultPaths.RoamingRootEnvVar, Path.Combine(root, "roaming"));
        Environment.SetEnvironmentVariable(VaultPaths.LocalRootEnvVar, Path.Combine(root, "local"));
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable(VaultPaths.RoamingRootEnvVar, null);
        Environment.SetEnvironmentVariable(VaultPaths.LocalRootEnvVar, null);
        try { Directory.Delete(root, recursive: true); } catch { }
    }
}

/// <summary>LAMP (OC-T28): OpenCredentials' settings in Vault, one end-to-end test per setting.</summary>
[NonParallelizable]
public class LampSettingsTests
{
    private string dir = "";
    private JsonSettingsStore<OpenCredentialsSettings> Store() => new(dir);
    private static readonly Func<string, string?> NoEnv = _ => null;

    [SetUp]
    public void SetUp() => dir = Path.Combine(Path.GetTempPath(), "opencreds-lamp-" + Guid.NewGuid().ToString("N"));

    [TearDown]
    public void TearDown()
    {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }

    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Test]
    public void Setting_DatabaseConnection_ImportsRoundTripsAndIsTheDatabaseBothToolsUse()
    {
        const string today = "Server=.;Database=OC;Trusted_Connection=True";
        var s = OpenCredentialsSettings.Load(Config(new() { ["ConnectionStrings:OpenCredentials"] = today }), Store(), NoEnv);
        Assert.That(s.DatabaseConnection, Is.EqualTo(today), "appsettings value imported");
        Store().Update(x => x.DatabaseConnection = "Server=db2;Database=OC");
        var reloaded = OpenCredentialsSettings.Load(null, Store(), NoEnv);
        Assert.That(OpenCredentialsSettings.ResolveConnection(reloaded, NoEnv), Is.EqualTo("Server=db2;Database=OC"));
        Assert.That(OpenCredentialsSettings.ResolveConnection(reloaded, v => v == "OPENCREDS_DB" ? "Server=override" : null), Is.EqualTo("Server=override"),
            "OPENCREDS_DB still overrides for the CLI");
    }

    [Test]
    public void Setting_DatabaseConnection_ImportsFromTheEnvVarWhenAppSettingsHasNone()
    {
        var s = OpenCredentialsSettings.Load(Config(new()), Store(), v => v == "OPENCREDS_DB" ? "Server=fromenv" : null);
        Assert.That(s.DatabaseConnection, Is.EqualTo("Server=fromenv"));
    }

    [Test]
    public void Setting_NoticeChannel_ImportsRoundTripsAndIsTheNoticeTheDashboardSends()
    {
        var s = OpenCredentialsSettings.Load(Config(new() { ["OpenCredentials:NoticeChannel"] = "github_advisory" }), Store(), NoEnv);
        Assert.That(s.NoticeChannel, Is.EqualTo("github_advisory"));
        Store().Update(x => x.NoticeChannel = "github_issue");
        Assert.That(OpenCredentialsSettings.Load(null, Store(), NoEnv).ToNotice().Channel, Is.EqualTo("github_issue"));
    }

    [Test]
    public void Setting_NoticeTitle_ImportsRoundTripsAndIsTheNoticeTheDashboardSends()
    {
        var s = OpenCredentialsSettings.Load(Config(new() { ["OpenCredentials:NoticeTitle"] = "Leak in {repo}" }), Store(), NoEnv);
        Assert.That(s.NoticeTitle, Is.EqualTo("Leak in {repo}"));
        Store().Update(x => x.NoticeTitle = "Key exposed ({provider})");
        Assert.That(OpenCredentialsSettings.Load(null, Store(), NoEnv).ToNotice().Title, Is.EqualTo("Key exposed ({provider})"));
    }

    [Test]
    public void Setting_NoticeBody_ImportsRoundTripsAndIsTheNoticeTheDashboardSends()
    {
        var s = OpenCredentialsSettings.Load(Config(new() { ["OpenCredentials:NoticeBody"] = "Please rotate." }), Store(), NoEnv);
        Assert.That(s.NoticeBody, Is.EqualTo("Please rotate."));
        Store().Update(x => x.NoticeBody = "Line 1\nLine 2");
        Assert.That(OpenCredentialsSettings.Load(null, Store(), NoEnv).ToNotice().Body, Is.EqualTo("Line 1\nLine 2"));
    }

    [Test]
    public void EverySettingHasItsOwnTest()
    {
        var tested = GetType().GetMethods().Select(m => m.Name).Where(n => n.StartsWith("Setting_")).ToList();
        foreach (var field in SettingsManifestBuilder.Build<OpenCredentialsSettings>().Fields)
            Assert.That(tested.Any(t => t.StartsWith("Setting_" + char.ToUpperInvariant(field.Property[0]) + field.Property[1..] + "_")), Is.True, field.Property);
    }

    [Test]
    public void FreshMachine_SeedsTodaysDefaults()
    {
        var s = OpenCredentialsSettings.Load(Config(new()), Store(), NoEnv);
        Assert.That(s.DatabaseConnection, Is.EqualTo(Settings.DefaultConnectionString));
        Assert.That(s.ToNotice(), Is.EqualTo(NoticeConfig.Default));
        Assert.That(SettingsManifestFile.TryRead(Path.Combine(dir, SettingsManifest.FileName))!.Find("MindAttic:Settings:OpenCredentials:noticeBody")!.Kind,
            Is.EqualTo(SettingKind.Multiline));
    }

    [Test]
    public void DeployedConfiguration_WinsOverTheLocalFile()
    {
        Store().Save(new OpenCredentialsSettings { NoticeChannel = "github_issue" });
        var s = OpenCredentialsSettings.Load(Config(new() { ["MindAttic:Settings:OpenCredentials:noticeChannel"] = "github_advisory" }), Store(), NoEnv);
        Assert.That(s.NoticeChannel, Is.EqualTo("github_advisory"));
    }

    [Test]
    public void ExistingVaultFile_IsNeverOverwrittenByOldKeys()
    {
        Store().Save(new OpenCredentialsSettings { DatabaseConnection = "kept" });
        Assert.That(OpenCredentialsSettings.Load(Config(new() { ["ConnectionStrings:OpenCredentials"] = "other" }), Store(), NoEnv).DatabaseConnection,
            Is.EqualTo("kept"));
    }
}

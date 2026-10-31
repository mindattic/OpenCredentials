using OpenCredentials;
using OpenCredentials.Blazor.Components;
using Microsoft.EntityFrameworkCore;
using MindAttic.Vault.Configuration;
using MindAttic.Vault.DependencyInjection;

if (MindAttic.Vault.Settings.Manifest.SettingsManifestCommand.Switch is var manifestSwitch
    && args.Contains(manifestSwitch, StringComparer.OrdinalIgnoreCase))
{
    // Install step: import today's appsettings values once and write the manifest MindAttic Vault renders.
    OpenCredentialsSettings.Load(new ConfigurationBuilder().AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true).Build());
    return;
}

var builder = WebApplication.CreateBuilder(args);

// Cloud-native configuration chain. Lower sources first; later sources win.
//   AddJsonFile  — non-secret defaults (already present via WebApplicationBuilder).
//   AddMindAtticVaultFiles — %APPDATA%\MindAttic\<bucket> on dev machines.
//   AddEnvironmentVariables — App Service Application Settings + Key Vault refs in prod.
builder.Configuration
    .AddMindAtticVaultFiles()
    .AddEnvironmentVariables();

builder.Services.AddMindAtticVault(builder.Configuration);
builder.Services.AddSingleton<GitHubTokenProvider>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Settings are edited in MindAttic.Vault.Desktop; today's appsettings values were imported once.
var settings = OpenCredentialsSettings.Load(builder.Configuration);
var connectionString = settings.DatabaseConnection;

builder.Services.AddDbContextFactory<OpenCredentialsContext>(opts =>
    opts.UseSqlServer(connectionString));

// Db wraps the context factory; scoped matches Blazor Server's per-circuit
// lifetime but the underlying factory is a singleton.
builder.Services.AddScoped<Db>(sp =>
    new Db(sp.GetRequiredService<IDbContextFactory<OpenCredentialsContext>>()));

// Singleton: the GitHub HTTP client is cheap to share, and the token
// resolution only needs to happen once per process.
builder.Services.AddSingleton<GitHubClient>(sp =>
{
    var token = sp.GetRequiredService<GitHubTokenProvider>().Get()
        ?? throw new InvalidOperationException(
            "GitHub token is required. Set it via " +
            "%APPDATA%\\MindAttic\\Tokens\\tokens.json ({ \"github\": \"ghp_...\" }) " +
            "(dev), the GITHUB_TOKEN env var (legacy), or as the App Service " +
            "Application Setting MindAttic__Vault__Tokens__github (prod).");
    return new GitHubClient(token);
});

builder.Services.AddSingleton(settings.ToNotice());

builder.Services.AddScoped<NoticeService>(sp => new NoticeService(
    sp.GetRequiredService<Db>(),
    sp.GetRequiredService<GitHubClient>(),
    sp.GetRequiredService<NoticeConfig>()));

var app = builder.Build();

// Apply migrations + seed exposure types on host start. Idempotent: if
// the CLI scraper already created the schema, this is a fast no-op.
Db.EnsureCreatedAndSeeded(
    app.Services.GetRequiredService<IDbContextFactory<OpenCredentialsContext>>());

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

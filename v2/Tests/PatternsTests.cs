using System.Text.RegularExpressions;
using NUnit.Framework;

namespace OpenCredentials.Tests;

/// <summary>
/// Patterns.All / Patterns.PasswordPatterns / Patterns.InferModel are the product:
/// a silent regex regression here means either a missed leak or a false disclosure.
/// Every provider gets a synthetic positive sample (asserted to both match the regex
/// and contain the SearchNeedle) plus targeted near-miss negatives.
/// </summary>
public class PatternsTests
{
    private static string Letters(int n) => new string('a', n);
    private static string Digits(int n) => new string('1', n);
    private static string Hex(int n) => new string('a', n);

    // --- Synthetic positive samples, one per provider in Patterns.All -----

    private static readonly Dictionary<string, string> PositiveSamples = new()
    {
        ["anthropic"] = "sk-ant-api03-" + Letters(93) + "AA",
        ["openai"] = "sk-proj-" + Letters(40),
        ["openai-legacy"] = "\"sk-\" sk-" + Letters(48) + " end",
        ["google-gemini"] = "AIza" + Letters(35),
        ["aws-access-key"] = " AKIA1234567890ABCDEF ",
        ["digitalocean-pat"] = "dop_v1_" + Hex(64),
        ["digitalocean-oauth"] = "doo_v1_" + Hex(64),
        ["github-pat-classic"] = "ghp_" + Letters(36),
        ["github-pat-fine"] = "github_pat_" + Letters(82),
        ["github-oauth"] = "gho_" + Letters(36),
        ["github-app-user"] = "ghu_" + Letters(36),
        ["github-app-server"] = "ghs_" + Letters(36),
        ["npm-token"] = "npm_" + Letters(36),
        ["pypi-token"] = "pypi-AgEIcHlwaS5vcmc" + Letters(50),
        ["stripe-secret-live"] = "sk_live_" + Letters(24),
        ["stripe-restricted-live"] = "rk_live_" + Letters(24),
        ["shopify-private"] = "shppa_" + Hex(32),
        ["shopify-access"] = "shpat_" + Hex(32),
        ["square-access"] = "sq0atp-" + Letters(22),
        ["square-secret"] = "sq0csp-" + Letters(43),
        ["slack-bot"] = "xoxb-" + Digits(10) + "-" + Digits(10) + "-" + Letters(24),
        ["slack-user"] = "xoxp-" + Digits(10) + "-" + Digits(10) + "-" + Digits(10) + "-" + Letters(24),
        ["slack-webhook"] = "https://hooks.slack.com/services/TABC123/BXYZ789/" + Letters(20),
        ["discord-webhook"] = "https://discord.com/api/webhooks/" + Digits(18) + "/" + Letters(60),
        ["sendgrid"] = "SG." + Letters(22) + "." + Letters(43),
        ["mailgun"] = "key-" + Hex(32),
        ["twilio-sk"] = " SK" + Hex(32) + " ",
        ["jwt"] = "eyJ" + Letters(10) + ".eyJ" + Letters(10) + "." + Letters(10),
        ["postgres-uri"] = "postgres://user:password@host/db",
        ["mysql-uri"] = "mysql://user:password@host/db",
        ["mongodb-uri"] = "mongodb://user:password@host/db",
        ["redis-uri"] = "redis://user:password@host/db",
        ["private-key-rsa"] = "-----BEGIN RSA PRIVATE KEY-----\n" + Letters(40) + "\n-----END RSA PRIVATE KEY-----",
        ["private-key-openssh"] =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Letters(40) + "\n-----END OPENSSH PRIVATE KEY-----",
        ["private-key-ec"] = "-----BEGIN EC PRIVATE KEY-----\n" + Letters(40) + "\n-----END EC PRIVATE KEY-----",
        ["private-key-pgp"] =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + Letters(40) + "\n-----END PGP PRIVATE KEY BLOCK-----",
    };

    [Test]
    public void Every_provider_in_Patterns_All_has_a_positive_sample()
    {
        var providers = Patterns.All.Select(p => p.Provider).ToHashSet();
        Assert.That(PositiveSamples.Keys.ToHashSet(), Is.EqualTo(providers));
    }

    public static IEnumerable<object[]> AllProviders =>
        Patterns.All.Select(p => new object[] { p.Provider });

    [TestCaseSource(nameof(AllProviders))]
    public void Positive_sample_matches_and_contains_the_search_needle(string provider)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        var sample = PositiveSamples[provider];

        Assert.That(pattern.Regex.IsMatch(sample), Is.True, $"{provider}: regex did not match its own synthetic sample.");
        Assert.That(sample, Does.Contain(pattern.SearchNeedle));
    }

    // --- Near-miss: one char short of a fixed-count run, no trailing literal ---
    // (the run isn't followed by any required literal, so "one too long" would
    // still match as a substring — only "too short" is a meaningful negative here)

    public static CaseRows FixedCountNoTrailingLiteral => new()
    {
        { "digitalocean-pat", "dop_v1_" + Hex(63) },
        { "digitalocean-oauth", "doo_v1_" + Hex(63) },
        { "github-pat-classic", "ghp_" + Letters(35) },
        { "github-pat-fine", "github_pat_" + Letters(81) },
        { "github-oauth", "gho_" + Letters(35) },
        { "github-app-user", "ghu_" + Letters(35) },
        { "github-app-server", "ghs_" + Letters(35) },
        { "npm-token", "npm_" + Letters(35) },
        { "shopify-private", "shppa_" + Hex(31) },
        { "shopify-access", "shpat_" + Hex(31) },
        { "square-access", "sq0atp-" + Letters(21) },
        { "square-secret", "sq0csp-" + Letters(42) },
        { "mailgun", "key-" + Hex(31) },
        { "google-gemini", "AIza" + Letters(34) },
    };

    [TestCaseSource(nameof(FixedCountNoTrailingLiteral))]
    public void One_char_short_of_the_fixed_run_does_not_match(string provider, string tooShort)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.That(pattern.Regex.IsMatch(tooShort), Is.False, tooShort);
    }

    // --- Near-miss: below the minimum of a ranged quantifier ---

    public static CaseRows RangedMinimum => new()
    {
        { "openai", "sk-proj-" + Letters(39) },
        { "stripe-secret-live", "sk_live_" + Letters(23) },
        { "stripe-restricted-live", "rk_live_" + Letters(23) },
        { "pypi-token", "pypi-AgEIcHlwaS5vcmc" + Letters(49) },
        { "jwt", "eyJ" + Letters(9) + ".eyJ" + Letters(10) + "." + Letters(10) },
        { "slack-bot", "xoxb-" + Digits(9) + "-" + Digits(10) + "-" + Letters(24) },
        { "slack-user", "xoxp-" + Digits(9) + "-" + Digits(10) + "-" + Digits(10) + "-" + Letters(24) },
        { "discord-webhook", "https://discord.com/api/webhooks/" + Digits(16) + "/" + Letters(60) },
    };

    [TestCaseSource(nameof(RangedMinimum))]
    public void Below_the_minimum_length_does_not_match(string provider, string tooShort)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.That(pattern.Regex.IsMatch(tooShort), Is.False, tooShort);
    }

    // --- Near-miss: one char too long, where a trailing literal makes it meaningful ---

    [Test]
    public void Anthropic_key_one_char_too_long_misaligns_the_AA_suffix_and_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "anthropic");
        var tooLong = "sk-ant-api03-" + Letters(94) + "AA";
        Assert.That(pattern.Regex.IsMatch(tooLong), Is.False, tooLong);
    }

    [Test]
    public void Slack_bot_token_with_an_extra_digit_before_the_dash_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "slack-bot");
        var tooLong = "xoxb-" + Digits(14) + "-" + Digits(10) + "-" + Letters(24);
        Assert.That(pattern.Regex.IsMatch(tooLong), Is.False, tooLong);
    }

    [Test]
    public void Slack_user_token_with_an_extra_digit_before_the_dash_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "slack-user");
        var tooLong = "xoxp-" + Digits(14) + "-" + Digits(10) + "-" + Digits(10) + "-" + Letters(24);
        Assert.That(pattern.Regex.IsMatch(tooLong), Is.False, tooLong);
    }

    // --- Near-miss: wrong charset breaks the run ---

    public static CaseRows WrongCharset => new()
    {
        // AWS suffix is [0-9A-Z]; a lowercase letter isn't in the class.
        { "aws-access-key", " AKIA123456789abcDE " },
        // GitHub classic PAT is [A-Za-z0-9]; a hyphen isn't in the class.
        { "github-pat-classic", "ghp_" + Letters(17) + "-" + Letters(18) },
        // Shopify body is hex [a-fA-F0-9]; 'g'/'z' aren't hex digits.
        { "shopify-private", "shppa_" + Hex(16) + "zz" + Hex(14) },
        // Mailgun body is hex [a-f0-9]; 'g'/'z' aren't hex digits.
        { "mailgun", "key-" + Hex(16) + "zz" + Hex(14) },
    };

    [TestCaseSource(nameof(WrongCharset))]
    public void Wrong_charset_in_the_run_does_not_match(string provider, string sample)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.That(pattern.Regex.IsMatch(sample), Is.False, sample);
    }

    // --- Near-miss: lookaround boundaries for the 3 patterns that guard against
    // matching inside a longer token (openai-legacy, aws-access-key, twilio-sk) ---

    [Test]
    public void Openai_legacy_key_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "openai-legacy");
        var embedded = "X" + "sk-" + Letters(48) + "Y";
        Assert.That(pattern.Regex.IsMatch(embedded), Is.False, embedded);
    }

    [Test]
    public void Aws_access_key_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "aws-access-key");
        var embedded = "Z" + "AKIA1234567890ABCDEF" + "Z";
        Assert.That(pattern.Regex.IsMatch(embedded), Is.False, embedded);
    }

    [Test]
    public void Twilio_sk_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "twilio-sk");
        var embedded = "x" + "SK" + Hex(32) + "y";
        Assert.That(pattern.Regex.IsMatch(embedded), Is.False, embedded);
    }

    // --- Near-miss: PEM blocks with a body shorter than the {20,} minimum ---

    public static CaseRows PemMarkers => new()
    {
        { "private-key-rsa", "BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY" },
        { "private-key-openssh", "BEGIN OPENSSH PRIVATE KEY", "END OPENSSH PRIVATE KEY" },
        { "private-key-ec", "BEGIN EC PRIVATE KEY", "END EC PRIVATE KEY" },
        { "private-key-pgp", "BEGIN PGP PRIVATE KEY BLOCK", "END PGP PRIVATE KEY BLOCK" },
    };

    [TestCaseSource(nameof(PemMarkers))]
    public void Pem_block_with_a_too_short_body_does_not_match(string provider, string begin, string end)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        var tooShortBody = $"-----{begin}-----\n" + Letters(10) + $"\n-----{end}-----";
        Assert.That(pattern.Regex.IsMatch(tooShortBody), Is.False, tooShortBody);
    }

    // --- Near-miss: DB URIs with no password, or a password under the 4-char minimum ---

    public static CaseRows DbUriSchemes => new()
    {
        { "postgres-uri", "postgres://" },
        { "mysql-uri", "mysql://" },
        { "mongodb-uri", "mongodb://" },
        { "redis-uri", "redis://" },
    };

    [TestCaseSource(nameof(DbUriSchemes))]
    public void Db_uri_with_no_password_does_not_match(string provider, string scheme)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.That(pattern.Regex.IsMatch(scheme + "user@host/db"), Is.False, scheme + "user@host/db");
    }

    [TestCaseSource(nameof(DbUriSchemes))]
    public void Db_uri_with_a_password_under_four_chars_does_not_match(string provider, string scheme)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.That(pattern.Regex.IsMatch(scheme + "user:abc@host/db"), Is.False, scheme + "user:abc@host/db");
    }

    // --- Patterns.All / WithPasswords() composition -----------------------

    [Test]
    public void Patterns_All_contains_no_PlainTextPassword_entries()
    {
        Assert.That(!Patterns.All.Any(p => p.ExposureType == ExposureTypes.PlainTextPassword), Is.True);
    }

    [Test]
    public void WithPasswords_adds_exactly_the_PasswordPatterns_on_top_of_All()
    {
        var withPasswords = Patterns.WithPasswords();

        Assert.That(withPasswords.Length, Is.EqualTo(Patterns.All.Length + Patterns.PasswordPatterns.Length));
        Assert.That(withPasswords.Take(Patterns.All.Length), Is.EqualTo(Patterns.All));
        Assert.That(withPasswords.Skip(Patterns.All.Length), Is.EqualTo(Patterns.PasswordPatterns));
    }

    // --- password-contextual ------------------------------------------------

    private static ProviderPattern PasswordContextual =>
        Patterns.PasswordPatterns.Single(p => p.Provider == "password-contextual");

    [TestCase("password = \"Secret123\"", "Secret123")]
    [TestCase("passwd: \"Secret123\"", "Secret123")]
    [TestCase("pwd = \"Secret123\"", "Secret123")]
    [TestCase("secret = \"Secret123\"", "Secret123")]
    public void Bare_key_assignment_forms_match_the_password_value(string sample, string expected)
    {
        var match = PasswordContextual.Regex.Match(sample);
        Assert.That(match.Success, Is.True);
        Assert.That(match.Value, Is.EqualTo(expected));
    }

    [TestCase("{\"password\": \"Secret123\"}", "Secret123")]
    [TestCase("{\"api_key\": \"Secret123\"}", "Secret123")]
    public void Json_quoted_key_forms_match_the_password_value(string sample, string expected)
    {
        var match = PasswordContextual.Regex.Match(sample);
        Assert.That(match.Success, Is.True);
        Assert.That(match.Value, Is.EqualTo(expected));
    }

    [Test]
    public void Password_value_five_chars_is_below_the_minimum_and_does_not_match()
    {
        Assert.That(PasswordContextual.Regex.IsMatch("password = \"abcde\""), Is.False, "password = \"abcde\"");
    }

    [Test]
    public void Password_value_six_chars_is_the_minimum_and_matches()
    {
        var match = PasswordContextual.Regex.Match("password = \"abcdef\"");
        Assert.That(match.Success, Is.True);
        Assert.That(match.Value, Is.EqualTo("abcdef"));
    }

    [Test]
    public void Password_value_128_chars_is_the_maximum_and_matches()
    {
        var value = Letters(128);
        var match = PasswordContextual.Regex.Match($"password = \"{value}\"");
        Assert.That(match.Success, Is.True);
        Assert.That(match.Value, Is.EqualTo(value));
    }

    [Test]
    public void Password_value_129_chars_exceeds_the_maximum_and_does_not_match_in_full()
    {
        var value = Letters(129);
        var match = PasswordContextual.Regex.Match($"password = \"{value}\"");
        // The 128-char cap means the full 129-char value is never captured whole.
        Assert.That(match.Value, Is.Not.EqualTo(value));
    }

    [TestCase("PASSWORD = \"Secret123\"")]
    [TestCase("Password = \"Secret123\"")]
    [TestCase("PaSsWoRd = \"Secret123\"")]
    public void Key_name_matching_is_case_insensitive(string sample)
    {
        Assert.That(PasswordContextual.Regex.IsMatch(sample), Is.True, sample);
    }

    // --- InferModel -----------------------------------------------------------

    [Test]
    public void InferModel_returns_the_first_matching_hint_case_insensitively()
    {
        var hints = new[] { "gpt-4o", "gpt-4" };

        var result = Patterns.InferModel("... uses GPT-4O under the hood ...", hints);

        Assert.That(result, Is.EqualTo("gpt-4o"));
    }

    [Test]
    public void InferModel_returns_the_first_hint_in_array_order_not_first_occurring_in_text()
    {
        // "a" occurs earlier in the text, but hints is checked in its own order,
        // so "b" (matched via "bb") wins because it's first in the hints array.
        var hints = new[] { "b", "a" };

        var result = Patterns.InferModel("xx a bb", hints);

        Assert.That(result, Is.EqualTo("b"));
    }

    [Test]
    public void InferModel_returns_null_when_no_hint_matches()
    {
        var hints = new[] { "gpt-4o", "gpt-4" };

        var result = Patterns.InferModel("no recognizable model name here", hints);

        Assert.That(result, Is.Null);
    }
}

using System.Text.RegularExpressions;
using Xunit;

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

    [Fact]
    public void Every_provider_in_Patterns_All_has_a_positive_sample()
    {
        var providers = Patterns.All.Select(p => p.Provider).ToHashSet();
        Assert.Equal(providers, PositiveSamples.Keys.ToHashSet());
    }

    public static IEnumerable<object[]> AllProviders =>
        Patterns.All.Select(p => new object[] { p.Provider });

    [Theory]
    [MemberData(nameof(AllProviders))]
    public void Positive_sample_matches_and_contains_the_search_needle(string provider)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        var sample = PositiveSamples[provider];

        Assert.True(pattern.Regex.IsMatch(sample), $"{provider}: regex did not match its own synthetic sample.");
        Assert.Contains(pattern.SearchNeedle, sample);
    }

    // --- Near-miss: one char short of a fixed-count run, no trailing literal ---
    // (the run isn't followed by any required literal, so "one too long" would
    // still match as a substring — only "too short" is a meaningful negative here)

    public static TheoryData<string, string> FixedCountNoTrailingLiteral => new()
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

    [Theory]
    [MemberData(nameof(FixedCountNoTrailingLiteral))]
    public void One_char_short_of_the_fixed_run_does_not_match(string provider, string tooShort)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.DoesNotMatch(pattern.Regex, tooShort);
    }

    // --- Near-miss: below the minimum of a ranged quantifier ---

    public static TheoryData<string, string> RangedMinimum => new()
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

    [Theory]
    [MemberData(nameof(RangedMinimum))]
    public void Below_the_minimum_length_does_not_match(string provider, string tooShort)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.DoesNotMatch(pattern.Regex, tooShort);
    }

    // --- Near-miss: one char too long, where a trailing literal makes it meaningful ---

    [Fact]
    public void Anthropic_key_one_char_too_long_misaligns_the_AA_suffix_and_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "anthropic");
        var tooLong = "sk-ant-api03-" + Letters(94) + "AA";
        Assert.DoesNotMatch(pattern.Regex, tooLong);
    }

    [Fact]
    public void Slack_bot_token_with_an_extra_digit_before_the_dash_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "slack-bot");
        var tooLong = "xoxb-" + Digits(14) + "-" + Digits(10) + "-" + Letters(24);
        Assert.DoesNotMatch(pattern.Regex, tooLong);
    }

    [Fact]
    public void Slack_user_token_with_an_extra_digit_before_the_dash_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "slack-user");
        var tooLong = "xoxp-" + Digits(14) + "-" + Digits(10) + "-" + Digits(10) + "-" + Letters(24);
        Assert.DoesNotMatch(pattern.Regex, tooLong);
    }

    // --- Near-miss: wrong charset breaks the run ---

    public static TheoryData<string, string> WrongCharset => new()
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

    [Theory]
    [MemberData(nameof(WrongCharset))]
    public void Wrong_charset_in_the_run_does_not_match(string provider, string sample)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.DoesNotMatch(pattern.Regex, sample);
    }

    // --- Near-miss: lookaround boundaries for the 3 patterns that guard against
    // matching inside a longer token (openai-legacy, aws-access-key, twilio-sk) ---

    [Fact]
    public void Openai_legacy_key_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "openai-legacy");
        var embedded = "X" + "sk-" + Letters(48) + "Y";
        Assert.DoesNotMatch(pattern.Regex, embedded);
    }

    [Fact]
    public void Aws_access_key_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "aws-access-key");
        var embedded = "Z" + "AKIA1234567890ABCDEF" + "Z";
        Assert.DoesNotMatch(pattern.Regex, embedded);
    }

    [Fact]
    public void Twilio_sk_embedded_in_a_longer_alnum_token_does_not_match()
    {
        var pattern = Patterns.All.Single(p => p.Provider == "twilio-sk");
        var embedded = "x" + "SK" + Hex(32) + "y";
        Assert.DoesNotMatch(pattern.Regex, embedded);
    }

    // --- Near-miss: PEM blocks with a body shorter than the {20,} minimum ---

    public static TheoryData<string, string, string> PemMarkers => new()
    {
        { "private-key-rsa", "BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY" },
        { "private-key-openssh", "BEGIN OPENSSH PRIVATE KEY", "END OPENSSH PRIVATE KEY" },
        { "private-key-ec", "BEGIN EC PRIVATE KEY", "END EC PRIVATE KEY" },
        { "private-key-pgp", "BEGIN PGP PRIVATE KEY BLOCK", "END PGP PRIVATE KEY BLOCK" },
    };

    [Theory]
    [MemberData(nameof(PemMarkers))]
    public void Pem_block_with_a_too_short_body_does_not_match(string provider, string begin, string end)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        var tooShortBody = $"-----{begin}-----\n" + Letters(10) + $"\n-----{end}-----";
        Assert.DoesNotMatch(pattern.Regex, tooShortBody);
    }

    // --- Near-miss: DB URIs with no password, or a password under the 4-char minimum ---

    public static TheoryData<string, string> DbUriSchemes => new()
    {
        { "postgres-uri", "postgres://" },
        { "mysql-uri", "mysql://" },
        { "mongodb-uri", "mongodb://" },
        { "redis-uri", "redis://" },
    };

    [Theory]
    [MemberData(nameof(DbUriSchemes))]
    public void Db_uri_with_no_password_does_not_match(string provider, string scheme)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.DoesNotMatch(pattern.Regex, scheme + "user@host/db");
    }

    [Theory]
    [MemberData(nameof(DbUriSchemes))]
    public void Db_uri_with_a_password_under_four_chars_does_not_match(string provider, string scheme)
    {
        var pattern = Patterns.All.Single(p => p.Provider == provider);
        Assert.DoesNotMatch(pattern.Regex, scheme + "user:abc@host/db");
    }

    // --- Patterns.All / WithPasswords() composition -----------------------

    [Fact]
    public void Patterns_All_contains_no_PlainTextPassword_entries()
    {
        Assert.DoesNotContain(Patterns.All, p => p.ExposureType == ExposureTypes.PlainTextPassword);
    }

    [Fact]
    public void WithPasswords_adds_exactly_the_PasswordPatterns_on_top_of_All()
    {
        var withPasswords = Patterns.WithPasswords();

        Assert.Equal(Patterns.All.Length + Patterns.PasswordPatterns.Length, withPasswords.Length);
        Assert.Equal(Patterns.All, withPasswords.Take(Patterns.All.Length));
        Assert.Equal(Patterns.PasswordPatterns, withPasswords.Skip(Patterns.All.Length));
    }

    // --- password-contextual ------------------------------------------------

    private static ProviderPattern PasswordContextual =>
        Patterns.PasswordPatterns.Single(p => p.Provider == "password-contextual");

    [Theory]
    [InlineData("password = \"Secret123\"", "Secret123")]
    [InlineData("passwd: \"Secret123\"", "Secret123")]
    [InlineData("pwd = \"Secret123\"", "Secret123")]
    [InlineData("secret = \"Secret123\"", "Secret123")]
    public void Bare_key_assignment_forms_match_the_password_value(string sample, string expected)
    {
        var match = PasswordContextual.Regex.Match(sample);
        Assert.True(match.Success);
        Assert.Equal(expected, match.Value);
    }

    [Theory]
    [InlineData("{\"password\": \"Secret123\"}", "Secret123")]
    [InlineData("{\"api_key\": \"Secret123\"}", "Secret123")]
    public void Json_quoted_key_forms_match_the_password_value(string sample, string expected)
    {
        var match = PasswordContextual.Regex.Match(sample);
        Assert.True(match.Success);
        Assert.Equal(expected, match.Value);
    }

    [Fact]
    public void Password_value_five_chars_is_below_the_minimum_and_does_not_match()
    {
        Assert.DoesNotMatch(PasswordContextual.Regex, "password = \"abcde\"");
    }

    [Fact]
    public void Password_value_six_chars_is_the_minimum_and_matches()
    {
        var match = PasswordContextual.Regex.Match("password = \"abcdef\"");
        Assert.True(match.Success);
        Assert.Equal("abcdef", match.Value);
    }

    [Fact]
    public void Password_value_128_chars_is_the_maximum_and_matches()
    {
        var value = Letters(128);
        var match = PasswordContextual.Regex.Match($"password = \"{value}\"");
        Assert.True(match.Success);
        Assert.Equal(value, match.Value);
    }

    [Fact]
    public void Password_value_129_chars_exceeds_the_maximum_and_does_not_match_in_full()
    {
        var value = Letters(129);
        var match = PasswordContextual.Regex.Match($"password = \"{value}\"");
        // The 128-char cap means the full 129-char value is never captured whole.
        Assert.NotEqual(value, match.Value);
    }

    [Theory]
    [InlineData("PASSWORD = \"Secret123\"")]
    [InlineData("Password = \"Secret123\"")]
    [InlineData("PaSsWoRd = \"Secret123\"")]
    public void Key_name_matching_is_case_insensitive(string sample)
    {
        Assert.Matches(PasswordContextual.Regex, sample);
    }

    // --- InferModel -----------------------------------------------------------

    [Fact]
    public void InferModel_returns_the_first_matching_hint_case_insensitively()
    {
        var hints = new[] { "gpt-4o", "gpt-4" };

        var result = Patterns.InferModel("... uses GPT-4O under the hood ...", hints);

        Assert.Equal("gpt-4o", result);
    }

    [Fact]
    public void InferModel_returns_the_first_hint_in_array_order_not_first_occurring_in_text()
    {
        // "a" occurs earlier in the text, but hints is checked in its own order,
        // so "b" (matched via "bb") wins because it's first in the hints array.
        var hints = new[] { "b", "a" };

        var result = Patterns.InferModel("xx a bb", hints);

        Assert.Equal("b", result);
    }

    [Fact]
    public void InferModel_returns_null_when_no_hint_matches()
    {
        var hints = new[] { "gpt-4o", "gpt-4" };

        var result = Patterns.InferModel("no recognizable model name here", hints);

        Assert.Null(result);
    }
}

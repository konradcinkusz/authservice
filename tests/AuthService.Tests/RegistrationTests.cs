using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// What registration validates, what it records about the consent given, and how it names the
/// account. The accepted-versions rule is covered with the rest of sign-up in
/// <see cref="AuthenticationTests"/>.
/// </summary>
public class RegistrationTests : IntegrationTestBase
{
    private Task<HttpResponseMessage> RegisterAsync(object body) =>
        Factory.ClientFor().PostAsJsonAsync("/api/v1/auth/register", body);

    private static object Body(string email, string password = TestData.ValidPassword, string? locale = null) => new
    {
        email,
        password,
        acceptedTermsVersion = TestData.TermsVersion,
        acceptedPrivacyVersion = TestData.PrivacyVersion,
        locale
    };

    [Fact]
    public async Task The_consent_given_is_recorded_with_its_version_locale_and_user_agent()
    {
        var email = TestData.NewEmail();
        var client = Factory.ClientFor();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("registration-test/1.0");

        (await client.PostAsJsonAsync("/api/v1/auth/register", Body(email, locale: "pl-PL"))).EnsureSuccessStatusCode();

        List<UserConsent> consents = [];
        var id = await Factory.UserIdAsync(email);
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            consents = await context.UserConsents.AsNoTracking().Where(c => c.UserId == id).ToListAsync();
        });

        Assert.Equal(2, consents.Count);
        var terms = Assert.Single(consents, c => c.Type == ConsentType.Terms);
        var privacy = Assert.Single(consents, c => c.Type == ConsentType.Privacy);
        Assert.Equal(TestData.TermsVersion, terms.Version);
        Assert.Equal(TestData.PrivacyVersion, privacy.Version);
        Assert.All(consents, c =>
        {
            Assert.True(c.Accepted);
            Assert.Equal("pl-PL", c.Locale);
            Assert.Equal("registration-test/1.0", c.UserAgent);
        });
    }

    [Fact]
    public async Task A_welcome_email_is_sent_to_the_new_account()
    {
        var email = TestData.NewEmail();

        (await RegisterAsync(Body(email))).EnsureSuccessStatusCode();

        var welcome = Assert.Single(Factory.Emails.To(email, EmailKind.Welcome));
        Assert.False(string.IsNullOrWhiteSpace(welcome.Detail));
    }

    [Fact]
    public async Task A_failing_email_provider_does_not_stop_registration()
    {
        Factory.Emails.FailWith = new InvalidOperationException("provider down");
        var email = TestData.NewEmail();

        var response = await RegisterAsync(Body(email));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(string.IsNullOrEmpty(await Factory.UserIdAsync(email)));
    }

    [Fact]
    public async Task An_address_that_is_taken_is_refused_whatever_its_case()
    {
        var (email, _) = await Factory.ClientFor().RegisterAsync();

        var same = await RegisterAsync(Body(email));
        var shouted = await RegisterAsync(Body(email.ToUpperInvariant()));

        Assert.Equal(HttpStatusCode.BadRequest, same.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, shouted.StatusCode);
        Assert.True((await same.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errors", out _));
    }

    [Theory]
    [InlineData("not-an-email", TestData.ValidPassword)]
    [InlineData("", TestData.ValidPassword)]
    [InlineData("user@example.test", "short")]
    [InlineData("user@example.test", "")]
    public async Task A_malformed_registration_is_refused_with_the_reasons(string email, string password)
    {
        var response = await RegisterAsync(Body(email, password));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task A_locale_longer_than_the_limit_is_refused()
    {
        var response = await RegisterAsync(Body(TestData.NewEmail(), locale: new string('x', 17)));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("alllowercase1!")]
    [InlineData("ALLUPPERCASE1!")]
    [InlineData("NoDigitsHere!!")]
    [InlineData("NoSymbolsHere12")]
    public async Task A_password_that_breaks_the_policy_is_refused(string password)
    {
        var email = TestData.NewEmail();

        var response = await RegisterAsync(Body(email, password));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True((await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errors", out _));
        Assert.Empty(Factory.Emails.To(email));
    }

    // ─── Naming ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task The_username_comes_from_the_address_and_a_clash_gets_a_numeric_suffix()
    {
        var domain = $"d{Guid.NewGuid():N}"[..8];
        var first = $"jane.doe@{domain}.test";
        var second = $"janedoe@{domain}.test";
        var third = $"jane+news.doe@{domain}.test";

        foreach (var email in new[] { first, second, third })
            (await RegisterAsync(Body(email))).EnsureSuccessStatusCode();

        Assert.Equal($"janedoe_{domain}", await Factory.ReadUserAsync(first, u => u.UserName));
        Assert.Equal($"janedoe_{domain}1", await Factory.ReadUserAsync(second, u => u.UserName));
        Assert.Equal($"janenewsdoe_{domain}", await Factory.ReadUserAsync(third, u => u.UserName));
    }

    [Fact]
    public async Task A_very_long_address_still_gives_a_username_within_the_limit()
    {
        var email = $"{new string('a', 80)}@example.test";

        (await RegisterAsync(Body(email))).EnsureSuccessStatusCode();

        var name = await Factory.ReadUserAsync(email, u => u.UserName);
        Assert.Equal(50, name!.Length);
    }

    [Fact]
    public async Task Characters_a_username_cannot_hold_are_dropped_from_the_name()
    {
        var email = $"first_last-9@my-corp.example.test";

        (await RegisterAsync(Body(email))).EnsureSuccessStatusCode();

        Assert.Equal("first_last-9_my-corp", await Factory.ReadUserAsync(email, u => u.UserName));
    }
}

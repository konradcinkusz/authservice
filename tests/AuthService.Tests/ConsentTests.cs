using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Data;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// Versioned Terms, Privacy and Cookies consent: what the status says, what a later version
/// does to it, and what recording a decision stores.
/// </summary>
public class ConsentTests : IntegrationTestBase
{
    private async Task<ConsentStatusResponse> StatusAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/v1/auth/consents");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
    }

    private async Task<List<UserConsent>> StoredAsync(string userId, ConsentType? type = null)
    {
        List<UserConsent> rows = [];
        await Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            rows = await context.UserConsents.AsNoTracking()
                .Where(c => c.UserId == userId && (type == null || c.Type == type)).ToListAsync();
        });
        return rows;
    }

    /// <summary>Pretends the user accepted an older version, as if the documents had since moved on.</summary>
    private Task AgeConsentsAsync(string userId) =>
        Factory.WithScopeAsync(async services =>
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            foreach (var row in context.UserConsents.Where(c => c.UserId == userId))
                row.Version = "2020-01-01";
            await context.SaveChangesAsync();
        });

    [Fact]
    public async Task The_required_versions_are_public_because_a_sign_up_form_has_no_token_yet()
    {
        var response = await Factory.ClientFor().GetAsync("/api/v1/auth/consents/versions");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var versions = (await response.Content.ReadFromJsonAsync<ConsentVersionsResponse>(TestData.Json))!;
        Assert.Equal(TestData.TermsVersion, versions.Terms);
        Assert.Equal(TestData.PrivacyVersion, versions.Privacy);
        Assert.Equal(TestData.CookiesVersion, versions.Cookies);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public async Task Consent_status_and_decisions_need_a_signed_in_user(string method)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), "/api/v1/auth/consents")
        {
            Content = method == "POST" ? JsonContent.Create(new { acceptedTerms = true }) : null
        };

        var response = await Factory.ClientFor().SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A_new_account_has_accepted_terms_and_privacy_but_has_not_chosen_on_cookies()
    {
        var account = await Factory.CreateAccountAsync();

        var status = await StatusAsync(Factory.ClientFor(account.Tokens));

        Assert.True(status.Terms.Accepted);
        Assert.True(status.Privacy.Accepted);
        Assert.Equal(TestData.TermsVersion, status.Terms.AcceptedVersion);
        Assert.NotNull(status.Terms.AcceptedAt);
        Assert.False(status.Cookies.Accepted);
        Assert.Null(status.Cookies.AcceptedVersion);
        Assert.False(status.RequiresConsent);
    }

    [Fact]
    public async Task A_version_the_user_has_not_accepted_means_consent_is_required_again()
    {
        var account = await Factory.CreateAccountAsync();
        await AgeConsentsAsync(account.Id);

        var status = await StatusAsync(Factory.ClientFor(account.Tokens));

        Assert.False(status.Terms.Accepted);
        Assert.False(status.Privacy.Accepted);
        Assert.Equal("2020-01-01", status.Terms.AcceptedVersion);
        Assert.Equal(TestData.TermsVersion, status.Terms.RequiredVersion);
        Assert.True(status.RequiresConsent);
    }

    [Fact]
    public async Task Accepting_again_records_the_current_versions_and_clears_the_requirement()
    {
        var account = await Factory.CreateAccountAsync();
        await AgeConsentsAsync(account.Id);
        var client = Factory.ClientFor(account.Tokens);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("consent-test/1.0");

        var response = await client.PostAsJsonAsync("/api/v1/auth/consents",
            new { acceptedTerms = true, acceptedPrivacy = true, locale = "de-DE" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var status = (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
        Assert.False(status.RequiresConsent);
        Assert.Equal(TestData.TermsVersion, status.Terms.AcceptedVersion);

        // The earlier acceptances stay: consent is a history, not a flag.
        var terms = await StoredAsync(account.Id, ConsentType.Terms);
        Assert.Equal(2, terms.Count);
        var latest = terms.OrderByDescending(c => c.AcceptedAt).First();
        Assert.Equal("de-DE", latest.Locale);
        Assert.Equal("consent-test/1.0", latest.UserAgent);
    }

    [Fact]
    public async Task Declining_or_omitting_a_document_records_nothing_for_it()
    {
        var account = await Factory.CreateAccountAsync();
        await AgeConsentsAsync(account.Id);

        var response = await Factory.ClientFor(account.Tokens).PostAsJsonAsync("/api/v1/auth/consents",
            new { acceptedTerms = false, acceptedPrivacy = (bool?)null });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var status = (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
        Assert.True(status.RequiresConsent);
        Assert.All(await StoredAsync(account.Id), c => Assert.Equal("2020-01-01", c.Version));
    }

    [Fact]
    public async Task A_cookie_choice_is_stored_with_its_categories_and_accepted_when_any_optional_one_is_on()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var response = await client.PostAsJsonAsync("/api/v1/auth/consents", new
        {
            cookies = new { necessary = true, preferences = false, analytics = true, thirdParty = false }
        });

        var status = (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
        Assert.True(status.Cookies.Accepted);
        Assert.Equal(TestData.CookiesVersion, status.Cookies.AcceptedVersion);
        var stored = Assert.Single(await StoredAsync(account.Id, ConsentType.Cookies));
        using var categories = JsonDocument.Parse(stored.CookieCategories!);
        Assert.True(categories.RootElement.GetProperty("Analytics").GetBoolean());
        Assert.False(categories.RootElement.GetProperty("ThirdParty").GetBoolean());
    }

    [Fact]
    public async Task Choosing_only_necessary_cookies_is_a_recorded_refusal_not_an_acceptance()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);

        var response = await client.PostAsJsonAsync("/api/v1/auth/consents", new
        {
            cookies = new { necessary = true, preferences = false, analytics = false, thirdParty = false }
        });

        var status = (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
        Assert.False(status.Cookies.Accepted);
        Assert.False(Assert.Single(await StoredAsync(account.Id, ConsentType.Cookies)).Accepted);
        Assert.False(status.RequiresConsent);
    }

    [Fact]
    public async Task The_latest_decision_wins()
    {
        var account = await Factory.CreateAccountAsync();
        var client = Factory.ClientFor(account.Tokens);
        await client.PostAsJsonAsync("/api/v1/auth/consents",
            new { cookies = new { necessary = true, preferences = true, analytics = true, thirdParty = true } });
        await Task.Delay(20);

        var response = await client.PostAsJsonAsync("/api/v1/auth/consents",
            new { cookies = new { necessary = true, preferences = false, analytics = false, thirdParty = false } });

        var status = (await response.Content.ReadFromJsonAsync<ConsentStatusResponse>(TestData.Json))!;
        Assert.False(status.Cookies.Accepted);
        Assert.Equal(2, (await StoredAsync(account.Id, ConsentType.Cookies)).Count);
    }
}

using System.Net;
using System.Text;
using AuthService.Models;
using AuthService.Tests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// An access token is good until it expires, whatever has happened to the account since: the
/// reaper may have deleted it for good a minute ago. Every endpoint that looks the account up
/// must say there is none, not fall over.
/// </summary>
public class TokenOutlivingAccountTests : IntegrationTestBase
{
    public static TheoryData<string, string, string?> Calls => new()
    {
        { "GET", "/api/v1/auth/me", null },
        { "GET", "/api/v1/auth/export", null },
        { "PUT", "/api/v1/auth/profile", """{"userName":"someone"}""" },
        { "POST", "/api/v1/auth/change-password", """{"currentPassword":"Passw0rd!23","newPassword":"Another-Passw0rd!"}""" },
        { "DELETE", "/api/v1/auth/account", """{"confirmation":"DELETE","password":"Passw0rd!23"}""" },
        { "GET", "/api/v1/organizations/invitations", null },
        { "POST", "/api/v1/organizations/invitations/accept", """{"token":"anything"}""" },
    };

    [Theory]
    [MemberData(nameof(Calls))]
    public async Task A_token_whose_account_has_been_deleted_for_good_finds_no_account(string method, string url, string? json)
    {
        var account = await Factory.CreateAccountAsync();
        await Factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            (await users.DeleteAsync((await users.FindByIdAsync(account.Id))!)).ThrowIfFailed();
        });
        using var request = new HttpRequestMessage(new HttpMethod(method), url)
        {
            Content = json is null ? null : new StringContent(json, Encoding.UTF8, "application/json")
        };

        var response = await Factory.ClientFor(account.Tokens).SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}

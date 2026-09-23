using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// External mode (A11-A13): the consumer's frontend signs the user in and asks for consent in
/// its own pages, and talks to authservice only through the interaction API, with the user's
/// bearer token, from its BFF. The frontend is simulated here by those API calls; the browser
/// by a cookie-keeping client.
/// </summary>
public class ExternalInteractionTests : IAsyncLifetime
{
    private const string ExternalUrl = "https://frontend.example.test/connect";

    private AuthorizationServerFactory _factory = null!;
    private AuthorizationFlowClient _flow = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory(settings =>
        {
            settings["AuthorizationServer:Interaction:Mode"] = "External";
            settings["AuthorizationServer:Interaction:ExternalUrl"] = ExternalUrl;
        });
        await _factory.InitializeAsync();
        _flow = new AuthorizationFlowClient(_factory);
    }

    public Task DisposeAsync()
    {
        _flow.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task A_user_connects_a_client_through_the_consumers_frontend()
    {
        var (email, api) = await _flow.Backchannel.RegisterAsync();
        await using var resource = await TestResourceServer.StartAsync(_factory);
        var pkce = Pkce.Create();

        // The browser is sent to the configured frontend page, never anywhere the request named.
        var handle = await StartAsync(_flow.Browser, pkce, "state-ext");

        // The frontend's BFF asks what is being requested...
        var details = await InteractionAsync(api.AccessToken, handle);
        Assert.Equal(HttpStatusCode.OK, details.StatusCode);
        using (var body = JsonDocument.Parse(await details.Content.ReadAsStringAsync()))
        {
            var root = body.RootElement;
            Assert.Equal(AuthorizationServerFactory.ClientDisplayName, root.GetProperty("clientName").GetString());
            Assert.Equal("claude.example.test", root.GetProperty("redirectHost").GetString());
            Assert.Equal(AuthorizationServerFactory.Resource, root.GetProperty("resource").GetString());
            var scopes = root.GetProperty("scopes").EnumerateArray()
                .ToDictionary(s => s.GetProperty("name").GetString()!, s => s.GetProperty("description").GetString()!);
            Assert.Equal(AuthorizationServerFactory.ScopeDescription, scopes[AuthorizationServerFactory.Scope]);
            Assert.True(scopes.ContainsKey("offline_access"));
        }

        // ...reports the user's consent, and sends the browser where it is told.
        var redirectTo = await AcceptAsync(api.AccessToken, handle);
        Assert.StartsWith($"{AuthorizationServerFactory.Issuer}/connect/authorize?", redirectTo, StringComparison.Ordinal);

        var completed = await _flow.Browser.GetAsync(redirectTo);
        Assert.Equal(HttpStatusCode.Redirect, completed.StatusCode);
        var response = AuthorizationFlowClient.Query(completed.Headers.Location!);
        Assert.StartsWith(AuthorizationServerFactory.RedirectUri, completed.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.Equal("state-ext", response["state"]);
        Assert.Equal(AuthorizationServerFactory.Issuer, response["iss"]);

        var tokens = await AuthorizationFlowClient.ReadTokensAsync(await _flow.ExchangeCodeAsync(response["code"], pkce.Verifier));
        Assert.Equal(HttpStatusCode.OK, (await resource.CallAsync(tokens.AccessToken)).StatusCode);

        using (var payload = TestAccounts.DecodeSegment(tokens.AccessToken, 1))
            Assert.Equal(await UserIdAsync(email), payload.RootElement.GetProperty("sub").GetString());

        var refreshed = await AuthorizationFlowClient.ReadTokensAsync(await _flow.RefreshAsync(tokens.RefreshToken!));
        Assert.Equal(HttpStatusCode.OK, (await resource.CallAsync(refreshed.AccessToken)).StatusCode);
    }

    [Fact]
    public async Task A_replayed_ticket_is_refused()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var handle = await StartAsync(_flow.Browser, Pkce.Create(), "once");
        var redirectTo = await AcceptAsync(api.AccessToken, handle);
        Assert.True(AuthorizationFlowClient.Query((await _flow.Browser.GetAsync(redirectTo)).Headers.Location!).ContainsKey("code"));

        var replay = await _flow.Browser.GetAsync(redirectTo);

        AssertDenied(replay);
    }

    [Fact]
    public async Task A_ticket_cannot_complete_a_different_request()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var first = await AcceptAsync(api.AccessToken, await StartAsync(_flow.Browser, Pkce.Create(), "first"));
        var second = await AcceptAsync(api.AccessToken, await StartAsync(_flow.Browser, Pkce.Create(), "second"));

        // The second request's parameters, carrying the first interaction's ticket.
        var firstTicket = AuthorizationFlowClient.Query(new Uri(first))["interaction_ticket"];
        var secondTicket = AuthorizationFlowClient.Query(new Uri(second))["interaction_ticket"];
        var swapped = second.Replace(secondTicket, firstTicket, StringComparison.Ordinal);

        var response = await _flow.Browser.GetAsync(swapped);

        Assert.False(AuthorizationFlowClient.Query(response.Headers.Location!).ContainsKey("code"));
        Assert.Equal("invalid_request", AuthorizationFlowClient.Query(response.Headers.Location!)["error"]);
    }

    [Fact]
    public async Task A_browser_without_the_binding_cookie_cannot_finish_someone_elses_request()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var redirectTo = await AcceptAsync(api.AccessToken, await StartAsync(_flow.Browser, Pkce.Create(), "victim"));

        // The link, followed by a browser that did not start the request.
        using var other = new AuthorizationFlowClient(_factory);
        var response = await other.Browser.GetAsync(redirectTo);

        AssertDenied(response);
    }

    [Fact]
    public async Task A_browser_with_its_own_binding_cookie_cannot_finish_someone_elses_request()
    {
        // Login CSRF: the attacker gets a ticket for a request bound to their own browser, and
        // hands the link to a victim whose browser is bound to a request of its own.
        var (_, attackerApi) = await _flow.Backchannel.RegisterAsync();
        var attackerLink = await AcceptAsync(attackerApi.AccessToken, await StartAsync(_flow.Browser, Pkce.Create(), "attacker"));

        using var victim = new AuthorizationFlowClient(_factory);
        await StartAsync(victim.Browser, Pkce.Create(), "victim");

        var response = await victim.Browser.GetAsync(attackerLink);

        AssertDenied(response);
    }

    [Fact]
    public async Task An_expired_interaction_cannot_be_read_or_decided()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var handle = await StartAsync(_flow.Browser, Pkce.Create(), "late");
        await _factory.WithScopeAsync(async services =>
            await services.GetRequiredService<ApplicationDbContext>().AuthorizationInteractions
                .ExecuteUpdateAsync(set => set.SetProperty(i => i.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))));

        Assert.Equal(HttpStatusCode.NotFound, (await InteractionAsync(api.AccessToken, handle)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(api.AccessToken, handle, "accept")).StatusCode);
    }

    [Fact]
    public async Task Once_one_user_has_decided_no_other_user_can()
    {
        var (aliceEmail, alice) = await _flow.Backchannel.RegisterAsync();
        var (_, bob) = await _flow.Backchannel.RegisterAsync();
        var pkce = Pkce.Create();
        var handle = await StartAsync(_flow.Browser, pkce, "contested");

        var redirectTo = await AcceptAsync(alice.AccessToken, handle);

        Assert.Equal(HttpStatusCode.NotFound, (await DecideAsync(bob.AccessToken, handle, "accept")).StatusCode);

        // The code is Alice's.
        var completed = await _flow.Browser.GetAsync(redirectTo);
        var tokens = await AuthorizationFlowClient.ReadTokensAsync(
            await _flow.ExchangeCodeAsync(AuthorizationFlowClient.Query(completed.Headers.Location!)["code"], pkce.Verifier));
        using var payload = TestAccounts.DecodeSegment(tokens.AccessToken, 1);
        Assert.Equal(await UserIdAsync(aliceEmail), payload.RootElement.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task The_frontend_cannot_add_a_scope_or_change_the_resource()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var handle = await StartAsync(_flow.Browser, Pkce.Create(), "narrow");

        var widened = await DecideAsync(api.AccessToken, handle, "accept", new
        {
            scopes = new[] { AuthorizationServerFactory.Scope, "offline_access", "notes:delete" }
        });
        Assert.Equal(HttpStatusCode.BadRequest, widened.StatusCode);

        var retargeted = await DecideAsync(api.AccessToken, handle, "accept", new { resource = "https://other.example.test/mcp" });
        Assert.Equal(HttpStatusCode.BadRequest, retargeted.StatusCode);

        // Still pending, and accepting exactly what was asked works.
        var confirmed = await DecideAsync(api.AccessToken, handle, "accept", new
        {
            scopes = new[] { "offline_access", AuthorizationServerFactory.Scope },
            resource = AuthorizationServerFactory.Resource
        });
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
    }

    [Fact]
    public async Task A_denial_returns_access_denied_to_the_client()
    {
        var (_, api) = await _flow.Backchannel.RegisterAsync();
        var handle = await StartAsync(_flow.Browser, Pkce.Create(), "no");

        var denied = await DecideAsync(api.AccessToken, handle, "deny");
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        var redirectTo = (await denied.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirectTo").GetString()!;

        var response = AuthorizationFlowClient.Query((await _flow.Browser.GetAsync(redirectTo)).Headers.Location!);
        Assert.Equal("access_denied", response["error"]);
        Assert.Equal("no", response["state"]);
        Assert.False(response.ContainsKey("code"));
    }

    [Fact]
    public async Task The_interaction_api_needs_the_users_token()
    {
        var handle = await StartAsync(_flow.Browser, Pkce.Create(), "anonymous");

        Assert.Equal(HttpStatusCode.Unauthorized, (await _flow.Backchannel.GetAsync($"/api/v1/oauth/interactions/{handle}")).StatusCode);
    }

    [Fact]
    public async Task The_hosted_pages_do_not_exist_in_external_mode()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await _flow.Browser.GetAsync("/connect/signin?returnUrl=%2Fconnect%2Fauthorize%3Fx%3D1")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _flow.Browser.GetAsync("/oauth/callback?code=x&resume=y")).StatusCode);
    }

    /// <summary>Starts an authorization request in <paramref name="browser"/>; returns the handle the frontend receives.</summary>
    private static async Task<string> StartAsync(HttpClient browser, Pkce pkce, string state)
    {
        var response = await browser.GetAsync(AuthorizationFlowClient.AuthorizeUrl(pkce, state));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(ExternalUrl, location.GetLeftPart(UriPartial.Path));
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("__Secure-authservice-as-binding=", StringComparison.Ordinal));

        return AuthorizationFlowClient.Query(location)["interaction"];
    }

    private async Task<HttpResponseMessage> InteractionAsync(string accessToken, string handle)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/oauth/interactions/{handle}").WithBearer(accessToken);
        return await _flow.Backchannel.SendAsync(request);
    }

    private async Task<HttpResponseMessage> DecideAsync(string accessToken, string handle, string decision, object? body = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/oauth/interactions/{handle}/{decision}")
        {
            Content = JsonContent.Create(body ?? new { })
        };
        return await _flow.Backchannel.SendAsync(request.WithBearer(accessToken));
    }

    private async Task<string> AcceptAsync(string accessToken, string handle)
    {
        var response = await DecideAsync(accessToken, handle, "accept");
        Assert.True(response.StatusCode == HttpStatusCode.OK, await AuthorizationFlowClient.DescribeAsync(response));
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("redirectTo").GetString()!;
    }

    private static void AssertDenied(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = AuthorizationFlowClient.Query(response.Headers.Location!);
        Assert.False(query.ContainsKey("code"));
        Assert.Equal("access_denied", query["error"]);
    }

    private async Task<string> UserIdAsync(string email)
    {
        string id = string.Empty;
        await _factory.WithScopeAsync(async services =>
            id = (await services.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<AuthService.Models.ApplicationUser>>()
                .FindByEmailAsync(email))!.Id);
        return id;
    }
}

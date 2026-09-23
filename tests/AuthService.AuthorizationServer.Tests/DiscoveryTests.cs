using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// RFC 8414 metadata (AC1): what it advertises is exactly what the server does, and turning the
/// server on changes neither the existing OIDC document nor the JWKS (AC7, A2).
/// </summary>
public class DiscoveryTests : IAsyncLifetime
{
    private AuthorizationServerFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory();
        await _factory.InitializeAsync();
        _client = _factory.CreateClient();
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Metadata_advertises_exactly_the_flow_the_server_supports()
    {
        var response = await _client.GetAsync("/.well-known/oauth-authorization-server");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;

        Assert.Equal(
            new[]
            {
                "authorization_endpoint", "authorization_response_iss_parameter_supported",
                "code_challenge_methods_supported", "grant_types_supported", "issuer", "jwks_uri",
                "response_types_supported", "scopes_supported", "token_endpoint",
                "token_endpoint_auth_methods_supported"
            },
            root.PropertyNames());

        // A1: the configured origin, no trailing slash — the form the well-known URL is built from.
        const string issuer = AuthorizationServerFactory.Issuer;
        Assert.Equal(issuer, root.GetProperty("issuer").GetString());
        Assert.Equal($"{issuer}/connect/authorize", root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal($"{issuer}/connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{issuer}/.well-known/jwks.json", root.GetProperty("jwks_uri").GetString());

        Assert.Equal(["code"], Strings(root, "response_types_supported"));
        Assert.Equal(["authorization_code", "refresh_token"], Strings(root, "grant_types_supported"));
        Assert.Equal(["S256"], Strings(root, "code_challenge_methods_supported"));
        Assert.Equal(["client_secret_basic", "client_secret_post"], Strings(root, "token_endpoint_auth_methods_supported"));

        // F5: offline_access is listed, or Claude never asks for it and never gets a refresh token.
        Assert.Equal(["notes:read", "offline_access"], Strings(root, "scopes_supported"));
        Assert.True(root.GetProperty("authorization_response_iss_parameter_supported").GetBoolean());
    }

    [Fact]
    public async Task The_existing_discovery_document_is_unchanged_with_the_server_enabled()
    {
        using var document = JsonDocument.Parse(await _client.GetStringAsync("/.well-known/openid-configuration"));
        var root = document.RootElement;

        Assert.Equal(
            ["id_token_signing_alg_values_supported", "issuer", "jwks_uri", "response_types_supported", "subject_types_supported"],
            root.PropertyNames());
        Assert.Equal("AuthService", root.GetProperty("issuer").GetString());
        Assert.Empty(Strings(root, "response_types_supported"));
        Assert.Equal(["RS256"], Strings(root, "id_token_signing_alg_values_supported"));
        Assert.EndsWith("/.well-known/jwks.json", root.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task The_key_set_is_the_existing_one_with_the_key_id_derived_from_the_key()
    {
        var jwks = new JsonWebKeySet(await _client.GetStringAsync("/.well-known/jwks.json"));

        var key = Assert.Single(jwks.Keys);
        Assert.Equal("RS256", key.Alg);
        Assert.Equal(Thumbprint(_factory.SigningKey), key.Kid);
    }

    [Fact]
    public async Task The_library_publishes_no_key_set_or_discovery_document_of_its_own()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/.well-known/jwks")).StatusCode);
    }

    [Fact]
    public async Task The_startup_banner_reports_the_authorization_server()
    {
        Assert.Contains(_factory.Logs.Entries, e =>
            e.Contains("AuthorizationServer=enabled (1 client(s), Hosted interaction, issuer https://localhost)", StringComparison.Ordinal));
    }

    private static string[] Strings(JsonElement root, string name) =>
        root.GetProperty(name).EnumerateArray().Select(e => e.GetString()!).ToArray();

    /// <summary>RFC 7638, computed independently of JwtSigningKeys.</summary>
    internal static string Thumbprint(RSA key)
    {
        var parameters = key.ExportParameters(false);
        var json = $"{{\"e\":\"{Base64UrlEncoder.Encode(parameters.Exponent!)}\",\"kty\":\"RSA\",\"n\":\"{Base64UrlEncoder.Encode(parameters.Modulus!)}\"}}";
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }
}

/// <summary>
/// With no client configured there is no authorization server at all (A5): no metadata, no
/// endpoint, no page and no API — only the stores, which revocation keeps using.
/// </summary>
public class DisabledAuthorizationServerTests : IAsyncLifetime
{
    private AuthorizationServerFactory _factory = null!;
    private HttpClient _client = null!;

    public async Task InitializeAsync()
    {
        _factory = new AuthorizationServerFactory(settings =>
        {
            foreach (var key in settings.Keys.Where(k => k.StartsWith("AuthorizationServer:", StringComparison.Ordinal)).ToList())
                settings.Remove(key);
        });
        await _factory.InitializeAsync();
        _client = _factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(AuthorizationServerFactory.Issuer)
        });
    }

    public Task DisposeAsync()
    {
        _client.Dispose();
        _factory.Dispose();
        return Task.CompletedTask;
    }

    [Theory]
    [InlineData("GET", "/.well-known/oauth-authorization-server")]
    [InlineData("GET", "/connect/authorize?response_type=code&client_id=claude-test")]
    [InlineData("POST", "/connect/token")]
    [InlineData("GET", "/connect/signin?returnUrl=%2Fconnect%2Fauthorize%3Fx%3D1")]
    [InlineData("GET", "/connect/consent")]
    [InlineData("GET", "/oauth/callback?code=x")]
    [InlineData("GET", "/api/v1/oauth/interactions/some-handle")]
    [InlineData("DELETE", "/api/v1/auth/connected-clients/claude-test")]
    public async Task Nothing_of_the_authorization_server_is_served(string method, string path)
    {
        var (_, tokens) = await _client.RegisterAsync();
        using var request = new HttpRequestMessage(new HttpMethod(method), path).WithBearer(tokens.AccessToken);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task The_startup_banner_says_it_is_off()
    {
        Assert.Contains(_factory.Logs.Entries, e =>
            e.Contains("AuthorizationServer=disabled (no client configured)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Global_revocation_still_works_against_the_stores()
    {
        var (_, tokens) = await _client.RegisterAsync();
        using var logout = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout").WithBearer(tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(logout)).StatusCode);
    }

    [Fact]
    public async Task A_database_without_the_authorization_servers_tables_still_signs_out_and_deletes_accounts()
    {
        // A database EnsureCreated made before this release has none of these tables, and
        // nothing requires them while no client is configured (AuthorizationServerPosture).
        await _factory.WithScopeAsync(services => services.GetRequiredService<ApplicationDbContext>().Database.ExecuteSqlRawAsync(
            "DROP TABLE OpenIddictTokens; DROP TABLE OpenIddictAuthorizations; DROP TABLE OpenIddictScopes; " +
            "DROP TABLE OpenIddictApplications; DROP TABLE AuthorizationInteractions;"));
        var (email, tokens) = await _client.RegisterAsync();

        using var logout = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout").WithBearer(tokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(logout)).StatusCode);

        using var change = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/change-password")
        {
            Content = JsonContent.Create(new { currentPassword = TestAccounts.Password, newPassword = "N3w-Passw0rd!" })
        };
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(change.WithBearer(tokens.AccessToken))).StatusCode);

        using var delete = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/auth/account")
        {
            Content = JsonContent.Create(new { password = "N3w-Passw0rd!", confirmation = "DELETE" })
        };
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(delete.WithBearer(tokens.AccessToken))).StatusCode);

        // The reaper's permanent deletion and its pruning, run directly rather than hourly.
        await _factory.WithScopeAsync(async services =>
        {
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByEmailAsync(email);
            Assert.True(user!.IsDeleted);
            user.ScheduledPermanentDeletionAt = DateTime.UtcNow.AddMinutes(-1);
            await users.UpdateAsync(user);
        });
        var cleanup = ActivatorUtilities.CreateInstance<UserCleanupService>(_factory.Services);
        await cleanup.CleanupExpiredUsersAsync(CancellationToken.None);
        await cleanup.PruneAuthorizationServerAsync(CancellationToken.None);

        await _factory.WithScopeAsync(async services =>
            Assert.Null(await services.GetRequiredService<UserManager<ApplicationUser>>().FindByEmailAsync(email)));
    }
}

using System.Net;
using AuthService.AuthorizationServer.Tests.Infrastructure;
using AuthService.Services;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.AuthorizationServer.Tests;

/// <summary>
/// Pre-registered confidential clients from configuration (AC5): refused at startup when unsafe,
/// with a message naming the setting; registered with the secret hashed; kept in line with
/// configuration, which is authoritative (A8); and limited per client at the token endpoint (N4).
/// </summary>
public class ClientRegistrationTests
{
    public static TheoryData<string, string?, string> UnsafeSettings => new()
    {
        { "AuthorizationServer:Clients:0:ClientSecret", "too-short", "AuthorizationServer:Clients:0:ClientSecret must be at least 256 bits" },
        { "AuthorizationServer:Clients:0:ClientSecret", null, "AuthorizationServer:Clients:0:ClientSecret must be at least 256 bits" },
        { "AuthorizationServer:Clients:0:RedirectUris:0", "http://claude.example.test/callback", "AuthorizationServer:Clients:0:RedirectUris:0" },
        { "AuthorizationServer:Clients:0:RedirectUris:0", "https://claude.example.test/callback#fragment", "AuthorizationServer:Clients:0:RedirectUris:0" },
        { "AuthorizationServer:Clients:0:AllowedResources:0", "http://mcp.example.test/mcp", "AuthorizationServer:Clients:0:AllowedResources:0" },
        { "AuthorizationServer:Clients:0:AllowedResources:0", "https://mcp.example.test/mcp#part", "AuthorizationServer:Clients:0:AllowedResources:0" },
        { "AuthorizationServer:Clients:0:AllowedScopes:1", null, "AllowedScopes must include offline_access" },
        { "AuthorizationServer:EncryptionKey", null, "AuthorizationServer:EncryptionKey" },
        { "AuthorizationServer:EncryptionKey", "c2hvcnQ=", "AuthorizationServer:EncryptionKey" },
        { "Jwt:PublicBaseUrl", null, "Jwt:PublicBaseUrl" },
        { "Jwt:PublicBaseUrl", "http://localhost", "Jwt:PublicBaseUrl" },
        { "AuthorizationServer:Interaction:Mode", "External", "AuthorizationServer:Interaction:ExternalUrl" },
    };

    [Theory]
    [MemberData(nameof(UnsafeSettings))]
    public async Task Startup_refuses_unsafe_configuration_naming_the_setting(string key, string? value, string expected)
    {
        using var factory = new AuthorizationServerFactory(settings =>
        {
            if (value is null)
                settings.Remove(key);
            else
                settings[key] = value;
        });

        var exception = await Assert.ThrowsAnyAsync<Exception>(factory.InitializeAsync);

        Assert.Contains(expected, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Startup_refuses_symmetric_signing_naming_the_setting()
    {
        using var factory = new AuthorizationServerFactory(settings =>
        {
            settings.Remove("Jwt:Algorithm");
            settings.Remove("Jwt:PrivateKeyPem");
            settings["Jwt:SecretKey"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
        });

        var exception = await Assert.ThrowsAnyAsync<Exception>(factory.InitializeAsync);

        Assert.Contains("Jwt:Algorithm=RS256", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_loopback_redirect_uri_over_http_is_accepted()
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:RedirectUris:1"] = "http://127.0.0.1:33418/callback");

        await factory.InitializeAsync();
    }

    [Fact]
    public async Task A_configured_client_is_registered_as_confidential_with_its_secret_hashed()
    {
        using var factory = new AuthorizationServerFactory();
        await factory.InitializeAsync();

        await factory.WithScopeAsync(async services =>
        {
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(AuthorizationServerFactory.ClientId);
            Assert.NotNull(application);

            Assert.Equal(ClientTypes.Confidential, await applications.GetClientTypeAsync(application));
            Assert.Equal(AuthorizationServerFactory.ClientDisplayName, await applications.GetDisplayNameAsync(application));
            Assert.Equal(new[] { AuthorizationServerFactory.RedirectUri }, (await applications.GetRedirectUrisAsync(application)).ToArray());

            var permissions = await applications.GetPermissionsAsync(application);
            Assert.Contains(Permissions.Prefixes.Scope + AuthorizationServerFactory.Scope, permissions);
            Assert.Contains(Permissions.Prefixes.Resource + AuthorizationServerFactory.Resource, permissions);
            Assert.Contains(Permissions.GrantTypes.RefreshToken, permissions);

            // The library stores a PBKDF2 hash (AC5 notes), never the secret itself.
            var stored = (IOpenIddictApplicationStore<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>)
                services.GetRequiredService(typeof(IOpenIddictApplicationStore<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>));
            var secret = await stored.GetClientSecretAsync((OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication)application, default);
            Assert.NotEqual(factory.ClientSecret, secret);
            Assert.True(await applications.ValidateClientSecretAsync(application, factory.ClientSecret));
        });
    }

    [Fact]
    public async Task An_origin_root_resource_is_allowed_with_and_without_its_trailing_slash()
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:AllowedResources:0"] = "https://mcp.example.test");
        await factory.InitializeAsync();

        await factory.WithScopeAsync(async services =>
        {
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(AuthorizationServerFactory.ClientId);
            var permissions = await applications.GetPermissionsAsync(application!);

            Assert.Contains(Permissions.Prefixes.Resource + "https://mcp.example.test", permissions);
            Assert.Contains(Permissions.Prefixes.Resource + "https://mcp.example.test/", permissions);
        });
    }

    [Fact]
    public async Task Configuration_is_authoritative_for_an_existing_client()
    {
        using var original = new AuthorizationServerFactory();
        await original.InitializeAsync();

        // The same deployment restarted with the client's secret, name and redirect URI changed.
        using var restarted = new AuthorizationServerFactory(
            settings =>
            {
                settings["AuthorizationServer:Clients:0:DisplayName"] = "Claude (renamed)";
                settings["AuthorizationServer:Clients:0:RedirectUris:0"] = "https://claude.example.test/new_callback";
            },
            sharedConnection: original.Connection);
        await restarted.InitializeAsync();

        await restarted.WithScopeAsync(async services =>
        {
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(AuthorizationServerFactory.ClientId);

            Assert.Equal("Claude (renamed)", await applications.GetDisplayNameAsync(application!));
            Assert.Equal(new[] { "https://claude.example.test/new_callback" }, (await applications.GetRedirectUrisAsync(application!)).ToArray());
            Assert.True(await applications.ValidateClientSecretAsync(application!, restarted.ClientSecret));
            Assert.False(await applications.ValidateClientSecretAsync(application!, original.ClientSecret));
        });
    }

    [Fact]
    public async Task A_client_removed_from_configuration_is_deleted_with_its_grants()
    {
        using var original = new AuthorizationServerFactory();
        await original.InitializeAsync();
        using (var flow = new AuthorizationFlowClient(original))
        {
            var (email, _) = await flow.Backchannel.RegisterAsync();
            await flow.ConnectAsync(email);
        }

        // Restarted with a different client in its place.
        using var restarted = new AuthorizationServerFactory(
            settings => settings["AuthorizationServer:Clients:0:ClientId"] = "another-client",
            sharedConnection: original.Connection);
        await restarted.InitializeAsync();

        await restarted.WithScopeAsync(async services =>
        {
            var applications = services.GetRequiredService<IOpenIddictApplicationManager>();
            Assert.Null(await applications.FindByClientIdAsync(AuthorizationServerFactory.ClientId));
            Assert.NotNull(await applications.FindByClientIdAsync("another-client"));

            Assert.Equal(0, await services.GetRequiredService<IOpenIddictAuthorizationManager>().CountAsync());
            Assert.Equal(0, await services.GetRequiredService<IOpenIddictTokenManager>().CountAsync());
        });
    }

    [Fact]
    public async Task The_token_endpoint_is_limited_per_client_without_queueing()
    {
        using var factory = new AuthorizationServerFactory(settings =>
            settings["AuthorizationServer:Clients:0:TokenRequestsPerMinute"] = "2");
        await factory.InitializeAsync();
        using var flow = new AuthorizationFlowClient(factory);
        var (email, _) = await flow.Backchannel.RegisterAsync();

        var tokens = await flow.ConnectAsync(email); // the code exchange: request 1
        var refreshed = await AuthorizationFlowClient.ReadTokensAsync(await flow.RefreshAsync(tokens.RefreshToken!)); // 2

        var limited = await flow.RefreshAsync(refreshed.RefreshToken!); // 3

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        using var body = System.Text.Json.JsonDocument.Parse(await limited.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.TryGetProperty("retryAfter", out _));
    }

    [Fact]
    public void Options_validation_accepts_the_documented_shape()
    {
        var options = new AuthorizationServerOptions
        {
            EncryptionKey = Convert.ToBase64String(new byte[32]),
            Clients =
            [
                new AuthorizationServerClient
                {
                    ClientId = "claude",
                    DisplayName = "Claude",
                    ClientSecret = new string('a', 64),
                    RedirectUris = ["https://claude.ai/api/mcp/auth_callback"],
                    AllowedScopes = ["notes:read", "offline_access"],
                    AllowedResources = ["https://mcp.example.com/mcp"]
                }
            ]
        };

        Assert.Empty(options.Validate(JwtSigningAlgorithm.RS256, "https://auth.example.com/"));
    }
}

using System.Net;
using System.Text.Json;
using AuthService.Tests.Infrastructure;
using Xunit;

namespace AuthService.Tests;

/// <summary>
/// The endpoints a downstream service consumes. The test host signs with HS256 (the factory
/// supplies a secret, not a keypair), which is exactly why the empty-key-set behaviour is worth
/// asserting: the failure to avoid is serving the shared secret to anonymous callers.
/// </summary>
public class JwksEndpointTests : IntegrationTestBase
{
    [Fact]
    public async Task Jwks_is_served_anonymously()
    {
        var response = await Client.GetAsync("/.well-known/jwks.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Jwks_is_empty_under_symmetric_signing()
    {
        var response = await Client.GetAsync("/.well-known/jwks.json");
        var body = await response.Content.ReadAsStringAsync();

        using var document = JsonDocument.Parse(body);

        Assert.Equal(0, document.RootElement.GetProperty("keys").GetArrayLength());
    }

    [Fact]
    public async Task Discovery_reports_the_issuer_tokens_actually_carry()
    {
        // Not this service's URL: `iss` is the bare string "AuthService" by default, and a
        // consumer that trusted the URL here would reject every real token.
        var response = await Client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;

        Assert.Equal("AuthService", root.GetProperty("issuer").GetString());
        Assert.EndsWith("/.well-known/jwks.json", root.GetProperty("jwks_uri").GetString());
        Assert.Equal("HS256", root.GetProperty("id_token_signing_alg_values_supported")[0].GetString());
    }

    [Fact]
    public async Task Discovery_advertises_no_authorization_flows()
    {
        // ADR 0003: this is metadata for key discovery, not a claim to be an OIDC provider.
        var response = await Client.GetAsync("/.well-known/openid-configuration");

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(0, document.RootElement.GetProperty("response_types_supported").GetArrayLength());
    }
}
